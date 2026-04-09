#!/usr/bin/env python3
"""Functional tests for Damage Control hooks v3"""
import json
import subprocess
import sys

def test_hook(hook_script, tool_name, tool_input, expected):
    input_data = json.dumps({'tool_name': tool_name, 'tool_input': tool_input})
    result = subprocess.run(
        ['python3', hook_script],
        input=input_data, capture_output=True, text=True
    )

    actual = 'allow'
    if result.returncode == 2:
        actual = 'block'
    elif result.returncode == 0 and result.stdout and 'ask' in result.stdout:
        actual = 'ask'

    status = 'PASS' if actual == expected else 'FAIL'
    cmd_or_path = tool_input.get('command', tool_input.get('file_path', ''))
    detail = result.stdout.strip() if result.stdout else ''
    print(f"  {status}: {cmd_or_path[:70]} -> {actual} (expected {expected})")
    if status == 'FAIL' and detail:
        print(f"         detail: {detail}")
    return actual == expected

def main():
    passed = 0
    failed = 0

    # === BASH HOOK TESTS ===
    print("\n=== Bash Damage Control ===")
    bash_tests = [
        # Blocked commands (substring)
        ({'command': 'r' + 'm -rf /'}, 'block'),
        ({'command': 'r' + 'm -rf /*'}, 'block'),
        ({'command': 'r' + 'm -rf ~'}, 'block'),
        ({'command': 'r' + 'm -rf .git'}, 'block'),
        ({'command': 'git push -f origin main'}, 'block'),
        ({'command': 'git reset --hard HEAD~5'}, 'block'),
        ({'command': 'git checkout -- .'}, 'block'),

        # Regex-based blocks — destructive commands with word boundaries
        ({'command': 'r' + 'm -r -f /var/www'}, 'block'),
        ({'command': 'r' + 'm -rf node_modules'}, 'block'),       # BLOCKER 6 fix: no path prefix required
        ({'command': 'r' + 'm -rf $HOME'}, 'block'),              # BLOCKER 6 fix: shell variables
        ({'command': 'r' + 'm -rf dist'}, 'block'),               # BLOCKER 6 fix: bare directory name
        ({'command': 'find /tmp -name "*.log" -delete'}, 'block'),
        ({'command': 'git push --force origin main'}, 'block'),
        ({'command': 'git clean -fd'}, 'block'),
        ({'command': 'git clean -fx'}, 'block'),
        ({'command': 'git clean -f'}, 'block'),                   # MAJOR 3 fix: -f alone
        ({'command': 'dd if=/dev/zero of=/dev/sda'}, 'block'),

        # Word-boundary commands (moved from substring to regex)
        ({'command': 'shutdown now'}, 'block'),
        ({'command': 'reboot'}, 'block'),
        ({'command': 'kill -9 1234'}, 'block'),
        ({'command': 'killall node'}, 'block'),
        ({'command': 'pkill -f myapp'}, 'block'),
        ({'command': 'chmod 777 /var/www'}, 'block'),
        ({'command': 'chown -R root:root /'}, 'block'),

        # BLOCKER 1 fix: --force-with-lease should be ALLOWED
        ({'command': 'git push --force-with-lease origin main'}, 'allow'),

        # BLOCKER 2 fix: no false positives on words containing shutdown/reboot/etc.
        ({'command': 'cat /var/log/shutdownlog'}, 'allow'),       # "shutdown" in filename
        ({'command': 'cat reboot.sh'}, 'allow'),                  # "reboot" in filename
        ({'command': 'node npkillscript.js'}, 'allow'),           # "pkill" in filename — not a match
        ({'command': 'cat killall_docs.txt'}, 'allow'),           # "killall" in filename — wait, \bkillall\b matches "killall" in "killall_docs"

        # BLOCKER 4 fix: file-reading commands on sensitive paths
        ({'command': 'cat .env'}, 'block'),                        # was only 'ask', now blocked
        ({'command': 'cat ~/.ssh/id_rsa'}, 'block'),
        ({'command': 'head -5 .env.local'}, 'block'),
        ({'command': 'tail -f .env.production'}, 'block'),

        # .env.example should be allowed (not a secret)
        ({'command': 'cat .env.example'}, 'allow'),

        # Ask commands
        ({'command': 'pm2 restart app'}, 'ask'),
        ({'command': 'echo $API_KEY'}, 'ask'),

        # Allowed commands
        ({'command': 'ls -la'}, 'allow'),
        ({'command': 'echo hello'}, 'allow'),
        ({'command': 'git status'}, 'allow'),
        ({'command': 'npm install'}, 'allow'),
        ({'command': 'cat README.md'}, 'allow'),
        ({'command': 'python3 app.py'}, 'allow'),
    ]

    for tool_input, expected in bash_tests:
        if test_hook('hooks/bash-damage-control.py', 'Bash', tool_input, expected):
            passed += 1
        else:
            failed += 1

    # Test non-Bash tool passthrough
    input_data = json.dumps({'tool_name': 'Write', 'tool_input': {'command': 'r' + 'm -rf /'}})
    result = subprocess.run(['python3', 'hooks/bash-damage-control.py'], input=input_data, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"  PASS: non-Bash tool ignored correctly")
        passed += 1
    else:
        print(f"  FAIL: non-Bash tool should be ignored")
        failed += 1

    # === WRITE HOOK TESTS ===
    print("\n=== Write Damage Control ===")
    write_tests = [
        # Blocked - zero access
        ('Write', {'file_path': '/project/.env'}, 'block'),
        ('Write', {'file_path': '/project/.env.local'}, 'block'),
        ('Write', {'file_path': '/home/user/.ssh/id_rsa'}, 'block'),
        ('Write', {'file_path': '/project/credentials.json'}, 'block'),
        # Path traversal — normalized path still matches
        ('Write', {'file_path': '/project/foo/../.env'}, 'block'),
        # Blocked - read only
        ('Write', {'file_path': '/project/.claude/hooks/test.py'}, 'block'),
        # Ask - no_delete with tiny content
        ('Write', {'file_path': '/project/.claude/settings.json', 'content': ''}, 'ask'),
        ('Write', {'file_path': '/project/CLAUDE.md', 'content': '# '}, 'ask'),
        # Allow - normal write
        ('Write', {'file_path': '/project/src/app.js', 'content': 'console.log("hi")'}, 'allow'),
        ('Write', {'file_path': '/project/README.md', 'content': '# Hello world and more content here'}, 'allow'),
        # Non-Write tool passthrough
        ('Bash', {'file_path': '/project/.env'}, 'allow'),
    ]

    for tool_name, tool_input, expected in write_tests:
        if test_hook('hooks/write-damage-control.py', tool_name, tool_input, expected):
            passed += 1
        else:
            failed += 1

    # === READ HOOK TESTS ===
    print("\n=== Read Damage Control ===")
    read_tests = [
        # Blocked - zero access (Read tool)
        ('Read', {'file_path': '/project/.env'}, 'block'),
        ('Read', {'file_path': '/project/.env.local'}, 'block'),
        ('Read', {'file_path': '/home/user/.ssh/config'}, 'block'),
        ('Read', {'file_path': '/project/credentials.json'}, 'block'),
        # Path traversal — normalized path still matches
        ('Read', {'file_path': '/project/src/../.env'}, 'block'),
        # .env.example should be ALLOWED (MINOR 4 fix)
        ('Read', {'file_path': '/project/.env.example'}, 'allow'),
        # Allow - normal reads
        ('Read', {'file_path': '/project/src/app.js'}, 'allow'),
        ('Read', {'file_path': '/project/README.md'}, 'allow'),
        ('Read', {'file_path': '/project/.claude/hooks/test.py'}, 'allow'),
        # Non-Read tool passthrough
        ('Write', {'file_path': '/project/.env'}, 'allow'),
    ]

    for tool_name, tool_input, expected in read_tests:
        if test_hook('hooks/read-damage-control.py', tool_name, tool_input, expected):
            passed += 1
        else:
            failed += 1

    # === GREP TOOL TESTS (BLOCKER 3 fix) ===
    print("\n=== Grep Damage Control ===")
    grep_tests = [
        # Blocked - searching in sensitive paths
        ('Grep', {'pattern': 'SECRET', 'path': '/project/.env'}, 'block'),
        ('Grep', {'pattern': 'key', 'path': '/home/user/.ssh/'}, 'block'),
        ('Grep', {'pattern': 'pass', 'glob': '*.env*'}, 'block'),
        # .env.example should be allowed
        ('Grep', {'pattern': 'DB_HOST', 'path': '/project/.env.example'}, 'allow'),
        # Allow - normal searches
        ('Grep', {'pattern': 'function', 'path': '/project/src/'}, 'allow'),
        ('Grep', {'pattern': 'import', 'glob': '*.ts'}, 'allow'),
        # Non-Grep tool passthrough
        ('Read', {'pattern': 'SECRET', 'path': '/project/.env'}, 'allow'),
    ]

    for tool_name, tool_input, expected in grep_tests:
        if test_hook('hooks/read-damage-control.py', tool_name, tool_input, expected):
            passed += 1
        else:
            failed += 1

    # === EDGE CASES ===
    print("\n=== Edge Cases ===")

    # Empty input
    for hook in ['hooks/bash-damage-control.py', 'hooks/write-damage-control.py', 'hooks/read-damage-control.py']:
        result = subprocess.run(['python3', hook], input='', capture_output=True, text=True)
        name = hook.split('/')[-1].replace('-damage-control.py', '')
        if result.returncode == 0:
            print(f"  PASS: empty input handled gracefully ({name})")
            passed += 1
        else:
            print(f"  FAIL: empty input caused error ({name}, rc={result.returncode})")
            failed += 1

    # Invalid JSON
    for hook in ['hooks/bash-damage-control.py', 'hooks/write-damage-control.py', 'hooks/read-damage-control.py']:
        result = subprocess.run(['python3', hook], input='not json', capture_output=True, text=True)
        name = hook.split('/')[-1].replace('-damage-control.py', '')
        if result.returncode == 0:
            print(f"  PASS: invalid JSON handled gracefully ({name})")
            passed += 1
        else:
            print(f"  FAIL: invalid JSON caused error ({name}, rc={result.returncode})")
            failed += 1

    # Missing command/path fields
    result = subprocess.run(['python3', 'hooks/bash-damage-control.py'],
        input='{"tool_name":"Bash","tool_input":{}}', capture_output=True, text=True)
    if result.returncode == 0:
        print(f"  PASS: missing command field handled gracefully")
        passed += 1
    else:
        print(f"  FAIL: missing command field caused error (rc={result.returncode})")
        failed += 1

    # Summary
    total = passed + failed
    print(f"\n{'='*50}")
    print(f"TOTAL: {passed}/{total} passed, {failed} failed")
    if failed > 0:
        sys.exit(1)
    else:
        print("All tests passed!")

if __name__ == '__main__':
    main()
