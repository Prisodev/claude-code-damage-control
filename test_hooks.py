#!/usr/bin/env python3
"""Functional tests for Damage Control hooks"""
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
    print(f"  {status}: {cmd_or_path[:60]} -> {actual} (expected {expected}) {detail}")
    return actual == expected

def main():
    passed = 0
    failed = 0

    # === BASH HOOK TESTS ===
    print("\n=== Bash Damage Control ===")
    bash_tests = [
        # Blocked commands
        ({'command': 'r' + 'm -rf /'}, 'block'),
        ({'command': 'r' + 'm -rf /*'}, 'block'),
        ({'command': 'r' + 'm -rf ~'}, 'block'),
        ({'command': 'r' + 'm -rf .git'}, 'block'),
        ({'command': 'git push --force origin main'}, 'block'),
        ({'command': 'git push -f origin main'}, 'block'),
        ({'command': 'git reset --hard HEAD~5'}, 'block'),
        ({'command': 'git clean -fd'}, 'block'),
        ({'command': 'git checkout -- .'}, 'block'),
        ({'command': 'chmod -R 777 /'}, 'block'),
        ({'command': 'kill -9 1234'}, 'block'),
        ({'command': 'shutdown now'}, 'block'),
        ({'command': 'reboot'}, 'block'),
        # Regex-based blocks (sneaky variants)
        ({'command': 'r' + 'm -r -f /var/www'}, 'block'),
        ({'command': 'find /tmp -name "*.log" -delete'}, 'block'),
        ({'command': 'git clean -fx'}, 'block'),
        ({'command': 'dd if=/dev/zero of=/dev/sda'}, 'block'),
        # Ask commands
        ({'command': 'cat .env.local'}, 'ask'),
        ({'command': 'pm2 restart app'}, 'ask'),
        ({'command': 'echo $API_KEY'}, 'ask'),
        # Allowed commands
        ({'command': 'ls -la'}, 'allow'),
        ({'command': 'echo hello'}, 'allow'),
        ({'command': 'git status'}, 'allow'),
        ({'command': 'npm install'}, 'allow'),
        ({'command': 'cat README.md'}, 'allow'),
        # Non-Bash tool should be ignored
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
        # Blocked - zero access
        ('Read', {'file_path': '/project/.env'}, 'block'),
        ('Read', {'file_path': '/project/.env.local'}, 'block'),
        ('Read', {'file_path': '/home/user/.ssh/config'}, 'block'),
        ('Read', {'file_path': '/project/credentials.json'}, 'block'),
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

    # === EDGE CASES ===
    print("\n=== Edge Cases ===")

    # Empty input
    result = subprocess.run(['python3', 'hooks/bash-damage-control.py'], input='', capture_output=True, text=True)
    if result.returncode == 0:
        print(f"  PASS: empty input handled gracefully")
        passed += 1
    else:
        print(f"  FAIL: empty input caused error (rc={result.returncode})")
        failed += 1

    # Invalid JSON
    result = subprocess.run(['python3', 'hooks/bash-damage-control.py'], input='not json', capture_output=True, text=True)
    if result.returncode == 0:
        print(f"  PASS: invalid JSON handled gracefully")
        passed += 1
    else:
        print(f"  FAIL: invalid JSON caused error (rc={result.returncode})")
        failed += 1

    # Missing command field
    result = subprocess.run(['python3', 'hooks/bash-damage-control.py'], input='{"tool_name":"Bash","tool_input":{}}', capture_output=True, text=True)
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
