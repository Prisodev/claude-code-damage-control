#!/usr/bin/env python3
"""
Bash Damage Control v3 — pre_tool_use hook for Claude Code
Blocks destructive commands, catches regex variants, requires confirmation for sensitive ops
"""
import json
import sys
import os
import re

try:
    import yaml
except ImportError:
    print(json.dumps({"decision": "block", "reason": "PyYAML not installed. Run: pip install pyyaml"}))
    sys.exit(2)

def load_patterns():
    patterns_path = os.path.join(os.path.dirname(__file__), "patterns.yaml")
    try:
        with open(patterns_path) as f:
            return yaml.safe_load(f)
    except (FileNotFoundError, yaml.YAMLError):
        print(json.dumps({"decision": "block", "reason": "patterns.yaml missing or corrupt — blocking all commands for safety"}))
        sys.exit(2)

# Regex patterns for destructive commands — uses word boundaries to avoid false positives
DESTRUCTIVE_REGEXES = [
    # rm -rf variants: catches rm -rf, rm -r -f, rm -fr, etc. with ANY path argument
    (r'\brm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?|(-[a-zA-Z]*f[a-zA-Z]*\s+)?-[a-zA-Z]*r[a-zA-Z]*\s+)\S', "rm -rf variant"),
    (r'\bfind\b.*-delete\b', "find -delete"),
    # git push --force but NOT --force-with-lease (which is the safe alternative)
    (r'\bgit\s+push\b.*--force(?!-with-lease)\b', "git push --force variant"),
    (r'\bgit\s+reset\b.*--hard', "git reset --hard variant"),
    (r'\bgit\s+clean\b.*-[a-zA-Z]*f', "git clean -f variant"),
    # System commands with word boundaries to avoid matching in filenames
    (r'\bkill\s+-(KILL|9|SIGKILL)\b', "kill -9 variant"),
    (r'\bkillall\b', "killall command"),
    (r'\bpkill\b', "pkill command"),
    (r'\bchmod\b.*\b777\b', "chmod 777 variant"),
    (r'\bchown\s+-[a-zA-Z]*R', "chown -R variant"),
    (r'\bshutdown(\s|$)', "shutdown command"),
    (r'\breboot(\s|$)', "reboot command"),
    (r'\bdd\b\s+.*\b(if|of)=', "dd command"),
]

# Commands that read file contents — used to protect sensitive paths via bash
FILE_READ_COMMANDS = [
    r'\bcat\b', r'\bless\b', r'\bmore\b', r'\bhead\b', r'\btail\b',
    r'\bsed\b', r'\bawk\b', r'\bsource\b', r'\b\.\s',
]

def check_command(command: str, patterns: dict) -> tuple[str, str]:
    cmd_lower = command.lower().strip()

    # Check blocked commands (substring)
    for blocked in patterns.get("blocked_commands", []):
        if blocked.lower() in cmd_lower:
            return "block", f"Blocked: '{blocked}' is a destructive command"

    # Check destructive regex patterns
    for regex, label in DESTRUCTIVE_REGEXES:
        if re.search(regex, command, re.IGNORECASE):
            return "block", f"Blocked: '{label}' detected"

    # Check ask patterns
    for ask_pattern in patterns.get("ask_commands", []):
        if ask_pattern.lower() in cmd_lower:
            # Don't flag .env.example as sensitive
            if ask_pattern == ".env" and ".env.example" in command:
                continue
            return "ask", f"Confirmation required: command contains '{ask_pattern}'"

    return "allow", ""

def check_paths(command: str, patterns: dict) -> tuple[str, str]:
    # Check zero-access paths in any command
    for path in patterns.get("zero_access_paths", []):
        # Allow .env.example (not a secret)
        if path == ".env" and ".env.example" in command:
            continue
        if path in command:
            return "block", f"Zero-access path: '{path}' cannot be accessed"

    # Check for file-reading commands targeting sensitive paths
    is_read_cmd = any(re.search(regex, command, re.IGNORECASE) for regex in FILE_READ_COMMANDS)
    if is_read_cmd:
        for path in patterns.get("zero_access_paths", []):
            if path == ".env" and ".env.example" in command:
                continue
            if path in command:
                return "block", f"Zero-access path: cannot read '{path}' via shell command"

    # Check no-delete paths for ANY destructive file operation
    destructive_ops = ["rm ", "rm\t", "unlink ", "truncate ", "shred "]
    if any(op in command.lower() for op in destructive_ops):
        for path in patterns.get("no_delete_paths", []):
            if path in command:
                return "block", f"No-delete path: files in '{path}' cannot be deleted"

    return "allow", ""

def main():
    try:
        input_data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, EOFError):
        sys.exit(0)

    if input_data.get("tool_name") != "Bash":
        sys.exit(0)

    command = input_data.get("tool_input", {}).get("command", "")
    if not command:
        sys.exit(0)

    patterns = load_patterns()

    # Phase 1: check for hard blocks (commands + regexes)
    decision, reason = check_command(command, patterns)
    if decision == "block":
        print(json.dumps({"decision": "block", "reason": reason}))
        sys.exit(2)

    # Phase 2: check paths — zero_access blocks take priority over ask
    path_decision, path_reason = check_paths(command, patterns)
    if path_decision == "block":
        print(json.dumps({"decision": "block", "reason": path_reason}))
        sys.exit(2)

    # Phase 3: ask confirmations (from check_command)
    if decision == "ask":
        print(json.dumps({"decision": "ask", "reason": reason}))
        sys.exit(0)

    sys.exit(0)

if __name__ == "__main__":
    main()
