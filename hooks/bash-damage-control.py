#!/usr/bin/env python3
"""
Bash Damage Control v2 — pre_tool_use hook for Claude Code
Blocks destructive commands, catches regex variants, requires confirmation for sensitive ops
"""
import json
import sys
import os
import re
import yaml

def load_patterns():
    patterns_path = os.path.join(os.path.dirname(__file__), "patterns.yaml")
    try:
        with open(patterns_path) as f:
            return yaml.safe_load(f)
    except (FileNotFoundError, yaml.YAMLError):
        print(json.dumps({"decision": "block", "reason": "patterns.yaml missing or corrupt — blocking all commands for safety"}))
        sys.exit(2)

# Extra regex patterns voor destructieve commands die substring matching omzeilen
DESTRUCTIVE_REGEXES = [
    (r'\brm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?|(-[a-zA-Z]*f[a-zA-Z]*\s+)?-[a-zA-Z]*r[a-zA-Z]*\s+)[/~.]', "rm -rf variant"),
    (r'\bfind\b.*-delete\b', "find -delete"),
    (r'\bgit\s+push\b.*--force', "git push --force variant"),
    (r'\bgit\s+reset\b.*--hard', "git reset --hard variant"),
    (r'\bgit\s+clean\b.*-[a-zA-Z]*f', "git clean -f variant"),
    (r'\bkill\b\s+-(KILL|9|SIGKILL)', "kill -9 variant"),
    (r'\bchmod\b.*\b777\b', "chmod 777 variant"),
    (r'\bdd\b\s+.*\b(if|of)=', "dd command"),
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
            return "ask", f"Confirmation required: command contains '{ask_pattern}'"

    return "allow", ""

def check_paths(command: str, patterns: dict) -> tuple[str, str]:
    for path in patterns.get("zero_access_paths", []):
        if path in command:
            return "block", f"Zero-access path: '{path}' cannot be accessed"

    # Check no-delete paths for ANY destructive file operation
    destructive_ops = ["rm ", "rm\t", "unlink ", "del ", "> /dev/null", "truncate ", "shred "]
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

    decision, reason = check_command(command, patterns)
    if decision == "block":
        print(json.dumps({"decision": "block", "reason": reason}))
        sys.exit(2)
    if decision == "ask":
        print(json.dumps({"decision": "ask", "reason": reason}))
        sys.exit(0)

    decision, reason = check_paths(command, patterns)
    if decision == "block":
        print(json.dumps({"decision": "block", "reason": reason}))
        sys.exit(2)

    sys.exit(0)

if __name__ == "__main__":
    main()
