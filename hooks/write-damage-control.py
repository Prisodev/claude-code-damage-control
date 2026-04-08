#!/usr/bin/env python3
"""
Write/Edit Damage Control v2 — pre_tool_use hook for Claude Code
Protects secrets, read-only files, and guards against empty-content overwrites
"""
import json
import sys
import os
import yaml

def load_patterns():
    patterns_path = os.path.join(os.path.dirname(__file__), "patterns.yaml")
    try:
        with open(patterns_path) as f:
            return yaml.safe_load(f)
    except (FileNotFoundError, yaml.YAMLError):
        print(json.dumps({"decision": "block", "reason": "patterns.yaml missing or corrupt — blocking all writes for safety"}))
        sys.exit(2)

def main():
    try:
        input_data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, EOFError):
        sys.exit(0)

    tool_name = input_data.get("tool_name", "")
    if tool_name not in ("Write", "Edit", "MultiEdit"):
        sys.exit(0)

    file_path = input_data.get("tool_input", {}).get("file_path", "")
    if not file_path:
        sys.exit(0)

    patterns = load_patterns()

    # Zero access — geen schrijven
    for path in patterns.get("zero_access_paths", []):
        if path in file_path:
            print(json.dumps({
                "decision": "block",
                "reason": f"Zero-access: '{path}' cannot be written. May contain secrets."
            }))
            sys.exit(2)

    # Read-only — geen schrijven
    for path in patterns.get("read_only_paths", []):
        if path in file_path:
            print(json.dumps({
                "decision": "block",
                "reason": f"Read-only: '{file_path}' is protected. Ask the user to modify this manually."
            }))
            sys.exit(2)

    # No-delete bescherming: Write met lege/minimale content op beschermde bestanden
    # vereist bevestiging (ask) — voorkomt overschrijven als delete
    for path in patterns.get("no_delete_paths", []):
        if path in file_path:
            content = input_data.get("tool_input", {}).get("content", "")
            if len(content.strip()) < 10:
                print(json.dumps({
                    "decision": "ask",
                    "reason": f"Protected file '{file_path}' is being overwritten with minimal content ({len(content)} chars). Is this correct?"
                }))
            break

    sys.exit(0)

if __name__ == "__main__":
    main()
