#!/usr/bin/env python3
"""
Read Damage Control — pre_tool_use hook for Claude Code
Blocks reading of secrets, keys, and other sensitive files
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
        print(json.dumps({"decision": "block", "reason": "patterns.yaml missing or corrupt"}))
        sys.exit(2)

def main():
    try:
        input_data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, EOFError):
        sys.exit(0)

    if input_data.get("tool_name") != "Read":
        sys.exit(0)

    file_path = input_data.get("tool_input", {}).get("file_path", "")
    if not file_path:
        sys.exit(0)

    patterns = load_patterns()

    for path in patterns.get("zero_access_paths", []):
        if path in file_path:
            print(json.dumps({
                "decision": "block",
                "reason": f"Zero-access: '{path}' cannot be read. May contain secrets."
            }))
            sys.exit(2)

    sys.exit(0)

if __name__ == "__main__":
    main()
