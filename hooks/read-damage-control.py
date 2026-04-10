#!/usr/bin/env python3
"""
Read Damage Control v3 — pre_tool_use hook for Claude Code
Blocks reading of secrets, keys, and other sensitive files.
Also intercepts Grep and Glob tools to prevent searching through sensitive paths.
"""
import json
import sys
import os

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
        print(json.dumps({"decision": "block", "reason": "patterns.yaml missing or corrupt"}))
        sys.exit(2)

def main():
    try:
        input_data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, EOFError):
        sys.exit(0)

    tool_name = input_data.get("tool_name", "")

    # Handle Read tool
    if tool_name == "Read":
        file_path = input_data.get("tool_input", {}).get("file_path", "")
        if not file_path:
            sys.exit(0)

        patterns = load_patterns()
        file_path_normalized = os.path.normpath(file_path)

        for path in patterns.get("zero_access_paths", []):
            # Allow .env.example (not a secret)
            if path == ".env" and file_path_normalized.endswith(".env.example"):
                continue
            if path in file_path_normalized:
                print(json.dumps({
                    "decision": "block",
                    "reason": f"Zero-access: '{path}' cannot be read. May contain secrets."
                }))
                sys.exit(2)

    # Handle Grep tool — check the search path
    elif tool_name == "Grep":
        tool_input = input_data.get("tool_input", {})
        search_path = tool_input.get("path", "")
        glob_pattern = tool_input.get("glob", "")

        if not search_path and not glob_pattern:
            sys.exit(0)

        patterns = load_patterns()

        for path in patterns.get("zero_access_paths", []):
            # Check if grep is targeting a sensitive path
            if search_path and path in search_path:
                if path == ".env" and ".env.example" in search_path:
                    continue
                print(json.dumps({
                    "decision": "block",
                    "reason": f"Zero-access: cannot search in '{path}'. May contain secrets."
                }))
                sys.exit(2)

            # Check if glob pattern targets sensitive files
            if glob_pattern and path in glob_pattern:
                if path == ".env" and ".env.example" in glob_pattern:
                    continue
                print(json.dumps({
                    "decision": "block",
                    "reason": f"Zero-access: cannot search '{glob_pattern}'. May match secrets."
                }))
                sys.exit(2)

    # Handle Glob tool — check the search pattern and path
    elif tool_name == "Glob":
        tool_input = input_data.get("tool_input", {})
        glob_pattern = tool_input.get("pattern", "")
        search_path = tool_input.get("path", "")

        if not glob_pattern and not search_path:
            sys.exit(0)

        patterns = load_patterns()

        for path in patterns.get("zero_access_paths", []):
            # Check if glob pattern targets sensitive files
            if glob_pattern and path in glob_pattern:
                if path == ".env" and ".env.example" in glob_pattern:
                    continue
                print(json.dumps({
                    "decision": "block",
                    "reason": f"Zero-access: cannot glob for '{glob_pattern}'. May reveal secrets."
                }))
                sys.exit(2)

            # Check if search path targets sensitive directory
            if search_path and path in search_path:
                if path == ".env" and ".env.example" in search_path:
                    continue
                print(json.dumps({
                    "decision": "block",
                    "reason": f"Zero-access: cannot glob in '{search_path}'. May contain secrets."
                }))
                sys.exit(2)

    sys.exit(0)

if __name__ == "__main__":
    main()
