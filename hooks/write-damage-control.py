#!/usr/bin/env python3
"""
Write/Edit Damage Control v2 — pre_tool_use hook
Fixes: no_delete_paths check bij Write (voorkomt overschrijven als delete)
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
        print(json.dumps({"decision": "block", "reason": "patterns.yaml ontbreekt of is corrupt — alles geblokkeerd voor veiligheid"}))
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
                "reason": f"Zero-access: '{path}' mag niet geschreven worden. Bevat mogelijk secrets."
            }))
            sys.exit(2)

    # Read-only — geen schrijven
    for path in patterns.get("read_only_paths", []):
        if path in file_path:
            print(json.dumps({
                "decision": "block",
                "reason": f"Read-only: '{file_path}' is beschermd. Vraag de gebruiker om dit handmatig te wijzigen."
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
                    "reason": f"Beschermd bestand '{file_path}' wordt overschreven met minimale content ({len(content)} chars). Klopt dit?"
                }))
            break

    sys.exit(0)

if __name__ == "__main__":
    main()
