#!/usr/bin/env python3
"""
Write/Edit Damage Control v4 — pre_tool_use hook for Claude Code
Protects secrets, read-only files, scans for leaked tokens, guards against empty-content overwrites
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
        print(json.dumps({"decision": "block", "reason": "patterns.yaml missing or corrupt — blocking all writes for safety"}))
        sys.exit(2)

# Token patterns — detect leaked secrets in file content
TOKEN_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'(?<![a-zA-Z0-9/+=])(?:[A-Za-z0-9/+=]{40})(?![a-zA-Z0-9/+=])', None),  # skip — too many false positives
    (r'sk_live_[0-9a-zA-Z]{24,}', "Stripe Live Secret Key"),
    (r'pk_live_[0-9a-zA-Z]{24,}', "Stripe Live Publishable Key"),
    (r'sk-[a-zA-Z0-9]{20,}', "OpenAI/AI API Secret Key"),
    (r'ghp_[0-9a-zA-Z]{36}', "GitHub Personal Access Token"),
    (r'ghs_[0-9a-zA-Z]{36}', "GitHub Server-to-Server Token"),
    (r'gho_[0-9a-zA-Z]{36}', "GitHub OAuth Token"),
    (r'github_pat_[0-9a-zA-Z_]{22,}', "GitHub Fine-Grained PAT"),
    (r'glpat-[0-9a-zA-Z\-_]{20,}', "GitLab Personal Access Token"),
    (r'xoxb-[0-9]{10,}-[0-9a-zA-Z]{24,}', "Slack Bot Token"),
    (r'xoxp-[0-9]{10,}-[0-9a-zA-Z]{24,}', "Slack User Token"),
    (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "Private Key"),
    (r'sq0csp-[0-9A-Za-z\-_]{43}', "Square Access Token"),
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key"),
]

def scan_tokens(content, file_path):
    """Scan file content for leaked tokens/secrets. Returns (decision, reason) or None."""
    # Skip scanning for known safe files
    safe_extensions = ('.md', '.txt', '.yaml', '.yml', '.toml', '.cfg', '.ini', '.example')
    if any(file_path.endswith(ext) for ext in safe_extensions):
        return None
    # Skip test files
    if 'test' in file_path.lower() or 'spec' in file_path.lower() or 'mock' in file_path.lower():
        return None

    for pattern, label in TOKEN_PATTERNS:
        if label is None:
            continue  # skip disabled patterns
        if re.search(pattern, content):
            return "block", f"Leaked secret detected: {label} found in '{file_path}'. Never write secrets to source files."
    return None

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

    # Normalize path to prevent traversal bypasses
    file_path_normalized = os.path.normpath(file_path)
    patterns = load_patterns()

    # Zero access — no writing
    for path in patterns.get("zero_access_paths", []):
        # Allow .env.example (not a secret)
        if path == ".env" and ".env.example" in file_path_normalized:
            continue
        if path in file_path_normalized:
            print(json.dumps({
                "decision": "block",
                "reason": f"Zero-access: '{path}' cannot be written. May contain secrets."
            }))
            sys.exit(2)

    # Read-only — no writing
    for path in patterns.get("read_only_paths", []):
        if path in file_path_normalized:
            print(json.dumps({
                "decision": "block",
                "reason": f"Read-only: '{file_path}' is protected. Ask the user to modify this manually."
            }))
            sys.exit(2)

    # No-delete protection: Write with empty/minimal content on protected files
    # requires confirmation (ask) — prevents overwrite-as-delete
    content = input_data.get("tool_input", {}).get("content", "")
    for path in patterns.get("no_delete_paths", []):
        if path in file_path_normalized:
            if len(content.strip()) < 10:
                print(json.dumps({
                    "decision": "ask",
                    "reason": f"Protected file '{file_path}' is being overwritten with minimal content ({len(content)} chars). Is this correct?"
                }))
                sys.exit(0)
            break

    # Token scanning — detect leaked secrets in file content (Write tool only)
    if tool_name == "Write" and content:
        token_result = scan_tokens(content, file_path)
        if token_result:
            decision, reason = token_result
            print(json.dumps({"decision": decision, "reason": reason}))
            sys.exit(2)

    sys.exit(0)

if __name__ == "__main__":
    main()
