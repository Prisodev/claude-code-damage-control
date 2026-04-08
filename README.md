# Claude Code Damage Control

Pre-tool-use hooks that protect your production environment from destructive commands when using Claude Code.

## What it does

Damage Control intercepts every tool call Claude Code makes **before** it executes, and blocks or asks confirmation for dangerous operations:

- **Bash hooks** — blocks `rm -rf`, `git push --force`, `git reset --hard`, `dd`, fork bombs, and 20+ destructive command variants (including sneaky ones like `rm -r -f`, `find . -delete`)
- **Write/Edit hooks** — prevents overwriting secrets, protected files, and guards against empty-content overwrites on critical files  
- **Read hooks** — blocks reading `.env`, `.ssh`, credentials, and other sensitive files
- **YAML config** — all patterns are configurable per project via `patterns.yaml`

## Why you need this

Claude Code is powerful. It can also `rm -rf /var/www/your-production-app` if it thinks that's the right thing to do. This system catches those commands before they execute.

The hooks were battle-tested by a separate AI code reviewer agent, which found 2 critical bugs in the original implementation:
1. The "ask" flow fell through to "allow" (did nothing)
2. Substring matching could be bypassed with space variants (`rm  -r  -f`)

Both are fixed in this version.

## Quick install

```bash
# Clone into your project's .claude/hooks directory
git clone https://github.com/Prisodev/claude-code-damage-control.git /tmp/dc-install

# Copy hooks to your project
mkdir -p .claude/hooks
cp /tmp/dc-install/hooks/* .claude/hooks/

# Clean up
rm -rf /tmp/dc-install
```

Then add this to your `.claude/settings.local.json`:

```json
{
  "hooks": {
    "pre_tool_use": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "python3 .claude/hooks/bash-damage-control.py" }]
      },
      {
        "matcher": "Write|Edit|MultiEdit",
        "hooks": [{ "type": "command", "command": "python3 .claude/hooks/write-damage-control.py" }]
      },
      {
        "matcher": "Read",
        "hooks": [{ "type": "command", "command": "python3 .claude/hooks/read-damage-control.py" }]
      }
    ]
  }
}
```

## Configuration

Edit `hooks/patterns.yaml` to customize for your project:

```yaml
blocked_commands:      # Always blocked, no exceptions
  - "rm -rf /"
  - "git push --force"

ask_commands:          # Requires user confirmation
  - "pm2 restart"
  - ".env"

zero_access_paths:     # No read, no write, no touch
  - ".env"
  - ".ssh"

read_only_paths:       # Can read, cannot write
  - ".claude/hooks/"

no_delete_paths:       # Cannot delete or overwrite with empty content
  - "CLAUDE.md"
  - ".claude/"
```

## How it works

1. Claude Code calls a tool (Bash, Write, Read, etc.)
2. The pre_tool_use hook intercepts the call
3. The command/path is checked against `patterns.yaml` patterns AND regex patterns
4. Decision: `allow` (proceed), `ask` (user confirms), or `block` (rejected)

The Bash hook uses both substring matching AND regex patterns to catch creative variants:

```python
# Catches: rm -rf, rm -r -f, rm -fr, rm -r --force, etc.
r'\brm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?|...)'

# Catches: find . -delete, find /path -name "*.log" -delete
r'\bfind\b.*-delete\b'
```

## Requirements

- Python 3.8+
- PyYAML (`pip install pyyaml`)

## Want a complete production setup?

These hooks are just the foundation. A full production Claude Code setup includes:

- Custom AI agent teams (builder + validator pattern)
- Automated skills for deploy, audit, and scaffolding
- Library sync across machines
- Telegram/WhatsApp monitoring bots
- CI/CD integration

Interested? Reach out: [Richard van Leeuwen on LinkedIn](https://www.linkedin.com/in/richard-van-leeuwen-93651a171/)

## License

MIT
