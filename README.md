# Gitleaks Plugin for Claude Code

Secret detection plugin that scans staged files before `git commit` and `git push` to prevent credentials from leaking.

## Features

- **Automatic scanning** — Intercepts `git commit` and `git push` commands via PreToolUse hook
- **Staged files only** — Scans only the files being committed, not full history (fast)
- **Blocks leaks** — Denies commit/push if secrets are detected
- **Clear reporting** — Shows exactly what was found and where
- **Zero dependencies** — Uses embedded regex patterns (222 rules from gitleaks), no external CLI needed
- **Pure Node.js** — Only requires Node.js, no Python or binary downloads

## How It Works

```
Claude: Bash(git commit -m "fix auth bug")
    ↓
pre_bash.js hook intercepts
    ↓
Scans staged files with embedded gitleaks patterns (222 rules)
    ↓
[secrets found] → BLOCKED with findings
[clean]         → commit allowed
```

## Commands Scanned

- `git commit`
- `git push`
- `git merge`
- `git cherry-pick`

## Detection Coverage

The embedded scanner includes patterns for **222 secret types** including:

- AWS Access Keys
- GitHub/GitLab Tokens
- Slack/Discord Webhooks
- OpenAI/Anthropic API Keys
- Cloud provider credentials (Azure, GCP, DigitalOcean, etc.)
- Database connection strings
- Private keys and certificates
- And many more...

## Files

```
.claude-plugin/
├── marketplace.json      # Plugin distribution manifest
├── plugin.json           # Plugin manifest
hooks/
├── hooks.json            # PreToolUse hook configuration
├── pre_bash.js           # Hook script (uses embedded rules)
└── rules.js              # 222 embedded secret detection patterns
```

## Requirements

- **Node.js** (for hook script - already installed on macOS/Linux)

No external dependencies needed — all gitleaks patterns are embedded.