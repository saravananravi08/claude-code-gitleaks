# Gitleaks Plugin for Claude Code

Secret detection plugin that scans staged files before `git commit` and `git push` to prevent credentials from leaking.

## Features

- **Automatic scanning** — Intercepts `git commit` and `git push` commands via PreToolUse hook
- **Staged files only** — Scans only the files being committed, not full history (fast)
- **Blocks leaks** — Denies commit/push if secrets are detected
- **Clear reporting** — Shows exactly what was found and where

## Installation

### 1. Install gitleaks CLI

```bash
brew install gitleaks  # macOS
# or: https://github.com/gitleaks/gitleaks/releases
```

### 2. Enable the plugin

Copy or link this plugin to your Claude Code plugins directory, or reference it in your Claude Code configuration.

## How It Works

```
Claude: Bash(git commit -m "fix auth bug")
    ↓
pre_bash.js hook intercepts
    ↓
gitleaks git --staged .  (scans only staged files)
    ↓
[secrets found] → BLOCKED with findings
[clean]         → commit allowed
```

## Commands Scanned

- `git commit`
- `git push`
- `git merge`
- `git cherry-pick`

## Configuration

The plugin uses default gitleaks rules. To customize:

```bash
# Generate default config
gitleaks generate > .gitleaks.toml

# Or use your org's config
cp /path/to/org-gitleaks.toml .gitleaks.toml
```

## Skip Check (Emergency)

If you need to bypass the scan temporarily:

```bash
# Export env var to skip gitleaks check
export GITLEAKS_SKIP=true
git commit -m "emergency fix"
```

## Files

```
.claude-plugin/
├── plugin.json          # Plugin manifest
├── hooks/
│   └── pre_bash.js      # PreToolUse hook script
└── skills/
    └── scan/
        └── SKILL.md     # /scan skill documentation
```

## Requirements

- Node.js (for hook script)
- gitleaks CLI in PATH