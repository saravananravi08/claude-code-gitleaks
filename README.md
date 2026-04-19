# Claude Code Gitleaks Plugin — Secret Detection Before Git Commit

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)
![GitHub Stars](https://img.shields.io/github/stars/saravananravi08/claude-code-gitleaks)

**Stop accidentally leaking secrets in git commits.** This Claude Code plugin intercepts `git commit` and `git push` commands, scans staged files for secrets (API keys, tokens, passwords), and blocks the operation if secrets are detected.

No external dependencies. Zero configuration. Works out of the box.

## What It Does

```
You: /commit "fix auth bug"
    ↓
Plugin scans staged files with 54 secret detection patterns
    ↓
[AWS keys, GitHub tokens, Slack webhooks, OpenAI keys, etc.]
    ↓
[secrets found] → Blocked with line-by-line report
[clean]         → Commit proceeds normally
```

## Why This Plugin?

| Approach | Speed | Setup Required | Dependencies |
|----------|-------|----------------|--------------|
| Full repo scan (gitleaks CLI) | Slow (minutes) | `brew install gitleaks` | Binary + Python |
| **This plugin** | **Fast (seconds)** | **Zero** | **Node.js only** |

- **Zero dependencies** — All 54 gitleaks patterns are embedded in pure JavaScript
- **Staged files only** — Scans only what you're about to commit (not full history)
- **Works offline** — No external API calls or network requests
- **Claude Code native** — Uses PreToolUse hook system, no extra configuration

## Secret Types Detected

The embedded scanner covers **54 secret patterns** including:

- **Cloud Providers**: AWS, Azure, GCP, DigitalOcean, Alibaba, Cloudflare
- **AI Services**: OpenAI, Anthropic, Cohere, Hugging Face
- **Version Control**: GitHub, GitLab, Bitbucket tokens and keys
- **Communication**: Slack, Discord, Teams webhooks and tokens
- **Payments**: Stripe, Square, PayPal, Coinbase
- **Databases**: PostgreSQL, MySQL, MongoDB connection strings
- **Infrastructure**: Terraform, Kubernetes, Vault secrets
- **And 200+ more** — [View full rule list](hooks/rules.js)

## Installation

```
/plugin marketplace add https://github.com/saravananravi08/claude-code-gitleaks
/plugin install gitleaks@claude-code-gitleaks
/reload-plugins
```

That's it — plugin auto-activates when Claude Code runs in a project with the hooks configured.

## Commands Protected

The plugin intercepts and scans these git commands:

- `git commit` — Scans staged files before commit
- `git push` — Scans staged files before push
- `git merge` — Scans staged files before merge
- `git cherry-pick` — Scans staged files before cherry-pick

## Configuration

### Custom Rules

Edit `hooks/rules.js` to add or modify secret detection patterns:

```javascript
// Add a custom rule
{ id: 'my-api-key', regex: /\bMYCOMPANY_[A-Z0-9]{32}\b/, desc: 'My Company API Key' }
```

### Skip Scanning (Emergency)

If you need to bypass the scan temporarily:

```bash
export GITLEAKS_SKIP=true
git commit -m "emergency fix"
```

## Files

```
claude-code-gitleaks/
├── .claude-plugin/
│   ├── marketplace.json      # Plugin manifest
│   └── plugin.json           # Distribution config
├── hooks/
│   ├── hooks.json            # PreToolUse hook configuration
│   ├── pre_bash.js           # Hook script
│   └── rules.js              # 54 embedded secret detection patterns
└── README.md
```

## How It Works

1. **PreToolUse Hook** — Claude Code calls the hook before executing `Bash(git commit)`
2. **Staged File Extraction** — Uses `git diff --cached --name-only` to get staged files
3. **Content Retrieval** — Uses `git show :<filepath>` to read staged content
4. **Pattern Matching** — Runs 54 regex patterns against file contents
5. **Block/Allow Decision** — Returns `permissionDecision: "deny"` with findings if match found

## Comparison: This Plugin vs Alternatives

| Feature | Gitleaks CLI | detect-secrets | **This Plugin** |
|---------|--------------|----------------|-----------------|
| Setup | `brew install` | `pip install` | **Copy folder** |
| Dependencies | Binary | Python | **Node.js only** |
| Scan scope | Full repo | Full repo | **Staged only** |
| Pre-commit hook | Yes | Yes | **Yes** |
| Zero config | No | No | **Yes** |
| Embedded rules | No | No | **Yes (54)** |

## Contributing

Contributions welcome! To add new secret patterns:

1. Fork the repo
2. Add your rule to `hooks/rules.js` in the `RULES` array
3. Test against a file containing the secret
4. Submit a PR

## License

MIT — free to use, modify, and distribute.

---

**Made for Claude Code users who want to prevent credential leaks without installing extra tools.**