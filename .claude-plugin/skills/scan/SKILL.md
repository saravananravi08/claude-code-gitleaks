# Gitleaks Scan

Manually run a gitleaks scan on the repository, staged files, or specific paths.

## Usage

Invoke via `/scan` or describe in conversation.

## What This Does

Runs `gitleaks` to detect secrets in:
- **Staged files** — Files staged for commit (`git diff --cached`)
- **Working directory** — All files in the current checkout
- **Specific paths** — Files or directories you specify
- **Git history** — Commits (requires repo clone)

## When to Use

- Before pushing to a remote
- After pulling external changes
- When debugging a potential secret leak
- During security audits

## Examples

### Scan staged files only (fast)
```
/scan --staged
```

### Scan entire repository
```
/scan
```

### Scan specific file
```
/scan src/config/credentials.json
```

### Scan a directory
```
/scan --path ./secrets/
```

### Scan commit range
```
/scan --from HEAD~5 --to HEAD
```

## Output

Gitleaks outputs:
- **File path** where secret was found
- **Line number**
- **Secret type** (e.g., AWS Key, GitHub Token, Private Key)
- **Rule ID** that matched

## Exit Codes

- `0` — No secrets found
- `1` — Secrets detected
- `2` — Error

## Installation

Requires gitleaks CLI:
```bash
brew install gitleaks  # macOS
# or download from https://github.com/gitleaks/gitleaks/releases
```