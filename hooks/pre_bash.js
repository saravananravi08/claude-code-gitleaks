#!/usr/bin/env node
/**
 * pre_bash.js - Gitleaks PreToolUse Hook
 *
 * Intercepts Bash tool calls for git commit/push and scans staged files
 * for secrets before allowing the operation to proceed.
 */

const { execSync, spawn } = require('child_process');
const path = require('path');

// Git commands that modify remote state and should be scanned
const RISKY_COMMANDS = ['commit', 'push', 'merge', 'cherry-pick'];

/**
 * Check if a git command is risky (modifies remote state)
 */
function isRiskyGitCommand(command) {
  const lowerCmd = command.toLowerCase();
  return RISKY_COMMANDS.some(risk => lowerCmd.includes(risk));
}

/**
 * Get the git repository root directory
 */
function getGitRoot() {
  try {
    return execSync('git rev-parse --show-toplevel 2>/dev/null', {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe']
    }).trim();
  } catch {
    return process.cwd();
  }
}

/**
 * Get list of staged files in the current commit
 */
function getStagedFiles() {
  try {
    const files = execSync('git diff --cached --name-only 2>/dev/null', {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe']
    }).trim().split('\n').filter(f => f.length > 0);
    return files;
  } catch {
    return [];
  }
}

/**
 * Run gitleaks on staged files
 * Uses: gitleaks git --staged <repo-path>
 */
function runGitleaksScan(repoPath) {
  return new Promise((resolve) => {
    const findings = [];

    // Try gitleaks git --staged first (preferred method)
    let args = ['git', '--staged', repoPath, '--no-git', '-v'];

    try {
      const proc = spawn('gitleaks', args, {
        cwd: repoPath,
        stdio: ['pipe', 'pipe', 'pipe']
      });

      let stdout = '';
      let stderr = '';

      proc.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      proc.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      proc.on('close', (code) => {
        // Parse gitleaks output
        const output = stdout + stderr;

        // Check for secret findings
        if (output.includes('LEAK') || output.includes('Finding') || code === 1) {
          // Secrets found
          const lines = output.split('\n').filter(l =>
            l.includes('LEAK') ||
            l.includes('Finding') ||
            l.includes('file://') ||
            l.match(/^\s*\[/) // Rule match lines
          );

          resolve({
            blocked: true,
            findings: lines.slice(0, 20),
            rawOutput: output.substring(0, 2000)
          });
        } else {
          resolve({
            blocked: false,
            findings: [],
            rawOutput: output.substring(0, 500)
          });
        }
      });

      // Timeout after 30 seconds
      setTimeout(() => {
        proc.kill();
        resolve({
          blocked: false,
          findings: [],
          error: 'Gitleaks scan timed out, allowing operation'
        });
      }, 30000);

    } catch (err) {
      resolve({
        blocked: false,
        findings: [],
        error: `Gitleaks check skipped: ${err.message}`
      });
    }
  });
}

/**
 * Main hook handler
 */
async function main() {
  let input;
  try {
    input = JSON.parse(require('fs').readFileSync(0, 'utf-8'));
  } catch {
    process.exit(0);
  }

  const toolName = input.tool_name || '';
  const toolInput = input.tool_input || {};
  const command = toolInput.command || '';

  // Only intercept Bash tool calls
  if (toolName !== 'Bash') {
    process.exit(0);
  }

  // Only intercept risky git commands
  if (!isRiskyGitCommand(command)) {
    process.exit(0);
  }

  // Check if gitleaks is installed
  try {
    execSync('which gitleaks', { stdio: 'pipe' });
  } catch {
    console.error('Gitleaks not installed. Run: brew install gitleaks');
    process.exit(0);
  }

  // Get repo root and run scan
  const repoRoot = getGitRoot();
  const stagedFiles = getStagedFiles();

  // Skip if no staged files (nothing to scan)
  if (stagedFiles.length === 0) {
    console.error('No staged files to scan');
    process.exit(0);
  }

  console.error(`Gitleaks: Scanning ${stagedFiles.length} staged files...`);

  const scanResult = await runGitleaksScan(repoRoot);

  if (scanResult.blocked) {
    // Block the operation and report findings
    const findingsSummary = scanResult.findings.join('\n');

    const output = {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: `Gitleaks detected secrets in staged files:\n\n${findingsSummary}\n\nRemove secrets from staged files or use 'git restore --staged <file>' to unstage.\n\nGitleaks output:\n${scanResult.rawOutput}`,
      },
    };

    console.log(JSON.stringify(output));
    console.error('GITLEAKS BLOCKED:', findingsSummary);
  } else {
    process.exit(0);
  }
}

main();