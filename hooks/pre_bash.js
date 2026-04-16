#!/usr/bin/env node
/**
 * pre_bash.js - Gitleaks PreToolUse Hook (Embedded Scanner)
 *
 * Intercepts Bash tool calls for git commit/push and scans staged files
 * for secrets before allowing the operation to proceed.
 *
 * Uses embedded secret detection patterns (222 rules from gitleaks)
 * No external dependencies - pure Node.js regex matching.
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Import embedded rules
const { scanFile } = require('./rules');

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
 * Get list of staged files
 */
function getStagedFiles() {
  try {
    const output = execSync('git diff --cached --name-only 2>/dev/null', {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe']
    }).trim();

    if (!output) return [];

    return output.split('\n').filter(f => f.length > 0);
  } catch {
    return [];
  }
}

/**
 * Get staged content for a specific file
 */
function getStagedContent(filePath) {
  try {
    // Use git show to get staged content
    const content = execSync(`git show :${filePath} 2>/dev/null`, {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe']
    });
    return content;
  } catch {
    return null;
  }
}

/**
 * Format findings for display
 */
function formatFindings(findings) {
  const lines = [];

  // Group by file
  const byFile = {};
  for (const f of findings) {
    if (!byFile[f.file]) byFile[f.file] = [];
    byFile[f.file].push(f);
  }

  for (const [file, fileFindings] of Object.entries(byFile)) {
    lines.push(`\n[${file}]`);
    for (const finding of fileFindings) {
      lines.push(`  Line ${finding.line}: ${finding.description} (${finding.ruleId})`);
      lines.push(`    Match: ${finding.match.trim()}`);
    }
  }

  return lines.join('\n');
}

/**
 * Main hook handler
 */
function main() {
  let input;
  try {
    input = JSON.parse(fs.readFileSync(0, 'utf-8'));
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

  // Get repo root and staged files
  const repoRoot = getGitRoot();
  const stagedFiles = getStagedFiles();

  // Skip if no staged files
  if (stagedFiles.length === 0) {
    console.error('Gitleaks: No staged files to scan');
    process.exit(0);
  }

  console.error(`Gitleaks: Scanning ${stagedFiles.length} staged files...`);

  // Scan each staged file
  const allFindings = [];

  for (const file of stagedFiles) {
    const content = getStagedContent(file);
    if (content === null) continue;

    const findings = scanFile(file, content);
    allFindings.push(...findings);
  }

  if (allFindings.length > 0) {
    // Block the operation and report findings
    const findingsSummary = formatFindings(allFindings);

    const output = {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: `Gitleaks detected secrets in staged files:${findingsSummary}\n\nRemove secrets from staged files or use 'git restore --staged <file>' to unstage.`,
      },
    };

    console.log(JSON.stringify(output));
    console.error(`GITLEAKS BLOCKED: ${allFindings.length} secrets found`);
    process.exit(0);
  }

  console.error('Gitleaks: No secrets found');
  process.exit(0);
}

main();