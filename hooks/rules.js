/**
 * Gitleaks Rules - Embedded secret detection patterns (JavaScript compatible)
 * Simplified from gitleaks config - patterns valid in JavaScript regex
 * https://github.com/gitleaks/gitleaks
 */

const RULES = [
  // AWS
  { id: 'aws-access-token', regex: /\b(AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/, desc: 'AWS Access Key' },
  { id: 'aws-secret-key', regex: /\b[A-Za-z0-9\/+=]{40}\b/, desc: 'AWS Secret Key' },

  // GitHub
  { id: 'github-pat', regex: /ghp_[a-zA-Z0-9]{36}/, desc: 'GitHub Personal Access Token' },
  { id: 'github-oauth', regex: /gho_[a-zA-Z0-9]{36}/, desc: 'GitHub OAuth Token' },
  { id: 'github-fine-grained-pat', regex: /github_pat_[a-zA-Z0-9_]{82}/, desc: 'GitHub Fine-grained PAT' },
  { id: 'github-app-token', regex: /(?:ghu|ghs)_[a-zA-Z0-9]{36}/, desc: 'GitHub App Token' },

  // GitLab
  { id: 'gitlab-pat', regex: /glpat-[a-zA-Z0-9_-]{20}/, desc: 'GitLab Personal Access Token' },
  { id: 'gitlab-cicd-job-token', regex: /glcbt-[a-zA-Z0-9]{1,5}_[a-zA-Z0-9_-]{20}/, desc: 'GitLab CI/CD Job Token' },
  { id: 'gitlab-oauth', regex: /gl_oauth_[a-zA-Z0-9_-]{64}/, desc: 'GitLab OAuth Token' },
  { id: 'gitlab-runner-auth-token', regex: /glrauth-[a-zA-Z0-9_-]{43}/, desc: 'GitLab Runner Auth Token' },

  // OpenAI / Anthropic
  { id: 'openai-api-key', regex: /sk-[a-zA-Z0-9]{48}/, desc: 'OpenAI API Key' },
  { id: 'anthropic-api-key', regex: /sk-ant-api03-[a-zA-Z0-9_-]{93}AA/, desc: 'Anthropic API Key' },

  // Slack
  { id: 'slack-bot-token', regex: /xoxb-[a-zA-Z0-9-]{10,}/, desc: 'Slack Bot Token' },
  { id: 'slack-user-token', regex: /xoxp-[a-zA-Z0-9-]{10,}/, desc: 'Slack User Token' },
  { id: 'slack-webhook-url', regex: /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[a-zA-Z0-9]+/, desc: 'Slack Webhook URL' },

  // Discord
  { id: 'discord-api-token', regex: /[a-f0-9]{64}/i, desc: 'Discord API Token' },

  // Stripe
  { id: 'stripe-access-token', regex: /sk_live_[a-zA-Z0-9]{24}/, desc: 'Stripe Access Token' },
  { id: 'stripe-publishable-key', regex: /pk_live_[a-zA-Z0-9]{24}/, desc: 'Stripe Publishable Key' },

  // Database
  { id: 'postgres-connection-string', regex: /postgres(?:ql)?:\/\/[^:\s]+:[^@\s]+@[^:\/\s]+:\d+\/[^?\s]+/, desc: 'PostgreSQL Connection String' },
  { id: 'mysql-connection-string', regex: /mysql:\/\/[^:\s]+:[^@\s]+@[^:\/\s]+(?::\d+)?\//, desc: 'MySQL Connection String' },
  { id: 'mongodb-connection-string', regex: /mongodb(?:\+srv)?:\/\/[^:\s]+:[^@\s]+@[^:\/\s]+(?::\d+)?(?:\/[^?\s]+)?/, desc: 'MongoDB Connection String' },
  { id: 'redis-connection-string', regex: /redis:\/\/[^:\s]+:[^@\s]+@[^:\/\s]+(?::\d+)?/, desc: 'Redis Connection String' },

  // Cloud Providers
  { id: 'azure-storage-connection-string', regex: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+/, desc: 'Azure Storage Connection String' },
  { id: 'azure-sql-connection-string', regex: /Server=tcp:[^;]+;Database=[^;]+;User Id=[^;]+;Password=[^;]+;/, desc: 'Azure SQL Connection String' },
  { id: 'gcp-api-key', regex: /\bAIza[a-zA-Z0-9_-]{35}\b/, desc: 'GCP API Key' },
  { id: 'digitalocean-access-token', regex: /doo_v1_[a-f0-9]{64}/, desc: 'DigitalOcean Access Token' },

  // Private Keys
  { id: 'rsa-private-key', regex: /-----BEGIN RSA PRIVATE KEY-----/, desc: 'RSA Private Key' },
  { id: 'ec-private-key', regex: /-----BEGIN EC PRIVATE KEY-----/, desc: 'EC Private Key' },
  { id: 'private-key', regex: /-----BEGIN PRIVATE KEY-----/, desc: 'Private Key' },
  { id: 'openssh-private-key', regex: /-----BEGIN OPENSSH PRIVATE KEY-----/, desc: 'OpenSSH Private Key' },
  { id: 'pgp-private-key', regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/, desc: 'PGP Private Key' },

  // JWT
  { id: 'jwt', regex: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/, desc: 'JSON Web Token' },

  // SendGrid
  { id: 'sendgrid-api-key', regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/, desc: 'SendGrid API Key' },

  // Twilio
  { id: 'twilio-api-key', regex: /SK[a-f0-9]{32}/, desc: 'Twilio API Key' },

  // Shopify
  { id: 'shopify-access-token', regex: /shpat_[a-f0-9]{32}/i, desc: 'Shopify Access Token' },

  // Square
  { id: 'square-access-token', regex: /sq0atp-[a-zA-Z0-9_-]{22}/, desc: 'Square Access Token' },

  // NPM
  { id: 'npm-access-token', regex: /npm_[a-zA-Z0-9]{36}/, desc: 'npm Access Token' },

  // PyPI
  { id: 'pypi-upload-token', regex: /pypi-AgEIcBlb2[a-zA-Z0-9_-]{50}/, desc: 'PyPI Upload Token' },

  // Mailchimp
  { id: 'mailchimp-api-key', regex: /[a-f0-9]{32}-us[0-9]{1,2}/i, desc: 'Mailchimp API Key' },

  // Dropbox
  { id: 'dropbox-api-token', regex: /[a-z0-9]{11}AAAAAAAAAA[a-zA-Z0-9_-]{43}/i, desc: 'Dropbox API Token' },

  // Contentful
  { id: 'contentful-delivery-api-token', regex: /[a-zA-Z0-9=_-]{43}/, desc: 'Contentful Delivery API Token' },

  // HubSpot
  { id: 'hubspot-api-key', regex: /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/, desc: 'HubSpot API Key' },

  // Notion
  { id: 'notion-api-token', regex: /secret_[a-zA-Z0-9]{48}/, desc: 'Notion API Token' },

  // Linear
  { id: 'linear-api-key', regex: /lin_[a-zA-Z0-9]{43}/, desc: 'Linear API Token' },

  // Algolia
  { id: 'algolia-api-key', regex: /[a-zA-Z0-9]{32}/, desc: 'Algolia API Key' },

  // Sentry DSN
  { id: 'sentry-dsn', regex: /https:\/\/[a-f0-9]{32}@[a-z0-9.-]+\/sentry\/\d+/i, desc: 'Sentry DSN' },

  // Datadog
  { id: 'datadog-api-key', regex: /[a-f0-9]{32}/i, desc: 'Datadog API Key' },

  // Cloudflare
  { id: 'cloudflare-api-key', regex: /[a-zA-Z0-9]{37}/i, desc: 'Cloudflare API Key' },

  // Heroku
  { id: 'heroku-api-key', regex: /[a-f0-9]{32}/i, desc: 'Heroku API Key' },

  // Circle CI
  { id: 'circleci-api-token', regex: /[a-f0-9]{40}/i, desc: 'CircleCI API Token' },

  // Generic patterns
  { id: 'generic-api-key', regex: /(?:api[_-]?key|apikey|token|secret|password)\s*[=:]\s*['"]?[a-zA-Z0-9_=-]{20,}/i, desc: 'Generic API Key' },
  { id: 'bearer-token', regex: /Bearer\s+[a-zA-Z0-9_=-]{20,}/i, desc: 'Bearer Token' },
  { id: 'authorization-header', regex: /Authorization:\s*(?:Bearer|Basic)[^\n]{10,}/i, desc: 'Authorization Header' },
  { id: 'generic-secret', regex: /(?:password|passwd|pwd|secret)\s*[=:]\s*['"]?[\w!@#$%^&*()_+=][^\s]{8,}/, desc: 'Generic Secret' },
];

/**
 * Files/paths to skip scanning
 */
const SKIP_PATTERNS = [
  /\.(?:bmp|gif|jpe?g|png|svg|tiff?|woff2?|eot|otf)$/i,
  /\.(?:docx?|xlsx?|pdf|bin|socket|vsidx|suo|dll|exe|pdb|gltf)$/i,
  /(?:^|\/)node_modules\//,
  /(?:^|\/)\.git\//,
  /\.lock$/,
  /gitleaks\.toml/i,
  /(?:^|\/)vendor\//,
  /\.min\.(js|css)$/i,
  /(?:^|\/)dist\//,
  /(?:^|\/)build\//,
];

/**
 * Line patterns to skip (allowlisted false positives)
 */
const SKIP_LINE_PATTERNS = [
  /^true|false|null$/i,
  /^[a-z]+$/i,
  /^\*+$/,
  /^\.+$/,
  /^\$?\{[\w ]+\}$/,
  /^%[A-Z_]+%$/,
  /^\{\{.*\}\}$/,
  /^@[\w]+@$/,
  /^\/Users\/[\w]+\/[\w.\/]+$/,
  /^\/(?:bin|etc|home|opt|tmp|usr|var)\//,
  /^#.*$/,
  /^\/\/.*$/,
  /^--.*$/,
];

/**
 * Scan a single line for secrets
 */
function scanLine(line, filePath) {
  const findings = [];

  // Skip binary/skip files
  for (const pattern of SKIP_PATTERNS) {
    if (pattern.test(filePath)) {
      return findings;
    }
  }

  // Skip allowlisted lines
  const trimmed = line.trim();
  for (const pattern of SKIP_LINE_PATTERNS) {
    if (pattern.test(trimmed)) {
      return findings;
    }
  }

  // Check against all rules
  for (const rule of RULES) {
    try {
      if (rule.regex.test(line)) {
        findings.push({
          ruleId: rule.id,
          description: rule.desc,
          match: line.substring(0, 100),
        });
      }
    } catch {
      // Invalid regex, skip
    }
  }

  return findings;
}

/**
 * Scan a file for secrets
 */
function scanFile(filePath, content) {
  const findings = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const lineFindings = scanLine(lines[i], filePath);
    for (const finding of lineFindings) {
      findings.push({
        ...finding,
        line: i + 1,
        file: filePath,
      });
    }
  }

  return findings;
}

module.exports = { RULES, SKIP_PATTERNS, scanLine, scanFile };