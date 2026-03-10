import { Finding, FileInfo, Detector, Severity } from '../types';

interface SecretPattern {
  name: string;
  regex: RegExp;
  severity: Severity;
  recommendation: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: 'AWS Access Key',
    regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g,
    severity: 'critical',
    recommendation: 'Remove hardcoded AWS keys. Use environment variables or IAM roles instead.'
  },
  {
    name: 'AWS Secret Key',
    regex: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g,
    severity: 'critical',
    recommendation: 'Remove hardcoded AWS secret keys. Use environment variables instead.'
  },
  {
    name: 'GitHub Token',
    regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g,
    severity: 'critical',
    recommendation: 'Remove hardcoded GitHub tokens. Use GitHub Actions secrets.'
  },
  {
    name: 'GitHub OAuth Token',
    regex: /gho_[A-Za-z0-9]{36}/g,
    severity: 'critical',
    recommendation: 'Remove hardcoded GitHub OAuth tokens.'
  },
  {
    name: 'GitLab Token',
    regex: /glpat-[A-Za-z0-9\-]{20,}/g,
    severity: 'critical',
    recommendation: 'Remove hardcoded GitLab tokens.'
  },
  {
    name: 'Bitbucket Token',
    regex: /BBR-[A-Za-z0-9]{24}/g,
    severity: 'critical',
    recommendation: 'Remove hardcoded Bitbucket tokens.'
  },
  {
    name: 'Stripe API Key',
    regex: /sk_live_[0-9a-zA-Z]{24}/g,
    severity: 'critical',
    recommendation: 'Remove hardcoded Stripe keys. Use environment variables.'
  },
  {
    name: 'Stripe Publishable Key',
    regex: /pk_live_[0-9a-zA-Z]{24}/g,
    severity: 'high',
    recommendation: 'Avoid exposing Stripe publishable keys in source code.'
  },
  {
    name: 'Stripe Test Key',
    regex: /sk_test_[0-9a-zA-Z]{24}/g,
    severity: 'high',
    recommendation: 'Remove test keys from production code.'
  },
  {
    name: 'Private Key',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
    severity: 'critical',
    recommendation: 'Remove hardcoded private keys. Use a secrets manager.'
  },
  {
    name: 'RSA Private Key',
    regex: /-----BEGIN RSA PRIVATE KEY-----/g,
    severity: 'critical',
    recommendation: 'Remove hardcoded RSA private keys.'
  },
  {
    name: 'Generic API Key',
    regex: /(?:api[_-]?key|apikey|api_secret|apisecret)[\s]*[=:][\s]*["']([a-zA-Z0-9_\-]{16,})["']/gi,
    severity: 'high',
    recommendation: 'Avoid hardcoding API keys. Use environment variables.'
  },
  {
    name: 'Generic Secret',
    regex: /(?:password|passwd|pwd|secret|token)[\s]*[=:][\s]*["']([^"'\s]{8,})["']/gi,
    severity: 'high',
    recommendation: 'Avoid hardcoding passwords or secrets. Use environment variables.'
  },
  {
    name: 'Database Connection String',
    regex: /(?:mongodb|mysql|postgresql|postgres|redis|mssql):\/\/[^\s"']+/gi,
    severity: 'critical',
    recommendation: 'Remove hardcoded database connection strings. Use environment variables.'
  },
  {
    name: 'JWT Token',
    regex: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/g,
    severity: 'medium',
    recommendation: 'Avoid hardcoding JWT tokens.'
  },
  {
    name: 'Slack Token',
    regex: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g,
    severity: 'high',
    recommendation: 'Remove hardcoded Slack tokens. Use environment variables.'
  },
  {
    name: 'Discord Token',
    regex: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}/g,
    severity: 'high',
    recommendation: 'Remove hardcoded Discord tokens.'
  },
  {
    name: 'SendGrid API Key',
    regex: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,
    severity: 'critical',
    recommendation: 'Remove hardcoded SendGrid API keys.'
  },
  {
    name: 'Twilio API Key',
    regex: /SK[a-f0-9]{32}/g,
    severity: 'high',
    recommendation: 'Remove hardcoded Twilio API keys.'
  },
  {
    name: 'NPM Token',
    regex: /npm_[A-Za-z0-9]{36}/g,
    severity: 'critical',
    recommendation: 'Remove hardcoded NPM tokens.'
  },
  {
    name: 'Heroku API Key',
    regex: /[hH]eroku[_-]?[aA][pP][iI][_-]?[kK][eE][yY][\s]*[=:][\s]*["']?([a-f0-9-]{32})["']?/g,
    severity: 'critical',
    recommendation: 'Remove hardcoded Heroku API keys.'
  },
  {
    name: 'Facebook Access Token',
    regex: /EAACEdEose0cBA[0-9A-Za-z]+/g,
    severity: 'critical',
    recommendation: 'Remove hardcoded Facebook access tokens.'
  },
  {
    name: 'Google API Key',
    regex: /AIza[0-9A-Za-z\-_]{35}/g,
    severity: 'high',
    recommendation: 'Remove hardcoded Google API keys.'
  },
  {
    name: 'Google OAuth',
    regex: /[0-9]+-[A-Za-z0-9_]{32}\.apps\.googleusercontent\.com/g,
    severity: 'critical',
    recommendation: 'Remove hardcoded Google OAuth credentials.'
  },
  {
    name: 'Azure Subscription Key',
    regex: /[a-f0-9]{32}/g,
    severity: 'high',
    recommendation: 'Remove hardcoded Azure subscription keys.'
  },
  {
    name: 'Mailchimp API Key',
    regex: /[a-f0-9]{32}-us[0-9]{1,2}/g,
    severity: 'high',
    recommendation: 'Remove hardcoded Mailchimp API keys.'
  },
  {
    name: 'Mailgun API Key',
    regex: /key-[0-9a-zA-Z]{32}/g,
    severity: 'high',
    recommendation: 'Remove hardcoded Mailgun API keys.'
  },
  {
    name: 'Square API Key',
    regex: /sq0atp-[0-9A-Za-z\-_]{22}/g,
    severity: 'critical',
    recommendation: 'Remove hardcoded Square API keys.'
  },
  {
    name: 'PyPI Token',
    regex: /pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]+/g,
    severity: 'critical',
    recommendation: 'Remove hardcoded PyPI tokens.'
  },
  {
    name: '.env file exposure',
    regex: /\b(?:dotenv|dotenv\.config|require\(['"]dotenv['"]\))\s*\(\s*\)/g,
    severity: 'medium',
    recommendation: 'Ensure .env is in .gitignore and not committed.'
  }
];

export class SecretsDetector implements Detector {
  name = 'Secrets Scanner';
  description = 'Detects hardcoded secrets, API keys, tokens, passwords, and credentials';

  async scan(file: FileInfo, content: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const pattern of SECRET_PATTERNS) {
      let match;
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      
      while ((match = regex.exec(content)) !== null) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        const line = lines[lineNumber - 1] || '';
        
        findings.push({
          id: `secret-${pattern.name.toLowerCase().replace(/\s+/g, '-')}`,
          type: 'secret',
          severity: pattern.severity,
          title: `Hardcoded ${pattern.name}`,
          message: pattern.recommendation,
          file: file.relativePath,
          line: lineNumber,
          column: match.index - content.lastIndexOf('\n', match.index - 1),
          code: line.trim().substring(0, 100),
          detector: 'Secrets Scanner'
        });
      }
    }

    return findings;
  }
}
