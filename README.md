# 🔒 Uncloak

A powerful security auditing CLI tool for developers. Find vulnerabilities, code issues, backdoors, secrets, and malicious activity in your projects in seconds.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Node.js](https://img.shields.io/badge/node-%3E%3D18-green)
![License](https://img.shields.io/badge/license-MIT-green)

## Why Uncloak?

AI coding assistants are amazing, but they can also introduce security vulnerabilities into your code. Uncloak is built specifically to catch these issues before they become problems.

- ⚡ **Fast** - Scans entire projects in milliseconds
- 🎯 **Accurate** - Minimal false positives
- 🔍 **Comprehensive** - 40+ security checks
- 👨‍💻 **Developer-focused** - Clean, actionable output

## Features

### Security Checks

| Category | What it detects |
|----------|-----------------|
| 🔑 **Secrets** | API keys, tokens, passwords, private keys, database credentials |
| 💉 **Injection** | SQL injection, XSS, command injection, path traversal |
| 🔐 **Auth** | Hardcoded credentials, JWT issues, missing authentication |
| 🔐 **Crypto** | Weak algorithms (MD5, SHA1), hardcoded keys, insecure TLS |
| 🖥️ **Shell** | Dangerous exec(), eval(), child_process usage |
| 🌐 **Network** | Suspicious endpoints, unvalidated URLs |
| 🦠 **Backdoors** | Reverse shells, encoded payloads, suspicious patterns |
| ⚠️ **Code Quality** | TODO/FIXME comments, console.log in production |

## Installation

```bash
# Install globally
npm install -g uncloak

# Or use without installing
npx uncloak scan
```

## Quick Start

```bash
# Scan current directory
uncloak scan

# Scan specific path
uncloak scan /path/to/project

# Output as JSON
uncloak scan --output json

# Only show critical issues
uncloak scan --severity critical

# Verbose output
uncloak scan --verbose
```

## CLI Options

```bash
uncloak scan [path] [options]

Options:
  -o, --output <format>   Output format: cli, json, sarif (default: cli)
  -s, --severity <level>  Minimum severity: critical, high, medium, low, info
  -v, --verbose           Enable verbose output
  --skip-deps             Skip dependency vulnerability scanning
  --skip-secrets          Skip secrets scanning
  --skip-unsafe          Skip unsafe patterns scanning
  --skip-network          Skip network activity scanning
  --skip-backdoor        Skip backdoor detection
  --include <patterns>    File patterns to include
  --exclude <patterns>    File patterns to exclude

Examples:
  uncloak scan
  uncloak scan ./src --output json > results.json
  uncloak scan --severity critical
```

## Configuration

Create an `uncloak.config.json` in your project root:

```json
{
  "include": ["**/*.{js,ts,jsx,tsx}"],
  "exclude": ["**/node_modules/**", "**/dist/**"],
  "severity": "low",
  "output": "cli",
  "verbose": false
}
```

Or generate one automatically:

```bash
uncloak init
```

## Output Examples

### CLI Output
```
🔍 Uncloak Security Scanner v1.0.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 CRITICAL: 2 issues

   ⚠ Hardcoded Stripe API Key
   → src/config.js:12
   Remove hardcoded Stripe keys. Use environment variables.

   ⚠ SQL Injection Vulnerability
   → src/db.js:45
   SQL query built using string concatenation. Use parameterized queries.

🟠 HIGH: 3 issues
   ...

📊 Summary: 5 issues found
   Critical: 2 | High: 3 | Medium: 0 | Low: 0
   Scan completed in 245ms
```

### JSON Output
```bash
uncloak scan --output json
```

## Security Checks Explained

### 🔴 Critical
- Hardcoded API keys, tokens, passwords
- SQL injection vulnerabilities
- Command injection (eval, exec with user input)
- Path traversal
- Authentication bypasses

### 🟠 High
- XSS vulnerabilities (innerHTML, dangerouslySetInnerHTML)
- Weak cryptography (MD5, SHA1)
- Hardcoded JWT secrets
- Infinite loops
- Missing input validation

### 🟡 Medium
- Empty catch blocks
- Unclearable intervals
- Missing HTTP timeouts
- Debug mode enabled

## Contributing

Contributions are welcome! Please read our [contributing guidelines](CONTRIBUTING.md) first.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

Uncloak is a static analysis tool. It scans code patterns and may miss vulnerabilities that only appear at runtime. Always perform manual security reviews and penetration testing for production applications.

---

Made with ❤️ for developers who care about security
