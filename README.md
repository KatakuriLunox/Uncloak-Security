# 🔍 Uncloak

**Security scanner for AI-generated & vibe-coded projects.**

Vibe coding is great — until your AI writes code that leaks your API keys, opens SQL injection holes, or executes shell commands with user input. Uncloak catches all of that before it reaches production.

```bash
npm install -g uncloak
uncloak scan ./your-project
```

---

## Demo

```
🔍 Uncloak Security Scanner v1.0.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ Found 4 files (JSON: 3, JavaScript: 1)

🔴 CRITICAL: 10 issues
   ⚠ Hardcoded Stripe API Key → test.js:4
   ⚠ JWT Secret Hardcoded → test.js:42
   ⚠ SQL Injection - String Concatenation → test.js:9
   ⚠ XSS - innerHTML assignment → test.js:14
   ⚠ Eval with User Input → test.js:17
   ⚠ Path Traversal → test.js:21
   ⚠ Authentication Bypass → test.js:38

🟠 HIGH: 5 issues
   ⚠ MD5 Usage → test.js:26
   ⚠ Infinite Loop → test.js:29
   ⚠ Data Leakage to AI API → test.js:52
   ...

📊 Summary: 19 issues found
   Critical: 10 | High: 5 | Medium: 4
   Scan completed in 79ms
```

---

## Why Uncloak?

AI coding tools like Cursor, Copilot, and ChatGPT write code fast — but they also make consistent, predictable security mistakes:

- Hardcoding API keys and secrets
- Building SQL queries with string concatenation
- Passing user input directly to shell commands
- Using broken crypto like MD5
- Sending sensitive data to external AI APIs

Existing scanners weren't built with AI-generated code patterns in mind. Uncloak was.

---

## What it catches

### 🔴 Critical
| Check | What it detects |
|---|---|
| Hardcoded Secrets | API keys, Stripe keys, JWT secrets |
| SQL Injection | String concatenation in queries |
| XSS | Unescaped user input in innerHTML |
| Command Injection | User input passed to exec() |
| Eval with User Input | Dynamic code execution |
| Path Traversal | `../` patterns in file paths |
| Authentication Bypass | Conditionals that always return true |

### 🟠 High
| Check | What it detects |
|---|---|
| Weak Cryptography | MD5, SHA1 for passwords |
| Infinite Loops | while(true) with no exit |
| Data Leakage to AI | Sensitive data sent to external models |
| Hardcoded Passwords | Credentials in variable names |

### 🟡 Medium
| Check | What it detects |
|---|---|
| Silent Catch Blocks | Errors being swallowed silently |
| Uncleared Intervals | setInterval without clearInterval |
| Missing Timeouts | HTTP requests with no timeout |
| Unrestricted File Read | Unvalidated file paths |

---

## The VGUARD Standard

Uncloak introduces a lightweight declaration standard. Annotate your files with what they're allowed to do — Uncloak verifies the code actually respects those declarations.

```js
// VGUARD: no-network
// VGUARD: no-file-write
// VGUARD: no-shell
// VGUARD: no-eval
```

If the code violates its own declarations, Uncloak flags it. Intent vs behavior — a new approach to code safety.

---

## Supported Languages

- JavaScript (`.js`)
- TypeScript (`.ts`, `.tsx`)
- JSX (`.jsx`)
- Python (`.py`)
- Go (`.go`)
- Rust (`.rs`)

---

## Usage

```bash
# Scan a project
uncloak scan ./my-project

# Scan a single file
uncloak scan ./src/api.js

# Strict mode — exit code 1 on any critical issue (great for CI)
uncloak scan ./my-project --strict

# Generate a VGUARD declaration block
uncloak init

# JSON output for CI/CD
uncloak scan ./my-project --output json

# Only critical issues
uncloak scan ./my-project --severity critical

# Verbose output
uncloak scan ./my-project --verbose
```

### CLI Options

```bash
uncloak scan [path] [options]

Options:
  -o, --output <format>   Output format: cli, json, sarif (default: cli)
  -s, --severity <level>  Minimum severity: critical, high, medium, low, info
  -v, --verbose           Enable verbose output
  --skip-deps            Skip dependency vulnerability scanning
  --skip-secrets         Skip secrets scanning
  --skip-unsafe          Skip unsafe patterns scanning
  --skip-network         Skip network activity scanning
  --skip-backdoor        Skip backdoor detection
  --include <patterns>   File patterns to include (comma-separated)
  --exclude <patterns>  File patterns to exclude (comma-separated)
```

### CI/CD Integration

```yaml
# GitHub Actions
- name: Security Scan
  run: |
    npm install -g uncloak
    uncloak scan . --severity critical
```

---

## Installation

```bash
# Install globally
npm install -g uncloak

# Or use without installing
npx uncloak scan
```

### Configuration

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

---

## Built with

- TypeScript
- Zero heavy dependencies
- Runs entirely locally — your code never leaves your machine

---

## Contributing

Contributions welcome. Adding a new rule is as simple as adding a file to `src/detectors/`.

1. Fork the repo
2. Add your detector in `src/detectors/`
3. Test with `npm run build && npm start`
4. Open a PR

See [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

---

## License

MIT

---

<p align="center">Built from scratch by <a href="https://github.com/KatakuriLunox">KatakuriLunox</a></p>
