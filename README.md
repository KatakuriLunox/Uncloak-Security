# uncloak-security

A security scanner for AI-generated and "vibe-coded" projects.

AI coding tools like Cursor, Copilot, and ChatGPT write code fast — but they also make consistent, predictable security mistakes. Uncloak catches those mistakes before they reach production.

```bash
npm install -g uncloak-security
uncloak scan ./your-project
```

---

## Demo

```
Uncloak Security Scanner v2.2.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ Found 4 files (JSON: 3, JavaScript: 1)

CRITICAL: 10 issues
   ⚠ Hardcoded Stripe API Key    → src/api.js:4
   ⚠ JWT Secret Hardcoded        → src/api.js:42
   ⚠ SQL Injection               → src/db.js:9
   ⚠ XSS - innerHTML assignment  → src/ui.js:14
   ⚠ Eval with User Input        → src/utils.js:17
   ⚠ Path Traversal              → src/files.js:21
   ⚠ Authentication Bypass       → src/auth.js:38

HIGH: 5 issues
   ⚠ MD5 Usage              → src/crypto.js:26
   ⚠ Infinite Loop          → src/worker.js:29
   ⚠ Data Leakage to AI API → src/ai.js:52

Summary: 15 issues found
   Critical: 10 | High: 5
   Scan completed in 79ms
```

---

## Why Uncloak?

AI coding assistants write code quickly, but they tend to repeat the same security mistakes:

- Hardcoding API keys and secrets directly in source files
- Building SQL queries using string concatenation
- Passing user input directly to shell commands
- Using weak or broken cryptography like MD5
- Sending sensitive data to external AI APIs without sanitization

Most existing security scanners weren't designed with AI-generated code patterns in mind. Uncloak is.

---

## What It Catches

### Critical
| Check | What it detects |
|---|---|
| Hardcoded Secrets | API keys, Stripe keys, JWT secrets, tokens |
| SQL Injection | String concatenation or template literals in queries |
| XSS | Unescaped user input in innerHTML or dangerouslySetInnerHTML |
| Command Injection | User input passed to exec(), spawn(), or similar |
| Eval with User Input | Dynamic code execution using eval() or Function() |
| Path Traversal | `../` patterns in file read/write operations |
| Authentication Bypass | Conditionals that always evaluate to true |
| Backdoors | Reverse shells, encoded commands, suspicious eval patterns |

### High
| Check | What it detects |
|---|---|
| Weak Cryptography | MD5, SHA1, DES, RC4 usage |
| Infinite Loops | `while(true)` without proper exit conditions |
| Data Leakage to AI | Sensitive data sent to external AI APIs |
| Hardcoded Passwords | Credentials assigned directly to variables |
| Certificate Verification Disabled | `rejectUnauthorized: false` in HTTPS calls |
| CORS Wildcard | `Access-Control-Allow-Origin: *` in responses |

### Medium
| Check | What it detects |
|---|---|
| Silent Catch Blocks | Empty catch blocks that swallow errors |
| Uncleared Intervals | `setInterval` without a corresponding `clearInterval` |
| Missing Request Timeouts | HTTP requests with no timeout set |
| Unrestricted File Read | File reads without path validation |

### Low / Info
| Check | What it detects |
|---|---|
| Hardcoded IP Addresses | IP addresses that should be in config |
| TODO / FIXME Comments | Unresolved code notes |
| Console Logs | Debug statements left in production code |

---

## The VGUARD Standard

Uncloak supports a simple annotation system. Add a comment at the top of a file to declare what it is allowed to do — Uncloak verifies the code actually respects those declarations.

```js
// VGUARD: no-network
// VGUARD: no-file-write
// VGUARD: no-shell
// VGUARD: no-eval
```

If the code violates its own declarations, Uncloak flags it as a finding. This makes intent explicit and easy to audit.

---

## Supported Languages

- JavaScript (`.js`, `.mjs`, `.cjs`)
- TypeScript (`.ts`, `.tsx`)
- JSX (`.jsx`)
- Python (`.py`)
- Go (`.go`)
- Rust (`.rs`)
- HTML, CSS, SQL, Shell scripts, and more

---

## Installation

```bash
# Install globally
npm install -g uncloak-security

# Or run without installing
npx uncloak-security scan ./my-project
```

---

## Usage

```bash
# Scan the current directory
uncloak scan .

# Scan a specific folder
uncloak scan ./src

# Scan a single file
uncloak scan ./src/api.js

# Only show critical and high severity issues
uncloak scan . --severity high

# Output results as JSON (useful for CI/CD pipelines)
uncloak scan . --output json

# Show detailed output for each finding
uncloak scan . --verbose

# Generate a config file in the current directory
uncloak init
```

### All Options

```
uncloak scan [path] [options]

Options:
  -o, --output <format>    Output format: cli, json, sarif     (default: cli)
  -s, --severity <level>   Minimum severity level to show      (default: low)
                           Levels: critical, high, medium, low, info
  -v, --verbose            Show extra detail for each finding
  --skip-deps              Skip dependency vulnerability scanning
  --skip-secrets           Skip secrets and credential scanning
  --skip-unsafe            Skip unsafe code pattern scanning
  --skip-network           Skip network activity scanning
  --skip-backdoor          Skip backdoor detection
  --include <patterns>     Only scan files matching these patterns (comma-separated)
  --exclude <patterns>     Skip files matching these patterns (comma-separated)
  -h, --help               Show help
  -V, --version            Show version number
```

---

## Configuration File

Create an `uncloak.config.json` in your project root to set default options:

```json
{
  "include": ["**/*.{js,ts,jsx,tsx}"],
  "exclude": ["**/node_modules/**", "**/dist/**"],
  "severity": "low",
  "output": "cli",
  "verbose": false,
  "skipDependencies": false,
  "skipSecrets": false,
  "skipUnsafe": false,
  "skipNetwork": false,
  "skipBackdoor": false
}
```

Generate this file automatically with:

```bash
uncloak init
```

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run Uncloak Security Scan
  run: |
    npm install -g uncloak-security
    uncloak scan . --severity critical
```

This exits with code 1 if any critical issues are found, which will fail the pipeline automatically.

### SARIF Output (GitHub Code Scanning)

```yaml
- name: Run Uncloak Security Scan
  run: uncloak scan . --output sarif > results.sarif

- name: Upload SARIF results
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

---

## How It Works

1. **Maps your project** — finds all relevant files based on your include/exclude patterns
2. **Runs detectors** — each detector scans file content using regex patterns and AST analysis
3. **Deduplicates findings** — merges duplicate findings at the same file and line
4. **Filters by severity** — only shows findings at or above your chosen severity level
5. **Reports results** — outputs to CLI, JSON, or SARIF format

Your code never leaves your machine. Everything runs locally.

---

## Built With

- TypeScript
- Minimal dependencies — `@babel/parser`, `chalk`, `commander`, `fast-glob`, `ora`, `table`
- Runs entirely locally — no telemetry, no uploads

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to add new detectors, report bugs, and submit pull requests.

---

## License

MIT

---

<p align="center">Built by <a href="https://github.com/KatakuriLunox">KatakuriLunox</a></p>
