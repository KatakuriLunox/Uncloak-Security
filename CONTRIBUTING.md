# Contributing to uncloak-security

Thank you for your interest in contributing!

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in the [Issues](https://github.com/KatakuriLunox/Uncloak-Security/issues) tab
2. If not, open a new issue with:
   - A clear title describing the problem
   - Steps to reproduce it
   - What you expected to happen vs what actually happened
   - Your environment (Node.js version, OS)

### Suggesting Features

1. Open an issue explaining the use case
2. Include examples of what the output or behavior should look like
3. Consider whether it could break existing behavior

### Pull Requests

1. Fork the repository
2. Create a branch for your change: `git checkout -b feature/my-feature`
3. Make your changes
4. Build to check for errors: `npm run build`
5. Commit with a clear message describing what you changed
6. Push your branch and open a PR against `main`

---

## Development Setup

```bash
# Clone your fork
git clone https://github.com/KatakuriLunox/Uncloak-Security.git
cd Uncloak-Security

# Install dependencies
npm install

# Build the project (compiles TypeScript to dist/)
npm run build

# Run a test scan on the project itself
node dist/index.js scan .
```

---

## Project Structure

```
src/
  cli.ts              # CLI setup using commander
  index.ts            # Entry point
  commands/
    scan.ts           # The "uncloak scan" command
    init.ts           # The "uncloak init" command
  core/
    mapper.ts         # Finds and maps all project files
    scanner.ts        # Runs detectors against each file
    reporter.ts       # Formats and prints results
  detectors/          # One file per detection category
    secrets.ts        # API keys, tokens, passwords
    injection.ts      # SQL injection, XSS, command injection
    auth.ts           # Auth bypass, hardcoded credentials
    crypto.ts         # Weak algorithms, hardcoded keys
    filesystem.ts     # Unsafe file operations
    network.ts        # Network requests, hardcoded IPs
    backdoor.ts       # Reverse shells, obfuscated code
    ai.ts             # AI-specific risks (prompt injection, data leakage)
    errorhandling.ts  # Silent catch blocks, debug mode
    performance.ts    # Infinite loops, memory leaks
    quality.ts        # TODOs, console.logs, code hygiene
    dependencies.ts   # Known CVEs via OSV API
  types/
    index.ts          # Shared TypeScript types
  utils/
    config.ts         # Config file loading
    file.ts           # File system helpers
    logger.ts         # Logging with chalk
```

---

## Code Style

- Write everything in TypeScript
- Follow the same patterns used in existing detectors
- Add a comment above any non-obvious regex explaining what it matches
- Keep functions small and focused on one thing
- Avoid external dependencies unless absolutely necessary

---

## Adding a New Detector

1. Create a new file in `src/detectors/`, e.g. `src/detectors/mycheck.ts`
2. Implement the `Detector` interface from `../types`
3. Register it in `src/core/scanner.ts`

Here is a minimal example:

```typescript
import { Finding, FileInfo, Detector, Severity } from '../types';

// Define the patterns you want to detect
const MY_PATTERNS = [
  {
    name: 'Example Pattern',
    regex: /some-dangerous-pattern/gi,
    severity: 'high' as Severity,
    message: 'This pattern is dangerous because X. Do Y instead.'
  }
];

export class MyDetector implements Detector {
  name = 'My Check';
  description = 'Detects X type of vulnerability';

  async scan(file: FileInfo, content: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const pattern of MY_PATTERNS) {
      let match;
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);

      while ((match = regex.exec(content)) !== null) {
        // Calculate which line the match is on
        const lineNumber = content.substring(0, match.index).split('\n').length;
        const line = lines[lineNumber - 1] || '';

        findings.push({
          id: `mychek-${pattern.name.toLowerCase().replace(/\s+/g, '-')}`,
          type: 'unsafe',
          severity: pattern.severity,
          title: pattern.name,
          message: pattern.message,
          file: file.relativePath,
          line: lineNumber,
          code: line.trim().substring(0, 100),
          detector: 'My Check'
        });
      }
    }

    return findings;
  }
}
```

Then register it in `src/core/scanner.ts`:

```typescript
import { MyDetector } from '../detectors/mycheck';

// Inside runScanners(), add:
detectors.push(new MyDetector());
```

---

## Questions?

Open an issue and ask. All questions are welcome.
