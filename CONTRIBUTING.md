# Contributing to Uncloak

Thank you for your interest in contributing to Uncloak!

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported
2. Create a detailed issue with:
   - Clear title
   - Steps to reproduce
   - Expected vs actual behavior
   - Your environment (Node version, OS)

### Suggesting Features

1. Explain the use case
2. Provide examples
3. Consider backward compatibility

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `npm test`
5. Commit with clear messages
6. Push and create PR

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/Uncloak-Security.git
cd Uncloak-Security

# Install dependencies
npm install

# Build
npm run build

# Test
npm test
```

## Code Style

- Use TypeScript
- Follow existing patterns
- Add comments for complex logic
- Keep functions small and focused

## Adding New Detectors

1. Create a new file in `src/detectors/`
2. Implement the `Detector` interface
3. Add patterns to detect specific vulnerabilities
4. Register in `src/core/scanner.ts`

```typescript
import { Finding, FileInfo, Detector, Severity } from '../types';

export class MyDetector implements Detector {
  name = 'My Detector';
  description = 'Description of what this detects';

  async scan(file: FileInfo, content: string): Promise<Finding[]> {
    // Your detection logic here
    return findings;
  }
}
```

## Questions?

Open an issue for questions about contributing.
