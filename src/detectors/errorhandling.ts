import { Finding, FileInfo, Detector, Severity } from '../types';

interface ErrorPattern {
  name: string;
  regex: RegExp;
  severity: Severity;
  message: string;
}

const ERROR_PATTERNS: ErrorPattern[] = [
  {
    name: 'Silent Catch Block',
    regex: /catch\s*\([^)]*\)\s*{\s*}/g,
    severity: 'medium',
    message: 'Empty catch block swallowing errors. Log errors or handle them properly.'
  },
  {
    name: 'Debug Mode Enabled',
    regex: /(?:debug|DEBUG)\s*[=:]\s*(?:true|1|yes)/gi,
    severity: 'medium',
    message: 'Debug mode enabled. Disable in production.'
  }
];

export class ErrorHandlingDetector implements Detector {
  name = 'Error Handling';
  description = 'Detects improper error handling, silent catches, and exposed error details';

  async scan(file: FileInfo, content: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const pattern of ERROR_PATTERNS) {
      let match;
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      
      while ((match = regex.exec(content)) !== null) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        const line = lines[lineNumber - 1] || '';
        
        findings.push({
          id: `error-${pattern.name.toLowerCase().replace(/\s+/g, '-')}`,
          type: 'unsafe',
          severity: pattern.severity,
          title: pattern.name,
          message: pattern.message,
          file: file.relativePath,
          line: lineNumber,
          code: line.trim().substring(0, 100),
          detector: 'Error Handling'
        });
      }
    }

    return findings;
  }
}
