import { Finding, FileInfo, Detector, Severity } from '../types';

interface QualityPattern {
  name: string;
  regex: RegExp;
  severity: Severity;
  message: string;
}

const QUALITY_PATTERNS: QualityPattern[] = [
  {
    name: 'TODO Comment',
    regex: /\/\/\s*TODO|\/\*\s*TODO/gi,
    severity: 'info',
    message: 'TODO comment found. Address before production.'
  },
  {
    name: 'FIXME Comment',
    regex: /\/\/\s*FIXME|\/\*\s*FIXME/gi,
    severity: 'info',
    message: 'FIXME comment found. Fix before production.'
  },
  {
    name: 'Console.log in Code',
    regex: /console\.(?:log|debug|info)\s*\(/g,
    severity: 'info',
    message: 'Console.log detected. Use proper logging in production.'
  }
];

export class QualityDetector implements Detector {
  name = 'Code Quality';
  description = 'Detects code quality issues including dead code, deep nesting, and missing types';

  async scan(file: FileInfo, content: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const pattern of QUALITY_PATTERNS) {
      let match;
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      
      while ((match = regex.exec(content)) !== null) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        const line = lines[lineNumber - 1] || '';
        
        findings.push({
          id: `quality-${pattern.name.toLowerCase().replace(/\s+/g, '-')}`,
          type: 'unsafe',
          severity: pattern.severity,
          title: pattern.name,
          message: pattern.message,
          file: file.relativePath,
          line: lineNumber,
          code: line.trim().substring(0, 100),
          detector: 'Code Quality'
        });
      }
    }

    return findings;
  }
}
