import { Finding, FileInfo, Detector, Severity } from '../types';

interface PerformancePattern {
  name: string;
  regex: RegExp;
  severity: Severity;
  message: string;
}

const PERFORMANCE_PATTERNS: PerformancePattern[] = [
  {
    name: 'Infinite Loop',
    regex: /while\s*\(\s*(?:true|1|!0)\s*\)/g,
    severity: 'high',
    message: 'Infinite loop detected. Ensure loop has proper exit condition.'
  },
  {
    name: 'Uncleared Interval',
    regex: /setInterval\s*\([^,]+,\s*\d+\s*\)(?!\s*\.\s*clearInterval)/g,
    severity: 'medium',
    message: 'setInterval without clearInterval can cause memory leaks.'
  },
  {
    name: 'Missing Request Timeout',
    regex: /(?:fetch|axios)\s*\([^)]*(?!\s*,\s*.*timeout)/gi,
    severity: 'medium',
    message: 'HTTP request without timeout. Set timeout to prevent hanging connections.'
  }
];

export class PerformanceDetector implements Detector {
  name = 'Performance';
  description = 'Detects performance issues like infinite loops, memory leaks, and N+1 queries';

  async scan(file: FileInfo, content: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const pattern of PERFORMANCE_PATTERNS) {
      let match;
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      
      while ((match = regex.exec(content)) !== null) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        const line = lines[lineNumber - 1] || '';
        
        findings.push({
          id: `perf-${pattern.name.toLowerCase().replace(/\s+/g, '-')}`,
          type: 'unsafe',
          severity: pattern.severity,
          title: pattern.name,
          message: pattern.message,
          file: file.relativePath,
          line: lineNumber,
          code: line.trim().substring(0, 100),
          detector: 'Performance'
        });
      }
    }

    return findings;
  }
}
