import { Finding, FileInfo, Detector, Severity } from '../types';

interface UnsafePattern {
  name: string;
  regex: RegExp;
  severity: Severity;
  message: string;
}

const UNSAFE_PATTERNS: UnsafePattern[] = [
  {
    name: 'Eval Usage',
    regex: /\beval\s*\(/g,
    severity: 'high',
    message: 'eval() can execute arbitrary code and is a major security risk.'
  },
  {
    name: 'Function Constructor',
    regex: /\bnew\s+Function\s*\(/g,
    severity: 'medium',
    message: 'new Function() can execute arbitrary code like eval().'
  },
  {
    name: 'Exec Usage',
    regex: /(?:exec|execSync)\s*\(\s*(?!\[)/g,
    severity: 'high',
    message: 'Command execution with unsanitized input can lead to RCE.'
  },
  {
    name: 'InnerHTML Usage',
    regex: /(?:document\.)?innerHTML\s*=/g,
    severity: 'high',
    message: 'Assigning to innerHTML can lead to XSS attacks.'
  },
  {
    name: 'DangerouslySetInnerHTML',
    regex: /dangerouslySetInnerHTML/gi,
    severity: 'critical',
    message: 'dangerouslySetInnerHTML can lead to XSS attacks. Ensure content is sanitized.'
  },
  {
    name: 'Child Process - exec',
    regex: /(?:child_process\.)?(?:exec|spawn)\s*\(/g,
    severity: 'high',
    message: 'Child process execution found. Ensure input is sanitized.'
  },
  {
    name: 'Child Process - shell option',
    regex: /(?:exec|spawn)\s*\(\s*[^)]*shell\s*:\s*true/g,
    severity: 'high',
    message: 'Shell execution enabled. This can be dangerous with user input.'
  },
  {
    name: 'Path Disclosure - __dirname',
    regex: /__dirname|__filename/g,
    severity: 'low',
    message: 'Using __dirname/__filename may expose file system structure.'
  },
  {
    name: 'Process Env Direct Access',
    regex: /process\.env\.[A-Z_]+/g,
    severity: 'info',
    message: 'Direct process.env access. Consider using a config library.'
  },
  {
    name: 'Debug Mode',
    regex: /(?:debug|DEBUG)\s*[=:]\s*(?:true|1|yes)/gi,
    severity: 'medium',
    message: 'Debug mode enabled. Disable in production.'
  },
  {
    name: 'Console Logging',
    regex: /console\.(?:log|debug|info)\s*\(/g,
    severity: 'info',
    message: 'Console logging detected. Use proper logging in production.'
  },
  {
    name: 'Alert/Confirm/Prompt',
    regex: /\b(?:alert|confirm|prompt)\s*\(/g,
    severity: 'low',
    message: 'Browser dialog detected. Remove in production code.'
  }
];

export class UnsafeDetector implements Detector {
  name = 'Unsafe Patterns';
  description = 'Detects unsafe code patterns like eval(), exec(), and dangerous APIs';

  async scan(file: FileInfo, content: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const pattern of UNSAFE_PATTERNS) {
      let match;
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      
      while ((match = regex.exec(content)) !== null) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        const line = lines[lineNumber - 1] || '';
        
        findings.push({
          id: `unsafe-${pattern.name.toLowerCase().replace(/\s+/g, '-')}`,
          type: 'unsafe',
          severity: pattern.severity,
          title: pattern.name,
          message: pattern.message,
          file: file.relativePath,
          line: lineNumber,
          code: line.trim().substring(0, 100),
          detector: 'Unsafe Patterns'
        });
      }
    }

    return findings;
  }
}
