import { Finding, FileInfo, Detector, Severity } from '../types';

interface BackdoorPattern {
  name: string;
  regex: RegExp;
  severity: Severity;
  description: string;
}

const BACKDOOR_PATTERNS: BackdoorPattern[] = [
  {
    name: 'Base64 Encoded Code',
    regex: /fromBase64\s*\(\s*["'][A-Za-z0-9+/=]{50,}["']\s*\)/g,
    severity: 'critical',
    description: 'Base64 encoded string detected - possible obfuscated malicious code.'
  },
  {
    name: 'Encoded Shell Command',
    regex: /(?:echo|printf|base64)\s+["'][A-Za-z0-9+/=]{20,}["']/gi,
    severity: 'critical',
    description: 'Encoded shell command detected - possible obfuscated attack.'
  },
  {
    name: 'Suspicious Timer/Interval',
    regex: /set(?:Timeout|Interval)\s*\(\s*(?:require|eval|Function)/g,
    severity: 'high',
    description: 'Timer with dynamic code execution detected.'
  },
  {
    name: 'Hidden File Creation',
    regex: /\.(?:hidden|dot|conf)\b/i,
    severity: 'high',
    description: 'Potential hidden file creation detected.'
  },
  {
    name: 'Netcat Reverse Shell',
    regex: /(?:nc|netcat)\s+-[el]\s+/gi,
    severity: 'critical',
    description: 'Netcat reverse shell pattern detected.'
  },
  {
    name: 'Reverse Shell',
    regex: /(?:bash|zsh|sh)\s+-i\s+.*\/?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/gi,
    severity: 'critical',
    description: 'Reverse shell command pattern detected.'
  },
  {
    name: 'Download and Execute',
    regex: /(?:curl|wget|fetch).*\|\s*(?:bash|sh|python)/gi,
    severity: 'critical',
    description: 'Remote code download and execution detected.'
  },
  {
    name: 'Hardcoded Port',
    regex: /listen\s*\(\s*(\d{4,5})\s*\)/g,
    severity: 'medium',
    description: 'Hardcoded port number detected - could be backdoor listener.'
  },
  {
    name: 'Credentials in URL',
    regex: /https?:\/\/[^\s:]+:[^\s@]+@[^\s]+/gi,
    severity: 'high',
    description: 'Credentials embedded in URL detected.'
  },
  {
    name: 'Eval with User Input',
    regex: /eval\s*\(\s*(?:req\.|request\.|body\.|query\.|params\.|headers\.)/g,
    severity: 'critical',
    description: 'eval() with user input detected - direct RCE vulnerability.'
  },
  {
    name: 'Serialized Object Execution',
    regex: /(?:unserialize|eval)\s*\(\s*(?:\$_POST|\$_GET|\$_REQUEST)/g,
    severity: 'critical',
    description: 'Deserialization of user-controlled data detected.'
  },
  {
    name: 'SQL Injection Prone',
    regex: /(?:\+|\`|\').*(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*(?:\+|\`|\')/gi,
    severity: 'critical',
    description: 'Potential SQL injection vulnerability detected.'
  },
  {
    name: 'Template Injection',
    regex: /(?:\{\{|\<\%).*(?:\}\}|\%\>).*(?:eval|include|require)/gi,
    severity: 'critical',
    description: 'Server-side template injection detected.'
  },
  {
    name: 'Path Traversal',
    regex: /(?:readFile|readFileSync|open|read).*\.\.\//g,
    severity: 'high',
    description: 'Potential path traversal vulnerability detected.'
  },
  {
    name: 'Command Injection',
    regex: /(?:exec|spawn|execSync|system|popen)\s*\([^)]*(?:\+|&&|\|\||\;).*\)/g,
    severity: 'critical',
    description: 'Potential command injection vulnerability detected.'
  },
  {
    name: 'XML External Entity',
    regex: /<!DOCTYPE\s+.*ENTITY\s+/gi,
    severity: 'high',
    description: 'XML External Entity (XXE) vulnerability detected.'
  },
  {
    name: 'Zip Slip',
    regex: /(?:unzip|extract).*\.\.\//g,
    severity: 'high',
    description: 'Potential Zip Slip directory traversal detected.'
  }
];

const XOR_OPERATOR = /\w+\s*\^\s*\w+/;

function removeRegexAndComments(line: string): string {
  let cleaned = line.replace(/\/\/.*$/, '');
  cleaned = cleaned.replace(/\/[^\/\n]+\/[gimsuy]*/g, '""');
  cleaned = cleaned.replace(/"[^"]*"|'[^']*'|`[^`]*`/g, '""');
  return cleaned;
}

export class BackdoorDetector implements Detector {
  name = 'Backdoor Detection';
  description = 'Detects known malicious patterns, backdoors, and attack vectors';

  async scan(file: FileInfo, content: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const pattern of BACKDOOR_PATTERNS) {
      let match;
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);

      while ((match = regex.exec(content)) !== null) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        const line = lines[lineNumber - 1] || '';

        if (file.relativePath.includes('node_modules') || file.relativePath.includes('.git')) {
          continue;
        }

        findings.push({
          id: `backdoor-${pattern.name.toLowerCase().replace(/\s+/g, '-')}`,
          type: 'backdoor',
          severity: pattern.severity,
          title: pattern.name,
          message: pattern.description,
          file: file.relativePath,
          line: lineNumber,
          code: line.trim().substring(0, 100),
          detector: 'Backdoor Detection',
          recommendation: 'Review this code carefully. If not intentional, remove immediately.'
        });
      }
    }

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const cleaned = removeRegexAndComments(line);
      if (XOR_OPERATOR.test(cleaned)) {
        if (file.relativePath.includes('node_modules') || file.relativePath.includes('.git')) {
          continue;
        }
        findings.push({
          id: 'backdoor-suspicious-xor',
          type: 'backdoor',
          severity: 'high',
          title: 'Suspicious XOR',
          message: 'XOR obfuscation detected - common in malware.',
          file: file.relativePath,
          line: i + 1,
          code: line.trim().substring(0, 100),
          detector: 'Backdoor Detection',
          recommendation: 'Review this code carefully. If not intentional, remove immediately.'
        });
      }
    }

    return findings;
  }
}
