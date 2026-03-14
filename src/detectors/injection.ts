import { Finding, FileInfo, Detector, Severity } from '../types';

interface InjectionPattern {
  name: string;
  regex: RegExp;
  severity: Severity;
  message: string;
}

const INJECTION_PATTERNS: InjectionPattern[] = [
  {
    name: 'SQL Injection - Template Literal',
    regex: /`.*(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*\$\{/gi,
    severity: 'critical',
    message: 'SQL query built using template literal. Use parameterized queries instead.'
  },
  {
    name: 'SQL Injection - Execute with string',
    regex: /(?:execute|query|run)\s*\(\s*(?:["'`]|\$\{)/gi,
    severity: 'critical',
    message: 'SQL query passed directly to execute/query. Use parameterized queries.'
  },
  {
    name: 'XSS - innerHTML assignment',
    regex: /(?:document\.)?innerHTML\s*=|outerHTML\s*=/g,
    severity: 'critical',
    message: 'Assigning user input to innerHTML/outerHTML can lead to XSS attacks.'
  },
  {
    name: 'XSS - dangerouslySetInnerHTML',
    regex: /dangerouslySetInnerHTML/gi,
    severity: 'critical',
    message: 'dangerouslySetInnerHTML can lead to XSS. Ensure content is sanitized.'
  },
  {
    name: 'XSS - jQuery html()',
    regex: /\.\s*html\s*\(\s*(?:req|request|body|user|params|query)/gi,
    severity: 'critical',
    message: 'jQuery html() with user input can lead to XSS attacks.'
  },
  {
    name: 'Command Injection - exec',
    regex: /(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(\s*(?:["'`]|\$\{|req|request|body|user)/gi,
    severity: 'critical',
    message: 'Command execution with user input. Sanitize input or use execFile with args array.'
  },
  {
    name: 'Command Injection - shell=True equivalent',
    regex: /(?:child_process|spawn|exec)\s*\(.*(?:shell\s*:\s*true|\|\s*|\&\&|\|\||\;)/gi,
    severity: 'critical',
    message: 'Shell command execution can be vulnerable to injection attacks.'
  },
  {
    name: 'Path Traversal',
    regex: /\.\.\/|\.\.\\|%2e%2e/gi,
    severity: 'critical',
    message: 'Path traversal pattern detected. Validate and sanitize file paths.'
  },
  {
    name: 'Eval with User Input',
    regex: /\beval\s*\(\s*(?:req|request|body|user|params|query|input)/gi,
    severity: 'critical',
    message: 'eval() with user input can lead to remote code execution.'
  },
  {
    name: 'Dynamic Code Execution - Function constructor',
    regex: /\bnew\s+Function\s*\(\s*(?:req|request|body|user|params|query)/gi,
    severity: 'critical',
    message: 'Function constructor with user input can execute arbitrary code.'
  },
  {
    name: 'Dynamic Code Execution - setTimeout/Interval',
    regex: /(?:setTimeout|setInterval)\s*\(\s*(?:req|request|body|user|params|query)/gi,
    severity: 'critical',
    message: 'setTimeout/setInterval with dynamic code can be dangerous.'
  },
  {
    name: 'Server-Side Template Injection',
    regex: /(?:render|renderToString|renderToStaticMarkup)\s*\(\s*(?:req|request|body|user|params)/gi,
    severity: 'critical',
    message: 'Server-side template injection detected. Validate template input.'
  }
];

const SQL_KEYWORDS = /\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN|DROP|ALTER|UNION|CREATE)\b/i;
const STRING_CONCAT = /['"`]\s*\+\s*\w+|\w+\s*\+\s*['"`]/;

export class InjectionDetector implements Detector {
  name = 'Injection Attacks';
  description = 'Detects SQL injection, XSS, command injection, and path traversal vulnerabilities';

  async scan(file: FileInfo, content: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const pattern of INJECTION_PATTERNS) {
      let match;
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      
      while ((match = regex.exec(content)) !== null) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        const line = lines[lineNumber - 1] || '';
        
        findings.push({
          id: `injection-${pattern.name.toLowerCase().replace(/\s+/g, '-')}`,
          type: 'unsafe',
          severity: pattern.severity,
          title: pattern.name,
          message: pattern.message,
          file: file.relativePath,
          line: lineNumber,
          code: line.trim().substring(0, 100),
          detector: 'Injection Attacks'
        });
      }
    }

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const hasSQL = SQL_KEYWORDS.test(line);
      const hasConcat = STRING_CONCAT.test(line);

      if (hasSQL && hasConcat) {
        findings.push({
          id: 'injection-sql-injection-string-concatenation',
          type: 'unsafe',
          severity: 'critical',
          title: 'SQL Injection - String Concatenation',
          message: 'SQL query built using string concatenation. Use parameterized queries instead.',
          file: file.relativePath,
          line: i + 1,
          code: line.trim().substring(0, 100),
          detector: 'Injection Attacks'
        });
      }
    }

    return findings;
  }
}
