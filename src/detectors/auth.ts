import { Finding, FileInfo, Detector, Severity } from '../types';

interface AuthPattern {
  name: string;
  regex: RegExp;
  severity: Severity;
  message: string;
}

const AUTH_PATTERNS: AuthPattern[] = [
  {
    name: 'Hardcoded Username/Password',
    regex: /(?:username|user|login)\s*[=:]\s*["']([^"'\s]+)["']/gi,
    severity: 'high',
    message: 'Hardcoded username detected. Use environment variables or configuration.'
  },
  {
    name: 'Hardcoded Password in Variable',
    regex: /(?:password|passwd|pwd|secret)\s*[=:]\s*(?!.*(?:process\.env|require|import|from|config|env|getenv))["']([^"'\s]{4,})["']/gi,
    severity: 'high',
    message: 'Hardcoded password detected. Use environment variables or secrets manager.'
  },
  {
    name: 'Basic Auth Header',
    regex: /Authorization\s*:\s*Basic\s+[A-Za-z0-9+/=]+/gi,
    severity: 'high',
    message: 'Basic authentication header detected. Ensure credentials are not hardcoded.'
  },
  {
    name: 'Bearer Token in Code',
    regex: /Bearer\s+[A-Za-z0-9\-_\.]+/gi,
    severity: 'high',
    message: 'Bearer token detected in code. Use environment variables.'
  },
  {
    name: 'Missing Authentication Check',
    regex: /(?:router|route|app\.(?:get|post|put|delete|patch))\s*\(\s*["'][^"']+["']\s*,?\s*(?:function|\([^)]*\)\s*=>|async\s*(?:\([^)]*\))?\s*=>)/g,
    severity: 'high',
    message: 'Route without explicit authentication middleware. Ensure access is properly controlled.'
  },
  {
    name: 'JWT Secret Hardcoded',
    regex: /(?:jwt|JWT)\s*\.?\s*(?:secret|key)\s*[=:]\s*["']([^"'\s]{8,})["']/gi,
    severity: 'critical',
    message: 'Hardcoded JWT secret detected. Use environment variables.'
  },
  {
    name: 'Weak JWT Algorithm',
    regex: /(?:algorithm|alg)\s*[=:]\s*["'](?:none|HS256|HS512)["']/gi,
    severity: 'high',
    message: 'Weak or insecure JWT algorithm. Use RS256 or ES256.'
  },
  {
    name: 'Session Without Secure Flag',
    regex: /(?:cookie|Cookie)\s*\.\s*(?:session|httpOnly|secure)\s*[=:]\s*(?:false|0)/gi,
    severity: 'medium',
    message: 'Session cookie without secure flag. Set secure: true for HTTPS.'
  },
  {
    name: 'CORS Wildcard',
    regex: /Access-Control-Allow-Origin\s*:\s*\*/gi,
    severity: 'high',
    message: 'CORS wildcard origin detected. Restrict to specific domains in production.'
  },
  {
    name: 'Missing Authorization Header Check',
    regex: /(?:if|unless)\s*\(\s*!(?:req|request|ctx|context|user)\s*\.\s*(?:session|user|auth|isAuthenticated)/gi,
    severity: 'high',
    message: 'Missing authorization check. Ensure user is authenticated before allowing access.'
  },
  {
    name: 'SQL Auth Query',
    regex: /(?:SELECT|INSERT|UPDATE).*?(?:FROM|INTO|UPDATE).*?(?:users|accounts|admins).*?(?:WHERE|VALUES)/gi,
    severity: 'high',
    message: 'SQL query related to authentication. Use ORM or parameterized queries.'
  }
];

const AUTH_FUNCTION_PATTERN = /\b(auth|login|verify|isAdmin|hasPermission|checkAccess|validate|authenticate|isLoggedIn|isAuthorized)\b/i;

const AUTH_BYPASS_REGEX = /(?:return\s+true|if\s*\(\s*true\s*\)|if\s*\(\s*1\s*\))/gi;

function getContainingFunctionName(lines: string[], lineIndex: number): string {
  for (let i = lineIndex; i >= 0; i--) {
    const line = lines[i];
    const fnMatch = line.match(/function\s+(\w+)/);
    if (fnMatch) return fnMatch[1];
    const arrowFnMatch = line.match(/(\w+)\s*[=:]\s*(?:async\s*)?\(/);
    if (arrowFnMatch) return arrowFnMatch[1];
    const methodMatch = line.match(/(\w+)\s*\(.*\)\s*(?::\s*\w+)?\s*\{/);
    if (methodMatch) return methodMatch[1];
  }
  return '';
}

export class AuthDetector implements Detector {
  name = 'Authentication & Authorization';
  description = 'Detects authentication issues, hardcoded credentials, and authorization bypasses';

  async scan(file: FileInfo, content: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const pattern of AUTH_PATTERNS) {
      let match;
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      
      while ((match = regex.exec(content)) !== null) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        const line = lines[lineNumber - 1] || '';
        
        findings.push({
          id: `auth-${pattern.name.toLowerCase().replace(/\s+/g, '-')}`,
          type: 'unsafe',
          severity: pattern.severity,
          title: pattern.name,
          message: pattern.message,
          file: file.relativePath,
          line: lineNumber,
          code: line.trim().substring(0, 100),
          detector: 'Authentication & Authorization'
        });
      }
    }

    let match;
    while ((match = AUTH_BYPASS_REGEX.exec(content)) !== null) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      const line = lines[lineNumber - 1] || '';
      const fnName = getContainingFunctionName(lines, lineNumber - 1);
      
      if (AUTH_FUNCTION_PATTERN.test(fnName)) {
        findings.push({
          id: 'auth-authentication-bypass',
          type: 'unsafe',
          severity: 'critical',
          title: 'Authentication Bypass',
          message: 'Potential authentication bypass detected. Conditional that always returns true.',
          file: file.relativePath,
          line: lineNumber,
          code: line.trim().substring(0, 100),
          detector: 'Authentication & Authorization'
        });
      }
    }

    return findings;
  }
}
