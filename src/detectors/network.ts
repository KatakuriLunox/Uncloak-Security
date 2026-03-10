import { Finding, FileInfo, Detector, Severity } from '../types';

const SUSPICIOUS_DOMAINS = [
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  'metadata.google.internal',
  '169.254.169.254',
  'metadata.azure.com',
  'aws.amazon.com',
  'kubernetes.default.svc'
];

const NETWORK_PATTERNS = [
  {
    name: 'Hardcoded IP Address',
    regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    severity: 'low' as Severity,
    message: 'Hardcoded IP address found. Consider using environment variables.'
  },
  {
    name: 'Fetch/XHR Call',
    regex: /(?:fetch|axios|request|http\.(?:get|post|put|delete|patch))\s*\(/g,
    severity: 'info' as Severity,
    message: 'Network request detected. Ensure the endpoint is secure and trusted.'
  },
  {
    name: 'WebSocket Connection',
    regex: /new\s+WebSocket\s*\(/g,
    severity: 'info' as Severity,
    message: 'WebSocket connection found. Ensure the endpoint is secure.'
  },
  {
    name: 'HTTP URL',
    regex: /https?:\/\/[^\s"'<>]+/g,
    severity: 'info' as Severity,
    message: 'External URL detected. Ensure the endpoint is trusted.'
  }
];

export class NetworkDetector implements Detector {
  name = 'Network Activity';
  description = 'Detects network requests and suspicious external connections';

  async scan(file: FileInfo, content: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const pattern of NETWORK_PATTERNS) {
      let match;
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);

      while ((match = regex.exec(content)) !== null) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        const line = lines[lineNumber - 1] || '';

        findings.push({
          id: `network-${pattern.name.toLowerCase().replace(/\s+/g, '-')}`,
          type: 'network',
          severity: pattern.severity,
          title: pattern.name,
          message: pattern.message,
          file: file.relativePath,
          line: lineNumber,
          code: line.trim().substring(0, 100),
          detector: 'Network Activity'
        });
      }
    }

    for (const domain of SUSPICIOUS_DOMAINS) {
      const domainRegex = new RegExp(`['"\\s]${domain.replace(/\./g, '\\.')}['"\\s]`, 'g');
      let match;
      while ((match = domainRegex.exec(content)) !== null) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        const line = lines[lineNumber - 1] || '';
        
        if (line.includes('SUSPICIOUS_DOMAINS') || line.includes('const ') && line.includes('=') && line.includes(domain)) {
          continue;
        }

        findings.push({
          id: 'network-suspicious-endpoint',
          type: 'network',
          severity: 'medium',
          title: 'Suspicious endpoint access',
          message: `Access to ${domain} detected. This could indicate attempt to access metadata service.`,
          file: file.relativePath,
          line: lineNumber,
          code: line.trim().substring(0, 100),
          detector: 'Network Activity'
        });
      }
    }

    return findings;
  }
}
