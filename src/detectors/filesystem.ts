import { Finding, FileInfo, Detector, Severity } from '../types';

interface FileSystemPattern {
  name: string;
  pattern: string;
  severity: Severity;
  message: string;
}

const FILE_SYSTEM_PATTERNS: FileSystemPattern[] = [
  {
    name: 'Unrestricted File Write',
    pattern: 'writeFile',
    severity: 'high',
    message: 'File write operation detected. Ensure path is validated and not user-controlled.'
  },
  {
    name: 'Unrestricted File Delete',
    pattern: 'unlink(',
    severity: 'high',
    message: 'File deletion operation detected. Ensure path is validated.'
  },
  {
    name: 'Read Sensitive System File',
    pattern: '/etc/passwd',
    severity: 'critical',
    message: 'Attempting to read sensitive system file. This could indicate malicious activity.'
  },
  {
    name: 'File Upload Without Validation',
    pattern: 'multer',
    severity: 'high',
    message: 'File upload detected. Ensure file type, size, and content are validated.'
  },
  {
    name: 'Unrestricted File Read',
    pattern: 'readFile(',
    severity: 'medium',
    message: 'File read operation detected. Ensure path is validated to prevent path traversal.'
  },
  {
    name: 'Symbolic Link Creation',
    pattern: 'symlink(',
    severity: 'high',
    message: 'Symbolic link creation detected. This could be used for privilege escalation.'
  },
  {
    name: 'Chmod Execution',
    pattern: 'chmod(',
    severity: 'medium',
    message: 'File permission change detected. Ensure proper permissions are set.'
  },
  {
    name: 'Temporary File Usage',
    pattern: 'tmpfile',
    severity: 'low',
    message: 'Temporary file usage detected. Ensure secure temporary file handling.'
  },
  {
    name: 'Path Traversal Pattern',
    pattern: '../',
    severity: 'high',
    message: 'Path traversal pattern detected. This could lead to unauthorized file access.'
  },
  {
    name: 'Archive Extraction',
    pattern: 'unzip',
    severity: 'high',
    message: 'Archive extraction detected. Ensure archive contents are validated (Zip Slip vulnerability).'
  }
];

export class FileSystemDetector implements Detector {
  name = 'File System';
  description = 'Detects file system vulnerabilities including unrestricted file operations and path traversal';

  async scan(file: FileInfo, content: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const pattern of FILE_SYSTEM_PATTERNS) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.includes(pattern.pattern)) {
          findings.push({
            id: `filesystem-${pattern.name.toLowerCase().replace(/\s+/g, '-')}`,
            type: 'unsafe',
            severity: pattern.severity,
            title: pattern.name,
            message: pattern.message,
            file: file.relativePath,
            line: i + 1,
            code: line.trim().substring(0, 100),
            detector: 'File System'
          });
        }
      }
    }

    return findings;
  }
}
