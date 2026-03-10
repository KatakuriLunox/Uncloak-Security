import { Finding, FileInfo, Detector, Severity } from '../types';

interface CryptoPattern {
  name: string;
  regex: RegExp;
  severity: Severity;
  message: string;
}

const CRYPTO_PATTERNS: CryptoPattern[] = [
  {
    name: 'MD5 Usage',
    regex: /(?:\bmd5\b|MD5|crypto\.createHash\s*\(\s*["']md5["'])/gi,
    severity: 'high',
    message: 'MD5 is cryptographically broken. Use SHA-256 or stronger for security.'
  },
  {
    name: 'SHA1 Usage',
    regex: /(?:\bsha1\b|SHA1|crypto\.createHash\s*\(\s*["']sha1["'])/gi,
    severity: 'high',
    message: 'SHA-1 is cryptographically weak. Use SHA-256 or stronger.'
  },
  {
    name: 'Weak Random Number',
    regex: /(?:Math\.random\(\))/g,
    severity: 'high',
    message: 'Math.random() is predictable. Use crypto.randomBytes() for security.'
  },
  {
    name: 'Hardcoded Encryption Key',
    regex: /(?:encryptKey|decryptKey|encryptionKey|secretKey)\s*[=:]\s*["'][^"'\s]{8,}["']/gi,
    severity: 'critical',
    message: 'Hardcoded encryption key detected. Use environment variables or key management.'
  },
  {
    name: 'DES Algorithm',
    regex: /(?:crypto\.create(?:Cipher|Decipher)\s*\(\s*["']des["']|\bDES\b)/g,
    severity: 'high',
    message: 'DES is cryptographically weak. Use AES-256.'
  },
  {
    name: 'RC4 Algorithm',
    regex: /(?:crypto\.create(?:Cipher|Decipher)\s*\(\s*["']rc4["']|\brc4\b)/gi,
    severity: 'high',
    message: 'RC4 is cryptographically broken. Use AES.'
  },
  {
    name: 'ECB Mode',
    regex: /(?:ECB|ecb|crypto\.createCipheriv\s*\([^)]*,\s*null\s*,)/gi,
    severity: 'high',
    message: 'ECB mode is insecure. Use CBC or GCM with a random IV.'
  },
  {
    name: 'Missing Salt in Hash',
    regex: /(?:crypto\.createHash|crypto\.createHmac)\s*\([^)]*\)(?!\s*\.\s*update\s*\(\s*salt)/gi,
    severity: 'high',
    message: 'Hash without salt detected. Use salt for password hashing.'
  },
  {
    name: 'Password Hashing with Crypto',
    regex: /crypto\.createHash\s*\(\s*["'](?:md5|sha1|sha256)["']\s*\)\s*\.\s*update\s*\(\s*password/gi,
    severity: 'high',
    message: 'Using raw crypto for password hashing. Use bcrypt or Argon2.'
  },
  {
    name: 'Insecure TLS Version',
    regex: /(?:secureProtocol\s*[=:]\s*["'](?:SSLv3|TLSv1|TLSv1\.1)["']|minVersion\s*[=:]\s*(?:1|1\.0|1\.1))/gi,
    severity: 'high',
    message: 'Insecure TLS version. Use TLS 1.2 or higher.'
  },
  {
    name: 'Certificate Verification Disabled',
    regex: /(?:rejectUnauthorized\s*[=:]\s*(?:false|0)|verify\s*[=:]\s*(?:false|0))/gi,
    severity: 'critical',
    message: 'Certificate verification disabled. Always verify certificates in production.'
  },
  {
    name: 'IV Not Random',
    regex: /createIV\s*\(\s*(?:null|undefined|0|["'][0-9a-fA-F]+["'])\s*\)/gi,
    severity: 'high',
    message: 'Non-random IV detected. Use crypto.randomBytes() for IV.'
  },
  {
    name: 'HMAC with MD5/SHA1',
    regex: /createHmac\s*\(\s*["'](?:md5|sha1|MD5|SHA1)["']/gi,
    severity: 'high',
    message: 'HMAC with weak hash. Use SHA-256 or stronger.'
  }
];

export class CryptoDetector implements Detector {
  name = 'Cryptography';
  description = 'Detects weak cryptographic algorithms, hardcoded keys, and insecure practices';

  async scan(file: FileInfo, content: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const pattern of CRYPTO_PATTERNS) {
      let match;
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      
      while ((match = regex.exec(content)) !== null) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        const line = lines[lineNumber - 1] || '';
        
        findings.push({
          id: `crypto-${pattern.name.toLowerCase().replace(/\s+/g, '-')}`,
          type: 'unsafe',
          severity: pattern.severity,
          title: pattern.name,
          message: pattern.message,
          file: file.relativePath,
          line: lineNumber,
          code: line.trim().substring(0, 100),
          detector: 'Cryptography'
        });
      }
    }

    return findings;
  }
}
