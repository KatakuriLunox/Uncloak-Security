import { Finding, FileInfo, Detector, Severity } from '../types';

interface AIPattern {
  name: string;
  regex: RegExp;
  severity: Severity;
  message: string;
}

const AI_PATTERNS: AIPattern[] = [
  {
    name: 'Prompt Injection Risk',
    regex: /(?:prompt|Prompt|PROMPT|generate|completion|chat)\s*\(\s*(?:req|request|body|user|input|query)/gi,
    severity: 'high',
    message: 'User input passed directly to AI prompt. Sanitize and validate input.'
  },
  {
    name: 'Data Leakage to AI API',
    regex: /(?:openai|anthropic|google-ai|cohere|azure-openai)\s*\.(?:createChatCompletion|createCompletion|generateContent)\s*\(\s*{[^}]*(?:messages|prompt)/gi,
    severity: 'high',
    message: 'AI API call with potential sensitive data. Review what data is being sent.'
  },
  {
    name: 'Overly Permissive AI API',
    regex: /(?:max_tokens|temperature|top_p)\s*[=:]\s*(?:1000|null|undefined)/gi,
    severity: 'medium',
    message: 'AI API parameters not properly configured. Set reasonable limits.'
  },
  {
    name: 'AI Response Without Validation',
    regex: /(?:\.data|\.text|\.choices)\s*(?:\.|\[)0(?:\]|\.)/gi,
    severity: 'medium',
    message: 'AI response used without validation. Always validate AI output.'
  },
  {
    name: 'Missing Rate Limiting on AI',
    regex: /(?:openai|anthropic|ai)\s*\.(?:createChatCompletion|createCompletion)(?!\s*.*(?:rate|Rate|limit|Limit))/gi,
    severity: 'medium',
    message: 'AI API call without rate limiting. Implement rate limits to prevent abuse.'
  },
  {
    name: 'Hardcoded API Key for AI',
    regex: /(?:sk-[a-zA-Z0-9]{20,}|anthropic-api-key|google-ai-api-key)/gi,
    severity: 'critical',
    message: 'Hardcoded AI API key detected. Use environment variables.'
  }
];

export class AIDetector implements Detector {
  name = 'AI-Specific';
  description = 'Detects AI-related vulnerabilities including prompt injection and data leakage';

  async scan(file: FileInfo, content: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const pattern of AI_PATTERNS) {
      let match;
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      
      while ((match = regex.exec(content)) !== null) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        const line = lines[lineNumber - 1] || '';
        
        findings.push({
          id: `ai-${pattern.name.toLowerCase().replace(/\s+/g, '-')}`,
          type: 'unsafe',
          severity: pattern.severity,
          title: pattern.name,
          message: pattern.message,
          file: file.relativePath,
          line: lineNumber,
          code: line.trim().substring(0, 100),
          detector: 'AI-Specific'
        });
      }
    }

    return findings;
  }
}
