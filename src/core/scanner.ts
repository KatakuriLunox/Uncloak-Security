import { Finding, ProjectMap, ScanOptions, Detector } from '../types';
import { SecretsDetector } from '../detectors/secrets';
import { InjectionDetector } from '../detectors/injection';
import { FileSystemDetector } from '../detectors/filesystem';
import { AuthDetector } from '../detectors/auth';
import { ErrorHandlingDetector } from '../detectors/errorhandling';
import { CryptoDetector } from '../detectors/crypto';
import { PerformanceDetector } from '../detectors/performance';
import { AIDetector } from '../detectors/ai';
import { QualityDetector } from '../detectors/quality';
import { NetworkDetector } from '../detectors/network';
import { BackdoorDetector } from '../detectors/backdoor';
import { logger } from '../utils/logger';
import * as fs from 'fs';
import * as fsPromises from 'fs/promises';

const CONFIG_FILES = [
  'package.json',
  'package-lock.json',
  'yarn.lock',
  'tsconfig.json',
  'jsconfig.json',
  '.eslintrc',
  '.eslintrc.json',
  '.eslintrc.js',
  '.prettierrc',
  '.prettierrc.json',
  'jest.config.js',
  'jest.config.json',
  'webpack.config.js',
  'vite.config.ts',
  'next.config.js',
  'nuxt.config.js',
  '.npmrc',
  '.yarnrc'
];

function deduplicateFindings(findings: Finding[]): Finding[] {
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const seen = new Map<string, Finding>();
  
  for (const finding of findings) {
    const key = `${finding.file}:${finding.line}`;
    const existing = seen.get(key);
    
    if (!existing || severityOrder[finding.severity] < severityOrder[existing.severity]) {
      seen.set(key, finding);
    }
  }
  
  return Array.from(seen.values()).sort((a, b) => 
    severityOrder[a.severity] - severityOrder[b.severity]
  );
}

export async function runScanners(projectMap: ProjectMap, options: ScanOptions): Promise<Finding[]> {
  const allFindings: Finding[] = [];
  
  const detectors: Detector[] = [];
  
  if (!options.skipSecrets) {
    detectors.push(new SecretsDetector());
  }
  if (!options.skipUnsafe) {
    detectors.push(new InjectionDetector());
    detectors.push(new FileSystemDetector());
    detectors.push(new AuthDetector());
    detectors.push(new ErrorHandlingDetector());
    detectors.push(new CryptoDetector());
    detectors.push(new PerformanceDetector());
    detectors.push(new AIDetector());
    detectors.push(new QualityDetector());
  }
  if (!options.skipNetwork) {
    detectors.push(new NetworkDetector());
  }
  if (!options.skipBackdoor) {
    detectors.push(new BackdoorDetector());
  }

  for (const detector of detectors) {
    logger.debug(`Running detector: ${detector.name}`);
    
    for (const file of projectMap.files) {
      const isConfigFile = CONFIG_FILES.some(cfg => file.relativePath.endsWith(cfg));
      
      if (isConfigFile) {
        continue;
      }
      
      try {
        const content = await fsPromises.readFile(file.path, 'utf-8');
        const findings = await detector.scan(file, content);
        allFindings.push(...findings);
      } catch (error) {
        logger.debug(`Error scanning ${file.path}: ${error}`);
      }
    }
  }

  const deduplicated = deduplicateFindings(allFindings);

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const severityIndex = severityOrder[options.severity || 'low'];
  
  return deduplicated.filter(f => severityOrder[f.severity] <= severityIndex);
}
