import * as fs from 'fs';
import * as path from 'path';
import { ScanOptions, ScanResult } from '../types';
import { mapProject } from '../core/mapper';
import { runScanners } from '../core/scanner';
import { report } from '../core/reporter';
import { logger } from '../utils/logger';
import { version } from '../../package.json';

export async function scan(options: ScanOptions): Promise<void> {
  const startTime = Date.now();
  
  logger.header(`Uncloak Security Scanner v${version}`);
  logger.subHeader('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  
  if (options.verbose) {
    logger.info(`Scanning: ${options.path}`);
  }

  logger.info('Mapping project...');
  const projectMap = await mapProject(options.path, options);
  
  logger.success(`Found ${projectMap.totalFiles} files (${Array.from(projectMap.languages.entries()).map(([k, v]) => `${k}: ${v}`).join(', ')})`);
  
  logger.info('Running security scanners...');
  const findings = await runScanners(projectMap, options);
  
  const scanTime = Date.now() - startTime;
  
  const result: ScanResult = {
    projectMap,
    findings,
    scanTime,
    version
  };

  report(result, options);

  if (options.output === 'json') {
    console.log(JSON.stringify(result, null, 2));
  }
}
