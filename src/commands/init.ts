import * as fs from 'fs';
import * as path from 'path';
import { logger } from '../utils/logger';

export async function init(): Promise<void> {
  const configPath = path.join(process.cwd(), 'uncloak.config.json');
  
  const config = {
    include: ['**/*.{js,ts,jsx,tsx,mjs,cjs,json}'],
    exclude: [
      '**/node_modules/**',
      '**/dist/**',
      '**/build/**',
      '**/.git/**',
      '**/coverage/**'
    ],
    severity: 'low',
    output: 'cli',
    verbose: false,
    skipDependencies: false,
    skipSecrets: false,
    skipUnsafe: false,
    skipNetwork: false,
    skipBackdoor: false
  };

  try {
    await fs.promises.writeFile(configPath, JSON.stringify(config, null, 2), 'utf-8');
    logger.success(`Created ${configPath}`);
    logger.info('You can customize the configuration by editing this file.');
  } catch (error) {
    logger.error(`Failed to create config: ${error}`);
  }
}
