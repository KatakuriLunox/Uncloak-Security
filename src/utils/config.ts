import * as fs from 'fs';
import * as path from 'path';
import { ScanOptions } from '../types';

const DEFAULT_CONFIG = {
  include: ['**/*.{js,ts,jsx,tsx,mjs,cjs,json}'],
  exclude: [
    '**/node_modules/**',
    '**/dist/**',
    '**/build/**',
    '**/.git/**',
    '**/coverage/**',
    '**/*.log',
    '**/vendor/**'
  ],
  severity: 'low' as const,
  output: 'cli' as const,
  verbose: false,
  skipDependencies: false,
  skipSecrets: false,
  skipUnsafe: false,
  skipNetwork: false,
  skipBackdoor: false
};

export interface UncloakConfig extends ScanOptions {}

export async function loadConfig(configPath?: string): Promise<UncloakConfig> {
  const defaultConfig: UncloakConfig = { ...DEFAULT_CONFIG, path: process.cwd() };

  if (!configPath) {
    const possiblePaths = [
      path.join(process.cwd(), 'uncloak.config.json'),
      path.join(process.cwd(), '.uncloak.json'),
      path.join(process.cwd(), '.uncloakrc')
    ];

    for (const p of possiblePaths) {
      if (await fileExists(p)) {
        configPath = p;
        break;
      }
    }
  }

  if (configPath && await fileExists(configPath)) {
    try {
      const content = await fs.promises.readFile(configPath, 'utf-8');
      const userConfig = JSON.parse(content);
      return { ...defaultConfig, ...userConfig };
    } catch (error) {
      console.warn('Failed to load config, using defaults');
    }
  }

  return defaultConfig;
}

export async function saveConfig(config: Partial<UncloakConfig>, configPath?: string): Promise<void> {
  const pathToSave = configPath || path.join(process.cwd(), 'uncloak.config.json');
  const content = JSON.stringify({ ...DEFAULT_CONFIG, ...config }, null, 2);
  await fs.promises.writeFile(pathToSave, content, 'utf-8');
}

async function fileExists(filePath: string): Promise<boolean> {
  try {
    await fs.promises.access(filePath, fs.constants.F_OK);
    return true;
  } catch {
    return false;
  }
}
