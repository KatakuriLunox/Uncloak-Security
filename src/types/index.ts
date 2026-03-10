export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  id: string;
  type: 'secret' | 'unsafe' | 'vulnerability' | 'network' | 'backdoor';
  severity: Severity;
  title: string;
  message: string;
  file: string;
  line?: number;
  column?: number;
  code?: string;
  detector: string;
  cve?: string;
  recommendation?: string;
}

export interface FileInfo {
  path: string;
  relativePath: string;
  extension: string;
  size: number;
  language: string;
}

export interface ProjectMap {
  root: string;
  files: FileInfo[];
  totalFiles: number;
  languages: Map<string, number>;
  packageJson?: PackageJsonInfo;
}

export interface PackageJsonInfo {
  name: string;
  version: string;
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
}

export interface ScanOptions {
  path: string;
  include?: string[];
  exclude?: string[];
  severity?: Severity;
  output?: 'cli' | 'json' | 'sarif';
  verbose?: boolean;
  skipDependencies?: boolean;
  skipSecrets?: boolean;
  skipUnsafe?: boolean;
  skipNetwork?: boolean;
  skipBackdoor?: boolean;
}

export interface ScanResult {
  projectMap: ProjectMap;
  findings: Finding[];
  scanTime: number;
  version: string;
}

export interface Detector {
  name: string;
  description: string;
  scan(file: FileInfo, content: string): Promise<Finding[]>;
}
