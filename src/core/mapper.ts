import * as fs from 'fs';
import * as path from 'path';
import { FileInfo, ProjectMap, PackageJsonInfo, ScanOptions } from '../types';
import { findFiles, getFileExtension, getRelativePath, getLanguageFromExtension, getFileSize } from '../utils/file';

export async function mapProject(rootPath: string, options: ScanOptions): Promise<ProjectMap> {
  const absoluteRoot = path.resolve(rootPath);
  
  const includePatterns = options.include || [
    '**/*.{js,jsx,ts,tsx,mjs,cjs,json,html,css,scss,sass,less,md,mdx,yaml,yml,toml,xml,sql,sh,py,rb,go,rs,java,c,cpp,h,hpp,cs,php,swift,kt}'
  ];
  const excludePatterns = options.exclude || [
    '**/node_modules/**',
    '**/dist/**',
    '**/build/**',
    '**/.git/**',
    '**/coverage/**',
    '**/*.log',
    '**/vendor/**',
    '**/.next/**',
    '**/.nuxt/**',
    '**/.cache/**',
    '**/tmp/**',
    '**/.tmp/**',
    '**/src/**',
    '**/lib/**',
    '**/bin/**',
    '**/test/**',
    '**/tests/**',
    '**/__tests__/**',
    '**/.uncloak/**'
  ];

  const filePaths = await findFiles(absoluteRoot, includePatterns, excludePatterns);
  
  const files: FileInfo[] = [];
  const languages = new Map<string, number>();

  for (const filePath of filePaths) {
    const extension = getFileExtension(filePath);
    const language = getLanguageFromExtension(extension);
    const size = await getFileSize(filePath);
    
    files.push({
      path: filePath,
      relativePath: getRelativePath(filePath, absoluteRoot),
      extension,
      size,
      language
    });

    languages.set(language, (languages.get(language) || 0) + 1);
  }

  let packageJson: PackageJsonInfo | undefined;
  const packageJsonPath = path.join(absoluteRoot, 'package.json');
  
  try {
    const content = await fs.promises.readFile(packageJsonPath, 'utf-8');
    const pkg = JSON.parse(content);
    packageJson = {
      name: pkg.name || 'unknown',
      version: pkg.version || '0.0.0',
      dependencies: pkg.dependencies || {},
      devDependencies: pkg.devDependencies || {}
    };
  } catch {
  }

  return {
    root: absoluteRoot,
    files,
    totalFiles: files.length,
    languages,
    packageJson
  };
}
