import { Finding, FileInfo, Detector, Severity, ProjectMap } from '../types';

interface Vulnerability {
  id: string;
  severity: string;
  summary: string;
  details?: string;
}

interface OSVResponse {
  vulns: Vulnerability[];
}

interface DependencyInfo {
  name: string;
  version: string;
}

async function queryOSV(dependencies: DependencyInfo[]): Promise<Vulnerability[]> {
  if (dependencies.length === 0) return [];

  try {
    const response = await fetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        queries: dependencies.map(dep => ({
          package: {
            name: dep.name,
            ecosystem: 'npm'
          },
          version: dep.version
        }))
      })
    });

    if (!response.ok) {
      return [];
    }

    const data = await response.json() as OSVResponse;
    return data.vulns || [];
  } catch (error) {
    return [];
  }
}

export class DependencyDetector implements Detector {
  name = 'Dependency Vulnerabilities';
  description = 'Checks dependencies against known vulnerability databases';

  async scan(file: FileInfo, content: string): Promise<Finding[]> {
    return [];
  }

  async scanProject(projectMap: ProjectMap): Promise<Finding[]> {
    const findings: Finding[] = [];
    
    if (!projectMap.packageJson) {
      return findings;
    }

    const allDeps = [
      ...Object.entries(projectMap.packageJson.dependencies || {}),
      ...Object.entries(projectMap.packageJson.devDependencies || {})
    ];

    const dependencies = allDeps.map(([name, version]) => ({
      name,
      version: version.replace(/[\^~>=<]/, '')
    }));

    const vulnerabilities = await queryOSV(dependencies);

    for (const vuln of vulnerabilities) {
      const severity = this.mapSeverity(vuln.severity);
      
      findings.push({
        id: `vuln-${vuln.id}`,
        type: 'vulnerability',
        severity,
        title: `Vulnerability in ${vuln.id.split('-')[0]}`,
        message: vuln.summary,
        file: 'package.json',
        cve: vuln.id,
        recommendation: 'Update the package to the latest secure version.',
        detector: 'Dependency Vulnerabilities'
      });
    }

    return findings;
  }

  private mapSeverity(osvSeverity: string): Severity {
    const severityMap: Record<string, Severity> = {
      CRITICAL: 'critical',
      HIGH: 'high',
      MEDIUM: 'medium',
      LOW: 'low',
      SEVERITY_UNSPECIFIED: 'info'
    };
    return severityMap[osvSeverity?.toUpperCase()] || 'medium';
  }
}
