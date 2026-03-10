import { ScanResult, Severity } from '../types';
import { table } from 'table';

const severityColors: Record<Severity, (str: string) => string> = {
  critical: (s) => `\x1b[31m${s}\x1b[0m`,
  high: (s) => `\x1b[35m${s}\x1b[0m`,
  medium: (s) => `\x1b[33m${s}\x1b[0m`,
  low: (s) => `\x1b[36m${s}\x1b[0m`,
  info: (s) => `\x1b[90m${s}\x1b[0m`
};

const severityIcons: Record<Severity, string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🔵',
  info: '⚪'
};

export function report(result: ScanResult, options: { output?: string; severity?: string }): void {
  if (options.output === 'json' || options.output === 'sarif') {
    return;
  }

  console.log('\n');
  
  if (result.findings.length === 0) {
    console.log('\n✅ No security issues found!\n');
    return;
  }

  const grouped = {
    critical: result.findings.filter(f => f.severity === 'critical'),
    high: result.findings.filter(f => f.severity === 'high'),
    medium: result.findings.filter(f => f.severity === 'medium'),
    low: result.findings.filter(f => f.severity === 'low'),
    info: result.findings.filter(f => f.severity === 'info')
  };

  for (const [severity, findings] of Object.entries(grouped)) {
    if (findings.length === 0) continue;
    
    console.log(`\n${severityIcons[severity as Severity]} ${severity.toUpperCase()}: ${findings.length} issue${findings.length > 1 ? 's' : ''}\n`);
    
    for (const finding of findings) {
      console.log(`   ${severityColors[finding.severity]('⚠')} ${finding.title}`);
      console.log(`   → ${finding.file}${finding.line ? `:${finding.line}` : ''}`);
      console.log(`   ${finding.message}`);
      console.log('');
    }
  }

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`📊 Summary: ${result.findings.length} issues found`);
  console.log(`   Critical: ${grouped.critical.length} | High: ${grouped.high.length} | Medium: ${grouped.medium.length} | Low: ${grouped.low.length} | Info: ${grouped.info.length}`);
  console.log(`   Scan completed in ${result.scanTime}ms\n`);
}
