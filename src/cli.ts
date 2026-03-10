import { Command } from 'commander';
import { scan } from './commands/scan';
import { init } from './commands/init';
import { version } from '../package.json';

export function createCLI(): Command {
  const program = new Command();

  program
    .name('uncloak')
    .description('Security auditing CLI - finds vulnerabilities, code issues, backdoors, and malicious activity')
    .version(version);

  program
    .command('scan')
    .description('Scan a project for security issues')
    .argument('[path]', 'Path to scan (default: current directory)', process.cwd())
    .option('-o, --output <format>', 'Output format: cli, json, sarif', 'cli')
    .option('-s, --severity <level>', 'Minimum severity: critical, high, medium, low, info', 'low')
    .option('-v, --verbose', 'Enable verbose output', false)
    .option('--skip-deps', 'Skip dependency vulnerability scanning', false)
    .option('--skip-secrets', 'Skip secrets scanning', false)
    .option('--skip-unsafe', 'Skip unsafe patterns scanning', false)
    .option('--skip-network', 'Skip network activity scanning', false)
    .option('--skip-backdoor', 'Skip backdoor detection', false)
    .option('--include <patterns>', 'File patterns to include (comma-separated)')
    .option('--exclude <patterns>', 'File patterns to exclude (comma-separated)')
    .action(async (path, options) => {
      await scan({
        path,
        output: options.output,
        severity: options.severity,
        verbose: options.verbose,
        skipDependencies: options.skipDeps,
        skipSecrets: options.skipSecrets,
        skipUnsafe: options.skipUnsafe,
        skipNetwork: options.skipNetwork,
        skipBackdoor: options.skipBackdoor,
        include: options.include?.split(','),
        exclude: options.exclude?.split(',')
      });
    });

  program
    .command('init')
    .description('Initialize uncloak configuration')
    .action(async () => {
      await init();
    });

  return program;
}
