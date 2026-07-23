/**
 * Local one-off scanner: runChecks against a resolved ScanTarget.
 *
 * Usage:
 *   npx tsx src/scan.ts @modelcontextprotocol/server-filesystem
 *   npx tsx src/scan.ts --npm @modelcontextprotocol/server-filesystem --github modelcontextprotocol/servers
 *   npx tsx src/scan.ts --url https://example.com/mcp
 *
 * Optional: GITHUB_TOKEN for better repo-health results.
 */

import { runChecks } from './index.js';
import type { ScanTarget, SourceType } from './types.js';

function usage(): never {
  console.error(`Usage:
  npx tsx src/scan.ts <npm-package>
  npx tsx src/scan.ts --npm <pkg> [--github owner/repo] [--registry <name>]
  npx tsx src/scan.ts --url <https://...>

Env: GITHUB_TOKEN (optional)
`);
  process.exit(1);
}

function parseArgs(argv: string[]): ScanTarget {
  if (argv.length === 0) usage();

  let npmPackage: string | undefined;
  let github: { owner: string; repo: string } | undefined;
  let registryName: string | undefined;
  let remoteUrl: string | undefined;
  const positional: string[] = [];

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--npm') npmPackage = argv[++i];
    else if (a === '--github') {
      const v = argv[++i];
      if (!v?.includes('/')) usage();
      const [owner, repo] = v.split('/');
      github = { owner: owner!, repo: repo! };
    } else if (a === '--registry') registryName = argv[++i];
    else if (a === '--url') remoteUrl = argv[++i];
    else if (a.startsWith('-')) usage();
    else positional.push(a);
  }

  if (positional.length === 1 && !npmPackage && !remoteUrl) {
    const p = positional[0]!;
    if (p.startsWith('http://') || p.startsWith('https://')) remoteUrl = p;
    else npmPackage = p;
  }

  if (!npmPackage && !remoteUrl && !registryName && !github) usage();

  let sourceType: SourceType = 'npm';
  if (remoteUrl) sourceType = 'remote';
  else if (registryName) sourceType = 'registry';
  else if (github && !npmPackage) sourceType = 'github';

  const input = remoteUrl ?? npmPackage ?? registryName ?? `${github?.owner}/${github?.repo}`;
  return {
    input: input!,
    sourceType,
    displayName: input!,
    npmPackage,
    github,
    registryName,
    remoteUrl,
  };
}

async function main() {
  const target = parseArgs(process.argv.slice(2));
  const report = await runChecks({
    target,
    fetch: globalThis.fetch,
    githubToken: process.env.GITHUB_TOKEN,
  });

  console.log(
    JSON.stringify(
      {
        target: report.target,
        score: report.score,
        grade: report.grade,
        toolSource: report.toolSource,
        toolSchemaHash: report.toolSchemaHash,
        checks: report.checks.map((c) => ({
          id: c.id,
          policyRef: c.policyRef,
          status: c.status,
          summary: c.summary,
          evidence: c.evidence,
        })),
      },
      null,
      2,
    ),
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
