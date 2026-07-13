/**
 * @mcpscorecard/checks — the open rubric.
 *
 * runChecks() is the whole pipeline: resolve nothing, execute every
 * applicable check against an already-resolved ScanTarget, score the
 * results. Input resolution, persistence, and presentation live in the
 * application; everything that decides a score lives here, in the open.
 */

import type { CheckContext, CheckResult, ScanReport } from './types.js';
import { checkRegistryListed, checkRepoHealth } from './checks/provenance.js';
import { checkPackageHygiene } from './checks/package-hygiene.js';
import { checkVulnerabilities } from './checks/vulnerabilities.js';
import { checkTransport } from './checks/transport.js';
import { checkCapabilities, computeToolSchemaHash, getToolSurface } from './checks/capabilities.js';
import { checkPoisoning } from './checks/poisoning.js';
import { computeScore } from './scoring.js';

export async function runChecks(ctx: CheckContext): Promise<ScanReport> {
  const [surface, registryListed, repoHealth, packageHygiene, vulns, transport] = await Promise.all([
    getToolSurface(ctx),
    checkRegistryListed(ctx),
    checkRepoHealth(ctx),
    checkPackageHygiene(ctx),
    checkVulnerabilities(ctx),
    checkTransport(ctx),
  ]);

  const checks: CheckResult[] = [
    registryListed,
    repoHealth,
    packageHygiene,
    checkCapabilities(surface),
    ...transport,
    vulns,
    checkPoisoning(surface),
  ];

  const { score, grade } = computeScore(checks);
  const hasRealTools = surface.source === 'remote-tools-list' && surface.tools.length > 0;

  return {
    target: ctx.target,
    checks,
    score,
    grade,
    toolSchemaHash: hasRealTools ? await computeToolSchemaHash(surface.tools) : undefined,
    tools: hasRealTools ? surface.tools : undefined,
    toolSource: surface.source,
    createdAt: new Date().toISOString(),
  };
}

export * from './types.js';
export { computeScore, CHECK_WEIGHTS, GRADE_BANDS, UNVERIFIABLE_CAPABILITY_CAP } from './scoring.js';
export { POISON_PATTERNS, checkPoisoning } from './checks/poisoning.js';
export { RISK_PATTERNS, checkCapabilities, computeToolSchemaHash, getToolSurface } from './checks/capabilities.js';
export { checkRegistryListed, checkRepoHealth } from './checks/provenance.js';
export { checkPackageHygiene } from './checks/package-hygiene.js';
export { checkVulnerabilities } from './checks/vulnerabilities.js';
export { checkTransport } from './checks/transport.js';
