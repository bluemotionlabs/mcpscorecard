/**
 * §4.1 Known vulnerabilities — OSV.dev lookup for the published package.
 * Direct dependencies are deferred to a later version; the package itself
 * is the highest-signal, lowest-noise query.
 */

import type { CheckContext, CheckResult, Evidence } from '../types.js';
import { errMsg, fetchWithTimeout } from './provenance.js';

export async function checkVulnerabilities(ctx: CheckContext): Promise<CheckResult> {
  const base = {
    id: 'vulns.osv',
    policyRef: '§4.1',
    title: 'No known vulnerabilities (OSV.dev)',
  };
  const pkg = ctx.target.npmPackage;
  if (!pkg) {
    return { ...base, status: 'info', summary: 'No package to query (remote-only server).', evidence: [] };
  }

  try {
    const res = await fetchWithTimeout(ctx, 'https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ package: { name: pkg, ecosystem: 'npm' } }),
    });
    if (!res.ok) {
      return { ...base, status: 'unverifiable', summary: `OSV.dev error (HTTP ${res.status}).`, evidence: [] };
    }
    const body = (await res.json()) as { vulns?: Array<{ id: string; summary?: string }> };
    const vulns = body.vulns ?? [];

    if (vulns.length === 0) {
      return { ...base, status: 'pass', summary: 'No advisories on record for this package.', evidence: [] };
    }
    const evidence: Evidence[] = vulns.slice(0, 10).map((v) => ({
      label: v.id,
      value: v.summary,
      url: `https://osv.dev/vulnerability/${v.id}`,
    }));
    return {
      ...base,
      status: 'fail',
      summary: `${vulns.length} advisory(ies) on record — review whether the evaluated version is affected.`,
      evidence,
    };
  } catch (err) {
    return { ...base, status: 'unverifiable', summary: `OSV.dev unreachable: ${errMsg(err)}`, evidence: [] };
  }
}
