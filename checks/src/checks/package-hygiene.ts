/**
 * §1.3 Package integrity - npm registry signals.
 *
 * Typosquatting an MCP server yields agent-level access, so the package
 * itself is scrutinized: does it match its claimed repo, is it maintained,
 * does its age/download history fit its claimed role, and does it carry a
 * build-provenance attestation (npm provenance / Sigstore)?
 */

import type { CheckContext, CheckResult, Evidence } from '../types.js';
import { errMsg, fetchWithTimeout } from './provenance.js';

const YOUNG_PACKAGE_DAYS = 30;

export async function checkPackageHygiene(ctx: CheckContext): Promise<CheckResult> {
  const base = {
    id: 'provenance.package-hygiene',
    policyRef: '§1.3',
    title: 'Published package is consistent and attested',
  };
  const pkg = ctx.target.npmPackage;
  if (!pkg) {
    return {
      ...base,
      status: 'info',
      summary: 'No npm package associated with this server (remote-only or non-npm source).',
      evidence: [],
    };
  }

  try {
    const res = await fetchWithTimeout(ctx, `https://registry.npmjs.org/${encodeURIComponent(pkg)}`);
    if (res.status === 404) {
      return { ...base, status: 'fail', summary: `Package "${pkg}" does not exist on npm.`, evidence: [] };
    }
    if (!res.ok) {
      return { ...base, status: 'unverifiable', summary: `npm registry error (HTTP ${res.status}).`, evidence: [] };
    }
    const meta = (await res.json()) as {
      'dist-tags'?: Record<string, string>;
      time?: Record<string, string>;
      versions?: Record<string, { deprecated?: string; repository?: { url?: string }; dist?: { attestations?: unknown } }>;
      repository?: { url?: string };
    };

    const latest = meta['dist-tags']?.latest;
    const latestMeta = latest ? meta.versions?.[latest] : undefined;
    const created = meta.time?.created ? Date.parse(meta.time.created) : undefined;
    const ageDays = created ? Math.floor((Date.now() - created) / 86_400_000) : undefined;

    let weeklyDownloads: number | undefined;
    try {
      const dl = await fetchWithTimeout(ctx, `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(pkg)}`);
      if (dl.ok) weeklyDownloads = ((await dl.json()) as { downloads?: number }).downloads;
    } catch {
      // downloads API is best-effort
    }

    const repoUrl = (latestMeta?.repository?.url ?? meta.repository?.url ?? '').toLowerCase();
    const gh = ctx.target.github;
    const repoMatches = gh ? repoUrl.includes(`${gh.owner.toLowerCase()}/${gh.repo.toLowerCase()}`) : undefined;
    const hasAttestation = Boolean(latestMeta?.dist?.attestations);
    const deprecated = Boolean(latestMeta?.deprecated);

    const evidence: Evidence[] = [
      { label: 'Package', value: `${pkg}@${latest ?? '?'}`, url: `https://www.npmjs.com/package/${pkg}` },
      { label: 'Age', value: ageDays !== undefined ? `${ageDays} days` : 'unknown' },
      { label: 'Weekly downloads', value: weeklyDownloads !== undefined ? String(weeklyDownloads) : 'unknown' },
      { label: 'Repo field matches source repo', value: repoMatches === undefined ? 'n/a' : String(repoMatches) },
      { label: 'Build-provenance attestation', value: hasAttestation ? 'present' : 'absent' },
    ];

    if (deprecated) {
      return { ...base, status: 'fail', summary: 'Latest version is deprecated by its own maintainer.', evidence };
    }
    const warns: string[] = [];
    if (repoMatches === false) warns.push('package repository field does not match the claimed source repo');
    if (ageDays !== undefined && ageDays < YOUNG_PACKAGE_DAYS) warns.push(`package is only ${ageDays} days old`);
    if (!hasAttestation) warns.push('no npm provenance attestation');

    // Repo mismatch is the typosquat signal - worth more than the softer signals.
    if (repoMatches === false && warns.length >= 2) {
      return { ...base, status: 'fail', summary: `Integrity concerns: ${warns.join('; ')}.`, evidence };
    }
    if (warns.length > 0) {
      return { ...base, status: 'warn', summary: `Minor integrity gaps: ${warns.join('; ')}.`, evidence };
    }
    return { ...base, status: 'pass', summary: 'Package is consistent with its source and carries provenance attestation.', evidence };
  } catch (err) {
    return { ...base, status: 'unverifiable', summary: `npm registry unreachable: ${errMsg(err)}`, evidence: [] };
  }
}
