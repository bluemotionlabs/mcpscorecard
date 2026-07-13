/**
 * §1.1 Registry presence + §1.2 Source repository health.
 *
 * Provenance is the cheapest attack vector to close: an MCP server is a
 * supply-chain dependency with agent-level privileges, so "where does this
 * come from and is anyone maintaining it" is checked before anything else.
 * Same signal family as OpenSSF Scorecard, scoped to what matters pre-adoption.
 */

import type { CheckContext, CheckResult, Evidence } from '../types.js';

const REGISTRY_BASE = 'https://registry.modelcontextprotocol.io';
/** Commits older than this are a warn; repos are often "done" but agents-facing code rots fast. */
const STALE_PUSH_DAYS = 365;

export async function checkRegistryListed(ctx: CheckContext): Promise<CheckResult> {
  const base = {
    id: 'provenance.registry-listed',
    policyRef: '§1.1',
    title: 'Listed on the official MCP registry',
  };

  const query = ctx.target.registryName ?? ctx.target.npmPackage ?? ctx.target.github?.repo;
  if (!query) {
    return { ...base, status: 'unverifiable', summary: 'No identifier available to search the registry.', evidence: [] };
  }

  // Registry names (io.github.owner/thing) rarely equal npm names (@scope/server-thing),
  // so fall back to the bare name: "@modelcontextprotocol/server-filesystem" → "filesystem".
  const bareName = query.split('/').pop()?.replace(/^(mcp-|server-)+/, '').replace(/(-mcp|-server)+$/, '');
  const queries = bareName && bareName !== query ? [query, bareName] : [query];

  try {
    let match: Record<string, unknown> | undefined;
    for (const q of queries) {
      const res = await fetchWithTimeout(ctx, `${REGISTRY_BASE}/v0/servers?search=${encodeURIComponent(q)}&limit=50`);
      if (!res.ok) {
        return { ...base, status: 'unverifiable', summary: `Registry query failed (HTTP ${res.status}).`, evidence: [] };
      }
      const body = (await res.json()) as { servers?: Array<{ server?: Record<string, unknown> }> };
      // Entries are wrapped: {server: {...}, _meta: {...}}, one entry per published version.
      match = (body.servers ?? [])
        .map((s) => s.server)
        .filter((s): s is Record<string, unknown> => Boolean(s))
        .find((s) => matchesTarget(s, ctx));
      if (match) break;
    }

    if (match) {
      const name = String(match['name'] ?? query);
      return {
        ...base,
        status: 'pass',
        summary: `Listed on registry.modelcontextprotocol.io as ${name}.`,
        evidence: [{ label: 'Registry entry', value: name, url: `${REGISTRY_BASE}/v0/servers?search=${encodeURIComponent(name)}` }],
      };
    }
    return {
      ...base,
      status: 'warn',
      summary: 'Not found on the official MCP registry. Not disqualifying, but listed servers carry namespace-verified provenance.',
      evidence: [],
    };
  } catch (err) {
    return { ...base, status: 'unverifiable', summary: `Registry unreachable: ${errMsg(err)}`, evidence: [] };
  }
}

export async function checkRepoHealth(ctx: CheckContext): Promise<CheckResult> {
  const base = {
    id: 'provenance.repo-health',
    policyRef: '§1.2',
    title: 'Source repository is public and maintained',
  };
  const gh = ctx.target.github;
  if (!gh) {
    return {
      ...base,
      status: 'warn',
      summary: 'No public source repository could be identified for this server.',
      evidence: [],
    };
  }

  try {
    const headers: Record<string, string> = {
      accept: 'application/vnd.github+json',
      'user-agent': 'mcpscorecard-scanner',
    };
    if (ctx.githubToken) headers.authorization = `Bearer ${ctx.githubToken}`;

    const repoRes = await fetchWithTimeout(ctx, `https://api.github.com/repos/${gh.owner}/${gh.repo}`, { headers });
    if (repoRes.status === 404) {
      return { ...base, status: 'fail', summary: 'Claimed source repository does not exist (or is private).', evidence: [] };
    }
    if (!repoRes.ok) {
      return { ...base, status: 'unverifiable', summary: `GitHub API error (HTTP ${repoRes.status}).`, evidence: [] };
    }
    const repo = (await repoRes.json()) as {
      archived: boolean;
      pushed_at: string;
      stargazers_count: number;
      license: { spdx_id?: string } | null;
      html_url: string;
    };

    // SECURITY.md via the community-profile endpoint (covers root, .github/, docs/)
    let hasSecurityPolicy = false;
    const profileRes = await fetchWithTimeout(
      ctx,
      `https://api.github.com/repos/${gh.owner}/${gh.repo}/community/profile`,
      { headers },
    );
    if (profileRes.ok) {
      const profile = (await profileRes.json()) as { files?: { security?: unknown } };
      hasSecurityPolicy = Boolean(profile.files?.security);
    }

    const pushedDaysAgo = Math.floor((Date.now() - Date.parse(repo.pushed_at)) / 86_400_000);
    const evidence: Evidence[] = [
      { label: 'Repository', url: repo.html_url },
      { label: 'Last push', value: `${pushedDaysAgo} days ago` },
      { label: 'Stars', value: String(repo.stargazers_count) },
      { label: 'License', value: repo.license?.spdx_id ?? 'none detected' },
      { label: 'Security policy (SECURITY.md)', value: hasSecurityPolicy ? 'present' : 'absent' },
    ];

    if (repo.archived) {
      return { ...base, status: 'fail', summary: 'Repository is archived — unmaintained by declaration.', evidence };
    }
    const problems: string[] = [];
    if (pushedDaysAgo > STALE_PUSH_DAYS) problems.push(`no pushes in ${pushedDaysAgo} days`);
    if (!repo.license) problems.push('no license');
    if (!hasSecurityPolicy) problems.push('no security policy');

    if (problems.length === 0) {
      return { ...base, status: 'pass', summary: 'Active repository with license and security policy.', evidence };
    }
    return {
      ...base,
      status: problems.length >= 2 ? 'fail' : 'warn',
      summary: `Repository health issues: ${problems.join(', ')}.`,
      evidence,
    };
  } catch (err) {
    return { ...base, status: 'unverifiable', summary: `GitHub unreachable: ${errMsg(err)}`, evidence: [] };
  }
}

function matchesTarget(server: Record<string, unknown>, ctx: CheckContext): boolean {
  const name = String(server['name'] ?? '').toLowerCase();
  const { registryName, npmPackage, github } = ctx.target;
  if (registryName && name === registryName.toLowerCase()) return true;
  if (github && name.includes(`${github.owner.toLowerCase()}/${github.repo.toLowerCase()}`)) return true;
  if (npmPackage) {
    const packages = (server['packages'] as Array<Record<string, unknown>> | undefined) ?? [];
    return packages.some(
      (p) =>
        String(p['registryType'] ?? p['registry_type'] ?? '') === 'npm' &&
        String(p['identifier'] ?? p['name'] ?? '').toLowerCase() === npmPackage.toLowerCase(),
    );
  }
  return false;
}

export async function fetchWithTimeout(ctx: CheckContext, url: string, init?: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ctx.timeoutMs ?? 10_000);
  try {
    return await ctx.fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

export function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
