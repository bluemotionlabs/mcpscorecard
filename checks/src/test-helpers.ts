/**
 * Shared test helpers for offline unit tests (no live network).
 */

import type { CheckContext, CheckResult, CheckStatus, ScanTarget } from './types.js';

export function result(id: string, status: CheckResult['status']): CheckResult {
  return { id, policyRef: '§x', title: id, status, summary: '', evidence: [] };
}

export function makeTarget(partial: Partial<ScanTarget> = {}): ScanTarget {
  return {
    input: partial.input ?? 'test',
    sourceType: partial.sourceType ?? 'npm',
    displayName: partial.displayName ?? 'test',
    ...partial,
  };
}

export function makeCtx(
  target: Partial<ScanTarget>,
  fetchImpl: typeof globalThis.fetch,
  extras: Partial<Pick<CheckContext, 'githubToken' | 'timeoutMs'>> = {},
): CheckContext {
  return {
    target: makeTarget(target),
    fetch: fetchImpl,
    timeoutMs: extras.timeoutMs ?? 5_000,
    githubToken: extras.githubToken,
  };
}

type Json = unknown;

/** Build a minimal Response-like object for mocked fetch. */
export function jsonResponse(status: number, body: Json, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

export function textResponse(status: number, body = '', headers: Record<string, string> = {}): Response {
  return new Response(body, { status, headers });
}

/**
 * Route-based fetch mock. `routes` keys are substrings matched against the request URL
 * (first match wins). Values may be a Response or a factory.
 */
export function mockFetch(
  routes: Array<{
    match: string | RegExp;
    response: Response | ((url: string, init?: RequestInit) => Response | Promise<Response>);
  }>,
): typeof globalThis.fetch {
  return async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    for (const route of routes) {
      const ok =
        typeof route.match === 'string' ? url.includes(route.match) : route.match.test(url);
      if (!ok) continue;
      return typeof route.response === 'function' ? route.response(url, init) : route.response;
    }
    return textResponse(404, `unmocked: ${url}`);
  };
}

export function allPassChecks(overrides: Partial<Record<string, CheckStatus>> = {}): CheckResult[] {
  const ids = [
    'provenance.registry-listed',
    'provenance.repo-health',
    'provenance.package-hygiene',
    'capabilities.tool-surface',
    'vulns.osv',
    'poisoning.patterns',
  ] as const;
  return ids.map((id) => result(id, overrides[id] ?? 'pass'));
}
