/**
 * §3 Authentication & transport hardening — remote servers only.
 *
 * Since the 2025-06-18 spec revision, remote MCP servers are OAuth 2.1
 * resource servers. We check three structural facts, cheapest first:
 * HTTPS (§3.1), auth actually demanded (§3.2), and protected-resource
 * metadata published (§3.3). Local stdio servers get 'info' — they run with
 * host privileges by design, which is §1/§2's problem, not §3's.
 */

import type { CheckContext, CheckResult } from '../types.js';
import { errMsg, fetchWithTimeout } from './provenance.js';

export async function checkTransport(ctx: CheckContext): Promise<CheckResult[]> {
  const url = ctx.target.remoteUrl;
  if (!url) {
    return [
      {
        id: 'transport.https',
        policyRef: '§3',
        title: 'Transport & authentication',
        status: 'info',
        summary: 'Local (stdio) server: runs with host-process privileges by design. Transport checks apply to remote servers; scrutiny shifts to §1/§2.',
        evidence: [],
      },
    ];
  }

  const results: CheckResult[] = [];
  const parsed = new URL(url);

  results.push({
    id: 'transport.https',
    policyRef: '§3.1',
    title: 'HTTPS-only endpoint',
    status: parsed.protocol === 'https:' ? 'pass' : 'fail',
    summary: parsed.protocol === 'https:' ? 'Endpoint uses HTTPS.' : 'Endpoint is plain HTTP — credentials and tool traffic are exposed.',
    evidence: [{ label: 'Endpoint', value: url }],
  });

  // §3.2 — does the server demand auth for an unauthenticated MCP request?
  try {
    const res = await fetchWithTimeout(ctx, url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'ping' }),
    });
    const wwwAuth = res.headers.get('www-authenticate');
    if (res.status === 401 || res.status === 403) {
      results.push({
        id: 'transport.auth-required',
        policyRef: '§3.2',
        title: 'Authentication required',
        status: wwwAuth ? 'pass' : 'warn',
        summary: wwwAuth
          ? 'Server rejects anonymous requests and advertises its auth scheme.'
          : 'Server rejects anonymous requests but sends no WWW-Authenticate header.',
        evidence: wwwAuth ? [{ label: 'WWW-Authenticate', value: wwwAuth }] : [],
      });
    } else {
      results.push({
        id: 'transport.auth-required',
        policyRef: '§3.2',
        title: 'Authentication required',
        status: 'warn',
        summary: `Server answers anonymous requests (HTTP ${res.status}). Acceptable only for deliberately public, read-only servers.`,
        evidence: [],
      });
    }
  } catch (err) {
    results.push({
      id: 'transport.auth-required',
      policyRef: '§3.2',
      title: 'Authentication required',
      status: 'unverifiable',
      summary: `Endpoint unreachable: ${errMsg(err)}`,
      evidence: [],
    });
  }

  // §3.3 — OAuth 2.1 protected-resource metadata (RFC 9728)
  try {
    const wellKnown = `${parsed.origin}/.well-known/oauth-protected-resource`;
    const res = await fetchWithTimeout(ctx, wellKnown);
    if (res.ok) {
      const body = (await res.json()) as { authorization_servers?: string[] };
      results.push({
        id: 'transport.oauth-metadata',
        policyRef: '§3.3',
        title: 'OAuth protected-resource metadata published',
        status: 'pass',
        summary: 'Publishes /.well-known/oauth-protected-resource per the June 2025 authorization spec.',
        evidence: (body.authorization_servers ?? []).map((as) => ({ label: 'Authorization server', value: as })),
      });
    } else {
      results.push({
        id: 'transport.oauth-metadata',
        policyRef: '§3.3',
        title: 'OAuth protected-resource metadata published',
        status: 'warn',
        summary: 'No protected-resource metadata found — clients cannot discover the authorization server per spec.',
        evidence: [{ label: 'Checked', value: wellKnown }],
      });
    }
  } catch (err) {
    results.push({
      id: 'transport.oauth-metadata',
      policyRef: '§3.3',
      title: 'OAuth protected-resource metadata published',
      status: 'unverifiable',
      summary: `Metadata endpoint unreachable: ${errMsg(err)}`,
      evidence: [],
    });
  }

  return results;
}
