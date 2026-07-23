import { describe, expect, it } from 'vitest';
import { checkTransport, resolveAuthRequiredStatus } from './checks/transport.js';
import { jsonResponse, makeCtx, mockFetch, textResponse } from './test-helpers.js';

describe('resolveAuthRequiredStatus', () => {
  it('passes when auth is required with WWW-Authenticate', () => {
    expect(resolveAuthRequiredStatus('required-with-www-auth', 'pass')).toBe('pass');
    expect(resolveAuthRequiredStatus('required-with-www-auth', 'fail')).toBe('pass');
  });

  it('warns when auth is required without WWW-Authenticate', () => {
    expect(resolveAuthRequiredStatus('required-no-www-auth', 'pass')).toBe('warn');
  });

  it('warns on anonymous access when capabilities pass (Low/public)', () => {
    expect(resolveAuthRequiredStatus('anonymous', 'pass')).toBe('warn');
  });

  it('fails on anonymous access when capabilities are warn, fail, or unverifiable', () => {
    expect(resolveAuthRequiredStatus('anonymous', 'warn')).toBe('fail');
    expect(resolveAuthRequiredStatus('anonymous', 'fail')).toBe('fail');
    expect(resolveAuthRequiredStatus('anonymous', 'unverifiable')).toBe('fail');
  });

  it('returns unverifiable for unreachable probes', () => {
    expect(resolveAuthRequiredStatus('unverifiable', 'pass')).toBe('unverifiable');
  });
});

describe('checkTransport', () => {
  it('returns info for local/stdio servers (no remoteUrl)', async () => {
    const ctx = makeCtx({}, async () => textResponse(500));
    const results = await checkTransport(ctx);
    expect(results).toHaveLength(1);
    const only = results[0]!;
    expect(only.id).toBe('transport.https');
    expect(only.status).toBe('info');
  });

  it('passes HTTPS and fails plain HTTP', async () => {
    const fetchImpl = mockFetch([
      { match: 'example.com', response: textResponse(401, '', { 'www-authenticate': 'Bearer' }) },
      {
        match: 'oauth-protected-resource',
        response: jsonResponse(200, { authorization_servers: ['https://auth.example'] }),
      },
    ]);

    const httpsCtx = makeCtx({ remoteUrl: 'https://example.com/mcp' }, fetchImpl);
    const httpsResults = await checkTransport(httpsCtx, 'pass');
    expect(httpsResults.find((r) => r.id === 'transport.https')?.status).toBe('pass');

    const httpCtx = makeCtx({ remoteUrl: 'http://example.com/mcp' }, fetchImpl);
    const httpResults = await checkTransport(httpCtx, 'pass');
    expect(httpResults.find((r) => r.id === 'transport.https')?.status).toBe('fail');
  });

  it('warns on anonymous access when capability status is pass', async () => {
    const fetchImpl = mockFetch([
      { match: '/mcp', response: jsonResponse(200, { ok: true }) },
      { match: 'oauth-protected-resource', response: textResponse(404) },
    ]);
    const ctx = makeCtx({ remoteUrl: 'https://example.com/mcp' }, fetchImpl);
    const results = await checkTransport(ctx, 'pass');
    expect(results.find((r) => r.id === 'transport.auth-required')?.status).toBe('warn');
  });

  it('fails on anonymous access when capability status is fail', async () => {
    const fetchImpl = mockFetch([
      { match: '/mcp', response: jsonResponse(200, { ok: true }) },
      { match: 'oauth-protected-resource', response: textResponse(404) },
    ]);
    const ctx = makeCtx({ remoteUrl: 'https://example.com/mcp' }, fetchImpl);
    const results = await checkTransport(ctx, 'fail');
    expect(results.find((r) => r.id === 'transport.auth-required')?.status).toBe('fail');
  });

  it('passes auth-required when server returns 401 with WWW-Authenticate', async () => {
    const fetchImpl = mockFetch([
      { match: '/mcp', response: textResponse(401, '', { 'www-authenticate': 'Bearer realm="mcp"' }) },
      { match: 'oauth-protected-resource', response: textResponse(404) },
    ]);
    const ctx = makeCtx({ remoteUrl: 'https://example.com/mcp' }, fetchImpl);
    const results = await checkTransport(ctx, 'fail');
    expect(results.find((r) => r.id === 'transport.auth-required')?.status).toBe('pass');
  });

  it('passes oauth-metadata when well-known document exists', async () => {
    const fetchImpl = mockFetch([
      { match: '/mcp', response: textResponse(401, '', { 'www-authenticate': 'Bearer' }) },
      {
        match: 'oauth-protected-resource',
        response: jsonResponse(200, { authorization_servers: ['https://auth.example'] }),
      },
    ]);
    const ctx = makeCtx({ remoteUrl: 'https://example.com/mcp' }, fetchImpl);
    const results = await checkTransport(ctx);
    expect(results.find((r) => r.id === 'transport.oauth-metadata')?.status).toBe('pass');
  });

  it('warns when oauth-metadata is missing', async () => {
    const fetchImpl = mockFetch([
      { match: '/mcp', response: textResponse(401, '', { 'www-authenticate': 'Bearer' }) },
      { match: 'oauth-protected-resource', response: textResponse(404) },
    ]);
    const ctx = makeCtx({ remoteUrl: 'https://example.com/mcp' }, fetchImpl);
    const results = await checkTransport(ctx);
    expect(results.find((r) => r.id === 'transport.oauth-metadata')?.status).toBe('warn');
  });

  it('returns unverifiable when auth probe network errors out', async () => {
    const fetchImpl = mockFetch([
      { match: '/mcp', response: () => { throw new Error('ECONNREFUSED'); } },
      { match: 'oauth-protected-resource', response: textResponse(404) },
    ]);
    const ctx = makeCtx({ remoteUrl: 'https://example.com/mcp' }, fetchImpl);
    const results = await checkTransport(ctx);
    expect(results.find((r) => r.id === 'transport.auth-required')?.status).toBe('unverifiable');
  });

  it('returns unverifiable when oauth-metadata endpoint errors out', async () => {
    const fetchImpl = mockFetch([
      { match: '/mcp', response: textResponse(401, '', { 'www-authenticate': 'Bearer' }) },
      { match: 'oauth-protected-resource', response: () => { throw new Error('ENOTFOUND'); } },
    ]);
    const ctx = makeCtx({ remoteUrl: 'https://example.com/mcp' }, fetchImpl);
    const results = await checkTransport(ctx);
    expect(results.find((r) => r.id === 'transport.oauth-metadata')?.status).toBe('unverifiable');
  });

  it('fails on anonymous access when capability status is unverifiable', async () => {
    const fetchImpl = mockFetch([
      { match: '/mcp', response: jsonResponse(200, { ok: true }) },
      { match: 'oauth-protected-resource', response: textResponse(404) },
    ]);
    const ctx = makeCtx({ remoteUrl: 'https://example.com/mcp' }, fetchImpl);
    const results = await checkTransport(ctx, 'unverifiable');
    expect(results.find((r) => r.id === 'transport.auth-required')?.status).toBe('fail');
  });
});
