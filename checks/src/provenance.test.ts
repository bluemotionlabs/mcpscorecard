import { describe, expect, it } from 'vitest';
import { checkRegistryListed, checkRepoHealth, matchesTarget } from './checks/provenance.js';
import { checkPackageHygiene } from './checks/package-hygiene.js';
import { jsonResponse, makeCtx, mockFetch, textResponse } from './test-helpers.js';

describe('checkRegistryListed', () => {
  it('is unverifiable when no identifier is available', async () => {
    const ctx = makeCtx({}, async () => textResponse(500));
    const res = await checkRegistryListed(ctx);
    expect(res.id).toBe('provenance.registry-listed');
    expect(res.status).toBe('unverifiable');
  });

  it('passes when a matching registry entry is found', async () => {
    const fetchImpl = mockFetch([
      {
        match: 'registry.modelcontextprotocol.io',
        response: () =>
          jsonResponse(200, {
            servers: [
              {
                server: {
                  name: 'io.github.acme/weather',
                  packages: [{ registryType: 'npm', identifier: '@acme/weather' }],
                },
              },
            ],
          }),
      },
    ]);
    const ctx = makeCtx(
      { registryName: 'io.github.acme/weather', npmPackage: '@acme/weather' },
      fetchImpl,
    );
    const res = await checkRegistryListed(ctx);
    expect(res.status).toBe('pass');
  });

  it('warns when the server is not on the registry', async () => {
    const fetchImpl = mockFetch([
      {
        match: 'registry.modelcontextprotocol.io',
        // Factory: registry search may issue multiple queries; Response bodies are single-use.
        response: () => jsonResponse(200, { servers: [] }),
      },
    ]);
    const ctx = makeCtx({ npmPackage: '@nobody/unknown-mcp' }, fetchImpl);
    const res = await checkRegistryListed(ctx);
    expect(res.status).toBe('warn');
  });

  it('is unverifiable on registry HTTP errors', async () => {
    const fetchImpl = mockFetch([
      { match: 'registry.modelcontextprotocol.io', response: textResponse(503) },
    ]);
    const ctx = makeCtx({ npmPackage: '@acme/weather' }, fetchImpl);
    const res = await checkRegistryListed(ctx);
    expect(res.status).toBe('unverifiable');
  });

  it('falls back to bare name when package name includes scope and prefixes', async () => {
    const fetchImpl = mockFetch([
      {
        match: 'registry.modelcontextprotocol.io',
        response: () => jsonResponse(200, { servers: [] }),
      },
    ]);
    const ctx = makeCtx({ npmPackage: '@scope/mcp-server-filesystem' }, fetchImpl);
    const res = await checkRegistryListed(ctx);
    expect(res.status).toBe('warn');
  });

  it('matches by GitHub owner/repo in registry entry', async () => {
    const fetchImpl = mockFetch([
      {
        match: 'registry.modelcontextprotocol.io',
        response: () => jsonResponse(200, {
          servers: [{ server: { name: 'io.github.acme/weather', packages: [] } }],
        }),
      },
    ]);
    const ctx = makeCtx({ github: { owner: 'acme', repo: 'weather' } }, fetchImpl);
    const res = await checkRegistryListed(ctx);
    expect(res.status).toBe('pass');
  });
});

describe('checkRepoHealth', () => {
  it('warns when no github repo is identified', async () => {
    const ctx = makeCtx({ npmPackage: '@acme/x' }, async () => textResponse(500));
    const res = await checkRepoHealth(ctx);
    expect(res.id).toBe('provenance.repo-health');
    expect(res.status).toBe('warn');
  });

  it('fails when the claimed repo does not exist', async () => {
    const fetchImpl = mockFetch([{ match: 'api.github.com/repos/', response: textResponse(404) }]);
    const ctx = makeCtx({ github: { owner: 'acme', repo: 'missing' } }, fetchImpl);
    const res = await checkRepoHealth(ctx);
    expect(res.status).toBe('fail');
  });

  it('passes a healthy active repo with license and SECURITY.md', async () => {
    const fetchImpl = mockFetch([
      {
        match: '/community/profile',
        response: jsonResponse(200, { files: { security: { url: 'https://…' } } }),
      },
      {
        match: 'api.github.com/repos/acme/good',
        response: jsonResponse(200, {
          archived: false,
          pushed_at: new Date().toISOString(),
          stargazers_count: 10,
          license: { spdx_id: 'Apache-2.0' },
          html_url: 'https://github.com/acme/good',
        }),
      },
    ]);
    const ctx = makeCtx({ github: { owner: 'acme', repo: 'good' } }, fetchImpl, {
      githubToken: 't',
    });
    const res = await checkRepoHealth(ctx);
    expect(res.status).toBe('pass');
  });

  it('fails when the repository is archived', async () => {
    const fetchImpl = mockFetch([
      {
        match: '/community/profile',
        response: jsonResponse(200, { files: {} }),
      },
      {
        match: 'api.github.com/repos/acme/old',
        response: jsonResponse(200, {
          archived: true,
          pushed_at: new Date().toISOString(),
          stargazers_count: 1,
          license: { spdx_id: 'MIT' },
          html_url: 'https://github.com/acme/old',
        }),
      },
    ]);
    const ctx = makeCtx({ github: { owner: 'acme', repo: 'old' } }, fetchImpl);
    const res = await checkRepoHealth(ctx);
    expect(res.status).toBe('fail');
  });

  it('is unverifiable on GitHub API errors', async () => {
    const fetchImpl = mockFetch([{ match: 'api.github.com', response: textResponse(500) }]);
    const ctx = makeCtx({ github: { owner: 'acme', repo: 'x' } }, fetchImpl);
    const res = await checkRepoHealth(ctx);
    expect(res.status).toBe('unverifiable');
  });

  it('warns when last push is stale (>365 days)', async () => {
    const oldDate = new Date(Date.now() - 400 * 86_400_000).toISOString();
    const fetchImpl = mockFetch([
      {
        match: '/community/profile',
        response: jsonResponse(200, { files: { security: { url: 'https://…' } } }),
      },
      {
        match: 'api.github.com/repos/acme/stale',
        response: jsonResponse(200, {
          archived: false,
          pushed_at: oldDate,
          stargazers_count: 3,
          license: { spdx_id: 'MIT' },
          html_url: 'https://github.com/acme/stale',
        }),
      },
    ]);
    const ctx = makeCtx({ github: { owner: 'acme', repo: 'stale' } }, fetchImpl);
    const res = await checkRepoHealth(ctx);
    expect(res.status).toBe('warn');
  });

  it('warns when repo has no license', async () => {
    const fetchImpl = mockFetch([
      {
        match: '/community/profile',
        response: jsonResponse(200, { files: { security: { url: 'https://…' } } }),
      },
      {
        match: 'api.github.com/repos/acme/nolicense',
        response: jsonResponse(200, {
          archived: false,
          pushed_at: new Date().toISOString(),
          stargazers_count: 3,
          license: null,
          html_url: 'https://github.com/acme/nolicense',
        }),
      },
    ]);
    const ctx = makeCtx({ github: { owner: 'acme', repo: 'nolicense' } }, fetchImpl);
    const res = await checkRepoHealth(ctx);
    expect(res.status).toBe('warn');
  });

  it('warns when SECURITY.md is absent', async () => {
    const fetchImpl = mockFetch([
      {
        match: '/community/profile',
        response: jsonResponse(200, { files: {} }),
      },
      {
        match: 'api.github.com/repos/acme/nosec',
        response: jsonResponse(200, {
          archived: false,
          pushed_at: new Date().toISOString(),
          stargazers_count: 5,
          license: { spdx_id: 'MIT' },
          html_url: 'https://github.com/acme/nosec',
        }),
      },
    ]);
    const ctx = makeCtx({ github: { owner: 'acme', repo: 'nosec' } }, fetchImpl);
    const res = await checkRepoHealth(ctx);
    expect(res.status).toBe('warn');
  });

  it('fails when two or more health problems exist (stale + no license)', async () => {
    const oldDate = new Date(Date.now() - 400 * 86_400_000).toISOString();
    const fetchImpl = mockFetch([
      {
        match: '/community/profile',
        response: jsonResponse(200, { files: { security: { url: 'https://…' } } }),
      },
      {
        match: 'api.github.com/repos/acme/dead',
        response: jsonResponse(200, {
          archived: false,
          pushed_at: oldDate,
          stargazers_count: 1,
          license: null,
          html_url: 'https://github.com/acme/dead',
        }),
      },
    ]);
    const ctx = makeCtx({ github: { owner: 'acme', repo: 'dead' } }, fetchImpl);
    const res = await checkRepoHealth(ctx);
    expect(res.status).toBe('fail');
  });
});

describe('checkPackageHygiene', () => {
  it('returns info when there is no npm package', async () => {
    const ctx = makeCtx({ remoteUrl: 'https://example.com' }, async () => textResponse(500));
    const res = await checkPackageHygiene(ctx);
    expect(res.id).toBe('provenance.package-hygiene');
    expect(res.status).toBe('info');
  });

  it('fails when the package does not exist on npm', async () => {
    const fetchImpl = mockFetch([{ match: 'registry.npmjs.org', response: textResponse(404) }]);
    const ctx = makeCtx({ npmPackage: '@acme/missing' }, fetchImpl);
    const res = await checkPackageHygiene(ctx);
    expect(res.status).toBe('fail');
  });

  it('fails when the latest version is deprecated', async () => {
    const created = new Date(Date.now() - 400 * 86_400_000).toISOString();
    const fetchImpl = mockFetch([
      {
        match: 'registry.npmjs.org',
        response: jsonResponse(200, {
          'dist-tags': { latest: '1.0.0' },
          time: { created },
          versions: {
            '1.0.0': {
              deprecated: 'use something else',
              repository: { url: 'git+https://github.com/acme/pkg.git' },
              dist: { attestations: { url: 'https://…' } },
            },
          },
          repository: { url: 'git+https://github.com/acme/pkg.git' },
        }),
      },
      { match: 'api.npmjs.org/downloads', response: jsonResponse(200, { downloads: 100 }) },
    ]);
    const ctx = makeCtx(
      { npmPackage: '@acme/pkg', github: { owner: 'acme', repo: 'pkg' } },
      fetchImpl,
    );
    const res = await checkPackageHygiene(ctx);
    expect(res.status).toBe('fail');
  });

  it('warns when attestation is missing on an otherwise matching package', async () => {
    const created = new Date(Date.now() - 400 * 86_400_000).toISOString();
    const fetchImpl = mockFetch([
      {
        match: 'registry.npmjs.org',
        response: jsonResponse(200, {
          'dist-tags': { latest: '1.0.0' },
          time: { created },
          versions: {
            '1.0.0': {
              repository: { url: 'git+https://github.com/acme/pkg.git' },
              dist: {},
            },
          },
          repository: { url: 'git+https://github.com/acme/pkg.git' },
        }),
      },
      { match: 'api.npmjs.org/downloads', response: jsonResponse(200, { downloads: 50 }) },
    ]);
    const ctx = makeCtx(
      { npmPackage: '@acme/pkg', github: { owner: 'acme', repo: 'pkg' } },
      fetchImpl,
    );
    const res = await checkPackageHygiene(ctx);
    expect(res.status).toBe('warn');
  });

  it('passes when repo matches and provenance attestation is present', async () => {
    const created = new Date(Date.now() - 400 * 86_400_000).toISOString();
    const fetchImpl = mockFetch([
      {
        match: 'registry.npmjs.org',
        response: jsonResponse(200, {
          'dist-tags': { latest: '2.0.0' },
          time: { created },
          versions: {
            '2.0.0': {
              repository: { url: 'git+https://github.com/acme/pkg.git' },
              dist: { attestations: { url: 'https://…' } },
            },
          },
          repository: { url: 'git+https://github.com/acme/pkg.git' },
        }),
      },
      { match: 'api.npmjs.org/downloads', response: jsonResponse(200, { downloads: 1000 }) },
    ]);
    const ctx = makeCtx(
      { npmPackage: '@acme/pkg', github: { owner: 'acme', repo: 'pkg' } },
      fetchImpl,
    );
    const res = await checkPackageHygiene(ctx);
    expect(res.status).toBe('pass');
  });

  it('warns when package is younger than 30 days', async () => {
    const created = new Date(Date.now() - 10 * 86_400_000).toISOString();
    const fetchImpl = mockFetch([
      {
        match: 'registry.npmjs.org',
        response: jsonResponse(200, {
          'dist-tags': { latest: '1.0.0' },
          time: { created },
          versions: {
            '1.0.0': {
              repository: { url: 'git+https://github.com/acme/pkg.git' },
              dist: { attestations: { url: 'https://…' } },
            },
          },
          repository: { url: 'git+https://github.com/acme/pkg.git' },
        }),
      },
      { match: 'api.npmjs.org/downloads', response: jsonResponse(200, { downloads: 10 }) },
    ]);
    const ctx = makeCtx(
      { npmPackage: '@acme/pkg', github: { owner: 'acme', repo: 'pkg' } },
      fetchImpl,
    );
    const res = await checkPackageHygiene(ctx);
    expect(res.status).toBe('warn');
    expect(res.summary).toContain('Minor integrity gaps');
  });

  it('fails when repo field does not match source and attestation is also absent', async () => {
    const created = new Date(Date.now() - 400 * 86_400_000).toISOString();
    const fetchImpl = mockFetch([
      {
        match: 'registry.npmjs.org',
        response: jsonResponse(200, {
          'dist-tags': { latest: '1.0.0' },
          time: { created },
          versions: {
            '1.0.0': {
              repository: { url: 'git+https://github.com/other/wrong.git' },
              dist: {},
            },
          },
          repository: { url: 'git+https://github.com/other/wrong.git' },
        }),
      },
      { match: 'api.npmjs.org/downloads', response: jsonResponse(200, { downloads: 500 }) },
    ]);
    const ctx = makeCtx(
      { npmPackage: '@acme/pkg', github: { owner: 'acme', repo: 'pkg' } },
      fetchImpl,
    );
    const res = await checkPackageHygiene(ctx);
    expect(res.status).toBe('fail');
    expect(res.summary).toContain('Integrity concerns');
  });

  it('is resilient to downloads API failure', async () => {
    const created = new Date(Date.now() - 400 * 86_400_000).toISOString();
    const fetchImpl = mockFetch([
      {
        match: 'registry.npmjs.org',
        response: jsonResponse(200, {
          'dist-tags': { latest: '2.0.0' },
          time: { created },
          versions: {
            '2.0.0': {
              repository: { url: 'git+https://github.com/acme/pkg.git' },
              dist: { attestations: { url: 'https://…' } },
            },
          },
          repository: { url: 'git+https://github.com/acme/pkg.git' },
        }),
      },
      { match: 'api.npmjs.org/downloads', response: textResponse(500) },
    ]);
    const ctx = makeCtx(
      { npmPackage: '@acme/pkg', github: { owner: 'acme', repo: 'pkg' } },
      fetchImpl,
    );
    const res = await checkPackageHygiene(ctx);
    expect(res.status).toBe('pass');
    expect(res.evidence.some((e) => e.label === 'Weekly downloads' && e.value === 'unknown')).toBe(true);
  });
});

describe('matchesTarget', () => {
  it('matches exact registry name', () => {
    const ctx = makeCtx({ registryName: 'io.github.acme/server' }, async () => textResponse(500));
    expect(matchesTarget({ name: 'io.github.acme/server' }, ctx)).toBe(true);
  });

  it('is case-insensitive for registry name', () => {
    const ctx = makeCtx({ registryName: 'io.github.acme/server' }, async () => textResponse(500));
    expect(matchesTarget({ name: 'IO.GITHUB.ACME/SERVER' }, ctx)).toBe(true);
  });

  it('matches by github owner/repo in server name', () => {
    const ctx = makeCtx({ github: { owner: 'acme', repo: 'server' } }, async () => textResponse(500));
    expect(matchesTarget({ name: 'io.github.acme/server' }, ctx)).toBe(true);
  });

  it('matches by npm package in packages list', () => {
    const ctx = makeCtx({ npmPackage: '@acme/server' }, async () => textResponse(500));
    expect(matchesTarget({
      name: 'something-else',
      packages: [{ registryType: 'npm', identifier: '@acme/server' }],
    }, ctx)).toBe(true);
  });

  it('matches by npm package with registry_type field', () => {
    const ctx = makeCtx({ npmPackage: '@acme/server' }, async () => textResponse(500));
    expect(matchesTarget({
      name: 'x',
      packages: [{ registry_type: 'npm', name: '@acme/server' }],
    }, ctx)).toBe(true);
  });

  it('returns false when nothing matches', () => {
    const ctx = makeCtx({ npmPackage: '@acme/server' }, async () => textResponse(500));
    expect(matchesTarget({ name: 'io.github.other/stuff', packages: [] }, ctx)).toBe(false);
  });
});
