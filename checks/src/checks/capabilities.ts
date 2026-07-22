/**
 * §2 Capability scope & least privilege - the core check.
 *
 * The tool surface is obtained WITHOUT ever executing untrusted code:
 *   1. Remote servers: a standard MCP initialize + tools/list over
 *      streamable HTTP. A 401 here is signal, not failure (feeds §3.2).
 *   2. npm packages: the published tarball is fetched (size-capped,
 *      streamed, never executed) and statically scanned for risk-bearing
 *      capabilities and description strings.
 * If neither source yields anything, the result is 'unverifiable' - which
 * the scoring model treats as a finding (grade cap), not a blank.
 */

import type {
  CheckContext,
  CheckResult,
  Evidence,
  NamedText,
  RiskCategory,
  RiskHit,
  ToolInfo,
  ToolSurface,
} from '../types.js';
import { errMsg, fetchWithTimeout } from './provenance.js';

const TARBALL_MAX_BYTES = 10 * 1024 * 1024;
const MAX_SCANNED_FILES = 400;
const SOURCE_FILE_RE = /\.(m?[jt]s|cjs|py)$/;

/** Capability patterns scanned in package source. Public by design. */
export const RISK_PATTERNS: Array<{ category: RiskCategory; label: string; regex: RegExp }> = [
  { category: 'process-execution', label: 'child process execution', regex: /\b(child_process|execSync|execFile|spawnSync?|subprocess\.(run|Popen|call)|os\.system)\b/ },
  { category: 'process-execution', label: 'dynamic code evaluation', regex: /\b(eval|new Function|vm\.runInNewContext)\s*\(/ },
  { category: 'filesystem', label: 'filesystem write/delete', regex: /\bfs(?:\/promises)?[.'"]|\b(writeFileSync?|unlinkSync?|rmSync|rmdirSync?|shutil\.rmtree|os\.remove)\b/ },
  { category: 'network-egress', label: 'outbound network calls', regex: /\b(fetch\s*\(|axios|got\s*\(|node:https?|http\.request|requests\.(get|post)|urllib)\b/ },
  { category: 'credential-access', label: 'credential/env access', regex: /\b(process\.env|os\.environ)\s*[.[][^\s\]]*\b(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)/i },
];

/** Same categories applied to tool names/descriptions when we have real tool metadata. */
const TOOL_TEXT_RISKS: Array<{ category: RiskCategory; regex: RegExp }> = [
  { category: 'process-execution', regex: /\b(shell|exec|command|terminal|bash|run[_ ]?(command|script))\b/i },
  { category: 'filesystem', regex: /\b(delete|remove|write|overwrite|move)[_ ]?(file|directory|folder|path)|filesystem\b/i },
  { category: 'network-egress', regex: /\b(http[_ ]?request|fetch[_ ]?url|curl|webhook|send[_ ]?request)\b/i },
  { category: 'credential-access', regex: /\b(credential|api[_ ]?key|token|secret|password)\b/i },
];

export async function getToolSurface(ctx: CheckContext): Promise<ToolSurface> {
  const surface: ToolSurface = { source: 'none', tools: [], sourceRiskHits: [] };

  if (ctx.target.remoteUrl) {
    const remote = await tryRemoteToolsList(ctx, ctx.target.remoteUrl);
    if (remote.authRequired) surface.remoteAuthRequired = true;
    if (remote.instructions) surface.serverInstructions = remote.instructions;
    if (remote.prompts?.length) surface.prompts = remote.prompts;
    if (remote.resources?.length) surface.resources = remote.resources;
    if (remote.tools) {
      surface.source = 'remote-tools-list';
      surface.tools = remote.tools;
      return surface;
    }
  }

  // TODO(v1.1): try directory metadata (some directories index tool lists).

  if (ctx.target.npmPackage) {
    const pkgScan = await tryTarballScan(ctx, ctx.target.npmPackage);
    if (pkgScan) {
      surface.source = 'package-source';
      surface.tools = pkgScan.descriptionTools;
      surface.sourceRiskHits = pkgScan.hits;
      return surface;
    }
  }

  return surface;
}

export function checkCapabilities(surface: ToolSurface): CheckResult {
  const base = {
    id: 'capabilities.tool-surface',
    policyRef: '§2.1–§2.4',
    title: 'Tool surface is inspectable and proportionate',
  };

  if (surface.source === 'none') {
    return {
      ...base,
      status: 'unverifiable',
      summary:
        'Tool surface could not be inspected (no reachable tools/list, no public package source). Per policy, unverifiability caps the overall grade.',
      evidence: [],
    };
  }

  const evidence: Evidence[] = [];
  const categories = new Set<RiskCategory>();

  if (surface.source === 'remote-tools-list') {
    evidence.push({ label: 'Tools exposed', value: String(surface.tools.length) });
    for (const tool of surface.tools) {
      const text = `${tool.name} ${tool.description ?? ''}`;
      for (const risk of TOOL_TEXT_RISKS) {
        if (risk.regex.test(text)) {
          categories.add(risk.category);
          evidence.push({ label: `${tool.name}`, value: `${risk.category}` });
        }
      }
    }
  } else {
    for (const hit of surface.sourceRiskHits) {
      categories.add(hit.category);
      evidence.push({ label: `${hit.category} (${hit.label ?? hit.pattern})`, value: hit.file });
    }
  }

  const dangerous = categories.has('process-execution');
  // Policy §2 automation note: credential-access is the detectable proxy for
  // "read private data"; paired with egress it fails §2 / feeds §6.1.
  const toxicReadEgress =
    categories.has('credential-access') && categories.has('network-egress');
  const combo = categories.size;

  if (combo === 0) {
    return {
      ...base,
      status: 'pass',
      summary:
        surface.source === 'remote-tools-list'
          ? `${surface.tools.length} tool(s) enumerated; no high-risk capability signals.`
          : 'Package source scanned; no high-risk capability signals.',
      evidence,
    };
  }

  const status = dangerous || toxicReadEgress || combo >= 3 ? 'fail' : 'warn';
  const comboNote = toxicReadEgress
    ? ' Credential-access combined with network egress is a toxic flow (§2 combination rule / §6.1).'
    : '';
  return {
    ...base,
    status,
    summary: `High-risk capabilities detected: ${[...categories].join(', ')}. Verify each is essential to the server's stated purpose (§2.3).${comboNote}`,
    evidence,
  };
}

/* ---------------- remote: minimal MCP streamable-HTTP client ---------------- */

async function tryRemoteToolsList(
  ctx: CheckContext,
  url: string,
): Promise<{
  tools?: ToolInfo[];
  authRequired?: boolean;
  instructions?: string;
  prompts?: NamedText[];
  resources?: NamedText[];
}> {
  try {
    const initRes = await rpc(ctx, url, undefined, {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'mcpscorecard', version: '0.1.0' },
      },
    });
    if (initRes.status === 401 || initRes.status === 403) return { authRequired: true };
    if (!initRes.ok) return {};

    // The initialize result carries an optional `instructions` string the spec
    // permits clients to inject into the system prompt - a model-facing surface
    // that gets poison-scanned like a tool description (§5).
    const initResult = initRes.body?.result as
      | { instructions?: unknown; capabilities?: { prompts?: unknown; resources?: unknown } }
      | undefined;
    const instructions = typeof initResult?.instructions === 'string' ? initResult.instructions : undefined;
    const caps = initResult?.capabilities;

    const sessionId = initRes.response.headers.get('mcp-session-id') ?? undefined;
    await rpc(ctx, url, sessionId, { jsonrpc: '2.0', method: 'notifications/initialized' }).catch(() => undefined);

    // Prompts and resources also expose server-authored, model-facing text. Only
    // ask when the server advertised the capability, so we add no calls otherwise.
    let prompts: NamedText[] | undefined;
    if (caps?.prompts) {
      const r = await rpc(ctx, url, sessionId, { jsonrpc: '2.0', id: 3, method: 'prompts/list' }).catch(() => undefined);
      const list = (r?.body?.result as { prompts?: Array<{ name?: string; description?: string }> } | undefined)?.prompts;
      if (list) prompts = list.map((p) => ({ name: p.name ?? '', description: p.description }));
    }
    let resources: NamedText[] | undefined;
    if (caps?.resources) {
      const r = await rpc(ctx, url, sessionId, { jsonrpc: '2.0', id: 4, method: 'resources/list' }).catch(() => undefined);
      const list = (r?.body?.result as { resources?: Array<{ name?: string; description?: string }> } | undefined)?.resources;
      if (list) resources = list.map((x) => ({ name: x.name ?? '', description: x.description }));
    }

    const listRes = await rpc(ctx, url, sessionId, { jsonrpc: '2.0', id: 2, method: 'tools/list' });
    if (!listRes.ok) return { instructions, prompts, resources };
    const result = listRes.body?.result as { tools?: Array<{ name: string; description?: string; inputSchema?: unknown }> } | undefined;
    if (!result?.tools) return { instructions, prompts, resources };
    return {
      tools: result.tools.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })),
      instructions,
      prompts,
      resources,
    };
  } catch {
    return {};
  }
}

async function rpc(
  ctx: CheckContext,
  url: string,
  sessionId: string | undefined,
  payload: unknown,
): Promise<{ ok: boolean; status: number; response: Response; body?: { result?: unknown } }> {
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
  };
  if (sessionId) headers['mcp-session-id'] = sessionId;
  const response = await fetchWithTimeout(ctx, url, { method: 'POST', headers, body: JSON.stringify(payload) });
  if (!response.ok) return { ok: false, status: response.status, response };

  const contentType = response.headers.get('content-type') ?? '';
  let body: { result?: unknown } | undefined;
  if (contentType.includes('text/event-stream')) {
    body = parseFirstSseJson(await response.text());
  } else if (contentType.includes('json')) {
    body = (await response.json()) as { result?: unknown };
  }
  return { ok: true, status: response.status, response, body };
}

function parseFirstSseJson(text: string): { result?: unknown } | undefined {
  for (const line of text.split('\n')) {
    if (!line.startsWith('data:')) continue;
    try {
      return JSON.parse(line.slice(5).trim()) as { result?: unknown };
    } catch {
      continue;
    }
  }
  return undefined;
}

/* ---------------- npm: static tarball scan (never executed) ---------------- */

interface TarballScan {
  hits: Array<RiskHit & { label?: string }>;
  descriptionTools: ToolInfo[];
}

async function tryTarballScan(ctx: CheckContext, pkg: string): Promise<TarballScan | undefined> {
  try {
    const metaRes = await fetchWithTimeout(ctx, `https://registry.npmjs.org/${encodeURIComponent(pkg)}`);
    if (!metaRes.ok) return undefined;
    const meta = (await metaRes.json()) as {
      'dist-tags'?: Record<string, string>;
      versions?: Record<string, { dist?: { tarball?: string; unpackedSize?: number } }>;
    };
    const latest = meta['dist-tags']?.latest;
    const dist = latest ? meta.versions?.[latest]?.dist : undefined;
    if (!dist?.tarball) return undefined;
    if (dist.unpackedSize && dist.unpackedSize > TARBALL_MAX_BYTES * 4) return undefined;

    const tarRes = await fetchWithTimeout(ctx, dist.tarball);
    if (!tarRes.ok || !tarRes.body) return undefined;

    const gunzipped = tarRes.body.pipeThrough(new DecompressionStream('gzip'));
    const tarBytes = await readCapped(gunzipped, TARBALL_MAX_BYTES);
    if (!tarBytes) return undefined;

    const scan: TarballScan = { hits: [], descriptionTools: [] };
    let filesScanned = 0;
    for (const entry of iterateTar(tarBytes)) {
      if (filesScanned >= MAX_SCANNED_FILES) break;
      if (!SOURCE_FILE_RE.test(entry.name) || entry.name.includes('node_modules/')) continue;
      filesScanned++;
      const text = new TextDecoder('utf-8', { fatal: false, ignoreBOM: false }).decode(entry.data);

      for (const pattern of RISK_PATTERNS) {
        const match = pattern.regex.exec(text);
        if (match) {
          scan.hits.push({
            category: pattern.category,
            label: pattern.label,
            pattern: match[0],
            file: entry.name.replace(/^package\//, ''),
          });
        }
      }
      // Description string literals near MCP tool contexts feed the §5 poisoning scan.
      if (/@modelcontextprotocol|registerTool|mcp/i.test(text)) {
        for (const m of text.matchAll(/description:\s*(["'`])((?:(?!\1)[\s\S]){10,500})\1/g)) {
          if (scan.descriptionTools.length >= 100) break;
          scan.descriptionTools.push({
            name: `${entry.name.replace(/^package\//, '')} (source literal)`,
            description: m[2],
          });
        }
      }
    }
    return scan;
  } catch {
    return undefined;
  }
}

async function readCapped(stream: ReadableStream<Uint8Array>, cap: number): Promise<Uint8Array | undefined> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = stream.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > cap) {
        await reader.cancel();
        break; // scan what we have - partial coverage beats none
      }
      chunks.push(value);
    }
  } catch {
    return undefined;
  }
  const out = new Uint8Array(Math.min(total, cap));
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk.subarray(0, out.length - offset), offset);
    offset += chunk.byteLength;
    if (offset >= out.length) break;
  }
  return out;
}

/** Minimal ustar reader - enough for npm tarballs ("package/..." paths). */
function* iterateTar(bytes: Uint8Array): Generator<{ name: string; data: Uint8Array }> {
  let offset = 0;
  while (offset + 512 <= bytes.length) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every((b) => b === 0)) break;
    const name = readString(header, 0, 100);
    const size = parseInt(readString(header, 124, 12).trim() || '0', 8);
    const type = String.fromCharCode(header[156] ?? 48);
    offset += 512;
    if (Number.isNaN(size) || size < 0) break;
    const data = bytes.subarray(offset, Math.min(offset + size, bytes.length));
    if (type === '0' || type === '\0') {
      yield { name, data };
    }
    offset += Math.ceil(size / 512) * 512;
  }
}

function readString(bytes: Uint8Array, start: number, length: number): string {
  const slice = bytes.subarray(start, start + length);
  const end = slice.indexOf(0);
  return new TextDecoder().decode(end === -1 ? slice : slice.subarray(0, end));
}

/* ---------------- schema hash (rug-pull detection, §5.3) ---------------- */

export async function computeToolSchemaHash(tools: ToolInfo[]): Promise<string> {
  const canonical = JSON.stringify(
    [...tools]
      .sort((a, b) => a.name.localeCompare(b.name))
      .map((t) => ({ name: t.name, description: t.description ?? '', inputSchema: t.inputSchema ?? null })),
  );
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export { errMsg };
