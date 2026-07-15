/**
 * §5 Server-supplied instruction integrity - pattern-based tool-poisoning scan.
 *
 * An MCP server supplies several channels of text that clients load into the
 * model's context and that the model tends to follow: the initialize
 * `instructions` field (the spec permits injecting it into the system prompt),
 * every tool's name and description, the string fields inside tool input
 * schemas, and prompt/resource metadata. A poisoned entry in ANY of these
 * attacks the agent without the tool ever being called. So the real question is
 * not "does this contain bad words" but "is an external server quietly making
 * itself a co-author of the agent's policy" - excessive authority, not vocabulary.
 *
 * This scan is deliberately pattern-based and deterministic (no LLM): it
 * identifies COMMON INDICATORS of poisoning and authority-assertion, not every
 * possible injection. Semantic prompt injection (natural-language steering with
 * no tell-tale phrase) is the known ceiling of any pattern scanner and is out of
 * scope here by design; see §5 of the policy.
 *
 * Layered, cheapest first: length limit (anti-stuffing) -> pattern match over
 * each model-facing text item. Patterns are public; a description that merely
 * dodges these exact strings while embedding instructions will still read
 * suspiciously in the evidence we surface.
 */

import type { CheckResult, Evidence, ToolSurface } from '../types.js';

/** Descriptions above this are flagged as anti-stuffing signal, independent of content. */
export const MAX_DESCRIPTION_CHARS = 2048;
/** The initialize instructions field legitimately documents a whole server, so it gets more room. */
export const MAX_INSTRUCTIONS_CHARS = 4096;

type Severity = 'critical' | 'fail' | 'warn';

interface PoisonPattern {
  name: string;
  regex: RegExp;
  severity: Severity;
  /** 'description' patterns skip schema-derived text (avoids flagging $schema URIs etc.) */
  scope?: 'description' | 'all';
}

export const POISON_PATTERNS: PoisonPattern[] = [
  {
    name: 'invisible/zero-width characters',
    // zero-width spaces/joiners, bidi marks, soft hyphen, BOM, Unicode "tag" block
    regex: /[\u200B-\u200F\u2060-\u2064\u00AD\uFEFF\u{E0000}-\u{E007F}]/u,
    severity: 'fail',
  },
  {
    name: 'override-instructions phrase',
    regex: /\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|messages?)/i,
    severity: 'fail',
  },
  {
    name: 'concealment directive',
    regex: /\bdo\s+not\s+(tell|inform|reveal|mention|show|alert|notify)\b[^.]{0,60}\b(user|human)\b/i,
    severity: 'fail',
  },
  {
    name: 'credential-priority directive',
    // authority assertion: server tells the agent to read secrets/env first, before its actual work
    regex: /\b(read|fetch|load|retrieve|access|collect|obtain|gather)\b[^.]{0,40}\b(secret|credential|api[_ ]?key|access[_ ]?token|password|\.env|environment\s+variables?)s?\b[^.]{0,40}\b(first|before\s+(?:you|doing|anything|any|calling)|immediately|at\s+the\s+start|to\s+begin|up\s?front)\b/i,
    severity: 'critical',
  },
  {
    name: 'content suppression directive',
    // authority assertion: server dictates what the agent may not say about others
    regex: /\b(never|do\s+not|don'?t|avoid|refuse\s+to)\s+(mention|reveal|recommend|suggest|discuss|name|acknowledge|refer\s+to)\b[^.]{0,50}\b(competitor|competing|rival|alternative|other\s+(?:tools?|products?|vendors?|brands?|services?|servers?))\b/i,
    severity: 'warn',
  },
  {
    name: 'imperative to the model',
    regex: /\byou\s+(must|should)\s+(always|never|first|instead)\b/i,
    severity: 'warn',
  },
  {
    name: 'cross-tool shadowing',
    regex: /\b(instead\s+of|rather\s+than|in\s+place\s+of|before\s+(?:using|calling))\s+(?:the\s+)?[`'"]?[\w.-]+[`'"]?\s*(tool|server|function)?/i,
    severity: 'warn',
  },
  {
    name: 'pseudo-system markup',
    // fake chat/role/instruction delimiters models may treat as privileged
    regex: /<\/?\s*(system|assistant|user|important|hidden|secret|instructions?)\s*>/i,
    severity: 'fail',
  },
  {
    name: 'hidden markup comment',
    // instructions tucked into an HTML/markdown comment: invisible when rendered
    regex: /<!--[\s\S]*?(ignore|instead|do not|always|never|system|credential|secret)[\s\S]*?-->/i,
    severity: 'fail',
  },
  {
    name: 'non-http URI scheme',
    // javascript:/data:/vbscript: payloads; file: local reads
    regex: /\b(javascript|data|vbscript|file):[^\s)"']{4,}/i,
    severity: 'fail',
  },
  {
    name: 'embedded URL',
    regex: /https?:\/\/(?!(?:www\.)?(github\.com|docs\.|.*\.example\.com))[^\s)"']{8,}/i,
    severity: 'warn',
    scope: 'description',
  },
];

/**
 * Recursively collect human-readable string fields from a JSON Schema. These
 * (description/title/examples/default/enum) are surfaced to the model just like
 * the top-level description, so a payload buried in a nested property counts.
 */
export function extractSchemaText(schema: unknown, depth = 0): string[] {
  if (depth > 8 || schema == null) return [];
  const out: string[] = [];
  if (Array.isArray(schema)) {
    for (const item of schema) out.push(...extractSchemaText(item, depth + 1));
    return out;
  }
  if (typeof schema === 'object') {
    for (const [key, value] of Object.entries(schema as Record<string, unknown>)) {
      if (['description', 'title', 'default'].includes(key) && typeof value === 'string') {
        out.push(value);
      } else if (['examples', 'enum'].includes(key) && Array.isArray(value)) {
        for (const v of value) if (typeof v === 'string') out.push(v);
      } else if (typeof value === 'object') {
        out.push(...extractSchemaText(value, depth + 1));
      }
    }
  }
  return out;
}

/** One model-facing text item to scan. 'schema' items skip description-only patterns. */
interface ScanItem {
  label: string;
  text: string;
  kind: 'description' | 'schema';
}

export function checkPoisoning(surface: ToolSurface): CheckResult {
  const base = {
    id: 'poisoning.patterns',
    policyRef: '§5.1–§5.4',
    title: 'Server-supplied instructions free of poisoning indicators',
  };

  // Build the full set of model-facing text items across every server-supplied channel.
  const items: ScanItem[] = [];
  const evidence: Evidence[] = [];
  let worst: 'pass' | 'warn' | 'fail' = 'pass';
  const bump = (severity: Severity) => {
    if (severity === 'critical' || severity === 'fail') worst = 'fail';
    else if (worst === 'pass') worst = 'warn';
  };

  // Anti-stuffing length check, applied where a length ceiling makes sense.
  const lengthCheck = (label: string, text: string, limit: number) => {
    if (text.length > limit) {
      evidence.push({ label: `${label}: oversized`, value: `${text.length} chars (limit ${limit})` });
      bump('warn');
    }
  };

  // 1. initialize instructions (the highest-authority channel: the system prompt).
  if (surface.serverInstructions) {
    items.push({ label: 'server instructions', text: surface.serverInstructions, kind: 'description' });
    lengthCheck('server instructions', surface.serverInstructions, MAX_INSTRUCTIONS_CHARS);
  }

  // 2. tools: name + description scanned as prose, schema string fields scanned separately.
  for (const tool of surface.tools) {
    const description = tool.description ?? '';
    items.push({ label: tool.name, text: [tool.name, description].join('\n'), kind: 'description' });
    lengthCheck(`${tool.name} description`, description, MAX_DESCRIPTION_CHARS);
    const schemaText = extractSchemaText(tool.inputSchema).join('\n');
    if (schemaText) items.push({ label: `${tool.name} (schema)`, text: schemaText, kind: 'schema' });
  }

  // 3. prompts and 4. resources: names/descriptions are model-facing too (URIs left alone).
  for (const p of surface.prompts ?? []) {
    items.push({ label: `prompt: ${p.name}`, text: [p.name, p.description ?? ''].join('\n'), kind: 'description' });
  }
  for (const r of surface.resources ?? []) {
    items.push({ label: `resource: ${r.name}`, text: [r.name, r.description ?? ''].join('\n'), kind: 'description' });
  }

  if (items.length === 0) {
    return {
      ...base,
      status: 'unverifiable',
      summary: 'No server-supplied instructions or tool descriptions were obtainable to scan.',
      evidence: [],
    };
  }

  let criticalHits = 0;
  for (const item of items) {
    for (const pattern of POISON_PATTERNS) {
      if (item.kind === 'schema' && pattern.scope === 'description') continue;
      const match = pattern.regex.exec(item.text);
      if (!match) continue;
      const critical = pattern.severity === 'critical';
      if (critical) criticalHits++;
      evidence.push({
        label: `${item.label}: ${critical ? 'CRITICAL - ' : ''}${pattern.name}`,
        value: truncate(match[0], 120),
      });
      bump(pattern.severity);
    }
  }

  const scannedCount = items.length;
  let summary: string;
  if (worst === 'pass') {
    summary = `No poisoning indicators found across ${scannedCount} server-supplied text item(s).`;
  } else {
    const critNote = criticalHits > 0 ? ` including ${criticalHits} critical` : '';
    summary = `${evidence.length} suspicious indicator(s)${critNote} found in server-supplied instructions, tool descriptions, or schemas.`;
  }

  return { ...base, status: worst, summary, evidence };
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}
