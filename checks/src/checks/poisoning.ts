/**
 * §5 Tool-description integrity - pattern-based tool-poisoning scan.
 *
 * Tool descriptions (and the string fields inside their input schemas) are
 * loaded into the model's context and followed, so a poisoned description
 * attacks the agent without the tool ever being called. This is deliberately
 * pattern-based and deterministic (no LLM): it identifies COMMON INDICATORS
 * of tool-description poisoning and suspicious prompt-like content, not every
 * possible injection. Semantic prompt injection (natural-language steering
 * with no tell-tale phrase) is the known ceiling of any pattern scanner and
 * is out of scope here by design; see §5 of the policy.
 *
 * Layered, cheapest first: length limit (anti-stuffing) -> pattern match over
 * the description AND recursively-extracted schema string fields. Patterns are
 * public; a description that merely dodges these exact strings while embedding
 * instructions will still read suspiciously in the evidence we surface.
 */

import type { CheckResult, Evidence, ToolSurface } from '../types.js';

/** Descriptions above this are flagged as anti-stuffing signal, independent of content. */
export const MAX_DESCRIPTION_CHARS = 2048;

interface PoisonPattern {
  name: string;
  regex: RegExp;
  severity: 'fail' | 'warn';
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

export function checkPoisoning(surface: ToolSurface): CheckResult {
  const base = {
    id: 'poisoning.patterns',
    policyRef: '§5.1–§5.4',
    title: 'Tool descriptions free of poisoning indicators',
  };

  if (surface.tools.length === 0) {
    return {
      ...base,
      status: 'unverifiable',
      summary: 'No tool descriptions were obtainable to scan.',
      evidence: [],
    };
  }

  const evidence: Evidence[] = [];
  let worst: 'pass' | 'warn' | 'fail' = 'pass';
  const bump = (severity: 'fail' | 'warn') => {
    if (severity === 'fail') worst = 'fail';
    else if (worst === 'pass') worst = 'warn';
  };

  for (const tool of surface.tools) {
    const description = tool.description ?? '';
    const descriptionText = [tool.name, description].join('\n');
    // Schema-derived strings are surfaced to the model too, so they get scanned
    // like the description (minus the description-only patterns, e.g. URLs, to
    // avoid flagging benign $schema/$ref URIs).
    const schemaText = extractSchemaText(tool.inputSchema).join('\n');
    const fullText = [descriptionText, schemaText].join('\n');

    // Anti-stuffing: an oversized description is suspicious independent of content
    // (a payload can be buried thousands of tokens deep, past any single phrase).
    if (description.length > MAX_DESCRIPTION_CHARS) {
      evidence.push({
        label: `${tool.name}: oversized description`,
        value: `${description.length} chars (limit ${MAX_DESCRIPTION_CHARS})`,
      });
      bump('warn');
    }

    for (const pattern of POISON_PATTERNS) {
      const match = pattern.regex.exec(pattern.scope === 'description' ? descriptionText : fullText);
      if (!match) continue;
      evidence.push({
        label: `${tool.name}: ${pattern.name}`,
        value: truncate(match[0], 120),
      });
      bump(pattern.severity);
    }
  }

  return {
    ...base,
    status: worst,
    summary:
      worst === 'pass'
        ? `No poisoning indicators found across ${surface.tools.length} tool description(s).`
        : `${evidence.length} suspicious indicator(s) found in tool descriptions or schemas.`,
    evidence,
  };
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}
