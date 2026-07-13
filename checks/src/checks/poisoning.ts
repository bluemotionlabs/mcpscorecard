/**
 * §5 Tool-description integrity — pattern-based tool-poisoning scan.
 *
 * Tool descriptions are loaded into the model's context and followed, so a
 * poisoned description attacks the agent without the tool ever being called.
 * v1 is deliberately pattern-based (no LLM): patterns below cover the
 * documented attack classes — hidden instructions, invisible Unicode,
 * cross-tool shadowing. Patterns are public; a description that merely
 * avoids these exact strings while embedding instructions will still read
 * suspiciously to a human reviewing the evidence we surface.
 */

import type { CheckResult, Evidence, ToolSurface } from '../types.js';

interface PoisonPattern {
  name: string;
  regex: RegExp;
  severity: 'fail' | 'warn';
  /** 'description' patterns skip inputSchema JSON (avoids flagging $schema URIs etc.) */
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
    regex: /<\/?\s*(system|important|hidden|secret|instructions?)\s*>/i,
    severity: 'fail',
  },
  {
    name: 'embedded URL',
    regex: /https?:\/\/(?!(?:www\.)?(github\.com|docs\.|.*\.example\.com))[^\s)"']{8,}/i,
    severity: 'warn',
    scope: 'description',
  },
];

export function checkPoisoning(surface: ToolSurface): CheckResult {
  const base = {
    id: 'poisoning.patterns',
    policyRef: '§5.1–§5.2',
    title: 'Tool descriptions free of hidden instructions',
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

  for (const tool of surface.tools) {
    const descriptionText = [tool.name, tool.description ?? ''].join('\n');
    const fullText = [descriptionText, JSON.stringify(tool.inputSchema ?? '')].join('\n');
    for (const pattern of POISON_PATTERNS) {
      const match = pattern.regex.exec(pattern.scope === 'description' ? descriptionText : fullText);
      if (!match) continue;
      evidence.push({
        label: `${tool.name}: ${pattern.name}`,
        value: truncate(match[0], 120),
      });
      if (pattern.severity === 'fail') worst = 'fail';
      else if (worst === 'pass') worst = 'warn';
    }
  }

  return {
    ...base,
    status: worst,
    summary:
      worst === 'pass'
        ? `No poisoning patterns found across ${surface.tools.length} tool description(s).`
        : `${evidence.length} suspicious pattern(s) found in tool descriptions.`,
    evidence,
  };
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}
