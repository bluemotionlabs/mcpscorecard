/**
 * Scoring: fully public by design. A score you can't audit is a score you
 * shouldn't trust — weights, bands, and caps all live here, in the open.
 *
 * Model:
 *  - Each check earns points: pass = 1.0, warn = 0.5, fail = 0.
 *  - 'info' results are displayed but unscored.
 *  - 'unverifiable' results are excluded from the denominator, EXCEPT the
 *    capability check (§2): if the tool surface cannot be inspected at all,
 *    the overall grade is capped at B (Policy: "cannot verify is a finding").
 *  - Check weights reflect policy-section importance (§2 capability scope
 *    dominates: what a server can do matters more than where it's listed).
 */

import type { CheckResult, Grade } from './types.js';

export const CHECK_WEIGHTS: Record<string, number> = {
  'provenance.registry-listed': 5,
  'provenance.repo-health': 10,
  'provenance.package-hygiene': 10,
  'capabilities.tool-surface': 30,
  'transport.https': 5,
  'transport.auth-required': 10,
  'transport.oauth-metadata': 5,
  'vulns.osv': 10,
  'poisoning.patterns': 15,
};

export const GRADE_BANDS: Array<{ min: number; grade: Grade }> = [
  { min: 90, grade: 'A' },
  { min: 80, grade: 'B' },
  { min: 65, grade: 'C' },
  { min: 50, grade: 'D' },
  { min: 0, grade: 'F' },
];

/** Grade cap applied when the tool surface is unverifiable (Policy §2.1). */
export const UNVERIFIABLE_CAPABILITY_CAP: Grade = 'B';

const STATUS_POINTS: Record<string, number | null> = {
  pass: 1,
  warn: 0.5,
  fail: 0,
  info: null, // displayed, unscored
  unverifiable: null, // excluded from denominator (capability cap handled separately)
};

export function computeScore(checks: CheckResult[]): { score: number; grade: Grade } {
  let earned = 0;
  let possible = 0;

  for (const check of checks) {
    const weight = CHECK_WEIGHTS[check.id];
    if (weight === undefined) continue;
    const points = STATUS_POINTS[check.status];
    if (points === null || points === undefined) continue;
    earned += points * weight;
    possible += weight;
  }

  // No scorable checks at all → score 0/F rather than a divide-by-zero A.
  const score = possible === 0 ? 0 : Math.round((earned / possible) * 100);
  let grade = toGrade(score);

  const capabilityUnverifiable = checks.some(
    (c) => c.id === 'capabilities.tool-surface' && c.status === 'unverifiable',
  );
  if (capabilityUnverifiable && gradeRank(grade) < gradeRank(UNVERIFIABLE_CAPABILITY_CAP)) {
    grade = UNVERIFIABLE_CAPABILITY_CAP;
  }

  return { score, grade };
}

export function toGrade(score: number): Grade {
  for (const band of GRADE_BANDS) {
    if (score >= band.min) return band.grade;
  }
  return 'F';
}

/** Lower rank = better grade. */
function gradeRank(grade: Grade): number {
  return ['A', 'B', 'C', 'D', 'F'].indexOf(grade);
}
