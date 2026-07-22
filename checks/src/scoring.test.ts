import { describe, expect, it } from 'vitest';
import { computeScore, CHECK_WEIGHTS } from './scoring.js';
import { allPassChecks, result } from './test-helpers.js';

describe('computeScore', () => {
  it('gives A for all passes', () => {
    const { score, grade } = computeScore(allPassChecks());
    expect(score).toBe(100);
    expect(grade).toBe('A');
  });

  it('caps grade at B when capabilities are unverifiable, even if all else passes', () => {
    const { grade, score } = computeScore(
      allPassChecks({
        'capabilities.tool-surface': 'unverifiable',
        'poisoning.patterns': 'unverifiable',
      }),
    );
    expect(score).toBe(100);
    expect(grade).toBe('B');
  });

  it('forces grade F when poisoning.patterns fails even if every other check passes', () => {
    const { grade, score } = computeScore(allPassChecks({ 'poisoning.patterns': 'fail' }));
    // Weighted score would still be high (poisoning is 15 of ~80); grade must be F per policy.
    expect(score).toBeGreaterThanOrEqual(80);
    expect(grade).toBe('F');
  });

  it('does not force F when poisoning.patterns is only a warn', () => {
    const { grade } = computeScore(allPassChecks({ 'poisoning.patterns': 'warn' }));
    expect(grade).not.toBe('F');
    expect(grade === 'A' || grade === 'B').toBe(true);
  });

  it('returns 0/F when nothing is scorable', () => {
    const { score, grade } = computeScore([result('capabilities.tool-surface', 'unverifiable')]);
    expect(score).toBe(0);
    expect(grade).toBe('F');
  });

  it('excludes info and unknown check ids from the denominator', () => {
    const checks = [
      result('provenance.registry-listed', 'pass'),
      result('transport.https', 'info'),
      result('not.a.real.check', 'fail'),
    ];
    const { score, grade } = computeScore(checks);
    expect(score).toBe(100);
    expect(grade).toBe('A');
  });

  it('scores warn as half weight', () => {
    // Only poisoning scored: warn → 0.5 * 15 / 15 = 50 → D
    const { score, grade } = computeScore([result('poisoning.patterns', 'warn')]);
    expect(score).toBe(50);
    expect(grade).toBe('D');
    expect(CHECK_WEIGHTS['poisoning.patterns']).toBe(15);
  });

  it('poisoning fail overrides the unverifiable-capability B cap to F', () => {
    const { grade } = computeScore([
      result('provenance.registry-listed', 'pass'),
      result('capabilities.tool-surface', 'unverifiable'),
      result('poisoning.patterns', 'fail'),
    ]);
    expect(grade).toBe('F');
  });
});
