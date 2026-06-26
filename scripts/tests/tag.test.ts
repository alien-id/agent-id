import { describe, expect, test } from 'bun:test';
import { deriveTag } from '../lib/tag';

describe('deriveTag', () => {
  test('stable semver maps to latest', () => {
    expect(deriveTag('2.1.0')).toBe('latest');
    expect(deriveTag('1.0.0')).toBe('latest');
    expect(deriveTag('10.20.30')).toBe('latest');
  });

  test('beta prerelease maps to beta', () => {
    expect(deriveTag('2.1.0-beta.0')).toBe('beta');
    expect(deriveTag('2.1.0-beta.42')).toBe('beta');
    expect(deriveTag('1.0.0-beta')).toBe('beta');
  });

  test('alpha prerelease maps to alpha', () => {
    expect(deriveTag('2.1.0-alpha.0')).toBe('alpha');
    expect(deriveTag('1.0.0-alpha.99')).toBe('alpha');
  });

  test('rc prerelease maps to rc', () => {
    expect(deriveTag('2.0.0-rc.1')).toBe('rc');
  });

  test('snapshot-style hyphenated identifier maps to identifier', () => {
    // changesets --snapshot produces "x.y.z-alpha-20260528120000"
    expect(deriveTag('2.1.0-alpha-20260528120000')).toBe('alpha');
    expect(deriveTag('2.1.0-canary-abc1234')).toBe('canary');
  });

  test('rejects invalid version strings', () => {
    expect(() => deriveTag('')).toThrow();
    expect(() => deriveTag('not-semver')).toThrow();
    expect(() => deriveTag('1.0')).toThrow();
  });
});
