import { describe, expect, test } from 'bun:test';
import { selectTarball } from '../lib/tarball';

describe('selectTarball', () => {
  test('returns the exact bun-pack filename for a scoped package', () => {
    const entries = ['alien-id-miniapps-bridge-2.1.0.tgz'];
    expect(selectTarball(entries, '@alien-id/miniapps-bridge', '2.1.0')).toBe(
      'alien-id-miniapps-bridge-2.1.0.tgz',
    );
  });

  test('picks the exact version over a stale prerelease tarball of the same package', () => {
    // The bug: a leftover `-beta.1` tarball contains the version as a
    // substring AND sorts before the final tarball ('-' < '.'), so the
    // old `f.includes(version)` fallback would publish the wrong artifact.
    const entries = [
      'alien-id-miniapps-bridge-2.1.0-beta.1.tgz',
      'alien-id-miniapps-bridge-2.1.0.tgz',
    ];
    expect(selectTarball(entries, '@alien-id/miniapps-bridge', '2.1.0')).toBe(
      'alien-id-miniapps-bridge-2.1.0.tgz',
    );
  });

  test('throws when only a loose version-substring match exists (no exact filename)', () => {
    const entries = ['alien-id-miniapps-bridge-2.1.0-beta.1.tgz'];
    expect(() =>
      selectTarball(entries, '@alien-id/miniapps-bridge', '2.1.0'),
    ).toThrow(/not found/i);
  });

  test('throws when no tarball is present', () => {
    expect(() =>
      selectTarball([], '@alien-id/miniapps-bridge', '2.1.0'),
    ).toThrow(/not found/i);
  });
});
