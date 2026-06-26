import { describe, expect, test } from 'bun:test';
import { hasPendingChangesets, needsPublish } from '../lib/detect';

const pkgs = [
  { name: '@scope/a', version: '2.1.0' },
  { name: '@scope/b', version: '2.1.0' },
];

describe('hasPendingChangesets', () => {
  test('empty .changeset directory → false', () => {
    expect(hasPendingChangesets([])).toBe(false);
  });

  test('only the template README.md → false', () => {
    expect(hasPendingChangesets(['README.md'])).toBe(false);
  });

  test('non-markdown config files (config.json, pre.json) → false', () => {
    expect(hasPendingChangesets(['config.json', 'pre.json'])).toBe(false);
  });

  test('a real changeset markdown among boilerplate → true', () => {
    expect(
      hasPendingChangesets(['README.md', 'config.json', 'brave-lions-cry.md']),
    ).toBe(true);
  });

  // Pre-mode lifecycle (verified against @changesets/cli 2.31.0): the changeset
  // `.md` persists through the whole beta cycle and past `pre exit`; only the
  // stable version consumes it. So a pending `.md` keeps the Version PR alive
  // even while `pre.json` exists — and `pre.json` alone never counts as work.
  test('pre-mode: a pending .md alongside pre.json → true', () => {
    expect(
      hasPendingChangesets(['config.json', 'pre.json', 'cool-feature.md']),
    ).toBe(true);
  });

  test('pre.json on its own (no pending .md) → false', () => {
    expect(hasPendingChangesets(['config.json', 'pre.json'])).toBe(false);
  });
});

describe('needsPublish', () => {
  test('every package already on the registry → false', () => {
    expect(needsPublish(pkgs, () => 'published')).toBe(false);
  });

  test('one package missing from the registry → true', () => {
    const classify = (name: string) =>
      name === '@scope/b' ? 'not-published' : 'published';
    expect(needsPublish(pkgs, classify)).toBe(true);
  });

  test('a transient (unknown) registry error throws — never guesses', () => {
    const classify = (name: string) =>
      name === '@scope/b' ? 'unknown' : 'published';
    expect(() => needsPublish(pkgs, classify)).toThrow(/@scope\/b/);
  });

  test('no publishable packages → false', () => {
    expect(needsPublish([], () => 'unknown')).toBe(false);
  });
});
