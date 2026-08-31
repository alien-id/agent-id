import { describe, expect, test } from 'bun:test';
import { CYRILLIC_ALLOWLIST, RULES, type Rule, SELF_EXEMPT, adviceFor, scanFile } from '../lib/hygiene';

const SOURCE = 'plugins/agent-id-browser/lib/auto-login.mjs';

// The matching behaviour is tested against a stand-in rule rather than the real
// ones: a test that restated the terms would put them back in the repo, which is
// the whole thing this check exists to prevent. What the real rules match is
// proved where it counts — by the check running over every tracked file in CI.
const STAND_IN: Rule[] = [
  { name: 'stand-in', pattern: /forbidden-token/i, advice: 'say it another way' },
];

describe('scanFile', () => {
  test('flags a rule match and reports where it is', () => {
    const findings = scanFile(SOURCE, ['clean', '// a forbidden-token here'].join('\n'), STAND_IN);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule).toBe('stand-in');
    expect(findings[0]?.line).toBe(2);
  });

  test('matches case-insensitively and inside a compound word', () => {
    expect(scanFile(SOURCE, '// Forbidden-Token-hosted containers', STAND_IN)).toHaveLength(1);
    expect(scanFile(SOURCE, '// the file stays under /home/forbidden-token', STAND_IN)).toHaveLength(1);
  });

  test('reports every rule a single line trips', () => {
    const rules: Rule[] = [...STAND_IN, { name: 'second', pattern: /token/i, advice: 'no' }];
    expect(scanFile(SOURCE, '// forbidden-token', rules).map((f) => f.rule)).toEqual([
      'stand-in',
      'second',
    ]);
  });

  test('leaves ordinary prose alone', () => {
    const lines = [
      "// agent-browser's message shapes (frame/status/ack/config/input_*)",
      '// see https://agent-browser.dev/streaming',
      "// the caller's own 16-minute ceiling kills the whole run",
      '// resolution mirrors the desktop host: an explicit BIN override',
    ];
    expect(scanFile(SOURCE, lines.join('\n'), STAND_IN)).toEqual([]);
    expect(scanFile(SOURCE, lines.join('\n'))).toEqual([]);
  });

  test('flags Cyrillic in our own prose', () => {
    // Built from escapes so this file does not itself carry the thing under test.
    const cyrillic = `// ${String.fromCodePoint(0x43f, 0x440, 0x438, 0x432, 0x435, 0x442)}`;
    expect(scanFile(SOURCE, cyrillic).map((f) => f.rule)).toEqual(['Cyrillic prose']);
  });

  test('allows Cyrillic where it is page copy the product must match', () => {
    const cyrillic = String.fromCodePoint(0x43f, 0x430, 0x440, 0x43e, 0x43b, 0x44c);
    for (const path of CYRILLIC_ALLOWLIST) {
      expect(scanFile(path, cyrillic)).toEqual([]);
    }
  });

  test('the files that must carry the terms do not flag themselves', () => {
    for (const path of SELF_EXEMPT) {
      expect(scanFile(path, '// forbidden-token', STAND_IN)).toEqual([]);
    }
  });

  test('skips binary and generated files', () => {
    expect(scanFile('.github/assets/logo.png', '// forbidden-token', STAND_IN)).toEqual([]);
    expect(scanFile('bun.lock', '// forbidden-token', STAND_IN)).toEqual([]);
  });
});

describe('the real rules', () => {
  test('every one carries advice a reader can act on', () => {
    expect(RULES.length).toBeGreaterThan(0);
    for (const rule of RULES) {
      expect(rule.advice.length).toBeGreaterThan(20);
      expect(adviceFor(rule.name)).toBe(rule.advice);
    }
  });

  test('an unknown rule name still answers with the Cyrillic advice', () => {
    expect(adviceFor('Cyrillic prose')).toMatch(/English/);
  });
});
