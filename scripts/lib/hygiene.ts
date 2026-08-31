// This repository is public, and three of its packages ship their `lib/` to npm.
// A comment written for a colleague therefore leaves with the next release.
//
// These rules say what may not appear. They are deliberately narrow: widening
// them is a decision to take on purpose, because a rule that fires on ordinary
// prose gets disabled, and then it protects nothing.
//
// `scanFile` takes its rules as an argument so tests can exercise the mechanism
// without restating the terms below — the point of the check is that those
// appear in exactly one place.

export type Rule = {
  name: string;
  pattern: RegExp;
  // Shown under the finding, so whoever trips a rule can fix it without going
  // to find whoever wrote it.
  advice: string;
};

export type Finding = {
  path: string;
  line: number;
  rule: string;
  excerpt: string;
};

export const RULES: Rule[] = [
  {
    name: 'external project name',
    pattern: /lethe/i,
    advice: 'Describe the behaviour in terms of this package — "the caller", "the desktop host".',
  },
  {
    name: 'path into another codebase',
    pattern: /\bsrc\/[\w/-]*\.rs\b/,
    advice: 'Cite no file path outside this repo; say what the behaviour is instead.',
  },
];

// The file that defines the terms cannot avoid containing them, and the test
// file carries a Cyrillic fixture. Exempting them by name is what every scanner
// of this shape does; spelling the terms obfuscated would hide them from the
// reader without hiding them from anyone else.
export const SELF_EXEMPT = new Set(['scripts/lib/hygiene.ts', 'scripts/tests/hygiene.test.ts']);

// Cyrillic is allowed only where it is data the product must match: the
// rejection vocabulary a Russian-language sign-in page prints, the fixtures
// that pin it, and the changelog entry describing that feature. Our own prose
// is English.
export const CYRILLIC_ALLOWLIST = new Set([
  'plugins/agent-id-browser/lib/login-detect.mjs',
  'tests/test-login-detect.mjs',
  'plugins/agent-id-browser/CHANGELOG.md',
]);

const BINARY_OR_GENERATED = /\.(png|jpg|jpeg|gif|ico|svg|woff2?|tgz|lock)$|^bun\.lock$/;
const CYRILLIC = /[Ѐ-ӿ]/;

export function scanFile(path: string, text: string, rules: Rule[] = RULES): Finding[] {
  if (SELF_EXEMPT.has(path) || BINARY_OR_GENERATED.test(path)) return [];

  const findings: Finding[] = [];
  const cyrillicAllowed = CYRILLIC_ALLOWLIST.has(path);

  text.split('\n').forEach((line, index) => {
    for (const rule of rules) {
      if (rule.pattern.test(line)) {
        findings.push({ path, line: index + 1, rule: rule.name, excerpt: excerpt(line) });
      }
    }
    if (!cyrillicAllowed && CYRILLIC.test(line)) {
      findings.push({ path, line: index + 1, rule: 'Cyrillic prose', excerpt: excerpt(line) });
    }
  });

  return findings;
}

export function adviceFor(rule: string, rules: Rule[] = RULES): string {
  return (
    rules.find((r) => r.name === rule)?.advice ??
    'Write our own prose in English. Cyrillic belongs only in matched page copy and its fixtures.'
  );
}

function excerpt(line: string): string {
  return line.trim().slice(0, 100);
}
