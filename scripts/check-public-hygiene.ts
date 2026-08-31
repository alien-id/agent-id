#!/usr/bin/env bun

// Fail the build when a tracked file reaches outside this repo or carries
// Russian prose of our own. The rules and their reasoning live in ./lib/hygiene;
// this is the I/O shell: enumerate what git tracks, scan it, report.
//
// Run locally with `bun run ci:hygiene`.

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { adviceFor, scanFile } from './lib/hygiene';

const REPO_ROOT = new URL('..', import.meta.url).pathname;

function trackedFiles(): string[] {
  const result = spawnSync('git', ['ls-files', '-z'], { cwd: REPO_ROOT, encoding: 'utf8' });
  if (result.status !== 0) {
    throw new Error(`git ls-files failed: ${result.stderr.trim()}`);
  }
  return result.stdout.split('\0').filter(Boolean);
}

function main() {
  const findings = trackedFiles().flatMap((path) => {
    // A file git tracks but that cannot be read as text (or was deleted from the
    // working tree) is not this check's business.
    let text: string;
    try {
      text = readFileSync(join(REPO_ROOT, path), 'utf8');
    } catch {
      return [];
    }
    return scanFile(path, text);
  });

  if (findings.length === 0) {
    console.log('check-public-hygiene: clean');
    return;
  }

  const byRule = new Map<string, typeof findings>();
  for (const finding of findings) {
    byRule.set(finding.rule, [...(byRule.get(finding.rule) ?? []), finding]);
  }

  for (const [rule, hits] of byRule) {
    console.error(`\n${rule} — ${hits.length} ${hits.length === 1 ? 'line' : 'lines'}`);
    console.error(`  ${adviceFor(rule)}\n`);
    for (const hit of hits) {
      // The `file:line: error:` shape is what GitHub Actions renders inline.
      console.error(`${hit.path}:${hit.line}: error: ${hit.excerpt}`);
    }
  }

  console.error(`\nThis repository is public. ${findings.length} line(s) must not ship.`);
  process.exit(1);
}

main();
