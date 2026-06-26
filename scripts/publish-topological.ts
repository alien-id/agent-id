#!/usr/bin/env bun

// Topological publish loop. Packs each publishable plugin and uploads it with
// `npm publish <tgz> --provenance` (OIDC trusted publishing — no NPM_TOKEN).
// We pack with `bun pm pack` for parity with the dev toolchain; internal deps
// are plain `^semver` (not `workspace:*`), so no specifier substitution is
// needed and an `npm pack` would work too. `bun publish` lacks `--provenance`,
// so the upload goes through the npm CLI. Idempotent across re-runs via
// `npm view`. Tagging is left to canonical `changeset tag` (run after this
// script in `ci:publish`).

import { spawnSync } from 'node:child_process';
import { readdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { runNpmView } from './lib/npm-view';
import { readPackages } from './lib/packages';
import { deriveTag } from './lib/tag';
import { selectTarball } from './lib/tarball';
import { topoSort } from './lib/topo';

const REPO_ROOT = new URL('..', import.meta.url).pathname;
const PLUGINS_DIR = join(REPO_ROOT, 'plugins');
const DRY_RUN = process.argv.includes('--dry-run');

function alreadyPublished(name: string, version: string): boolean {
  // Unknown failures throw rather than degrade to "not published" — a transient
  // network blip must not cause a re-publish attempt against an existing version.
  const classification = runNpmView(name, version);
  if (classification === 'unknown') {
    throw new Error(
      `npm view ${name}@${version} failed unexpectedly. Re-run the workflow ` +
        `to retry; this is treated as transient on purpose so a real publish ` +
        `is never skipped.`,
    );
  }
  return classification === 'published';
}

function run(
  cmd: string,
  args: string[],
  cwd: string,
  skipInDryRun = true,
): void {
  const prefix = DRY_RUN && skipInDryRun ? '  [dry] $' : '  $';
  console.log(`${prefix} ${cmd} ${args.join(' ')}`);
  if (DRY_RUN && skipInDryRun) return;
  const result = spawnSync(cmd, args, { cwd, stdio: 'inherit' });
  if (result.status !== 0) {
    throw new Error(
      `${cmd} ${args.join(' ')} (cwd: ${cwd}) exited with ${result.status}`,
    );
  }
}

// Remove any leftover tarballs before packing so `selectTarball` can never
// pick up a stale artifact from a prior run (defence-in-depth alongside its
// exact-name match).
function cleanTarballs(cwd: string): void {
  for (const entry of readdirSync(cwd)) {
    if (entry.endsWith('.tgz')) rmSync(join(cwd, entry));
  }
}

async function main() {
  const pkgs = await readPackages(PLUGINS_DIR);
  const publishable = pkgs.filter((p) => !p.private);
  const publishableNames = new Set(publishable.map((p) => p.name));

  const graph = new Map<string, string[]>(
    publishable.map((p) => [
      p.name,
      p.deps.filter((d) => publishableNames.has(d)),
    ]),
  );
  const order = topoSort(graph);
  const byName = new Map(publishable.map((p) => [p.name, p]));

  console.log(`Topological publish order: ${order.join(' → ')}`);
  if (DRY_RUN)
    console.log('--- DRY RUN: no network operations will be performed ---\n');

  const summary: string[] = [];
  for (const name of order) {
    const pkg = byName.get(name);
    if (!pkg) throw new Error(`Package ${name} missing from byName map`);
    const cwd = join(PLUGINS_DIR, pkg.dir);
    const tag = deriveTag(pkg.version);
    console.log(`\n=== ${pkg.name}@${pkg.version} (tag: ${tag}) ===`);

    if (!DRY_RUN && alreadyPublished(pkg.name, pkg.version)) {
      console.log(`  ✓ already on registry — skipping`);
      summary.push(`skipped ${pkg.name}@${pkg.version}`);
      continue;
    }

    // Pack always runs — local-only. Clear stale tarballs first so the
    // exact-name match can't be fooled.
    cleanTarballs(cwd);
    run('bun', ['pm', 'pack'], cwd, false);
    const tarball = selectTarball(readdirSync(cwd), pkg.name, pkg.version);
    run(
      'npm',
      [
        'publish',
        `./${tarball}`,
        '--access',
        'public',
        '--provenance',
        '--tag',
        tag,
      ],
      cwd,
    );
    summary.push(`published ${pkg.name}@${pkg.version} → ${tag}`);
  }

  console.log('\n=== Summary ===');
  for (const line of summary) console.log(`  ${line}`);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
