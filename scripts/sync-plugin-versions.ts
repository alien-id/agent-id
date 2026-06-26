#!/usr/bin/env bun

// Propagate each plugin's package.json (the source of truth changesets bumps)
// into the two manifests the marketplace reads but changesets ignores:
// plugins/<name>/.claude-plugin/plugin.json and .claude-plugin/marketplace.json.
// Two things flow through:
//   1. the plugin's own `version`
//   2. each internal dependency RANGE from package.json `dependencies`
//      (e.g. "@alien-id/agent-id-core": "^7.1.0", maintained by changesets'
//      updateInternalDependencies) -> plugin.json `dependencies[].version`
// Without (2), plugin.json's cross-plugin pins are maintained by nobody and
// drift stale (a bare "7.0.0" is an EXACT semver constraint to Claude Code, so
// an installed 7.1.0 fails it). The planning logic lives in ./lib/sync.ts;
// this is the I/O shell. Run by `ci:version`. Idempotent; the CI drift check
// (`git diff --exit-code`) catches any manifest that fell behind.

import { readFile, readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  type Marketplace,
  type PluginManifest,
  type PluginPkg,
  planMarketplace,
  planPluginManifest,
} from './lib/sync';

const REPO_ROOT = new URL('..', import.meta.url).pathname;
const PLUGINS_DIR = join(REPO_ROOT, 'plugins');
const MARKETPLACE = join(REPO_ROOT, '.claude-plugin', 'marketplace.json');

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, 'utf8')) as T;
}

// Write JSON with a trailing newline so the manifests round-trip cleanly through
// formatters and don't churn the diff.
async function writeJson(path: string, value: unknown): Promise<void> {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
}

async function main() {
  const entries = await readdir(PLUGINS_DIR, { withFileTypes: true });
  const dirs = entries.filter((e) => e.isDirectory()).map((e) => e.name);

  // Collect every plugin's package.json + plugin.json, then build the cross-plugin
  // name map the planner needs to resolve dependency ranges.
  const collected: { path: string; pkg: PluginPkg; manifest: PluginManifest }[] = [];
  const pkgNameToShort = new Map<string, string>();
  const versions = new Map<string, string>();

  for (const dir of dirs) {
    const pkg = await readJson<Record<string, unknown>>(join(PLUGINS_DIR, dir, 'package.json')).catch(
      () => null,
    );
    if (!pkg || typeof pkg.version !== 'string' || typeof pkg.name !== 'string') continue;

    const path = join(PLUGINS_DIR, dir, '.claude-plugin', 'plugin.json');
    const manifest = await readJson<PluginManifest>(path).catch((err) => {
      throw new Error(
        `${path} is missing or unreadable (every plugin needs a .claude-plugin/plugin.json): ` +
          `${err instanceof Error ? err.message : err}`,
      );
    });
    if (typeof manifest.name !== 'string') throw new Error(`${path} has no string "name"`);

    pkgNameToShort.set(pkg.name, manifest.name);
    versions.set(manifest.name, pkg.version);
    collected.push({
      path,
      pkg: {
        shortName: manifest.name,
        pkgName: pkg.name,
        version: pkg.version,
        pkgDependencies: (pkg.dependencies as Record<string, string> | undefined) ?? {},
      },
      manifest,
    });
  }

  for (const { path, pkg, manifest } of collected) {
    const planned = planPluginManifest(pkg, manifest, pkgNameToShort);
    if (planned.changes.length > 0) {
      await writeJson(path, planned.manifest);
      planned.changes.forEach((c) => console.log(c));
    }
  }

  const marketplace = await readJson<Marketplace>(MARKETPLACE);
  const plannedMarketplace = planMarketplace(marketplace, versions);
  if (plannedMarketplace.changes.length > 0) {
    await writeJson(MARKETPLACE, plannedMarketplace.marketplace);
    plannedMarketplace.changes.forEach((c) => console.log(c));
  }

  console.log('sync-plugin-versions: done');
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
