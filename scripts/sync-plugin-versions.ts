#!/usr/bin/env bun

// Propagate each plugin's package.json version (the source of truth changesets
// bumps) into the two manifests the marketplace reads but changesets ignores:
// plugins/<name>/.claude-plugin/plugin.json and .claude-plugin/marketplace.json.
// Run by `ci:version`. Idempotent; exits non-zero on drift so CI catches it.

import { readFile, readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const REPO_ROOT = new URL('..', import.meta.url).pathname;
const PLUGINS_DIR = join(REPO_ROOT, 'plugins');
const MARKETPLACE = join(REPO_ROOT, '.claude-plugin', 'marketplace.json');

type Json = Record<string, unknown>;

async function readJson(path: string): Promise<Json> {
  return JSON.parse(await readFile(path, 'utf8')) as Json;
}

// Write JSON with a trailing newline so the manifests round-trip cleanly through
// formatters and don't churn the diff.
async function writeJson(path: string, value: unknown): Promise<void> {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
}

async function main() {
  const entries = await readdir(PLUGINS_DIR, { withFileTypes: true });
  const dirs = entries.filter((e) => e.isDirectory()).map((e) => e.name);

  // shortName (plugin.json `name`) -> version, collected from package.json.
  const versions = new Map<string, string>();

  for (const dir of dirs) {
    const pkgPath = join(PLUGINS_DIR, dir, 'package.json');
    const pkg = await readJson(pkgPath).catch(() => null);
    if (!pkg || typeof pkg.version !== 'string') continue;
    const version = pkg.version;

    const pluginJsonPath = join(PLUGINS_DIR, dir, '.claude-plugin', 'plugin.json');
    const plugin = await readJson(pluginJsonPath).catch((err) => {
      throw new Error(
        `${pluginJsonPath} is missing or unreadable (every plugin needs a ` +
          `.claude-plugin/plugin.json): ${err instanceof Error ? err.message : err}`,
      );
    });
    const shortName = plugin.name;
    if (typeof shortName !== 'string') {
      throw new Error(`${pluginJsonPath} has no string "name"`);
    }

    if (plugin.version !== version) {
      plugin.version = version;
      await writeJson(pluginJsonPath, plugin);
      console.log(`plugin.json  ${shortName} -> ${version}`);
    }
    versions.set(shortName, version);
  }

  const marketplace = await readJson(MARKETPLACE);
  const plugins = marketplace.plugins;
  if (!Array.isArray(plugins)) {
    throw new Error(`${MARKETPLACE} has no "plugins" array`);
  }

  const marketplaceNames = new Set<string>();
  let changed = false;
  for (const entry of plugins as Json[]) {
    const name = entry.name;
    if (typeof name !== 'string') continue;
    marketplaceNames.add(name);
    const version = versions.get(name);
    if (!version) {
      throw new Error(`marketplace entry "${name}" has no matching plugin package.json`);
    }
    if (entry.version !== version) {
      entry.version = version;
      changed = true;
      console.log(`marketplace   ${name} -> ${version}`);
    }
  }

  // Reverse check: every plugin must appear in the marketplace, or a plugin
  // dropped from marketplace.json would silently pass (drift the other way).
  for (const shortName of versions.keys()) {
    if (!marketplaceNames.has(shortName)) {
      throw new Error(`plugin "${shortName}" has no entry in ${MARKETPLACE}`);
    }
  }

  if (changed) await writeJson(MARKETPLACE, marketplace);

  console.log('sync-plugin-versions: done');
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
