#!/usr/bin/env bun

// Decide what a push to `main` should do, from ground truth: changeset files
// gate the Version PR, npm registry state gates the publish. Writes booleans to
// $GITHUB_OUTPUT (`hasChangesets`, `shouldPublish`) consumed by release.yml.

import { appendFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { hasPendingChangesets, needsPublish } from './lib/detect';
import { runNpmView } from './lib/npm-view';
import { readPackages } from './lib/packages';

const REPO_ROOT = new URL('..', import.meta.url).pathname;

async function changesetEntries(): Promise<string[]> {
  // Only a missing `.changeset` directory means "no changesets"; any other
  // read failure must abort rather than silently skip the Version PR.
  try {
    return await readdir(join(REPO_ROOT, '.changeset'));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw err;
  }
}

async function main() {
  const hasChangesets = hasPendingChangesets(await changesetEntries());

  const pkgs = await readPackages(join(REPO_ROOT, 'plugins'));
  const publishable = pkgs.filter((p) => !p.private);
  const shouldPublish = needsPublish(publishable, runNpmView);

  console.log(`hasChangesets=${hasChangesets} shouldPublish=${shouldPublish}`);

  const out = process.env.GITHUB_OUTPUT;
  if (out) {
    await appendFile(
      out,
      `hasChangesets=${hasChangesets}\nshouldPublish=${shouldPublish}\n`,
    );
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
