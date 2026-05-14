#!/usr/bin/env node
// Sync bin/ and docs/reference/ into each skill's scripts/ and references/.
// Each skill is self-contained — `npx skills add` clients receive the full bundle.

import { cp, readdir, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const binDir = join(repoRoot, "bin");
const docsRefDir = join(repoRoot, "docs", "reference");
const skillsDir = join(repoRoot, "skills");

async function syncSkill(skillDir) {
  const scriptsDest = join(skillDir, "scripts");
  const referencesDest = join(skillDir, "references");

  await rm(scriptsDest, { recursive: true, force: true });
  await rm(referencesDest, { recursive: true, force: true });

  await cp(binDir, scriptsDest, { recursive: true });
  await cp(docsRefDir, referencesDest, { recursive: true });
}

async function main() {
  const entries = await readdir(skillsDir, { withFileTypes: true });
  const skills = entries
    .filter((e) => e.isDirectory() && e.name.startsWith("alien-id-"))
    .map((e) => e.name);

  for (const name of skills) {
    await syncSkill(join(skillsDir, name));
    console.log(`✓ ${name}`);
  }
  console.log(`Done — ${skills.length} skills synced.`);
}

await main();
