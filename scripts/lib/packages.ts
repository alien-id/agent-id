import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';

export type Pkg = {
  name: string;
  version: string;
  dir: string;
  private: boolean;
  deps: string[];
};

// Read every `packages/*/package.json` with a name and version. Manifests that
// are unreadable or lack name/version are skipped (e.g. non-package directories).
export async function readPackages(packagesDir: string): Promise<Pkg[]> {
  const entries = await readdir(packagesDir, { withFileTypes: true });
  const dirs = entries.filter((e) => e.isDirectory()).map((e) => e.name);
  const pkgs: Pkg[] = [];
  for (const dir of dirs) {
    const manifestPath = join(packagesDir, dir, 'package.json');
    const raw = await readFile(manifestPath, 'utf8').catch(() => null);
    if (!raw) continue;
    const m = JSON.parse(raw) as {
      name?: string;
      version?: string;
      private?: boolean;
      dependencies?: Record<string, string>;
    };
    if (!m.name || !m.version) continue;
    pkgs.push({
      name: m.name,
      version: m.version,
      dir,
      private: m.private === true,
      deps: Object.keys(m.dependencies ?? {}),
    });
  }
  return pkgs;
}
