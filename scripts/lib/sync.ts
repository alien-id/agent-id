// Pure planning core for `sync-plugin-versions`. Given parsed manifests (no
// I/O), compute what each plugin's `.claude-plugin/plugin.json` and the
// marketplace catalog SHOULD contain, plus a human-readable change log. The
// entry script is a thin shell that reads files, calls these, and writes back.

export type PluginPkg = {
  shortName: string; // plugin.json "name"
  pkgName: string; // package.json "name"
  version: string; // package.json "version"
  pkgDependencies: Record<string, string>; // package.json "dependencies"
};

export type PluginManifest = {
  name: string;
  version?: string;
  dependencies?: { name: string; version: string }[];
  [k: string]: unknown;
};

// Compute the desired plugin.json: its own version (from package.json) and each
// cross-plugin dependency's range (the depended plugin's package.json range,
// mapped from npm name to plugin shortName via `pkgNameToShort`). Returns a new
// manifest and the changes applied. Throws when the manifest declares a
// dependency that package.json doesn't — that range can't be resolved.
export function planPluginManifest(
  pkg: PluginPkg,
  manifest: PluginManifest,
  pkgNameToShort: Map<string, string>,
): { manifest: PluginManifest; changes: string[] } {
  const next: PluginManifest = { ...manifest };
  const changes: string[] = [];

  if (next.version !== pkg.version) {
    next.version = pkg.version;
    changes.push(`plugin.json  ${pkg.shortName} -> ${pkg.version}`);
  }

  // Internal dependency shortName -> range, resolved from package.json deps.
  const rangeByShort = new Map<string, string>();
  for (const [depPkgName, range] of Object.entries(pkg.pkgDependencies)) {
    const depShort = pkgNameToShort.get(depPkgName);
    if (depShort) rangeByShort.set(depShort, range);
  }

  if (Array.isArray(next.dependencies)) {
    next.dependencies = next.dependencies.map((dep) => {
      const range = rangeByShort.get(dep.name);
      if (!range) {
        throw new Error(
          `${pkg.shortName} plugin.json declares dependency "${dep.name}" with no ` +
            `matching entry in package.json "dependencies"`,
        );
      }
      if (dep.version !== range) {
        changes.push(`plugin.json  ${pkg.shortName} dep ${dep.name} -> ${range}`);
      }
      return { ...dep, version: range };
    });
  }

  return { manifest: next, changes };
}

export type Marketplace = {
  plugins: { name: string; version?: string }[];
  [k: string]: unknown;
};

// Propagate each plugin's version into its marketplace catalog entry. Pure.
// Throws on drift either way: a catalog entry with no matching plugin, or a
// plugin absent from the catalog (which would otherwise silently ship stale).
export function planMarketplace(
  marketplace: Marketplace,
  versions: Map<string, string>,
): { marketplace: Marketplace; changes: string[] } {
  const changes: string[] = [];
  const seen = new Set<string>();

  const plugins = marketplace.plugins.map((entry) => {
    seen.add(entry.name);
    const version = versions.get(entry.name);
    if (!version) {
      throw new Error(`marketplace entry "${entry.name}" has no matching plugin package.json`);
    }
    if (entry.version !== version) {
      changes.push(`marketplace   ${entry.name} -> ${version}`);
    }
    return { ...entry, version };
  });

  for (const shortName of versions.keys()) {
    if (!seen.has(shortName)) {
      throw new Error(`plugin "${shortName}" has no entry in the marketplace catalog`);
    }
  }

  return { marketplace: { ...marketplace, plugins }, changes };
}
