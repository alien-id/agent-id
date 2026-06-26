// Select the tarball `bun pm pack` produced for a package.
//
// `bun pm pack` writes a deterministic `<scope>-<name>-<version>.tgz` into
// the package cwd, so we require an *exact* filename match. A substring
// fallback (`f.includes(version)`) is dangerous: a stale prerelease tarball
// (`...-2.1.0-beta.1.tgz`) contains the release version as a substring and
// would be uploaded under the wrong version/tag with a provenance
// attestation — silent and irreversible. Demand the exact name instead.

export function selectTarball(
  entries: string[],
  name: string,
  version: string,
): string {
  const expected = `${name.replace('@', '').replace('/', '-')}-${version}.tgz`;
  if (!entries.includes(expected)) {
    throw new Error(`Tarball not found (expected ${expected})`);
  }
  return expected;
}
