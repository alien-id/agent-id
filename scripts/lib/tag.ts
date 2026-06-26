// Map a semver version to an npm dist-tag: stable → `latest`, prereleases →
// the leading prerelease identifier (`-beta.0` → `beta`, `-alpha-202601` → `alpha`).
const SEMVER_RE =
  /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

export function deriveTag(version: string): string {
  const match = SEMVER_RE.exec(version);
  if (!match) throw new Error(`Invalid semver: ${JSON.stringify(version)}`);
  const prerelease = match[4];
  if (!prerelease) return 'latest';
  const identifier = prerelease.split(/[.-]/)[0];
  if (!identifier)
    throw new Error(
      `Empty prerelease identifier in ${JSON.stringify(version)}`,
    );
  return identifier;
}
