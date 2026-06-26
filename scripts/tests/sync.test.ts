import { describe, expect, test } from 'bun:test';
import { planMarketplace, planPluginManifest, type PluginPkg } from '../lib/sync';

// Two-plugin world: a dependent (vault) that depends on a library (core).
const CORE: PluginPkg = {
  shortName: 'agent-id-core',
  pkgName: '@alien-id/agent-id-core',
  version: '7.1.0',
  pkgDependencies: {},
};
const VAULT: PluginPkg = {
  shortName: 'agent-id-vault',
  pkgName: '@alien-id/agent-id-vault',
  version: '7.1.0',
  pkgDependencies: { '@alien-id/agent-id-core': '^7.1.0' },
};
const PKG_NAME_TO_SHORT = new Map([
  [CORE.pkgName, CORE.shortName],
  [VAULT.pkgName, VAULT.shortName],
]);

describe('planPluginManifest', () => {
  test('propagates the package.json version into the manifest', () => {
    const { manifest } = planPluginManifest(
      CORE,
      { name: 'agent-id-core', version: '7.0.0' },
      PKG_NAME_TO_SHORT,
    );
    expect(manifest.version).toBe('7.1.0');
  });

  test('propagates the internal dependency range from package.json', () => {
    // The bug: a bare "7.0.0" pin is an exact semver constraint, so an
    // installed 7.1.0 fails it. The range must mirror package.json's "^7.1.0".
    const { manifest } = planPluginManifest(
      VAULT,
      {
        name: 'agent-id-vault',
        version: '7.1.0',
        dependencies: [{ name: 'agent-id-core', version: '7.0.0' }],
      },
      PKG_NAME_TO_SHORT,
    );
    expect(manifest.dependencies).toEqual([{ name: 'agent-id-core', version: '^7.1.0' }]);
  });

  test('leaves an already-correct manifest unchanged with no change log', () => {
    const { manifest, changes } = planPluginManifest(
      VAULT,
      {
        name: 'agent-id-vault',
        version: '7.1.0',
        dependencies: [{ name: 'agent-id-core', version: '^7.1.0' }],
      },
      PKG_NAME_TO_SHORT,
    );
    expect(changes).toEqual([]);
    expect(manifest.dependencies).toEqual([{ name: 'agent-id-core', version: '^7.1.0' }]);
  });

  test('throws when plugin.json declares a dependency package.json lacks', () => {
    expect(() =>
      planPluginManifest(
        VAULT,
        {
          name: 'agent-id-vault',
          version: '7.1.0',
          dependencies: [{ name: 'agent-id-core', version: '^7.1.0' }, { name: 'ghost', version: '1.0.0' }],
        },
        PKG_NAME_TO_SHORT,
      ),
    ).toThrow(/ghost/);
  });
});

describe('planMarketplace', () => {
  const versions = new Map([
    ['agent-id-core', '7.1.0'],
    ['agent-id-vault', '7.1.0'],
  ]);

  test('propagates plugin versions into catalog entries', () => {
    const { marketplace, changes } = planMarketplace(
      {
        plugins: [
          { name: 'agent-id-core', version: '7.0.0' },
          { name: 'agent-id-vault', version: '7.1.0' },
        ],
      },
      versions,
    );
    expect(marketplace.plugins.map((p) => p.version)).toEqual(['7.1.0', '7.1.0']);
    expect(changes).toEqual(['marketplace   agent-id-core -> 7.1.0']);
  });

  test('throws when a catalog entry has no matching plugin', () => {
    expect(() =>
      planMarketplace({ plugins: [{ name: 'ghost', version: '1.0.0' }] }, versions),
    ).toThrow(/ghost/);
  });

  test('throws when a plugin is missing from the catalog', () => {
    expect(() =>
      planMarketplace({ plugins: [{ name: 'agent-id-core', version: '7.1.0' }] }, versions),
    ).toThrow(/agent-id-vault/);
  });
});
