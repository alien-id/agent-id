# @alien-id/agent-id-vault

## 7.1.1

### Patch Changes

- [#40](https://github.com/alien-id/agent-id/pull/40) [`b0f95cd`](https://github.com/alien-id/agent-id/commit/b0f95cd8ec40fd0c2043be9a1608cc2baa0a27a7) Thanks [@truehazker-eti](https://github.com/truehazker-eti)! - Fix stale cross-plugin dependency pins in the marketplace manifests. Each
  `plugin.json` `dependencies[].version` was a bare exact pin (`7.0.0`), which
  Claude Code treats as an exact semver constraint — so an installed `7.1.0`
  failed it (`Requires "agent-id-core" 7.0.0, installed 7.1.0`). `sync-plugin-versions`
  now also propagates the internal dependency range from each `package.json`
  (e.g. `^7.1.0`, maintained by changesets) into `plugin.json`, keeping the
  ranges in lockstep with the versions changesets bumps. The CI drift check
  guards them going forward.
- Updated dependencies [[`b0f95cd`](https://github.com/alien-id/agent-id/commit/b0f95cd8ec40fd0c2043be9a1608cc2baa0a27a7)]:
  - @alien-id/agent-id-core@7.1.1

## 7.1.0

### Minor Changes

- 61c3859: Unified 7.1.0 release. The vault gains a runtime dependency-install hook and minor library refinements, and both packages now ship as `@alien-id` npm modules. The companion marketplace plugins (auth, git, proxy, browser) bump to 7.1.0 in step — headlined by the browser plugin now defaulting to **one shared session**, so a "Sign in with Google" done once carries across sites (`login` is additive; `--name` opts into an isolated session).

### Patch Changes

- Updated dependencies [61c3859]
  - @alien-id/agent-id-core@7.1.0
