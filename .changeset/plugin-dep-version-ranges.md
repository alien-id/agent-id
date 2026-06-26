---
"@alien-id/agent-id-core": patch
"@alien-id/agent-id-vault": patch
---

Fix stale cross-plugin dependency pins in the marketplace manifests. Each
`plugin.json` `dependencies[].version` was a bare exact pin (`7.0.0`), which
Claude Code treats as an exact semver constraint — so an installed `7.1.0`
failed it (`Requires "agent-id-core" 7.0.0, installed 7.1.0`). `sync-plugin-versions`
now also propagates the internal dependency range from each `package.json`
(e.g. `^7.1.0`, maintained by changesets) into `plugin.json`, keeping the
ranges in lockstep with the versions changesets bumps. The CI drift check
guards them going forward.
