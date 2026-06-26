---
name: release
description: Drive the changesets-based release flow for the agent-id npm packages. Use when the user wants to release packages, cut a version, declare a release intent, enter or exit a beta cycle, or check what's pending for the next release.
disable-model-invocation: false
user-invocable: true
---

# Release

Only two packages publish to npm: `@alien-id/agent-id-core` and
`@alien-id/agent-id-vault`. The four consuming plugins (`agent-id-auth`,
`agent-id-git`, `agent-id-proxy`, `agent-id-browser`) are `private` and
`ignore`d by changesets — they ship through the Claude Code marketplace, not npm.

The pipeline is fully automated by changesets. A maintainer's only manual gates
are: write a `.changeset/*.md` on the feature PR, merge the bot-opened
"chore: release packages" Version PR, and approve the `npm-publish` environment.

See `RELEASING.md` for the full mental model. This skill drives the
conversational shape of the flow.

## Decision tree

When invoked, first run `bun changeset status --verbose` and figure out which
branch applies:

1. **Feature PR in progress.** If the change touches `plugins/agent-id-core/**`
   or `plugins/agent-id-vault/**`, help the user declare a release intent with
   `bun changeset` and commit the resulting `.changeset/*.md` alongside the code.
   Stop after that. (Changes to only the private plugins need no changeset.)

2. **Pending changesets on `main`, no Version PR yet.** `changesets/action`
   opens it on the next push to `main`. If they just merged, wait ~30s then point
   them at the PR list.

3. **Version PR open.** Read it (it lists computed bumps + cascade + the synced
   `plugin.json`/`marketplace.json` versions). If ready: review → squash-merge →
   approve the `npm-publish` environment → watch the workflow. Surface the
   GitHub Actions URL.

4. **Beta cycle decision.** If `.changeset/pre.json` is absent and the user wants
   a beta cycle, run `bun changeset pre enter beta` and open a one-line PR. If
   `pre.json` exists and they want stable, run `bun changeset pre exit` and open a
   one-line PR.

5. **Partial publish failure.** Re-run the workflow from the GitHub Actions UI.
   `publish-topological.ts` skips already-published packages (via `npm view`) and
   resumes. Do NOT manually edit versions or tags.

6. **First-ever publish (bootstrap).** `@alien-id/agent-id-core@7.0.0` and
   `@alien-id/agent-id-vault@7.0.0` must exist on npm before the dependent
   marketplace plugins can install. Either let the gated publish job do it on the
   first merge, or publish manually once (see RELEASING.md → Bootstrap).

## How to add a changeset (verbatim)

```bash
bun changeset
# Interactive: pick core and/or vault, bump type (patch/minor/major), summary.
git add .changeset/<id>.md
```

The summary line becomes the per-package CHANGELOG entry. Write it for a
consumer: "Add X", "Fix Y", "Breaking: rename Z."

## Behaviours to surface to the user

- **Cascade is automatic.** Bumping `@alien-id/agent-id-core` patches
  `@alien-id/agent-id-vault` (the only published dependent). The four `ignore`d
  plugins are NOT version-bumped, but `changeset version` DOES rewrite their
  `@alien-id/agent-id-{core,vault}` dependency ranges — so the Version PR carries
  package.json diffs for them too. That is intended (the runtime install hook
  copies each plugin's package.json).
- **Version propagation.** `ci:version` runs `changeset version && bun install &&
  bun run sync-plugin-versions`. The sync step copies each plugin's package.json
  version into its `.claude-plugin/plugin.json` and the `marketplace.json` entry.
  `package.json` is the single source of truth; CI fails on drift either way.
- **No build step.** Plugins are plain ESM `.mjs`; `ci:publish` packs and
  publishes raw — there is no compile.
- **Internal deps are `^semver`, not `workspace:*`.** The marketplace installer
  runs `npm`, which can't resolve `workspace:`. bun workspaces still link locally.
- **Trusted publishing, no NPM_TOKEN.** Auth is OIDC + sigstore provenance. An
  `npm publish` auth failure means the trusted-publisher config on npm needs to
  authorize `release.yml` for the failing package — an operator task, not code.
- **Version PR force-pushes on every new changeset**, resetting prior approvals.
  Re-review before merging.

## Hard rules

- NEVER edit `plugins/*/package.json` `version` fields by hand. `changeset
  version` computes them, and `sync-plugin-versions` propagates them.
- NEVER hand-edit `plugin.json` / `marketplace.json` versions — they are derived.
- NEVER edit `bun.lock` manually after `changeset version`; `ci:version`'s
  `bun install` regenerates it.
- NEVER push a tag directly. `changeset tag` (inside `ci:publish`) creates them.
- NEVER bypass the `npm-publish` environment reviewer gate.
