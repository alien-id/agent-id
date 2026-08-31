# Alien Agent ID

Universal, verifiable identity for AI agents, optionally linked to a human owner
via Alien Network SSO. Ships as a set of Claude Code marketplace plugins plus two
shared npm libraries.

## Project structure

Monorepo using **Bun workspaces**. Plain ESM `.mjs` — **no TypeScript build** for
the plugins (the only `.ts` is the release tooling under `scripts/`).

```
agent-id/
├── plugins/
│   ├── agent-id-core/     # @alien-id/agent-id-core  (npm, public) — crypto, v3 bundle, verifier, OIDC, state
│   ├── agent-id-vault/    # @alien-id/agent-id-vault (npm, public) — encrypted credential vault (→ core)
│   ├── agent-id-auth/     # marketplace-only (private) — DPoP calls (→ core)
│   ├── agent-id-git/      # marketplace-only (private) — SSH-signed commits (→ core)
│   ├── agent-id-proxy/    # marketplace-only (private) — credential-injecting proxy (→ core, vault)
│   └── agent-id-browser/  # @alien-id/agent-id-browser (npm, public) + marketplace — vault-sealed browser (→ core, vault)
├── .claude-plugin/marketplace.json   # marketplace catalog (versions synced from package.json)
├── scripts/               # changesets release tooling (.ts, run with bun)
├── tests/                 # node --test suite (test-*.mjs)
└── .changeset/            # changesets config + pending release intents
```

### Two distribution layers

- **npm**: `@alien-id/agent-id-core`, `@alien-id/agent-id-vault` and
  `@alien-id/agent-id-browser` are published. `core` and `vault` are the shared
  libraries the other plugins import; `browser` is dual-channel — a marketplace
  plugin **and** an npm package, so external apps can depend on it instead of
  vendoring a tarball. See RELEASING.md.
- **Claude Code marketplace**: all six plugins. `auth`/`git`/`proxy` are
  `private` (never on npm) and consume the libs at runtime.

### This repository is public

Everything here is world-readable, and the three npm packages above carry their
`lib/` to the registry — a comment written for a colleague is published with the
next release. Two rules, both enforced by `bun run ci:hygiene` (CI):

- **Write about this repo only.** No project, repository, or file path from
  another codebase, and no detail of how anything else is deployed. State what
  holds here — "the caller's 16-minute ceiling" — rather than where someone else
  implements it. This applies to commit messages, changesets and PR descriptions
  as much as to comments; a cleanup that explains what it removed puts it back.
- **Our prose is English.** Cyrillic is allowed only as data the product must
  match: the rejection copy in `login-detect.mjs` and the fixtures pinning it.

### Cross-plugin code sharing

Plugins import shared code as **bare specifiers** (`@alien-id/agent-id-core/lib/*.mjs`),
never relative sibling paths. Resolution:

- **Dev**: bun workspaces symlink `@alien-id/*` to the local `plugins/*`.
- **Installed (marketplace)**: a `SessionStart` hook (`plugins/<name>/hooks/install-deps.sh`)
  `npm install`s the libs into `$CLAUDE_PLUGIN_DATA` (persistent) and symlinks
  `node_modules` into the ephemeral `$CLAUDE_PLUGIN_ROOT` so the bare imports
  resolve. This is why core/vault must be published before the other plugins can
  install.

  This is the official Claude Code **"Persistent data directory"** pattern
  (Plugins reference): a `SessionStart` hook that `npm install`s into
  `$CLAUDE_PLUGIN_DATA`. The docs pair it with `NODE_PATH`, but `NODE_PATH` is
  CJS-only and our plugins are ESM (plus one CJS `createRequire` for
  `qrcode.cjs`), so we substitute a regenerated `node_modules` **symlink** — one
  mechanism that resolves both. `$CLAUDE_PLUGIN_ROOT` is treated as ephemeral as
  the docs require: the symlink is a pointer (not persistent state), recreated
  each session, with all real packages in `$CLAUDE_PLUGIN_DATA`, so it survives
  plugin updates and never clobbers a real dev `node_modules`.

Internal deps pin `^semver` (e.g. `^7.0.0`), **not** `workspace:*` — the
marketplace installer uses `npm`, which can't resolve the `workspace:` protocol.

## Development

Use **Bun**.

```bash
bun install            # install + link workspaces
bun run test           # node --test tests/test-*.mjs (the plugin test suite)
bun test scripts/tests # the release-tooling unit tests
```

Per-plugin CLIs run directly in dev (workspace symlinks are in place):

```bash
node plugins/agent-id-core/bin/cli.mjs --help
node plugins/agent-id-vault/bin/cli.mjs --help
```

## Releases

Uses [changesets](https://github.com/changesets/changesets) in canonical
bot-driven mode. See `RELEASING.md` for the full mental model and the
repo-scoped `/release` skill to drive it. The shape:

1. A feature PR touching `plugins/agent-id-core/**` or `plugins/agent-id-vault/**`
   includes a `.changeset/*.md` (add via `bun changeset`). Changes to only the
   private plugins need no changeset.
2. On push to `main`, `changesets/action` opens/updates a `chore: release
   packages` Version PR. `ci:version` runs `changeset version && bun install &&
   bun run sync-plugin-versions`, so the PR also carries the propagated
   `plugin.json` / `marketplace.json` versions.
3. Merging the Version PR triggers the publish path, gated by the `npm-publish`
   environment reviewer.
4. `scripts/publish-topological.ts` walks the published packages dependency-first
   (`core → vault`), packs each with `bun pm pack`, and uploads via `npm publish
   <tgz> --provenance` (OIDC trusted publishing, sigstore attestation, no
   `NPM_TOKEN`). Idempotent via `npm view`; `changeset tag` runs after.
5. `bun pm pack` (not `bun publish`) because `bun publish` lacks `--provenance`.
   There is **no build step** — the plugins are raw `.mjs`.
6. **Version sync**: `scripts/sync-plugin-versions.ts` is the single propagation
   point from each `plugins/*/package.json` version into that plugin's
   `.claude-plugin/plugin.json` and the `marketplace.json` entry. `package.json`
   is the source of truth; CI fails on any drift.

**Bootstrap (one-time):** `@alien-id/agent-id-core@7.0.0` and
`@alien-id/agent-id-vault@7.0.0` must exist on npm before the dependent
marketplace plugins can install. Operator setup: configure npm trusted publishers
for both packages to authorize `release.yml`, and create the `npm-publish`
GitHub Environment with required reviewers.

Pre-release lines: enter/exit via one-line PRs (`bun changeset pre enter beta` /
`bun changeset pre exit`).

## Skills

Local Claude skills for common workflows:

- `/release` — drive the changesets-based release flow (add changeset, manage the
  Version PR, toggle pre mode, recover from partial failures).

The six plugin skills (`agent-id-core`, `-vault`, `-auth`, `-git`, `-proxy`,
`-browser`) live under each `plugins/*/skills/` and are documented in their own
`SKILL.md`.

<!-- skrrt:ship -->
## Git workflow — skrrt skills

Use the installed skrrt skills for all git shipping operations:

- **Commits**: Use `/commit` to stage changes and write conventional commits with gitmojis.
- **Pull requests**: Use `/pr` to push branches and open PRs with the matching forge CLI.
- **Releases**: Releases are automated by `changesets/action`. Use the local
  `/release` skill (repo-scoped) to drive the changesets flow — adding changesets,
  toggling pre mode, and recovering from partial failures. Do NOT use a generic
  release-notes drafting skill here; CHANGELOGs and tags are created by
  `changesets/action` and the publish workflow.

Do not write raw `git commit`, `gh pr create`, or `gh release create` commands
manually when these skills are available.

<!-- skrrt:branching -->
## Branching strategy — GitHub Flow

This project uses **GitHub Flow**. All agents and contributors must follow these rules:

### Branch rules

- `main` is the only long-lived branch and is always deployable.
- All work happens on short-lived, descriptively named branches.
- Never commit directly to `main` — all changes reach `main` through a pull request.
- PRs always target `main`.
- Feature branches must be up to date with `main` before merging.
- Feature branches are deleted after merge.
- CI runs on every PR.
- Releases are cut by `changesets/action` — merging the Version PR triggers
  publish + `git tag` automatically. No human creates or pushes tags.
- Do not create `develop`, `release/*`, or `hotfix/*` branches.

### Branch naming

Use `<type>/<short-description>` with lowercase and hyphens:
- Features: `feat/add-auth`, `feat/search-index`
- Fixes: `fix/login-redirect`, `fix/null-check`
- Other: `docs/api-guide`, `chore/update-deps`, `refactor/auth-module`

### Keeping branches up to date (Skrrt convention)

- Before opening a PR, rebase the feature branch onto `main`: `git pull --rebase origin main`
- If the rebase has conflicts, resolve them and run `git rebase --continue`.
- If the rebase cannot be resolved cleanly, abort with `git rebase --abort` and ask the user for help.

### PR merge strategy (Skrrt convention)

- Use **squash merge** — each PR becomes one clean commit on `main`.
- This keeps `main` history linear: one commit = one PR = one logical change.

### Tagging and environment (Skrrt convention)

This repo ships libraries to npm rather than to deploy environments, so npm
**dist-tags** play the role of staging/production. All tags are created and
pushed by `changesets/action` after a Version PR merges and the `npm-publish`
environment reviewer approves the publish job — no human ever runs `git tag` or
`git push --tags` against `main`.

| npm dist-tag | Trigger | Source version pattern |
| --- | --- | --- |
| (none) | Merge to `main` (no Version PR yet) | n/a |
| `@beta` | Version PR merges while `.changeset/pre.json` is in `beta` mode | `x.y.z-beta.N` |
| `@alpha` | Version PR merges while `.changeset/pre.json` is in `alpha` mode | `x.y.z-alpha.N` |
| `@latest` | Version PR merges while pre mode is exited | `x.y.z` |

Dist-tag derivation lives in `scripts/lib/tag.ts` — no maintainer ever picks the
tag manually. See `RELEASING.md` for the full mental model.

### Agent lifecycle (full auto)

1. Create a branch from `main`: `git switch -c <type>/<description>`
2. If the change touches `plugins/agent-id-core/**` or `plugins/agent-id-vault/**`,
   run `bun changeset` to declare the release intent. Commit the resulting
   `.changeset/*.md`.
3. Commit using `/commit`.
4. Before opening a PR, rebase onto `main`: `git pull --rebase origin main`
5. Push and open a PR using `/pr` — target is always `main`.
6. After squash merge, the branch is deleted automatically by the forge.
7. Releasing is automatic from there: `changesets/action` opens a `chore: release
   packages` Version PR, a maintainer merges it, the `npm-publish` environment
   reviewer approves, and packages publish in topological order. **No manual tag
   creation or pushing.**
<!-- /skrrt:branching -->
