# Releasing

Alien Agent ID uses [changesets](https://github.com/changesets/changesets) in
canonical bot-driven mode. Versions, cascade patches, CHANGELOGs, and git tags
are computed by the tool; the human's role is to declare intent on feature PRs
and approve two gates.

## What is published

Only the two shared libraries go to npm:

| Package | npm | Why |
| --- | --- | --- |
| `@alien-id/agent-id-core` | public | shared crypto / bundle / verifier / OIDC / state |
| `@alien-id/agent-id-vault` | public | encrypted credential vault (depends on core) |

The four consuming plugins — `agent-id-auth`, `agent-id-git`,
`agent-id-proxy`, `agent-id-browser` — are **marketplace-only**. They are
`"private": true` and listed under `ignore` in `.changeset/config.json`, so
changesets never versions or publishes them. At runtime each one `npm install`s
`@alien-id/agent-id-core` (+ `-vault`) into its persistent plugin-data dir via a
`SessionStart` hook (`hooks/install-deps.sh`) and symlinks it into the plugin
root so the bare `@alien-id/*` ESM imports resolve. **Core and vault must exist
on npm before those plugins can install** — see Bootstrap below.

## Three manual gates

1. **Feature PR merge.** The developer adds a `.changeset/*.md` file declaring
   which packages bump and how, then a maintainer squash-merges.
2. **Version PR merge.** `changesets/action` (the `version-pr` job) opens or
   updates a `chore: release packages` PR on every push to `main` with pending
   changesets. This job holds only `contents: write` + `pull-requests: write` —
   no `id-token`. `ci:version` runs `changeset version && bun install && bun run
   sync-plugin-versions`, so the Version PR also carries the propagated
   `plugin.json` / `marketplace.json` versions.
3. **`npm-publish` environment approval.** Merging the Version PR triggers the
   `publish` job (the only job with `id-token: write`). A maintainer approves
   and the topological publish loop runs.

## Job gating

A read-only `detect` job runs `scripts/detect-release.ts` to decide what each
push should do from **ground truth**, so nothing reaches the `npm-publish`
environment unless a publish is actually pending:

| Output | Source of truth | Gates |
| --- | --- | --- |
| `hasChangesets` | a `.changeset/*.md` (other than `README.md`) exists | `version-pr` runs only when `true` |
| `shouldPublish` | a publishable `plugins/*` version is **not yet on npm** (`npm view name@version`) | `publish` runs only when `true` |

A transient registry error classifies as `unknown` and **throws** rather than
degrading to a decision, so a network blip can never skip a real publish.

## Adding a changeset

On any branch that touches code shipped to npm (`plugins/agent-id-core/**` or
`plugins/agent-id-vault/**`):

```bash
bun changeset
```

Pick the package(s), the bump type, and a one-line summary. This writes
`.changeset/<id>.md`; commit it with your change.

## Cascade rule

When a package bumps, every internal package that depends on it gets a patch
bump too (`updateInternalDependents: always`).

| Bumping... | Auto-patches |
| --- | --- |
| `@alien-id/agent-id-core` | `@alien-id/agent-id-vault` |
| `@alien-id/agent-id-vault` | (nothing published) |

The four `ignore`d plugins keep their own `version` (changesets never bumps
it), but `changeset version` **does rewrite their dependency range** — e.g. a
core minor turns `"@alien-id/agent-id-core": "^7.0.0"` into `"^7.1.0"` in each
plugin's `package.json`. So a Version PR carries package.json diffs for the
ignored plugins too. That is intended: the runtime `install-deps.sh` hook copies
the plugin's `package.json`, so the bumped range is what the marketplace install
pulls. (The `dependencies[].version` field in each `plugin.json` is separate
display metadata that `sync-plugin-versions` does not touch.)

## Version propagation

`changeset version` only edits `plugins/*/package.json`. `sync-plugin-versions`
(run inside `ci:version`) copies each plugin's `package.json` version into:

- `plugins/<name>/.claude-plugin/plugin.json` → `version`
- `.claude-plugin/marketplace.json` → the matching `plugins[].version`

`package.json` is the single source of truth; CI fails if the manifests drift.

## Topological publish

`scripts/publish-topological.ts` derives publish order from
`plugins/*/package.json` deps (core → vault), packs each with `bun pm pack`,
and uploads with `npm publish <tgz> --provenance` (OIDC trusted publishing, no
`NPM_TOKEN`). It is idempotent: already-published versions are skipped via
`npm view`, so a half-finished run resumes cleanly on **Re-run failed jobs**.
Tagging is left to `changeset tag` (run after the loop in `ci:publish`).

Internal deps are plain `^semver` (not `workspace:*`), so no specifier
substitution is needed — the published tarball carries `"@alien-id/agent-id-core":
"^7.0.0"`, letting the marketplace plugins float onto compatible patches.

### Why not `bun publish` or `changeset publish`?

`bun publish` lacks `--provenance` (no sigstore attestation). Packing with bun
and uploading with the npm CLI gives us provenance while keeping bun as the
single workspace toolchain.

## Bootstrap (one-time, manual)

The first-ever publish is a chicken-and-egg: the dependent plugins can't install
until core/vault are on npm. Publish them once by hand (OIDC or a local npm
login), in order:

```bash
cd plugins/agent-id-core  && bun pm pack && npm publish ./*.tgz --access public --provenance
cd ../agent-id-vault      && bun pm pack && npm publish ./*.tgz --access public --provenance
```

After that, the changesets pipeline owns all subsequent releases.

## Security posture

- All third-party actions are **SHA-pinned**.
- `version-pr` and `publish` are **separate jobs**; only `publish` holds
  `id-token: write`.
- `oven-sh/setup-bun` runs `no-cache: true` on the OIDC-holding jobs.
- **No long-lived `NPM_TOKEN`** — OIDC trusted publishing with sigstore
  provenance; `NPM_TOKEN: ''` is set explicitly to defeat any fallback.
- `harden-runner` egress is blocked outside an explicit allowlist.
- `persist-credentials: false` on checkout.
- `environment: npm-publish` reviewer gate lives only on `publish`.

## Manual operator tasks (one-time)

1. Configure npm **trusted publishers** for `@alien-id/agent-id-core` and
   `@alien-id/agent-id-vault` to authorize `.github/workflows/release.yml`
   (the `publish` job). Without this, OIDC publish fails `EUNAUTHORIZED`.
2. Create the **`npm-publish` GitHub Environment** with the maintainer set as
   required reviewers.
3. Do the one-time **Bootstrap** publish above so the marketplace plugins can
   install.

## Troubleshooting

- **"no changesets found" but I changed code** — run `bun changeset`, commit
  the `.md`, push.
- **`npm publish` fails `EUNAUTHORIZED`** — the npm trusted-publisher config
  isn't authorizing `release.yml`. Check the package's npm settings.
- **Marketplace install fails with `ERR_MODULE_NOT_FOUND`** — core/vault aren't
  on npm yet, or the `SessionStart` install hook hasn't run. The next session
  retries the install automatically.
