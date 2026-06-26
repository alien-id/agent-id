# Security

## Reporting a vulnerability

[Email us](mailto:security@alien.org) with details. Do not open a public issue.

## What we do

We publish two npm packages — `@alien-id/agent-id-core` and
`@alien-id/agent-id-vault` — and ship four more plugins through the Claude Code
marketplace (`agent-id-auth`, `-git`, `-proxy`, `-browser`). The marketplace
plugins `npm install` the two published libraries at runtime, so a supply-chain
compromise of either lib reaches every consumer. We harden in layers; each layer
assumes the layers below it have failed.

### Layer 1 — Accounts

- **WebAuthn / passkey 2FA only** on every npmjs and GitHub account that can
  publish. TOTP is disabled at the org level (real-time-phishable).
- **OIDC trusted publishing** is configured per package on npmjs.com → no
  long-lived `NPM_TOKEN` exists in repo secrets.

### Layer 2 — Lockfile & resolution

- `bunfig.toml` enforces:
  - `minimumReleaseAge = 259200` — 3-day cooldown. Every 2025-2026 worm was
    detected within 30 minutes; a 3-day gate is a near-complete consumer shield.
  - `exact = true` — newly added third-party deps land pinned, no `^`/`~` float.
    (Internal `@alien-id/*` deps intentionally keep `^` ranges so the marketplace
    plugins float onto compatible core/vault patches.)
  - registry pinned to `https://registry.npmjs.org/` (incl. the `@alien-id` scope).
- `.npmrc` mirrors this for the `npm publish` path and the runtime install hook:
  `ignore-scripts=true`, `min-release-age=3`, `audit-signatures=true`,
  `save-exact=true`, `engine-strict=true`.
- `package.json` declares `trustedDependencies: []` — explicit empty allowlist
  for Bun's lifecycle-script gate.
- `bun.lock` is committed; CI runs `bun install --frozen-lockfile`.

### Layer 3 — CI / CD

- Default-deny permissions: every workflow declares `permissions: {}` at the top
  level; each job re-grants only what it needs.
- **Version PR creation and publish are separate jobs.** `release.yml` splits
  into a `version-pr` job (holds only `contents: write` + `pull-requests: write`,
  never gated) and a `publish` job (holds `id-token: write` for OIDC, gated by the
  `npm-publish` environment reviewer, runs the topological publish loop +
  `changeset tag`). The OIDC token never coexists with version-bumping
  install code that processes contributor-supplied manifests — the TanStack/Astro
  2025 exfiltration class. There is no build step (plugins are raw `.mjs`).
- A read-only `detect` job decides what each push should do from ground truth
  (changeset files for the Version PR, registry state for the publish), so
  nothing reaches the publish gate without a pending release.
- **`step-security/harden-runner`** on every job. `block` mode on the `detect`
  and `publish` release jobs (publish is the only one holding `id-token`), with
  allowlists limited to npmjs, sigstore (publish only), and github.com. `audit`
  mode on CI and on the `version-pr` job — it holds no OIDC token, and block
  mode severs the GitHub GraphQL call `@changesets/changelog-github` makes
  during `changeset version` ("Premature close").
- **GitHub Environment `npm-publish`** gates only the publish job — required
  reviewers configured in repo settings. The Version PR is created without
  environment gating so reviewers see the proposed bumps first.
- **Every third-party Action is pinned to a commit SHA**, with the version in a
  trailing comment. Renovate keeps SHAs current via `config:best-practices`.
- Workflows do **not** use `pull_request_target` and do **not**
  shell-interpolate `${{ github.event.* }}`.
- Monthly cache purge (`purge-cache.yml`) — defends against poisoned cache reuse.

### Layer 4 — Dependency hygiene

- **Renovate** (`renovate.json`) enforces a uniform 3-day cooldown for all
  dependency types, matching the install-time enforcement in `bunfig.toml` and
  `.npmrc`. Vulnerability alerts bypass cooldown.
- SHA-pinned `github-actions` updates via `config:best-practices` — any Action
  bump is a digest change visible in the PR diff.
- `rangeStrategy: pin` — Renovate writes exact versions for devDependencies;
  `plugins/**/package.json` runtime deps keep ranges so consumers can dedupe.

## Consumer guidance

If you depend on `@alien-id/*` packages, adopt the same defaults — at minimum a
3-day cooldown on npm installs and frozen lockfiles in CI. Our manifests use
exact-version pins for devDependencies to make this easier.

## Incident response

If we suspect one of our published packages is compromised:

1. Revoke every npm token and GitHub PAT touching the affected scope.
2. Disable the OIDC trusted publisher binding in npmjs settings.
3. `npm deprecate '@alien-id/<pkg>@<bad>' "Compromised — do not use"`. If within
   the 72h window, also `npm unpublish`.
4. Cut a clean patch release that supersedes the bad version, signed via a
   freshly re-bound OIDC publisher.
5. Publish a GitHub Security Advisory with IoCs.
6. Post-mortem: which layer failed, which held, what changes.
