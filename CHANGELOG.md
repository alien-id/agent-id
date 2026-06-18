# Changelog

All notable changes are documented here.

## [Unreleased]

### Security

- **Control plane is no longer trusted by loopback alone.** It binds to its own
  `--control-host` (default `127.0.0.1`, decoupled from the data-plane `--host`,
  so `--host 0.0.0.0` no longer exposes it), and the credential-bearing routes
  (`/pending`, `/approve`, `/deny`, `/register`) require a bearer token
  (auto-generated, written to the `0600` proxy state file). `/status` stays open
  for liveness. A co-resident process or LAN host can no longer drive an approval
  or pair a rogue device.
- **SSRF guard on upstream connections.** Link-local (incl. the
  `169.254.169.254` cloud-metadata service), unspecified, and multicast targets
  are always refused (`403 upstream_blocked`); `--block-private-hosts` also
  refuses loopback/RFC1918/ULA/CGNAT. The check runs both synchronously on
  literal-IP hosts and at connect time via a custom DNS `lookup` (closing the
  DNS-rebinding gap), independent of the per-credential allowlist.
- **Wallet signing constraints (optional, default-allow).** `evm-keypair`
  records may pin a `chainIdAllowlist` and a recipient `toAllowlist`;
  `solana-keypair` records may pin a `programAllowlist` (every instruction's
  program id must be listed). The proxy refuses any transaction that violates a
  set constraint before signing. EVM `from` is pinned to the credential address
  when omitted. Set via `generate --chain-id-allowlist / --to-allowlist /
  --program-allowlist`.
- **Decrypted secrets dropped on lock.** Idle-lock now releases the whole
  decrypted credential payload (every bearer/cookie/password and wallet private
  key), not just the master key, so secrets don't linger in the heap past lock.
- **Stub-mode injection sites are pinned.** In legacy stub mode a bearer/basic
  stub is only materialized in `Authorization` and a cookie/cookie-jar stub only
  in `Cookie`; `header`/`query` credentials are pinned to their declared
  name. A stub the agent placed in some other (reflectable) header is refused,
  closing a credential-reflection leak.

### Added

- **Wallet credentials: keys born in the vault, never exported.**
  `agent-id-vault generate --type solana-keypair|evm-keypair` creates the
  keypair *inside* the vault process and prints only the public address.
  Records are sealed (`exportable: false`): `show` redacts the key,
  `add` refuses the type, `list` carries the address. The only way to
  exercise the key is transaction signing inside the proxy, gated by the
  per-credential RPC-host allowlist.
- **Proxy-side transaction signing.** `solana-keypair`: unsigned
  transactions inside `sendTransaction` JSON-RPC bodies are ed25519-signed
  at injection time (legacy + v0 messages, partial multi-sig preserved,
  base58/base64 encodings, batched requests). `evm-keypair`:
  `eth_sendTransaction` is rewritten to a signed EIP-1559
  `eth_sendRawTransaction` (RFC 6979 deterministic ECDSA, low-s,
  cross-validated byte-for-byte against eth-account). All other JSON-RPC
  methods pass through untouched. Access log records `solana_signed` /
  `evm_signed` events with public signatures / tx hashes only.
- **Zero-dependency chain primitives** in `agent-id-core`:
  `lib/solana.mjs` (base58, compact-u16, tx wire format, System Program
  transfer builder) and `lib/evm.mjs` (keccak-256, RLP, secp256k1 with
  public-key recovery parity, EIP-55 checksum addresses).
  Verified end-to-end on Solana and Polygon mainnet — see
  `examples/solana-transfer-via-proxy.mjs`.
- **`agent-id-vault` v5.0.0 — portable LUKS-style vault format.**
  Single file at `~/.agent-id/vault.enc` with a slot-wrapped master key:
  slot 0 = passphrase-wrapped (scrypt), slot 1 = agent-key-wrapped
  (HKDF, fast unattended unlock). Payload AEAD-encrypted with the
  master key. Copy the file to a second machine, type the passphrase,
  you're in.
- **Vault credential schema.** Records carry `type` (bearer / basic /
  header / query / cookie / totp / cookie-jar / oauth2), a `domains`
  allowlist (default-deny — required, no fallback), and timestamps.
- **`oauth2` credential type — refresh-on-demand access tokens.** Stores a
  refresh token + client credentials + token endpoint; the proxy mints
  and caches short-lived access tokens (RFC 6749 §6), refreshing within
  60 s of expiry and injecting them as `Authorization: Bearer …`. A
  rotated refresh token is persisted back to the vault; `invalid_grant`
  surfaces as `401 oauth_refresh_token_invalid`, other failures as `502
  oauth_refresh_failed`. The token endpoint must be `https` (loopback
  allowed). `agent-id-vault add --type oauth2 --token-endpoint … --client-id …
  --client-secret-env … --refresh-token-env … [--scope …]`. URL-rewrite mode
  only. Enables long-lived access to OAuth services (e.g. Gmail) without
  the agent ever seeing a token.
- **New vault subcommands.** `init`, `add`, `show`, `list`, `remove`,
  `rekey add-passphrase | add-agent-key | add-mobile | add-owner-approval |
  remove-slot`, `export`, `import`, `migrate`.
- **Phone- and owner-approval unlock + per-credential consent (control
  plane).** A locked vault re-unlocks on demand without restarting the
  proxy. Two unlock methods: a `mobile` slot (the phone unseals an ECDH
  sealed box and POSTs the master key — the private key never leaves the
  Secure Enclave) and an `owner-approval` slot (a random KEK escrowed with
  the Alien SSO, released only after the owner approves; every call is
  DPoP-bound and access-token-bound, and the KEK is single-use). For an
  owner-approval vault the proxy drives the approval itself — no phone app.
  `--require-consent` adds a per-`(credential, host)` prompt on first use,
  cached for `--grant-ttl`. Enrolled with `rekey add-mobile` /
  `rekey add-owner-approval`.
- **Gmail onboarding without Google Cloud Console.**
  `examples/gmail-cookie-bootstrap.mjs` captures the owner's existing Gmail
  web session (Firefox `cookies.sqlite`, or Chrome over the DevTools
  Protocol) into a `cookie-jar` credential; the agent then reads the
  cookie-authed Atom feed (`mail.google.com/mail/u/0/feed/atom`) through the
  proxy. `examples/gmail-login-bootstrap.mjs` is the durable alternative — a
  one-time PKCE OAuth flow that stores a refresh token. Both hand the secret
  to the vault via a `0600` temp file that is removed on exit (incl. Ctrl-C);
  nothing sensitive is printed.
- **Clean-room demo + consumer skill** (`examples/clean-room-demo/`). A
  drop-in `alien-vault` agent skill: starts the proxy if needed, calls
  `http://<proxy>/<cred>/<host>/<path>`, and walks the phone-approved
  unlock — so a fresh agent can read the owner's Gmail (or any vaulted
  service) without ever seeing a secret. Ships the skill only; never the
  vault file.
- **Trusted-input channel.** `/dev/tty` reader bypasses the agent's
  stdin pipe so credential entry and passphrase prompts never enter
  the agent transcript or prompt cache.
- **`agent-id-proxy` plugin (new) — credential-injecting local HTTP
  proxy.** Two request shapes:
  - **URL-rewrite mode (recommended).** Agent calls
    `http://<proxy>/<credname>/<upstream-host>/<path>`. Proxy resolves
    the credential, validates the host against its allowlist,
    materializes the credential by type (bearer / basic / header /
    query / cookie / cookie-jar / totp), and forwards to the real
    upstream over HTTPS. System CA bundle verifies upstream; no TLS
    interception on our side. Universal across services.
  - **HTTP_PROXY stub-injection mode (legacy).** Agent sets
    `HTTP_PROXY` and writes `AgentVault <name>` markers in headers /
    query params. Works for plain HTTP upstream only.
  Both modes enforce default-deny host allowlists and return structured
  4xx JSON on miss. Metadata-only access log at `~/.agent-id/proxy.log`.
- **`upstreamScheme` credential field.** Optional ("https" default,
  "http" opt-in) — lets internal/legacy services be reached over plain
  HTTP from URL-rewrite mode.
- **Idle auto-lock.** After `--idle-timeout` (default 12h) of no
  traffic the proxy zeroes the master key in memory and refuses
  subsequent requests with `401 vault_locked`. Restart the proxy to
  re-unlock. `--idle-timeout never` disables for unattended agents.

### v1 scope cuts (deferred)

- **TLS interception for HTTP_PROXY mode.** Mode 2 (stub injection)
  works for plain HTTP upstream only. Mode 1 (URL-rewrite) covers
  HTTPS upstream without requiring TLS interception.
- **TLS interception for HTTP_PROXY mode** remains deferred (URL-rewrite
  mode covers HTTPS upstream without it). Consent prompts and in-process
  re-unlock, previously deferred, shipped this cycle (see above).

### Migration

- Existing v4 vaults (`~/.agent-id/vault/*.json`) are migrated by
  `agent-id-vault migrate`. The old directory is renamed to
  `vault.bak/`. Migrated records get the placeholder allowlist
  `["UNCONFIGURED.invalid"]` — the proxy refuses to inject them
  until real domains are attached via `add`.

## [4.0.0] — 2026-05-15

Major release. The monolithic `skills/alien-agent-id/` is replaced by a
marketplace of four focused plugins under `plugins/`: `agent-id-core`,
`agent-id-git`, `agent-id-vault`, and `agent-id-auth`. The wire protocol
(RFC 9449 DPoP + RFC 9068 `at+jwt` + RFC 7800 `cnf.jkt` + v3 commit
attestation bundle) is unchanged; consumers on the verifier side
(`@alien-id/sso-agent-id`, `alien-sso-agent-id`) continue to work
without changes.

### Breaking changes

- **Repository layout.** `skills/alien-agent-id/` is gone. The CLI now
  lives at `plugins/agent-id-core/bin/cli.mjs` (and the per-plugin
  binaries for the other three plugins). `package.json#bin` (`alien-agent-id`)
  is repointed at core, so the global binary still works for the
  bootstrap and lifecycle subcommands.
- **CLI subcommand names.** In the focused per-plugin CLIs the
  `git-` / `vault-` / `auth-header` prefixes are redundant and dropped:
  - `git-commit` → `agent-id-git commit`
  - `git-verify` → `agent-id-git verify`
  - `git-setup` → `agent-id-git setup`
  - `vault-store` / `-get` / `-list` / `-remove` → `agent-id-vault store` / `get` / `list` / `remove`
  - `auth-header` → `agent-id-auth header`
  - `discover-service` → `agent-id-auth discover`
  - `service-support` → `agent-id-auth support`
  - `call`, `capabilities`, `bootstrap`, `init`, `auth`, `bind`,
    `refresh`, `status`, `sign`, `verify`, `export-proof`,
    `setup-owner-session` keep their names (within their owning plugins).
- **Bootstrap no longer auto-runs git-setup.** That coupling crossed
  plugin boundaries; `agent-id-core bootstrap` now stops after `init`
  + `auth` + `bind` and points the user at `agent-id-git setup` for the
  follow-up. Stderr message updated accordingly.
- **Library import paths.** Downstream consumers that imported from
  `skills/alien-agent-id/lib.mjs` should switch to the focused modules:
  `plugins/agent-id-core/lib/{crypto,bundle,state,errors,oidc,signature-engine,cli-runtime}.mjs`,
  plus `plugins/agent-id-auth/lib/manifest.mjs` and
  `plugins/agent-id-vault/lib/vault.mjs`. The `export *` shim in the
  old `lib.mjs` is removed alongside the directory.

### Added

- **`verifyBundle()` universal verifier** (`agent-id-core/lib/bundle.mjs`).
  Takes a v3 bundle (`{ version: 3, id_token, agent_jwk }`) and returns
  the verified facts (`{ jkt, ownerSub, issuer, aud, iat, … }`) or a
  typed `BundleVerifyError`. Transport-specific binding (Agent-ID
  trailers, SSH commit signature, future signed-tool-call attestations)
  layers on top — `agent-id-git verify` is the first consumer.
  Auditors and CI runners only need `agent-id-core`; the verifier is
  pure protocol and does not require a bound local identity.
- **Inter-plugin dependencies.** `agent-id-git`, `agent-id-vault`, and
  `agent-id-auth` declare `agent-id-core` as a `^4.0.0` dependency in
  their `plugin.json`. The Claude Code marketplace auto-resolves these
  on install (v2.1.110+); `claude plugin prune` cleans up orphans.
- **Per-plugin SKILL.md.** Each plugin ships its own focused skill
  that surfaces to Claude Code: `/agent-id-core`, `/agent-id-git`,
  `/agent-id-vault`, `/agent-id-auth`.

### Changed

- **`agent-id-core/lib/cli-runtime.mjs`** centralizes the CLI helpers
  every per-plugin binary needs: argv parsing, output formatting,
  state-dir resolution, the standardized `requireAgentKey` guard, and
  the `runCli({ commands, printHelp })` dispatch loop. No per-plugin
  CLI duplicates these.
- **`agent-id-core/lib/errors.mjs`** consolidates the typed error
  classes (`SubjectMismatchError`, `AuthRevokedError`,
  `BundleFormatError`, `BundleVerifyError`) plus an `errorMessage(err)`
  helper.
- **Marketplace structure.** `.claude-plugin/marketplace.json` lists
  the four plugins under `metadata.pluginRoot: "./plugins"`. Each
  plugin is independently versioned and tag-resolvable using the
  `{plugin-name}--v{version}` convention.

### Migration

The state directory (`~/.agent-id/`), all on-disk formats, the SSO
wire protocol, the v3 commit attestation bundle, and the marketplace
plugin name (`alien-agent-id` is now the meta-marketplace name; the
four focused plugins each have their own `agent-id-<name>` identifier)
are unchanged. Existing bound agents do not need to re-bootstrap.
Scripts that hardcode `node skills/alien-agent-id/cli.mjs <subcommand>`
need to switch to the per-plugin invocation; `node bin/cli.mjs` users
should follow the same break-down.

## [3.1.1] — 2026-05-12

Patch release. Fixes a CLI failure on machines with a custom global SSH signing program (most
commonly 1Password's git integration, which routes `gpg.ssh.program` through `op-ssh-sign`).

### Fixed

- `git-commit` and `git-verify` now pin `gpg.ssh.program=ssh-keygen` inline on the underlying
  `git` invocations. Previously, with `git config --global gpg.ssh.program` set to
  1Password's `op-ssh-sign`, every signed-commit attempt failed with
  `1Password: invalid ssh public key` because op-ssh-sign refuses to sign with keys it doesn't
  manage — and the agent-id key is intentionally not in 1Password. `git-verify` had the
  symmetric failure, since most custom SSH signers don't implement `ssh-keygen -Y verify`.
  The pin is a no-op for users without a custom signer (`ssh-keygen` is git's documented
  default for `gpg.ssh.program`); it only changes behavior when the user has configured a
  custom signer globally, and in that case the override is correct — the agent-id key is the
  agent's, not the user's.

## [3.1.0] — 2026-05-12

Minor release. Manifest v2 with inline operation catalogs, two new CLI subcommands (`call`,
`capabilities`), and a substantial skill rewrite. No breaking changes vs. 3.0.x — v1 manifests
still parse, all prior CLI subcommands behave the same.

### Added

- Service manifest v2: `api.operations[]` carries an inline capability catalog so agents can
  call Alien-aware services without trial-probing endpoints. Each operation is closed-key
  (`{name, description, method, path, auth, title?, inputSchema?, outputSchema?, annotations?}`).
  `inputSchema` / `outputSchema` are constrained to a small JSON Schema subset: root
  `type:"object"`, ≤20 properties, each property a scalar (`string` / `number` / `integer` /
  `boolean` / `array` of scalars). Anything richer belongs in `api.specUrl`. Path placeholders
  (`{id}`) are cross-validated against `inputSchema.properties` — declared-but-unbound
  parameters fail closed.
- `capabilities --url <U>` CLI subcommand: fetches a service manifest and emits LLM-friendly
  markdown listing every operation with a per-operation `Call:` line. Markdown is the only
  surface — the earlier speculative anthropic/openai/mcp output formats were dropped (no
  in-session agent consumes them).
- `call --url <U> [--method M] [--data JSON]` CLI subcommand: one-shot signed request. Builds
  the DPoP proof, fetches, returns the JSON response. Eliminates the two-header / single-use
  `jti` footgun for agents that just want to hit an endpoint with identity attached.
  `auth-header` remains the manual / curl-driven path.
- `renderCapabilities(manifest)` library export for SDK consumers that want the same markdown
  rendering outside the CLI.
- `reference/migrate-to-v3.md`: short migration guide for v2-bound agents whose state
  directory contains a legacy `owner-binding.json`. The v3 verifier rejects pre-cutover
  `id_tokens` because they lack the `cnf.jkt` confirmation claim — the doc covers detection
  (`test -f $STATE_DIR/owner-binding.json` after `status`), the safe `setup-owner-session`
  path that keeps keypair + vault + audit chain, and the timestamped-backup fallback.

### Changed

- SKILL.md rewritten per Anthropic skill best practices: body is 135 lines (was 436);
  detail moved into one level of `reference/*.md` files (bootstrap, services, vault,
  git-commits, state-and-errors). Description is a trigger string under the 1024-char cap.
  Frontmatter `compatibility` field removed (it was a string where the spec wants an object).
- SKILL.md `allowed-tools`: `Bash(node:*)` tightened to `Bash(node *alien-agent-id/cli.mjs:*)`
  so the grant only covers the CLI, not arbitrary `node` invocations. The leading `*` keeps
  the rule working across install locations (workspace, ccs mount, `~/.claude/plugins/...`).
- SKILL.md handles the auto-mode classifier denying a routine `cli.mjs` call: surface the
  full command, name what the subcommand does, and ask before retrying instead of silently
  falling back to plain curl (which 401s — DPoP requires the CLI).
- SKILL.md makes the `bound: false` path start bootstrap immediately. Previously the
  imperative wasn't strong enough to prevent a meta-confirmation prompt before the first
  user-facing question.

### Removed

- `--format` flag on `capabilities`. The provider tool-use JSON formats (anthropic / openai /
  mcp) were speculative — no in-session agent consumes them. `renderCapabilities` stays
  available as a library function for future provider-shaped adapters.

## [3.0.2] — 2026-05-12

Patch release. No runtime behavior change. Documentation cleanup and version-stamp bump.

### Documentation

- Trimmed `docs/` to the two user-facing references: `AGENT-SSO.md` (system overview) and
  `INTEGRATION.md` (service-side integration guide). Removed `MIGRATION-DPOP.md`,
  `RELEASE-NOTES.md`, and `TESTING.md` — none were linked from the top-level navigation and the
  3.0.x release content lives in this file now.
- Rewrote `docs/AGENT-SSO.md` to drop residual v2 "owner binding" prose; the SSO-signed
  `id_token` (with `cnf.jkt`, RFC 7800 §3.1) is the chain attestation in v3.
- Converted ASCII diagrams in `docs/AGENT-SSO.md` and `docs/INTEGRATION.md` to Mermaid.
- Fixed Mermaid parse errors: sequence-diagram messages and flowchart edge labels no longer
  embed `<br/>` (GitHub's Mermaid lexer interprets it as a NEWLINE token mid-arrow). Flowchart
  node labels still use `<br/>` where appropriate.
- Restored the README's original centered-logo HTML header (`<p align="center">` / centered
  `<h1>` / centered tagline) that a prior pass had converted to plain markdown.
- Fact-checked claims against `skills/alien-agent-id/lib.mjs` and `cli.mjs`: corrected the
  `examples/demo-service.mjs` size reference, fixed a stale cross-repo path in `INTEGRATION.md`,
  and aligned the file-layout table in `AGENT-SSO.md` with the actual `skills/alien-agent-id/`
  tree.

## [3.0.1] — 2026-05-12

Patch release. No runtime behavior change.

- Synced plugin and skill manifest versions with `package.json` and the git tag.
  `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, and
  `skills/alien-agent-id/SKILL.md` were still stamped `2.2.0` after the 3.0.0 cutover, which
  would have shown the wrong version in the Claude Code marketplace.
- Dropped internal-only pre-cutover docs from the repo: `COMPLIANCE.md`, `REFACTOR-PLAN.md`,
  `REVIEW-PLAN.md`, `PRD-DPOP-POP.md`, `DEPLOY-DPOP.md`. None of these were linked from
  `README.md` or any user-facing surface; they were planning snapshots for the 3.0 cutover work.
- Added `.DS_Store` to `.gitignore`.
- Added this `CHANGELOG.md`.

## [3.0.0] — 2026-05-11

Breaking. Agent-driven authentication cut over to DPoP-bound tokens (RFC 9449 + RFC 7800).
Pre-3.0 commits stop verifying because their `id_tokens` lack the `cnf.jkt` confirmation claim
the new verifier requires — by design; pre-cutover `id_tokens` are forgery primitives.

### Added

- `cnf.jkt` binding between agent keypair and SSO `id_token`.
- `/.well-known/alien-agent-id.json` service-manifest discovery (v1 schema, hardened fetch,
  same-authority enforcement).
- v3 commit-attestation bundle in `refs/notes/agent-id` — the SSO `id_token` is the chain;
  the agent-self-signed `ownerBinding` envelope is gone.
- Commit trailers `Agent-ID-JKT` and `Agent-ID-Owner` (replace `Agent-ID-Fingerprint` and
  `Agent-ID-Binding`).
- Library exports: `createDPoPProof`, `getUserInfo`, `ed25519PublicKeyToJwk`, service-manifest
  helpers, typed `AuthRevokedError` and `SubjectMismatchError`.

### Changed

- Wire scheme on the service edge is RFC 9449: `Authorization: DPoP <access_token>` plus
  `DPoP: <proof>`. The custom `Authorization: AgentID` envelope is gone.

### Removed

- Library surface: `verifyProofChain`, `ChainError`, `verifyOwnerBindingRecord`,
  `paths.ownerBinding`, `SessionEngine.ownerBinding` / `loadOwnerBinding` / `hasOwnerBinding` /
  `getOwnerBinding`, `decodeProofIdToken`, `createAgentToken`.
- Human "Sign in with Alien" flows are unchanged.

## Earlier versions

See git tags `v2.3.0` and earlier. Pre-3.0 release notes were not maintained in-repo.
