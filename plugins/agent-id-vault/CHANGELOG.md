# @alien-id/agent-id-vault

## 7.2.0

### Minor Changes

- [#43](https://github.com/alien-id/agent-id/pull/43) [`471030f`](https://github.com/alien-id/agent-id/commit/471030fb81df7103ff1b0c847b3ffcfccbd86b4b) Thanks [@atemerev](https://github.com/atemerev)! - Add a direct `login` credential type and a `set-totp` command, so a user can hand
  the vault a service login + password once and have an agent log in later (driven
  by `agent-id-browser auto-login`).

  - **vault**: new `login` type (username, password, `otp: none|totp|interactive`,
    optional `totpSecret`, `loginUrl`, `profile`, `selectors`/`recipe`), kept
    distinct from HTTP `basic`. `domains` is advisory for this type (browser-driven,
    not proxy-injected) and defaults to the `loginUrl` host. `add --type login
--form` captures username/password (and the 2FA seed when `--otp totp`) through
    the secure prompt, so they never enter the agent's transcript.
  - **vault**: new `set-totp --name N [--form]` attaches or updates a 2FA seed on an
    existing `login` (or `totp`) credential — for the common case where 2FA is
    enabled _after_ the login was first stored. It accepts a raw base32 secret or a
    full `otpauth://` URI, entered out-of-band via the secure prompt.
  - **vault**: `add --form` now routes through the secure-prompt resolver, so it
    works where no GUI browser is present (falls back to `/dev/tty` or a hosted
    harness form).
  - **core**: `totp.mjs` gains `validateBase32Secret`, `parseOtpauthUri`, and
    `normalizeTotpInput` (raw secret or `otpauth://` → normalized seed). The
    secure-prompt resolver gains an `AGENT_ID_SECURE_PROMPT=browser|tty|hosted`
    operator override to pin a backend.

- [#43](https://github.com/alien-id/agent-id/pull/43) [`471030f`](https://github.com/alien-id/agent-id/commit/471030fb81df7103ff1b0c847b3ffcfccbd86b4b) Thanks [@atemerev](https://github.com/atemerev)! - Add a pluggable secure-entry abstraction so the surface where a human types a
  secret is no longer hardwired to a loopback browser.

  `@alien-id/agent-id-core/lib/secure-prompt.mjs` introduces a provider interface
  (`isAvailable`/`capabilities`/`collect`) and a `resolveSecurePrompt` /
  `collectSecret` resolver that picks a backend per environment with a
  deterministic fallback chain: `hosted → …extraProviders (e.g. mobile) → browser
→ tty`. Shipped backends: **browser** (wraps the existing one-shot loopback form,
  the guaranteed last resort — it degrades to printing a URL), **tty** (`/dev/tty`
  echo-off prompt), and **hosted** (experimental seam — a unix-domain socket the
  hosting harness owns; TCP/URL endpoints are refused so the agent can't redirect
  the channel). WebAuthn stays browser-only and out of `collect()`.

  Two shared primitives moved into core so non-proxy plugins can reuse them:
  `trusted-input.mjs` (now also exports `notifyTty`) and the RFC 6238
  `totp.mjs`. `@alien-id/agent-id-vault/lib/trusted-input.mjs` is now a
  back-compat re-export of the core module (preserving the
  `TrustedInputUnavailable` class identity); the proxy keeps a matching
  `totp.mjs` re-export. No call sites change behavior.

### Patch Changes

- Updated dependencies [[`471030f`](https://github.com/alien-id/agent-id/commit/471030fb81df7103ff1b0c847b3ffcfccbd86b4b), [`471030f`](https://github.com/alien-id/agent-id/commit/471030fb81df7103ff1b0c847b3ffcfccbd86b4b)]:
  - @alien-id/agent-id-core@7.2.0

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
