# @alien-id/agent-id-core

## 7.3.0

### Minor Changes

- [#74](https://github.com/alien-id/agent-id/pull/74) [`e66be24`](https://github.com/alien-id/agent-id/commit/e66be24fbf4540763f7e846182c3bcdb8ccd3923) Thanks [@atemerev](https://github.com/atemerev)! - auto-login waits for device-approval prompts instead of failing

  A "tap Yes on your phone" challenge shares body copy with a 2FA step but has no
  input — the sign-in completes when the owner approves on their own device. It was
  classified `otp-required`, so auto-login went looking for a code that never
  appears and stalled until the round budget ran out.

  `classifyLogin` now returns `confirm-on-device` for a push prompt or number-match
  challenge, checked before `otp-required` and only when the page has no code input
  (an SMS step shows both). On that outcome auto-login raises a card through the
  host and polls until the page advances, with its own budget rather than the
  ordinary settle rounds.

  Notices are a new one-way message on the existing secure-prompt socket
  (`agent-id-core/lib/notice.mjs`): the host raises the named event and replies at
  once. Event names are namespaced under `browser.` and the host enforces it, so a
  child cannot forge identity or secure-input lifecycle events. Delivery is best
  effort — with no host configured, `notifyHost` resolves `false` and the login is
  unaffected.

  Device approval is the cheapest challenge to satisfy: unlike a password or a TOTP
  seed it needs no secret stored anywhere.

  ## a failed login says what to DO, not "try headed login"

  Every auto-login failure ended with the same advice: sign in yourself with headed
  `login`. On a host with no display that is a dead end — headed login refuses
  without a GUI session and points back at auto-login. The two pointed at each
  other, so the agent bounced between them, or asked the owner for a password that
  an account created through "Sign in with Google" does not have.

  Failures now carry a machine-readable `action` (`lib/escalation.mjs`), and there
  are only three: `owner_must_drive` (a human has to work the page — bot challenge,
  or an IdP that refuses automation), `owner_must_confirm` (the credential is fine;
  an approval on another device never arrived), and `fix_credential` (the stored
  values are wrong or incomplete). A device-approval timeout in particular no longer
  tells the agent to re-check credentials that were never the problem.

  ## read/fetch no longer answer from a stale profile

  `read` and `fetch` unsealed a _copy_ of the sealed profile even when a session
  was open. A live session's cookies only reach the vault on `close`, so the copy
  was stale: reading a site the session was signed into returned `loggedOut` and a
  redirect to the login page for a session that was working fine. Since that result
  feeds `sessionExpired`, it could raise a "sign in again" prompt for a healthy
  login — the worst kind of false alarm, because it teaches the owner to ignore the
  real one.

  Both now run as session actions when a session is open, falling back to the
  one-shot only when there is none. A session started by an older build reports
  `SESSION_TOO_OLD` naming the `close`/`open` cycle rather than falling back, since
  falling back would reintroduce exactly the stale read.

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

## 7.1.0

### Minor Changes

- 61c3859: Unified 7.1.0 release. The vault gains a runtime dependency-install hook and minor library refinements, and both packages now ship as `@alien-id` npm modules. The companion marketplace plugins (auth, git, proxy, browser) bump to 7.1.0 in step — headlined by the browser plugin now defaulting to **one shared session**, so a "Sign in with Google" done once carries across sites (`login` is additive; `--name` opts into an isolated session).
