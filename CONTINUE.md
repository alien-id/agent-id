# CONTINUE.md — Browser-driven authenticated access + vault modes

_Last updated: 2026-06-22 · branch: `feat/vault-proxy-mvp`_

> **Superseded.** A historical note, kept for the reasoning that led here.
> The browser is no longer driven in-process with a bundled engine and a
> vault-sealed profile: it is a separate process reached over an RPC port,
> holding its own profile, and this plugin only signs it in. See
> `plugins/agent-id-browser/skills/agent-id-browser/SKILL.md`.

## Where we landed

For authenticated access to sites that block API/OAuth/cookie approaches (notably
**Gmail/Workspace**), the working approach is **driving a real, logged-in browser**
whose session profile is **sealed in the vault**. This replaced the retired
browser-cookie-capture experiments (Chrome's app-bound encryption + Google's
automation-login blocks made those unshippable).

### New plugin: `agent-id-browser`

Universal browser the agent drives, with the logged-in profile sealed in the vault.

- **One-time HEADED login** establishes the session; afterwards the agent drives it
  **HEADLESS** (no window).
- **Fine-grained control** (Playwright-MCP style): `open` a persistent session, then
  `snapshot` (accessibility tree with element `ref`s) → `click` / `type` / `fill` /
  `select` / `press` / `hover` / `scroll` / `navigate` / `back` / `page-text` /
  `screenshot` / `eval` / `wait`, then `close` (reseals). Plus one-shot `read` /
  `fetch`. `status` / `sessions` for introspection.
- **Engine:** patchright (stealth-patched Playwright), **bundled** in the plugin
  (`node_modules/patchright{,-core}`, ~18 MB, no install). Hardened launch: real
  Chrome (`channel:"chrome"`), **renderer sandbox ON** (we strip patchright's
  `--no-sandbox`), `--test-type` (suppresses the banner), `--disable-blink-features=
  AutomationControlled` kept (hides `navigator.webdriver`).
- **Profile sealing:** the profile dir (caches excluded, ~2 MB) is tar'd + AES-256-GCM
  sealed with a per-profile DEK stored in a `browser-profile` vault credential
  (sidecar `<stateDir>/browser-profiles/<name>.tar.enc`). Unsealed to a temp dir only
  while running; resealed on close; DEK redacted from `vault show`.
- **Logout detection:** `read`/`fetch`/navigation return `sessionExpired:true` →
  re-run `login`.
- Files: `plugins/agent-id-browser/{lib/{launch,profile-store,session,session-server,unlock}.mjs,bin/cli.mjs,skills/...}`.

### Vault security modes (`agent-id-vault`)

Two **one-way** modes chosen at `init` (see [[vault-user-vs-dev-mode]] in dev notes):

- **user mode (default)** — no passphrase, ever; agent can't add one; cannot convert
  to dev. Tamper-evident via an HMAC `modeTag` bound to the master key.
- **dev mode** (`--dev`, or a passphrase at init) — passphrase allowed (devs/power
  users), plus all user-mode methods. (Providing a passphrase at init ⇒ dev, so
  existing `init --passphrase-file` scripts keep working.)

Enforcement in `format.mjs` (mode + modeTag + verify) and `vault.mjs`
(`addPassphraseSlot` refuses unless dev; `init` user-mode path; `verifyModeTag` on
unlock). `tests/test-vault-modes.mjs` covers it.

### Vault unlock + the browser plugin

Unlock order: **agent-key (auto)** → **passphrase** (dev only) → **owner-approval**
("approve in the Alien app"; wired into the browser plugin via `lib/unlock.mjs`,
reusing the proxy's owner-approval primitives directly — no control plane needed).
Mobile-slot unlock stays proxy-bound (needs the control-plane server).

## ⚠️ KNOWN LIMITATION (agreed: ship now, tighten later)

**Agent-key auto-unlock currently works in user mode too.** An agent-key slot derives
its KEK from the on-disk agent key, so the agent can self-unlock a user-mode vault
**unattended** — which undercuts user mode's intent ("the owner must approve in the
app"). We shipped as-is to unblock; the **TODO** is to make user mode reject agent-key
*and* passphrase (app-unlock only) and have `init` enroll owner-approval/mobile at
creation. That's SSO-dependent (only `examples/dev-sso.mjs` implements the escrow
today; the production Alien SSO hasn't shipped it), so it's a deliberate follow-up.

## Verification

- **Full suite: 386/386 pass** (`node --test --test-force-exit tests/test-*.mjs`).
- agent-id-browser E2E on example.com: login→seal→headless read/fetch, and
  open→snapshot→click→close (reseal verified). Vault-locked gate + DEK redaction
  tested. patchright login+headless-read against real Gmail proven earlier (the
  plugin wraps that exact flow).
- Owner-approval unlock primitives are e2e-tested against dev-sso; the
  browser-plugin owner-approval path reuses them (full browser-plugin-against-dev-sso
  e2e not yet run — needs an owner session + owner-approval slot).

## Next steps / TODO

- [ ] Tighten user mode: reject agent-key + passphrase; `init` enrolls
      owner-approval/mobile (awaits Alien SSO escrow for production).
- [ ] Full browser-plugin owner-approval unlock e2e against `examples/dev-sso.mjs`.
- [ ] Verify the Atom feed + the "Security alert" anomaly behavior on a real
      **Workspace** account (consumer is proven).
- [ ] Optional: prune patchright's trace-viewer UI (~3.6 MB) to shrink the bundle.
