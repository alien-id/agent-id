---
"@alien-id/agent-id-core": minor
"@alien-id/agent-id-vault": minor
---

Add a pluggable secure-entry abstraction so the surface where a human types a
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
