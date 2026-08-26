---
"@alien-id/agent-id-core": patch
"@alien-id/agent-id-vault": minor
"@alien-id/agent-id-browser": minor
"@alien-id/agent-id-mcp": minor
---

Support sites that have no password, and gate auto-login recipes on the credential's domain allowlist.

A `login` credential required both a username and a password, so a site that
signs you in with an identifier plus a code sent by mail or SMS could not be
expressed. Because the secure-input card is derived from the credential type,
every such sign-in reached the owner as a two-field login/password form that
could not be filled truthfully.

- `login` gains `passwordless`, a separate axis from `otp` so that "a password
  AND an e-mailed code" stays expressible. A passwordless login must carry
  `otp=interactive` or `otp=totp`, and its `--form` card renders a single
  identifier field; the code is collected at sign-in time instead.
- `recipe` became writable (`vault add --recipe`, and a new `vault set-recipe`).
  It was validated in the store and read by auto-login while nothing could set
  it. The step vocabulary is now checked on write rather than throwing mid-login.
- **Security:** `runRecipe` navigated anywhere and substituted `{password}` /
  `{otp}` into any selector with no host check. Now every navigation target, and
  the live origin of every step that resolves a secret, is checked against the
  credential's `domains` — the same gate `fill-secret` / `fill-otp` already
  apply. `runRecipe`'s `domains` option is required, so the check cannot be
  omitted by a caller.
- `login` no longer falls back to `domains: ["*"]`. `"*"` is a not-applicable
  placeholder that matches no host, so that default minted credentials which
  could never be typed anywhere.
- The e-mail-first screen of a passwordless flow no longer classifies as
  `logged-in`, which had been sealing unauthenticated profiles while reporting
  success.
- `vault list` reports a login's non-secret shape (`otp`, `passwordless`,
  `loginUrl`, `hasRecipe`).
- The secure form quotes the caller's real `timeoutMs` to the human instead of a
  hardcoded "5 min" — the sign-in card's window is 10 minutes, and that line is
  what a person reads to decide whether they can go fetch a mailed code.
- The classifier generalises past one site's markup: a phone-first opening screen
  (Airbnb, Uber, Telegram) is recognised as an identifier step, the code-copy
  vocabulary covers spelled-out digit counts and login / confirmation / access
  code wording, and a mailed sign-in LINK gets its own `magic-link` outcome that
  escalates to the owner instead of being reported as success.
- A QR sign-in (Telegram Web, WhatsApp Web, Discord) gets its own `qr-sign-in`
  outcome. A screen whose only affordance is a code to scan has no form left, so
  it read as a finished login; and since the code is drawn inside a browser the
  owner cannot see, it escalates to the browser view rather than a card.
- A typed code is now actually submitted. Enter alone only works where the form
  has a submit button or a single field — a code screen built from six
  one-character boxes has neither, so the code sat there, typed and unsent, until
  auto-login ran out of rounds. A submit control is found by its visible text,
  excluding the ones that discard the code ("resend", "use another method").
- "logged-in" is never believed on the first look: a heavy SPA a second into
  loading has no form, no code and no error, which is indistinguishable from
  success.

