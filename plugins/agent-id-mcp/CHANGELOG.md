# @alien-id/agent-id-mcp

## 7.3.2

### Patch Changes

- Updated dependencies [[`9402bf9`](https://github.com/alien-id/agent-id/commit/9402bf9b0bda3ac402df7fe4c8a5b93b991c7207)]:
  - @alien-id/agent-id-vault@7.6.0

## 7.3.1

### Patch Changes

- Updated dependencies [[`989a4ad`](https://github.com/alien-id/agent-id/commit/989a4ad054ce0045638bb0736daa7376d7369005)]:
  - @alien-id/agent-id-vault@7.5.0

## 7.3.0

### Minor Changes

- [#129](https://github.com/alien-id/agent-id/pull/129) [`f0417b8`](https://github.com/alien-id/agent-id/commit/f0417b83226c4556f18b18a89f47b66749f73d50) Thanks [@stelchankad](https://github.com/stelchankad)! - Support sites that have no password, and gate auto-login recipes on the credential's domain allowlist.

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
    `{otp}` into any selector with no host check. Now every navigation target is
    checked against the credential's `domains`, and so is the live origin of every
    step that resolves a secret — twice, before and after the value is resolved,
    because resolving `{otp}` awaits the owner for minutes and the page is free to
    navigate in that window. `runRecipe`'s `domains` option is required, so the
    check cannot be omitted by a caller. A step whose value is a literal is not
    gated; nothing secret is at stake in one.
  - `vault set-domains` edits that allowlist on a stored credential. It has to
    exist now that the list is load-bearing: a sign-in only reveals which hosts it
    redirects through once it has been driven, and the alternative was remove +
    re-add, which asks the owner for the secret again.
  - One run answers a code challenge twice at most, then reports `otp-rejected`.
    A code is mistyped or outrun often enough that one shot is the wrong budget;
    the retry card says the previous code was refused, so the owner reads the
    current one instead of retyping. For a stored seed the retry waits out the time
    window first — within one period the seed produces the same digits, so an
    immediate retry resubmits exactly what was just refused. Re-asking a human for
    a code the site has already refused is both useless and unaffordable: the first
    card waits ten minutes and the host kills the process at sixteen.
  - The retry card is sized by where the code comes from. A generated one is read
    off a device the owner is already holding, so its retry is a glance (2 min); a
    mailed one sends them back to the mailbox, and two minutes expired on a live
    sign-in with the owner still fetching it (4 min). Neither can be a second
    full-length card — the host's sixteen-minute ceiling covers the whole run, page
    work included.
  - An unanswered code card is reported as an `otp-timeout` outcome instead of
    throwing. The error used to travel straight out of auto-login, so the caller
    learned nothing about where the browser stopped — and it had stopped somewhere
    useful, on the code screen, where a fresh code still finishes the job. The
    escalation says as much: the credential is fine, and no password is missing.
  - The code field is not masked. Every other value this vault collects is, and for
    a password or a token that is right — it is long-lived, reusable, and the owner
    already knows what they typed. A code is none of those: single-use, dead in
    minutes, and copied by hand out of a mail client, which is exactly the
    transcription whose slips the dots would hide.
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

### Patch Changes

- Updated dependencies [[`f0417b8`](https://github.com/alien-id/agent-id/commit/f0417b83226c4556f18b18a89f47b66749f73d50)]:
  - @alien-id/agent-id-core@7.3.1
  - @alien-id/agent-id-vault@7.4.0

## 7.2.1

### Patch Changes

- Updated dependencies [[`e66be24`](https://github.com/alien-id/agent-id/commit/e66be24fbf4540763f7e846182c3bcdb8ccd3923)]:
  - @alien-id/agent-id-core@7.3.0
  - @alien-id/agent-id-vault@7.3.1
