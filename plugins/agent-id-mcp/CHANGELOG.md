# @alien-id/agent-id-mcp

## 7.3.10

### Patch Changes

- Updated dependencies [[`6ac3fa8`](https://github.com/alien-id/agent-id/commit/6ac3fa8ff80d2ccc1f7110032a4018013c2b21ce)]:
  - @alien-id/agent-id-vault@7.13.0

## 7.3.9

### Patch Changes

- Updated dependencies [[`c0381e2`](https://github.com/alien-id/agent-id/commit/c0381e21056e9b0efefd340ccece3d6d078a42c0)]:
  - @alien-id/agent-id-vault@7.12.0

## 7.3.8

### Patch Changes

- [#160](https://github.com/alien-id/agent-id/pull/160) [`093ad66`](https://github.com/alien-id/agent-id/commit/093ad66622dea34a5eb98ac2f9dbedca83d7c109) Thanks [@stelchankad](https://github.com/stelchankad)! - A payment card the owner can store, typed only into the secure form.

  `card` joins the credential types: four fields (`cardNumber`, `cardExpiry`,
  `cardSecurityCode`, `cardholderName`), validated where they are stored — 12-19
  digits and Luhn on the number, `MMYY` still ahead on the expiry, three or four
  digits on the security code. A number mistyped by one digit is otherwise only
  reported by the merchant, after the owner has approved a payment.

  Every one of the four is in `SECRET_FIELDS`, so a lock wipes all of it and
  `show` redacts all of it. The record is `access: "ro"` rather than
  `exportable: false` — the latter means "generated in-vault, never typed into a
  page", which is the one thing a card exists to do.

  `ro` is a rule and not a default. The access level is what decides whether
  `show` seals the record, and the caller of `vault_add` is the agent, so
  `--access rw` would have left the number, the expiry and the code readable
  through the agent's own channel. A card now refuses any level but `ro`, the
  way it refuses `--domains`.

  The four names are a wire contract, not labels: the secure-input envelope
  carries no field type, so the name a value is sealed under is what picks the
  keyboard and the paired expiry/code row on the phone.

  `add --type card` is form-only. A PAN passed as a flag is a PAN in the process
  table, in `ps` output and in the shell history. It also takes no `--domains`:
  a card carries no allowlist at all, and what says where it may be typed is the
  merchant host on the payment intent the owner approved, which the agent runtime
  enforces.
  The empty list matches no host, so default-deny holds literally here too.

  The form's own sentence says the card asks for approval on every payment. It
  drops the `ro` line that a login card carries — "the agent can read this" is
  the opposite of the promise being made to somebody typing a card number.

  `read-card --name N` is the one path that hands the four values over, for the
  process that types them into a checkout — `show` keeps sealing a card, so the
  values are not what an agent gets back when it asks what it has stored. The
  command is not a privilege boundary (the vault opens with the agent key, and
  anything that can run it can import the library); it is a named, greppable path
  in place of a flag on `show`. What guards a card is the owner's per-payment
  approval, enforced by the caller that spends it.

  Only the security code is masked as it is typed. `secret` on a form field
  decides masking and nothing else — `SECRET_FIELDS` is what makes a value a
  secret in storage, and it covers all four — so masking the number bought
  nothing and cost the owner the ability to check it against the card in their
  hand. The expiry is labelled `MM/YY`, the way a card face writes it, and the
  separators that invites are stripped on the way in: the stored form is bare
  digits, which is what the validators and the fill expect.

- Updated dependencies [[`058bcf5`](https://github.com/alien-id/agent-id/commit/058bcf52120c8f93cc5d34aad657a793816b38d6), [`093ad66`](https://github.com/alien-id/agent-id/commit/093ad66622dea34a5eb98ac2f9dbedca83d7c109)]:
  - @alien-id/agent-id-vault@7.11.0

## 7.3.7

### Patch Changes

- Updated dependencies [[`2bd9cc4`](https://github.com/alien-id/agent-id/commit/2bd9cc44ca52dc5025344b04905adf0ba2d70d98), [`5225e57`](https://github.com/alien-id/agent-id/commit/5225e573fbcfc68cc554f43a944cf32f08f48cd5)]:
  - @alien-id/agent-id-vault@7.10.0

## 7.3.6

### Patch Changes

- Updated dependencies [[`827dc5e`](https://github.com/alien-id/agent-id/commit/827dc5eed8ce6189e437313af32f71679d1c8ff8), [`0f5ea1f`](https://github.com/alien-id/agent-id/commit/0f5ea1f7821eacd765c0d4b6a6f70aea968b9a0c), [`0f5ea1f`](https://github.com/alien-id/agent-id/commit/0f5ea1f7821eacd765c0d4b6a6f70aea968b9a0c)]:
  - @alien-id/agent-id-vault@7.9.0
  - @alien-id/agent-id-core@7.7.0

## 7.3.5

### Patch Changes

- Updated dependencies [[`9aa1a4f`](https://github.com/alien-id/agent-id/commit/9aa1a4f2a8d7ea4143cda33324d20b068e74aaa9), [`cd0f741`](https://github.com/alien-id/agent-id/commit/cd0f74180768077d3be79c129776e2320514c517), [`6e893dc`](https://github.com/alien-id/agent-id/commit/6e893dc44c2b0054c129319144673fa5f268868c)]:
  - @alien-id/agent-id-vault@7.8.0
  - @alien-id/agent-id-core@7.6.0

## 7.3.4

### Patch Changes

- Updated dependencies [[`64f8c6c`](https://github.com/alien-id/agent-id/commit/64f8c6c5e4e2c0d2761921db16cad2e62e9a6865)]:
  - @alien-id/agent-id-core@7.5.0
  - @alien-id/agent-id-vault@7.7.1

## 7.3.3

### Patch Changes

- Updated dependencies [[`601be60`](https://github.com/alien-id/agent-id/commit/601be60541dbe3edb4e9cba437a0800b7f273b11), [`ce1e00c`](https://github.com/alien-id/agent-id/commit/ce1e00ca9f85b4cb6e44a1914cf7798350d4e67b)]:
  - @alien-id/agent-id-vault@7.7.0
  - @alien-id/agent-id-core@7.4.0

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
