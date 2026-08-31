# @alien-id/agent-id-vault

## 7.6.0

### Minor Changes

- [#136](https://github.com/alien-id/agent-id/pull/136) [`9402bf9`](https://github.com/alien-id/agent-id/commit/9402bf9b0bda3ac402df7fe4c8a5b93b991c7207) Thanks [@stelchankad](https://github.com/stelchankad)! - Say what a sign-in page asks for, and write the card for the person reading it.

  Both halves are corrections to the previous release, which shipped and did not
  work.

  **`form-inspect`'s output shape changed**, which is why the browser package takes a
  major: a control the page has staged now arrives under `staged` instead of among
  `controls`, and a sign-in page answers with `signIn`. The desktop host reads this contract in
  its `vault_add` description, so the two move together.

  **The staged password came back as a flag, and the flag was read straight past.**
  `form-inspect` was reporting a control the page had taken out of the
  accessibility tree with `hidden: true` rather than leaving it out. An agent
  inspecting Booking.com's e-mail screen saw a password control, said as much —
  "I saw a technical password field in the markup" — and stored a credential the
  site has no use for. It moves to `staged` — not left among the fields on offer, and not dropped either.
  Dropping was tried and was worse: "the page is asking for something else" is
  satisfied by ANY live input anywhere, so a cookie banner carrying a checkbox took a
  whole sign-in form out of reach with no ref left to recover it.

  And the conclusion is stated rather than implied. On a page with an identifier
  field and a submit beside it, `form-inspect` now answers with
  `signIn: { identifier, passwordAsked }`. The submit is what keeps a newsletter box
  in a footer from being reported as a site with no password.
  A caller acts on a statement; a flag on one control among ten is something it
  has to interpret, and interpretation is what failed.

  **The card was written for the system, not the owner.** It read "Sign in to
  account.booking.com / Identifier only — the sign-in code is asked for at
  sign-in · login · _.booking.com / Sealed with AES-256-GCM (key via
  HKDF-SHA256)". The type and the domain allowlist are how an agent addresses a
  credential — `_.booking.com` reads to a person as a typo — and the cipher names
  told them nothing they could act on while reading as a warning label on a screen
  meant to reassure.

  The title now says what is being asked and the line below says what it is for:

  ```
  Enter it securely
  Booking.com sign-in. You type it on a sealed screen. The code comes at sign-in.
  I never see it and it isn't saved anywhere
  ```

  The site is named as the owner would name it: a sign-in subdomain is dropped
  from the front (`account.booking.com` → `Booking.com`), and only from the front,
  because working out the registrable domain needs a public-suffix list and
  guessing turns `example.co.uk` into `co.uk`. The access level survives the cut —
  `ro` is a grant being made in the moment of typing.

## 7.5.0

### Minor Changes

- [#133](https://github.com/alien-id/agent-id/pull/133) [`989a4ad`](https://github.com/alien-id/agent-id/commit/989a4ad054ce0045638bb0736daa7376d7369005) Thanks [@stelchankad](https://github.com/stelchankad)! - Name the site on the secure card, and say where the code went.

  Three things a live Airbnb sign-in showed the owner, none of them true or useful.

  - **The card was titled with the credential's name.** The agent had named its
    record `airbnb-passwordless-again`, and that reached the screen verbatim —
    the owner was asked to "Add credential: airbnb-passwordless-again" while
    looking at Airbnb's sign-in page. The name is the vault's key and the agent's
    to choose; the title now names the site instead, taken from `loginUrl` or the
    narrowest literal entry in `domains` (a wildcard names a family of hosts, not
    a site). With nothing to derive a host from, the name is still better than
    nothing. The same swap applies to the code card, which had the same fault.
  - **The identifier field promised a mailbox.** It was labelled
    "Username / email" for every login, while Airbnb's own first screen says
    "Phone number or email". The owner entered an address and waited for a letter
    the site had sent as an SMS. A passwordless login now says "Email or phone
    number"; a password login keeps the old label, where the field really can be a
    username.
  - **The code card never said where the code went.** It read "airbnb.com sent
    you a code", so the channel was left to be guessed. The page has already said
    it — "We sent a code to +1 ••• ••• 4817" — and `codeDestination` reads that
    back. It reads it back only when the captured text is recognisably an address,
    a number, or a named place: naming the wrong channel is worse than naming
    none, because it sends the owner somewhere the code is not and then convinces
    them it never came. Unrecognised, the copy claims no channel and names both
    places to look.
  - **The card never said a second one was coming.** The chat row renders the
    description under the title, and for a passwordless login that line was
    metadata (`login · www.airbnb.com`). Submitting the first card looks like
    nothing happened — the site is off sending a code — so it now leads with "A
    sign-in code follows on the next card". The access level stays on that line:
    `ro` is a grant the owner is making while they type.

## 7.4.0

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

## 7.3.1

### Patch Changes

- Updated dependencies [[`e66be24`](https://github.com/alien-id/agent-id/commit/e66be24fbf4540763f7e846182c3bcdb8ccd3923)]:
  - @alien-id/agent-id-core@7.3.0

## 7.3.0

### Minor Changes

- [#45](https://github.com/alien-id/agent-id/pull/45) [`f58b6fb`](https://github.com/alien-id/agent-id/commit/f58b6fb59c71d65fa2f80ed1277d8d572c5cd5a8) Thanks [@atemerev](https://github.com/atemerev)! - Per-credential access levels: records can carry `access: "ro" | "rw"` (default
  `rw`) plus ordered `accessRules` (`{effect, methods, hosts, path}`), evaluated
  by the new `lib/access.mjs` policy engine. Read-only credentials permit
  GET/HEAD/OPTIONS and POST-tunneled reads (GraphQL query, JMAP get/query,
  JSON-RPC non-submitting calls); `show` redacts and `exec` refuses their secret
  fields. New `set-access` CLI command changes the level — tightening applies
  immediately, widening requires the owner's out-of-band confirmation via the
  secure prompt, and `add`/`generate` refuse to widen an existing record.
  Enforcement happens in agent-id-proxy (structured `403 access_denied`) and
  agent-id-browser (network-layer route gate for sealed sessions).

  Hardening: body classification runs only for POST (a read-shaped body can't
  promote a DELETE/PUT/PATCH); JSON-RPC is default-deny (unrecognized methods are
  not treated as reads); rule reordering counts as a relaxation (owner ceremony);
  rule-restricted `rw` credentials are sealed and their browser sessions block
  service workers and WebSockets (at the network layer via `routeWebSocket`, so a
  Worker-opened socket can't evade it) too; multi-operation GraphQL documents are
  writes if they contain any mutation/subscription. The relaxation check is
  precedence-aware — only an allow rule moving ahead of an overlapping deny needs
  the owner ceremony, so ordinary tightenings still apply immediately. The proxy
  closes the connection on early denials so an unconsumed request body can't
  corrupt the response status.

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
