# @alien-id/agent-id-core

## 7.5.0

### Minor Changes

- [#146](https://github.com/alien-id/agent-id/pull/146) [`64f8c6c`](https://github.com/alien-id/agent-id/commit/64f8c6c5e4e2c0d2761921db16cad2e62e9a6865) Thanks [@stelchankad](https://github.com/stelchankad)! - Reach the owner from the daemon, and spread a code across every box that asks for one.

## 7.4.0

### Minor Changes

- [#142](https://github.com/alien-id/agent-id/pull/142) [`601be60`](https://github.com/alien-id/agent-id/commit/601be60541dbe3edb4e9cba437a0800b7f273b11) Thanks [@stelchankad](https://github.com/stelchankad)! - Raise the code card from either path, and let a wrong record be corrected.

  A live sign-in on a phone found three ways this fell over, and they share a
  shape: a decision made before anyone had seen the sign-in page, and no way back
  once it turned out wrong.

  **A credential that says the site has no codes now gets corrected instead of
  ending the run.** `otp: "none"` is a claim about the site; the site asking for a
  code is the evidence against it. Auto-login used to return `otp-unexpected` and
  stop — password typed, code mailed, no card to type it into. Both paths that
  reach a code (auto-login and a sign-in driven by hand through `fill-otp`) now
  raise the card, and write the corrected mode back once the owner has supplied a
  code. Not before: `otp-required` is also what a signed-in page inviting the owner
  to switch on two-factor authentication classifies as, and correcting a record
  from that would overwrite an explicit `--otp none` off a page that asked for
  nothing.

  **`fill-otp` passes the same hints auto-login does.** It called `resolveOtp` with
  nothing at all, so a card raised that way carried neither the cell count nor
  where the code went — which is why the code screen kept drawing a plain field.
  The DOM read behind both is now one exported function.

  **A row of code boxes is counted even when it says nothing.** Booking.com renders
  six inputs and constrains them in script, with no `maxlength` anywhere; only
  boxes that declared it were counted, so the site this was built for got no count
  at all. A box now qualifies by taking a code — `one-time-code`, a numeric keypad,
  or a declared single character — and the row it belongs to has to look like one:
  siblings under a container of their own, nothing else in it, uniform shape, and
  either a declared single character or the page's own word that a code was sent.
  Four numeric inputs is a payment form, and a card drawn with four cells for it
  submits on the fourth character with no button to recover.

  **A code spread across a row is typed per box and checked per box.** Counting
  characters could not tell six boxes holding one each from one box holding all
  six, and the whole row is cleared first so a refused code leaves nothing behind
  to splice into the next one.

  **`set-otp` exists.** `set-totp`, `set-recipe`, `set-domains` and `set-access`
  could all fix a stored credential; how it answers a code could not. Re-adding was
  no answer: `vault add` on an existing name is a silent upsert that rebuilds the
  record from that one invocation, so it would have taken the TOTP seed, the recipe
  and the login URL with it — and asked the owner to retype the secret on the way.
  A targeted edit is the whole point.

  **A silent `otp` now means `interactive`, not `none`.** Sites add second factors
  far more often than they drop them, and the two mistakes do not cost the same: a
  card can be dismissed, an abandoned sign-in leaves a password typed and a code
  already sent. This holds wherever the field is read, not only where it is
  written — `add`, validation and `vault list` each used to resolve silence for
  themselves, so a credential the sign-in would raise a card for was reported to
  the agent as having no codes. One consequence worth stating: a stored
  `passwordless` login that never carried an `otp` field now validates, where it
  was previously refused for having neither a password nor a code step.

  **A dismissed card is told from a broken one, on both paths.** Closing the card
  answers 409, which arrived as a bare `HTTP 409` — a fault, and the sensible reply
  to a fault is a retry, so the owner who had just dismissed it got it straight
  back. The dismissal now carries its own code and becomes the `otp-declined`
  outcome. That code is set in `agent-id-core`, which is why it is released here:
  without the bump the browser plugin would resolve a published core that never
  sets it, and the retry loop would be exactly as open as before. The hosted
  provider's timeout gained its code for the same reason — `otp-timeout` was
  unreachable whenever the card came from it.

  **And the read-back guard covers the whole row.** A code spread across six boxes
  was tagged on one of them, leaving five characters readable through
  `get --what value` one at a time. Every box the code is written into is tagged
  now, and tagged before the code goes in.

- [#144](https://github.com/alien-id/agent-id/pull/144) [`ce1e00c`](https://github.com/alien-id/agent-id/commit/ce1e00ca9f85b4cb6e44a1914cf7798350d4e67b) Thanks [@stelchankad](https://github.com/stelchankad)! - Tell a card closed for the browser from a card simply closed.

  A card knows how to be answered and how to be dismissed, and the owner saying
  "not here — I will sign in myself, where I can see it" has nowhere to live
  between them. It arrives as a plain dismissal, so the agent reads a refusal,
  leaves the sign-in alone, and reports it as not done — when what was asked for
  was the browser.

  The host now says how a card was closed, and a dismissal carrying `use_browser`
  becomes its own outcome: `owner-will-drive`, escalating to the viewport the owner
  just asked for, with a message that says in as many words they did not refuse.

  Everything without a reason behaves exactly as before, which is what every client
  that has not been taught the button keeps sending.

## 7.3.1

### Patch Changes

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
