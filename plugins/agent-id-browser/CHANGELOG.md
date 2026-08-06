# @alien-id/agent-id-browser

## 7.8.0

### Minor Changes

- [#87](https://github.com/alien-id/agent-id/pull/87) [`5ba6ef2`](https://github.com/alien-id/agent-id/commit/5ba6ef274c83fcf9267788153929a5d63150e8eb) Thanks [@atemerev](https://github.com/atemerev)! - An owner can be handed a browser to sign into, and dead sessions stop haunting the viewer

  **A named profile can be created for the owner to sign into.** When a sign-in
  cannot be automated — a bot challenge, an IdP that refuses agents, no display for
  a headed `login` — the answer is to hand the browser to the owner. That was
  impossible for any site not already set up: `login` needs a GUI, `auto-login` had
  just failed, and `open` refuses to auto-create a named profile, so there was
  nowhere to sign in. `open --bootstrap-profile` mints an empty jar for a named
  profile; the owner signs in, and `close` seals it like any other. Without the
  flag a named profile still never auto-creates — the account boundary is
  unchanged, the opt-in is explicit.

  **Orphaned sessions are pruned.** A clean `close` reseals and removes its own
  session file, but an abrupt death (a recreated container, a killed daemon) leaves
  it behind, and the state dir usually outlives the process. Those orphans still
  advertise a `streamPort`, so a viewer picking "the newest session with a stream"
  can dial a dead port and show nothing, and `status` lists sessions that do not
  exist. `open` and `status` now drop session files whose pid is gone.

  **Stale plaintext profile copies are removed too.** `<name>.work` is the
  UNSEALED profile — cookies on disk, outside the vault. A clean close wipes it;
  an abrupt death left it there indefinitely (weeks-old copies were found for
  sessions long gone). Orphaned work dirs are now removed once they are old enough
  that they cannot belong to a launch still in flight.

## 7.7.0

### Minor Changes

- [#82](https://github.com/alien-id/agent-id/pull/82) [`289f2da`](https://github.com/alien-id/agent-id/commit/289f2da98e742f826a32d91c1bfedca5d815af77) Thanks [@atemerev](https://github.com/atemerev)! - Enterprise application forms are drivable: one ref space, real comboboxes, and no silently-dropped refs

  Three defects that together made an SAP/Taleo-shaped careers form unfillable. All
  three were observed on live applications, twice burning an agent's whole tool
  budget with no progress.

  **Refs meant different things in different tools.** `snapshot` and `form-inspect`
  each cleared every `data-aibref` and renumbered from `e1` — but over different
  element sets: snapshot over links/buttons/inputs, form-inspect over form controls
  only. So `e7` was the First Name input after a form-inspect and a toolbar button
  after a snapshot, and nothing detected the difference: a form-fill built from
  form-inspect refs silently drove the wrong elements, and the stale-ref error
  advised re-running two tools that disagreed. Both modes now number over the UNION
  of their selectors in document order, independently of what each reports, so a ref
  denotes the same element either way.

  **Refs are versioned by the observation that minted them.** They now read `3:e7`,
  so a ref held across a re-observation is refused by name instead of resolving
  against whatever currently holds that number. Clearing the attributes per scan is
  not sufficient alone: the next scan re-tags a possibly different element with the
  same `e7`. The check is skipped for unversioned refs and for callers driving
  `fillForm` against a hand-built state, so direct API use keeps working.

  **Comboboxes were driven with `selectOption`.** That only works on a native
  `<select>`; against an `<input role=combobox>` it fails every time with "Element
  is not a `<select>` element", and Oracle/Taleo/Workday/SAP render country and
  nationality pickers exactly that way. `form-fill` and the bare `select` action now
  dispatch on what the element actually is: `selectOption` for a real select, and
  for a combobox a click/type/pick that emits real key events via
  `pressSequentially`, because autocompletes ignore a value set in one shot and
  submit blank. The pick is verified against the control's own value, so a rejected
  choice surfaces as a failure instead of a cheerful `ok:true`.

  **`type-text`/`fill-text` silently discarded a `--ref`.** They type into whatever
  is focused and have no ref parameter, but the CLI dropped the flag before the
  session server saw it, so `type-text --ref e27 --text Switzerland` aimed at a
  country combobox typed into whatever held focus and reported success — the filter
  never saw the text and the widget answered "There were no results". A ref is now
  refused by name, pointing at the ref-taking tool (`type`/`fill`) instead.

## 7.6.1

### Patch Changes

- [#80](https://github.com/alien-id/agent-id/pull/80) [`05abd08`](https://github.com/alien-id/agent-id/commit/05abd0847a818f97525770bfaf861848f1f56647) Thanks [@atemerev](https://github.com/atemerev)! - A session daemon no longer dies when its parent stops listening to its std pipes

  The `open` daemon writes diagnostics to stderr for its whole lifetime — the
  read-only access-guard logs every blocked request there, and a busy site
  (LinkedIn fires dozens of telemetry POSTs seconds after load) produces a burst
  of them. A host that closes the pipe after reading the ready line turned that
  first burst into an unhandled `write EPIPE` that killed the live session: open
  reported ready, the first navigate succeeded, and every call after it got
  `session unreachable: ECONNREFUSED`.

  The CLI now swallows `error` events on `process.stdout`/`process.stderr`.
  Losing diagnostics must never cost the session.

## 7.6.0

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

### Patch Changes

- Updated dependencies [[`e66be24`](https://github.com/alien-id/agent-id/commit/e66be24fbf4540763f7e846182c3bcdb8ccd3923)]:
  - @alien-id/agent-id-core@7.3.0
  - @alien-id/agent-id-vault@7.3.1

## 7.5.1

### Patch Changes

- [#69](https://github.com/alien-id/agent-id/pull/69) Stream viewer input applies through a promise chain in arrival order — a same-tick move/press/release burst could previously reorder (unawaited page.mouse calls) and drop the click. Suspend/page checks re-run at apply time, so a credential fill starting mid-queue still gates the queued tail.
- [#69](https://github.com/alien-id/agent-id/pull/69) `open --url <START>` navigates before the ready line ("ready" now means "up and on the page"); the outcome rides in the ready JSON as `navigation:{url,status}`, and a bad or slow URL is non-fatal.

## 7.5.0

### Minor Changes

- [#69](https://github.com/alien-id/agent-id/pull/69) Typed form tools: `form-inspect` (compact controls with labels/types/requirements/options; never returns text/password values) and `form-fill --spec` (atomic multi-control fill — fields/checks/selects/uploads, max 50 — with per-control verification and native validation reporting).
- [#69](https://github.com/alien-id/agent-id/pull/69) The shared `main` profile auto-creates as an anonymous L0 browser-profile, so public browsing needs no login or prior setup. Explicitly named profiles remain opt-in account boundaries and never auto-create.

## 7.4.0

### Minor Changes

- [#69](https://github.com/alien-id/agent-id/pull/69) Live viewport stream for open sessions (watch / pair-browse): a per-session localhost WS server streams CDP screencast JPEG frames and accepts mouse/keyboard input via page.mouse/keyboard — no CDP debug port, the profile seal stays intact. The feed and input suspend (depth-counted) during `fill-secret`/`fill-otp`; the session file gains `streamPort`/`streamToken`.

## 7.3.2

### Patch Changes

- [#67](https://github.com/alien-id/agent-id/pull/67) [`b05a646`](https://github.com/alien-id/agent-id/commit/b05a646c144926c99bcbd81f7d3896655005058e) Thanks [@atemerev](https://github.com/atemerev)! - Correct the JPEG screenshot rationale in the browser skill and code comments.
  The shipped guidance claimed JPEG cut the dominant per-step cost of vision
  actions; images are billed by pixel dimensions, not bytes, so encoding does not
  change token cost. Point at the lever that does (shrinking the image), and drop
  the stale "read the PNG" wording now that the default output is JPEG.
