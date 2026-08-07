# @alien-id/agent-id-browser

## 7.11.0

### Minor Changes

- [#94](https://github.com/alien-id/agent-id/pull/94) [`89e316d`](https://github.com/alien-id/agent-id/commit/89e316d288346df33a01b8c066090ae35ca83058) Thanks [@atemerev](https://github.com/atemerev)! - Strict codec negotiation, text-only `char`, and a screencast watchdog

  **`codec=h264&strict=1` refuses instead of falling back.** An explicit h264
  request that landed on an unprovisioned host was quietly served JPEG, so broken
  provisioning stayed invisible while costing roughly 10× the traffic. With
  `strict=1` the handshake is refused immediately with close code **4002** — before
  a single frame — and an encoder that fails later closes the same way rather than
  downgrading a client that never agreed to it. `codec=auto` deliberately ignores
  `strict`: it asks for the best available, and JPEG is a valid answer.

  **`char` no longer needs a `key`.** The payload of a text-insertion event is
  `text`; `key` is only a fallback for it. Requiring `key` dropped well-formed
  `{eventType:"char", text:"…"}` on the floor without a word, silently losing the
  character. `keyDown`/`keyUp` still require a key — there is no pressing
  "nothing" — and input the server cannot act on now comes back to the sender as
  `{"type":"status","error":"…","for":"input_keyboard"}` instead of disappearing
  into a swallowed rejection.

  **A watchdog restarts a stalled screencast.** With viewers attached and no frame
  for `AGENT_ID_STREAM_WATCHDOG_MS` (default 15s, 0 disables), the screencast is
  restarted. The idle refinement pass is not a substitute: it is _armed_ by a
  screencast frame, so a cast that dies before or between frames never triggers
  it, and the retarget poll only fires when the current page CHANGES — which a
  silently-detached CDP session does not do. A healthy session never trips this
  (Chrome keeps emitting frames even on a blank page); when it does trip, the
  restart delivers a fresh keyframe, which is also how it proves the pipe is back.

## 7.10.0

### Minor Changes

- [#84](https://github.com/alien-id/agent-id/pull/84) [`f37fb58`](https://github.com/alien-id/agent-id/commit/f37fb586bc8ce58fa8bad075f553d944390d8738) Thanks [@atemerev](https://github.com/atemerev)! - Viewport stream v2 — binary frames, backpressure, H.264, provisioning

  The stream gains a negotiated wire protocol. Everything is opt-in per client via
  upgrade-URL query params, and a client that sends none of them gets the v1
  format unchanged, so existing viewers keep working byte for byte.

  - `binary=1` delivers frames as WS binary messages (`[u32 LE header length]
[JSON header][payload]`) instead of base64 — measured 25% less stream traffic
    at identical latency.
  - `codec=h264` encodes through an ffmpeg subprocess; `codec=auto` picks H.264
    only on a host provisioned with `agent-id-browser install-codecs`, and falls
    back to JPEG with a status notice anywhere else.
  - `pacing=ack` holds at most one frame in flight, released by the client's
    `{"type":"ack","seq":N}`; `maxFps` caps per-client delivery.
  - Delivery is latest-frame-wins for JPEG (one pending slot per client, newer
    frames overwrite it) so a slow viewer resumes at live rather than replaying a
    queue. H.264 can't drop mid-GOP, so a client whose socket buffer exceeds a
    bound is disconnected and reconnects at a fresh keyframe.
  - A settled page gets one high-quality refinement frame, so text is sharp at
    rest while motion runs at aggressive JPEG quality.
  - Experimental WebRTC transport and a bundled reference viewer page.

  `werift` is an optional dependency: WebRTC is unavailable without it and every
  other mode is unaffected.

  The seal is unchanged — no CDP debug port, frames come from the existing
  patchright pipe, and a credential fill still suspends the feed, drops pending
  frames, gates the encoder, and re-checks after every await.

## 7.9.0

### Minor Changes

- [#92](https://github.com/alien-id/agent-id/pull/92) [`193a0f8`](https://github.com/alien-id/agent-id/commit/193a0f8761c533f11f663f8873e45448c6032e61) Thanks [@atemerev](https://github.com/atemerev)! - Unused sessions close themselves

  A session holds a Chrome and a node process for as long as it lives, and nothing
  ended one: an agent that opened a browser and moved on — or failed a login and
  gave up — left it running until the container stopped. Sessions accumulated,
  holding memory and making "which browser is this?" genuinely ambiguous, since
  every host-side pick that falls back to "whichever started last" was choosing
  between browsers nobody was using.

  A session now closes itself after 20 minutes with no agent action, no viewer
  input, and nobody watching. Closing is the safe direction: the existing shutdown
  path reseals the profile into the vault first, so a signed-in session that times
  out keeps its cookies and simply reopens next time.

  A session with a viewer attached is never idle, however quiet it is — the owner
  may be reading a page or part-way through a sign-in they were handed. Set
  `AGENT_ID_BROWSER_IDLE_MS` to change the window, or `0` to disable it.

- [#86](https://github.com/alien-id/agent-id/pull/86) [`2847f48`](https://github.com/alien-id/agent-id/commit/2847f48971da2dac415aee37f03badcca3b0ed5e) Thanks [@atemerev](https://github.com/atemerev)! - Viewer `resize` in the stream protocol + profile name in the session file.

  - The viewport stream now accepts `{"type":"resize","width":W,"height":H}`
    from viewers: the session reshapes the page viewport to the viewer's own
    dimensions (window-chrome-compensated, lands the exact size), so a phone
    watching the stream gets the page's mobile layout instead of a shrunken
    desktop one. The achieved viewport is broadcast to every watcher as a
    `status` message; requests are clamped to 200–4096 per axis and ignored
    while a credential fill has the stream suspended.
  - Session files now name their `profile` in the body, so viewers scanning the
    sessions directory can attach to the right profile's stream instead of
    guessing by newest `startedAt`.

## 7.8.1

### Patch Changes

- [#89](https://github.com/alien-id/agent-id/pull/89) [`a0c5273`](https://github.com/alien-id/agent-id/commit/a0c527388cb12fd880993f7668b0ef30324a7ac8) Thanks [@atemerev](https://github.com/atemerev)! - The viewport blackout is always lifted, and a joining viewer always gets a frame

  Three faults that together made the live browser view look dead. An owner asked
  to finish a sign-in opened the view and watched a blank canvas — the relay said
  it was streaming, and not one frame ever arrived.

  **A failed credential fill blacked out the feed forever.** `fill-secret`
  suspends the stream, then unlocks the vault — but the unlock ran _outside_ the
  `try` whose `finally` resumes. Any failure there (locked vault, no agent-key
  slot, timeout) left the suspend depth stuck above zero for the rest of the
  session: frames were acked and dropped, so every later viewer saw
  `screencasting` and nothing else. That is exactly what a failed auto-login leaves
  behind, minutes before the owner is asked to take over. `fill-otp` already had
  the right shape; `fill-secret` now matches it.

  **A viewer joining an already-running screencast got no frame.** Frames are
  change-driven, and Chrome emits its first one when the cast starts — so a client
  that arrives afterwards has nothing to draw until the page happens to move. On a
  sign-in form that is never. A joining client now restarts the cast to force a
  fresh keyframe, the same trick `resume` uses.

  **A blacked-out feed was indistinguishable from a broken one.** The status sent
  on connect claimed `screencasting: true` and said nothing about the blackout, so
  a suspended feed and a dead one looked identical from the outside. The connect
  status now reports `suspended`.

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
