# @alien-id/agent-id-browser

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
