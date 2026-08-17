# Browser viewport stream

Every open `agent-id-browser` session runs a live viewport stream — the
pair-browsing feed. A viewer (the bundled test page, the host
runtime's relay to the owner's client, or any agent-browser-compatible client)
connects over WebSocket, sees what the sealed browser sees, and can optionally
drive it with mouse/keyboard input.

Implementation: `plugins/agent-id-browser/lib/stream-server.mjs` (server),
`stream-encoder.mjs` (H.264), `stream-webrtc.mjs` (experimental transport),
`stream-viewer.html` (reference viewer). No runtime dependencies — the
WebSocket server is hand-rolled, H.264 uses an ffmpeg subprocess, and WebRTC
uses the optional pure-JS `werift` package.

## Endpoint and authentication

The session process writes its session file
(`<stateDir>/browser-sessions/<name>.json`) with:

```json
{ "streamPort": 41723, "streamToken": "<48-hex>" }
```

- WebSocket upgrade: `ws://127.0.0.1:<streamPort>/?token=<streamToken>&…`
- Reference viewer: `http://127.0.0.1:<streamPort>/viewer?token=<streamToken>`
- Anything else on that port answers `426`; a bad token is refused before the
  upgrade completes.

The server binds `127.0.0.1`. `AGENT_ID_STREAM_BIND` overrides the bind
address for LAN viewer testing (e.g. from a phone) — testing only; the
intended remote path is the host runtime relaying the token-gated socket.

## Wire protocol (v2)

Everything is negotiated per client via query params on the upgrade URL. A
client that sends none of them gets the **v1 wire format, unchanged** — the
same message shapes as [agent-browser's streaming
protocol](https://agent-browser.dev/streaming), so one viewer works against
both browser stacks.

| Param | Values | Effect |
|---|---|---|
| `token` | hex | required, per-session gate |
| `binary` | `1` | `frame` messages become WS **binary** messages (layout below); everything else stays JSON text |
| `codec` | `jpeg` \| `h264` \| `auto` | `h264`/`auto` imply `binary=1`. `auto` resolves at join time: h264 on a provisioned host (see *Provisioning*), else jpeg. Omitting the param means `jpeg` — that is a compatibility floor, not a recommendation: a client that never asked can't be assumed to decode video. **New clients should always send `codec=auto`** (the bundled viewer does), which is how h264 becomes the effective default wherever the owner ran `install-codecs` |
| `pacing` | `push` (default) \| `ack` | `ack`: at most one frame in flight; the client releases the next with an `ack` message |
| `strict` | `1` | Only with an explicit `codec=h264`: make it a **requirement**. An unprovisioned host (or an encoder that fails to start) refuses with close code **4002** instead of quietly serving jpeg — broken provisioning is otherwise invisible and jpeg costs roughly 10× the traffic. `codec=auto` ignores it: `auto` asks for the best available, and jpeg is a valid answer |
| `maxFps` | 0–120 | per-client delivery cap (0 = uncapped) |

### Messages

Server → client (JSON text unless noted):

```jsonc
{ "type": "status", "source": "alien", "screencasting": true,
  "suspended": false, "binary": true, "codec": "h264",
  "h264Available": true, "pacing": "push", "maxFps": 0,
  "viewportWidth": 1440, "viewportHeight": 813 }   // sent on join; also on
                                                   // suspend/resume and codec
                                                   // fallback
{ "type": "frame", "seq": 7, "data": "<base64 jpeg>",
  "metadata": { "deviceWidth": 1440, "deviceHeight": 813,
                "pageScaleFactor": 1, "offsetTop": 0,
                "scrollOffsetX": 0, "scrollOffsetY": 0,
                "timestamp": 1754404261.7 },
  "refinement": true }                             // text mode only; the
                                                   // refinement flag marks an
                                                   // idle high-quality frame
```

Client → server (always JSON text):

```jsonc
{ "type": "ack", "seq": 7 }                        // pacing=ack: release next
{ "type": "config", "pacing": "ack", "maxFps": 10 }// adjust at runtime
{ "type": "status_request" }                       // reply: a status message
{ "type": "input_mouse", "eventType": "mousePressed",
  "x": 100, "y": 200, "button": "left", "clickCount": 1 }
{ "type": "input_mouse", "eventType": "mouseMoved" | "mouseReleased" | "mouseWheel",
  "deltaX": 0, "deltaY": 120 }
{ "type": "input_keyboard", "eventType": "keyDown" | "keyUp" | "char",
  "key": "Enter", "text": "a" }
// `char` carries its payload in `text`; `key` is only a fallback for it, so a
// text-only char is valid. `keyDown`/`keyUp` require `key`. Input the server
// cannot act on comes back to the SENDER as
// {"type":"status","error":"…","for":"input_keyboard"} rather than vanishing.
{ "type": "resize", "width": 390, "height": 844,
  "scale": 2 }                                     // viewport + optional HiDPI
                                                   // capture scale, see below
{ "type": "webrtc_offer", "sdp": "…" }             // experimental, see below
{ "type": "webrtc_ice", "candidate": { … } }
```

Input coordinates are in `metadata.deviceWidth/Height` space (CSS viewport
pixels). At the default 1× the capture is clamped to the CSS viewport, so the
mapping is 1:1; after a `resize` with `scale` > 1 the payload carries
`viewport × scale` pixels while coordinates and `metadata` stay CSS — map taps
through `metadata`, never through the payload's pixel size.
Mutating input (click, wheel, keydown, char) invalidates the agent's element
refs, exactly like any page mutation.

### Close codes

| Code | Meaning |
|---|---|
| `4002` | The requested codec cannot be served and the client sent `strict=1`. Typed on purpose: a strict client can tell this from a network drop and stop reconnecting. A `status` frame carrying `error` and `code` precedes the close, so a text-logging viewer sees the reason in words |

### Binary frame layout

With `binary=1`, each `frame` message is one WS binary message:

```
[u32 LE header length][JSON header][payload bytes]
```

The header is the frame message without `data` — e.g.
`{"type":"frame","seq":7,"codec":"jpeg","metadata":{…},"refinement":true}` —
and the payload is raw bytes: a JPEG (`codec:"jpeg"`) or an H.264 Annex-B
chunk (`codec:"h264"`). Every message is self-describing, so a relay can
apply its own latest-frame-wins dropping without decoding payloads, and a
`codec=auto` client just follows the per-message `codec` field.

Base64 inflates JPEG frames by a third; binary framing removes that
(measured: −25 % stream traffic, identical latency).

### Delivery semantics

**Latest-frame-wins (jpeg).** Each client has exactly one pending-frame slot.
Whenever the client is slower than the feed — socket backpressure (drain-
gated), an outstanding ack, or its fps cap — newer frames overwrite the slot.
A stalled viewer resumes at live instead of replaying the blackout, and the
server never queues stale frames. (Measured with a 6 s viewer stall: v1
replayed 76 stale frames; v2 replays only what the kernel already buffered.)

**H.264.** A temporally-dependent byte stream can't drop chunks mid-GOP, so a
client whose socket buffer exceeds 4 MB is disconnected instead; on reconnect
the encoder restart hands it a fresh SPS/PPS + IDR. `pacing=ack` is a no-op
for h264 clients.

**Idle refinement.** The CDP screencast is damage-driven; motion frames run
at aggressive JPEG quality (default 55). After ~600 ms without a screencast
frame, the server pushes one high-quality `Page.captureScreenshot` frame
(default quality 90, `refinement: true`) so text is sharp at rest. Refinement
frames also feed the H.264 encoder — that is what keeps an h264 viewer's
picture alive on a static page (see *Encoder notes*).

**Suspend blackout.** `fill-secret` / `fill-otp` suspend the feed while a
credential value is on its way into the page: pending frames are dropped,
encoder input and refinement capture are gated, viewer input is ignored, and
`status` messages bracket the window (`suspended: true/false`). On resume the
screencast restarts to force a fresh keyframe. A watcher never sees more than
the `screenshot` verb could show outside those windows; the seal is never
weakened — frames come from a patchright CDP session over the existing pipe,
never a CDP debug port.

## H.264: provisioning and encoding

H.264 cuts stream traffic ~10× (measured 608 → 61 kB/s on a 720 p test feed)
and decodes in every browser — it is the only codec Chrome, Firefox and
Safari (desktop + mobile) all handle equally well. It requires ffmpeg, so it
is **opt-in per host**:

```
agent-id-browser install-codecs [--no-download] [--force]
```

probes for a usable ffmpeg (`AGENT_ID_FFMPEG` → `PATH` → a previously
downloaded copy), on Linux falls back to downloading a static build (BtbN's
gpl build, into `<stateDir>/tools/ffmpeg`), verifies an H.264 encoder exists,
and records `<stateDir>/browser-codecs.json`. Sessions load that record at
startup — **or, when no record exists, the `AGENT_ID_FFMPEG` env override,
probed live**: setting the env var is the same explicit host-level opt-in the
record represents, and it is the only provisioning channel an immutable
container image has (`install-codecs` writes per-tenant state an image cannot
pre-write). Either form makes `codec=auto` resolve to h264
(`h264Available: true` in status) and lets a `strict=1` handshake succeed. A
host with neither never spawns ffmpeg implicitly; a broken override is
re-verified like a stale record and degrades to unprovisioned — non-strict
h264 viewers then fall back to jpeg with a status notice, strict ones are
refused with close 4002.

Encoder selection: `libx264` when the ffmpeg build has it (typical container
images; `-preset ultrafast -tune zerolatency`), else `libopenh264` (Cisco's
BSD-licensed encoder — what Fedora ships). Both emit Constrained Baseline,
GOP 30, no B-frames, as Annex B with **AUD NALs inserted** so viewers can
split the byte stream into access units without parsing slice headers
(WebCodecs requires AU-aligned chunks; jmuxer does not reassemble NALs split
across feeds).

### Encoder notes (hard-won)

- Input is the screencast's JPEGs piped as raw MJPEG with wallclock
  timestamps. Raw MJPEG has no length header: the demuxer only delimits frame
  N when frame N+1's SOI marker arrives. The refinement frame is therefore
  written **twice** — copy #1 flushes whatever was stuck and gets encoded,
  the identical stuck copy #2 loses nothing.
- `-analyzeduration 0 -probesize 32` are required; the 5 MB default probe
  window otherwise swallows the first frames indefinitely at screencast frame
  sizes.
- A freshly spawned encoder arms an immediate refinement, so an h264 viewer
  joining a quiet page gets a picture within ~250 ms instead of black until
  the next repaint.
- Dimension changes (tab switch, viewport resize, capture-scale change)
  restart the encoder; a crashed encoder restarts rate-limited (500 ms).

## WebRTC (experimental)

Signaling rides the stream WS (`webrtc_offer` → `webrtc_answer`, trickle
`webrtc_ice` both ways), so the token gate and lifecycle are unchanged —
WebRTC replaces only the frame transport. Media is the same H.264 as RTP from
a per-peer ffmpeg to loopback UDP, forwarded into the peer connection by
`werift` (optional dependency; absent → `webrtc_error`, viewer falls back).
Limits: host-only ICE (localhost/LAN, no STUN/TURN), no RTCP feedback (loss
recovery is the periodic GOP). Kept as an experiment; the WS modes are the
supported path.

## Reference viewer

`GET /viewer?token=…` serves a self-contained page (`stream-viewer.html`)
with a mode picker — auto (default), legacy JSON, binary jpeg, binary+ack,
h264 via WebCodecs, h264 via MSE/jmuxer (CDN), WebRTC — plus a live HUD
(kB/s, fps, capture→display latency) and full input forwarding. `auto`
degrades WebCodecs → MSE → binary jpeg automatically; WebCodecs support is
probed with a real decode because `isConfigSupported` misreports H.264 on
some Firefox builds.

## Tuning

| Env var | Default | Meaning |
|---|---|---|
| `AGENT_ID_STREAM_QUALITY` | 55 | screencast (motion) JPEG quality |
| `AGENT_ID_STREAM_REFINE_QUALITY` | 90 | idle refinement quality; 0 disables |
| `AGENT_ID_STREAM_BIND` | 127.0.0.1 | bind address (LAN testing only) |
| `AGENT_ID_FFMPEG` | `ffmpeg` | ffmpeg binary override |
| `AGENT_ID_STREAM_H264_ENCODER` | auto | force `libx264`/`libopenh264` |

Benchmark (synthetic 720 p screencast, 15 fps; v1 baseline measured from
`git show main:`, not simulated): `node tests/bench-browser-stream.mjs`.

| mode | kB/s | KB/frame |
|---|---|---|
| v1 text+base64 | 608 | 42.6 |
| v2 compat (default) | 609 | 42.6 |
| v2 binary | 457 | 32.0 |
| v2 h264 | 61 | 5.7/chunk |

## The `resize` message

`width`/`height` are the **viewer's** dimensions — the desired page
**viewport**, not the outer window size the session-protocol `resize` action
takes. This is how a phone-sized viewer gets the page's mobile layout instead
of a shrunken desktop one: send your own screen size and the page reflows.

The session converts viewport → outer window with one chrome-compensation
pass: resize the window to the requested size, measure how much the window
chrome ate, grow the window by that delta. The result lands on the exact
requested viewport (verified against headless Chrome: requesting 390×844
yields a 390×844 viewport).

An optional `scale` asks for the capture at `scale`× device pixels — a
retina-density viewer sends its own `devicePixelRatio` and gets text crisp at
native density instead of a 1× upscale. It is implemented as a device-metrics
override (`deviceScaleFactor: scale, mobile: false`) held on the capture's own
CDP session: the page keeps its CSS geometry and desktop UA, no touch
capability, no mobile emulation — the only page-visible change is
`devicePixelRatio`, the common desktop-retina configuration. The override
follows the capture: switching tabs moves it to the new tab (the old one
reverts), and a later resize without `scale` (or with `scale: 1`) drops it.

How a scaled session captures (all of it measured against real Chrome):
Chrome's screencast delivers CSS-pixel frames regardless of
`devicePixelRatio`, while `Page.captureScreenshot` renders at device pixels.
A scaled session therefore keeps the screencast running only as a damage
detector — its 1× frames are never delivered — and serves screenshot
captures as motion frames instead, coalesced to at most one in flight. A 2×
phone-viewport capture costs ~20 ms, so scaled motion tops out around
30–50 fps and idle cost is unchanged (captures are damage-driven, exactly
like classic delivery). Motion and the idle refinement use the same capture
call, so their pixel dimensions are identical in every mode. Frame payloads
become `viewport × scale` pixels; `metadata.deviceWidth/Height` and input
coordinates stay CSS (see *Messages*).

Rules:

- Dimensions clamp to **200–4096** per axis. Non-numeric dimensions are
  ignored entirely (not resized-to-minimum).
- `scale` is rounded to the **nearest integer** and clamped to **1–3**
  (fractional pixel dimensions are rejected at the CDP layer, and integer
  factors keep every capture path on identical dimensions); a missing or
  non-numeric `scale` means 1, so the two-field message behaves exactly as it
  always did.
- Budgets after multiplication: no axis of `viewport × scale` may exceed
  4096 device pixels, and the total may not exceed one 4K frame's worth of
  pixels (3840×2160). A request over budget is served at the largest scale
  that fits (down to 1), never refused.
- Requests are serialized behind pending viewer input, so a resize lands in
  arrival order relative to queued clicks and keys.
- The achieved viewport is broadcast to **every** watcher as the `status`
  message above — the request mirror in `resized` (which also carries the
  achieved `scale` after budgets, informational only), the authoritative
  result in `viewport`. For a scaled resize the viewport is re-measured after
  the override lands, so it reports what the page actually became. Do
  coordinate math against `viewport`; frame payload dimensions follow the
  frames themselves.
- A resize that enters, leaves, or changes a scaled mode restarts the
  screencast and the shared encoder (fresh SPS/PPS + IDR at the new pixel
  dimensions) — expect one keyframe's worth of latency, as on a tab switch.
  A 1× resize from a 1× session keeps the classic no-restart behavior.
- A resize does not invalidate element refs (the DOM is untouched; refs are
  sparse and stable) — but screenshot coordinates taken before the resize are
  stale, as after any reflow.

## Suspend (credential blackout)

While `fill-secret` / `fill-otp` inject a credential value, the session
suspends the feed: frames stop, and **all** viewer messages — input and
`resize` alike — are dropped at apply time, so a watcher can neither see nor
touch a form mid-injection. Suspension is depth-counted and announced with
`{"type":"status","suspended":true|false}`; on resume the screencast restarts
to force a fresh keyframe.
