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
{ "type": "webrtc_offer", "sdp": "…" }             // experimental, see below
{ "type": "webrtc_ice", "candidate": { … } }
```

Input coordinates are in `metadata.deviceWidth/Height` space (CSS viewport
pixels — capture is clamped to the CSS viewport, so the mapping is 1:1).
Mutating input (click, wheel, keydown, char) invalidates the agent's element
refs, exactly like any page mutation.

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
startup; only then does `codec=auto` resolve to h264 (`h264Available: true`
in status). An unprovisioned host never spawns ffmpeg implicitly — explicit
`?codec=h264` still probes `PATH`, and a failed probe falls back to jpeg with
a status notice.

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
- Dimension changes (tab switch, viewport resize) restart the encoder; a
  crashed encoder restarts rate-limited (500 ms).

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
