---
"@alien-id/agent-id-browser": minor
---

Strict codec negotiation, text-only `char`, and a screencast watchdog

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
restarted. The idle refinement pass is not a substitute: it is *armed* by a
screencast frame, so a cast that dies before or between frames never triggers
it, and the retarget poll only fires when the current page CHANGES — which a
silently-detached CDP session does not do. A healthy session never trips this
(Chrome keeps emitting frames even on a blank page); when it does trip, the
restart delivers a fresh keyframe, which is also how it proves the pipe is back.
