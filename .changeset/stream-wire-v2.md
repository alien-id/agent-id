---
"@alien-id/agent-id-browser": minor
---

Viewport stream v2 — binary frames, backpressure, H.264, provisioning

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
