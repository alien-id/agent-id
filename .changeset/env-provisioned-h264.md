---
"@alien-id/agent-id-browser": minor
---

`AGENT_ID_FFMPEG` now counts as codec provisioning: `loadCodecConfig` falls back to probing the env override when no `browser-codecs.json` record exists, so an immutable container image (which cannot pre-write per-tenant state) provisions H.264 by baking ffmpeg and setting the env var. `codec=auto` resolves to h264 and `strict=1` handshakes succeed on such hosts; a broken override degrades to unprovisioned exactly like a stale record, and nothing is probed on a host that set neither.
