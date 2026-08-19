---
"@alien-id/agent-id-browser": patch
---

Encode every frame instead of resampling to a fixed rate — the demuxer's
nominal 25 fps became a constant output rate and ffmpeg dropped every
screencast frame that missed the grid (78 frames in, 2 encoded).
