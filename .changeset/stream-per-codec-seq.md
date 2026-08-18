---
"@alien-id/agent-id-browser": patch
---

Viewport stream: number `seq` per codec. The stream server drew every message
from a single counter, so a JPEG frame delivery (which happens for each
screencast frame whether or not a JPEG viewer is attached, and again for the
idle refinement pass) consumed sequence numbers out of the H.264 stream. An
H.264 viewer therefore saw its sequence advance in steps of two or three,
read that as dropped frames, waited for a keyframe that was never missing,
and redialed — a relay that reconnected every few seconds on an otherwise
healthy stream. Each codec now has its own counter, so a viewer's sequence is
contiguous and a real gap once again means real loss. No wire-format or
client change: `seq` is still a monotonically increasing per-message ordinal.
