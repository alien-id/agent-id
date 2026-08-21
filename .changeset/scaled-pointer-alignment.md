---
"@alien-id/agent-id-browser": patch
---

Align scaled-session pointer input with the captured frame. On some hosts an
active device-metrics override (a `scale ≥ 2` viewer) leaves CDP-dispatched
pointer coordinates in a different space than the picture: the frame is
correct, wheel and keyboard work, but a click lands at roughly 1/scale of the
intended point — on nothing, or on the wrong element. The displacement is
host-specific (headless mac and Linux Chromium dispatch cleanly through the
same override), so the stream server now measures it on the live page instead
of deriving it from platform assumptions: one probe mousemove per cast epoch
reports where the page actually saw the pointer, and every subsequent pointer
coordinate is pre-scaled by the inverse. On aligned hosts the probe measures
identity and the correction disables itself.
