---
"@alien-id/agent-id-browser": minor
---

The viewport stream's `resize` message takes an optional `scale` (1–3, default
1), so a viewer on a high-density screen can ask for a HiDPI capture instead of
a 1× stream upscaled on the device. A scaled session applies
`Emulation.setDeviceMetricsOverride` with that `deviceScaleFactor` (`mobile:
false` — no touch capability, no mobile UA), and the capture path switches from
screencast to coalesced `captureScreenshot` calls: the screencast's `maxWidth`/
`maxHeight` are caps, not upsampling requests, so it can never deliver more than
1×, while a screenshot under the override already does. Motion and refinement
frames therefore come from the same call and are dimension-identical by
construction, which the encoder requires — a dimension flip between them
respawns it. Frame metadata stays CSS pixels at every scale, so viewer input
mapping is unchanged.

The override rides the long-lived capture session (overrides die with the
session that set them) and is re-applied per target on retarget, so a new tab
inherits the scale and the old one reverts. Scale is clamped, rounded to an
integer at every CDP boundary, and budgeted against per-axis and total-pixel
limits — an over-budget request is served at the largest scale that fits, and
the achieved geometry is broadcast in the `resized` status. Omitting `scale`, or
sending it to a build without support, behaves exactly as before.
