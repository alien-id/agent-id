---
"@alien-id/agent-id-browser": patch
---

Emit per-second frame counters for the viewport stream — one row for the
capture stage, one for the encode stage — so a frozen picture is localized to
the stage that lost the frame instead of guessed at. Two silent losses now
carry a number: a frame displaced in a stalled viewer's single pending slot,
and the RUN of frames a saturated encoder refuses until its input drains. The
capture row also reports how many idle refinement passes actually fired, which
is what flushes the last frame of a burst and is not answerable from the
configuration. The access-unit framer now reports what each unit carried
(keyframe, parameter sets) from the scan it was already making. Set
`AGENT_ID_STREAM_COUNTERS=0` to turn the rows off.
