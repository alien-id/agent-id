---
"@alien-id/agent-id-browser": patch
---

Stop a closed H.264 encoder from writing into the next one's stream

Closing an encoder destroyed its stdin and killed the process, but left the
listener on its stdout attached — and neither of those stops delivery: what the
kernel pipe already holds is still read out and handed to the caller after
close returned (measured: ~17 KB in 9 chunks). Because an encoder is replaced by
closing the old one and spawning a new one onto the same viewer sink, that tail
was written to live viewers interleaved into the replacement's output, carrying
slices that reference the previous encoder's parameter sets — which a decoder
can only fail on. A replacement happens on every viewer join, retarget, resume
and watchdog restart, so a viewport could go black right after reconnecting.

Closing now detaches the output listener before killing the process, so a closed
encoder delivers nothing, and repeated closes are a no-op.
