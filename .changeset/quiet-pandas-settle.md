---
"@alien-id/agent-id-browser": patch
---

login seals the profile when its own timeout fires

`login` waits for either the window closing or `--timeout-sec`. On the timeout
path the browser is usually already gone at the transport level, and
`ctx.close()` against a dead connection never settles — it does not throw, so
the surrounding `try/catch` does not help. The await simply never returned, and
`sealProfile()` on the next line was never reached: the command hung forever and
the sign-in the owner had just completed was discarded, leaving the next run
logged out with nothing to explain why.

The close is now bounded the way the read path already bounds it, so the seal
always runs.
