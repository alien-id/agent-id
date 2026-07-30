---
"@alien-id/agent-id-browser": patch
---

A session daemon no longer dies when its parent stops listening to its std pipes

The `open` daemon writes diagnostics to stderr for its whole lifetime — the
read-only access-guard logs every blocked request there, and a busy site
(LinkedIn fires dozens of telemetry POSTs seconds after load) produces a burst
of them. A host that closes the pipe after reading the ready line turned that
first burst into an unhandled `write EPIPE` that killed the live session: open
reported ready, the first navigate succeeded, and every call after it got
`session unreachable: ECONNREFUSED`.

The CLI now swallows `error` events on `process.stdout`/`process.stderr`.
Losing diagnostics must never cost the session.
