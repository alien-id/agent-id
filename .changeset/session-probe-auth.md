---
"@alien-id/agent-id-browser": patch
---

Session liveness is now authenticated: `pruneDeadSessions` follows the pid
check with a one-line token handshake against the session's control port
(new `probeSession` helper). On hosts where the state dir outlives the
container, a leftover session file's pid and port are routinely recycled to
unrelated processes — the pid answer alone then calls a dead session alive,
while a listener that rejects the token proves the daemon is gone. No reply
within the budget keeps the file (a busy daemon answers late); files without
control coordinates keep the pid-only behavior.
