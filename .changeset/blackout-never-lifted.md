---
"@alien-id/agent-id-browser": patch
---

The viewport blackout is always lifted, and a joining viewer always gets a frame

Three faults that together made the live browser view look dead. An owner asked
to finish a sign-in opened the view and watched a blank canvas — the relay said
it was streaming, and not one frame ever arrived.

**A failed credential fill blacked out the feed forever.** `fill-secret`
suspends the stream, then unlocks the vault — but the unlock ran *outside* the
`try` whose `finally` resumes. Any failure there (locked vault, no agent-key
slot, timeout) left the suspend depth stuck above zero for the rest of the
session: frames were acked and dropped, so every later viewer saw
`screencasting` and nothing else. That is exactly what a failed auto-login leaves
behind, minutes before the owner is asked to take over. `fill-otp` already had
the right shape; `fill-secret` now matches it.

**A viewer joining an already-running screencast got no frame.** Frames are
change-driven, and Chrome emits its first one when the cast starts — so a client
that arrives afterwards has nothing to draw until the page happens to move. On a
sign-in form that is never. A joining client now restarts the cast to force a
fresh keyframe, the same trick `resume` uses.

**A blacked-out feed was indistinguishable from a broken one.** The status sent
on connect claimed `screencasting: true` and said nothing about the blackout, so
a suspended feed and a dead one looked identical from the outside. The connect
status now reports `suspended`.
