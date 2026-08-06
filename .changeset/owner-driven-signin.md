---
"@alien-id/agent-id-browser": minor
---

An owner can be handed a browser to sign into, and dead sessions stop haunting the viewer

**A named profile can be created for the owner to sign into.** When a sign-in
cannot be automated — a bot challenge, an IdP that refuses agents, no display for
a headed `login` — the answer is to hand the browser to the owner. That was
impossible for any site not already set up: `login` needs a GUI, `auto-login` had
just failed, and `open` refuses to auto-create a named profile, so there was
nowhere to sign in. `open --bootstrap-profile` mints an empty jar for a named
profile; the owner signs in, and `close` seals it like any other. Without the
flag a named profile still never auto-creates — the account boundary is
unchanged, the opt-in is explicit.

**Orphaned sessions are pruned.** A clean `close` reseals and removes its own
session file, but an abrupt death (a recreated container, a killed daemon) leaves
it behind, and the state dir usually outlives the process. Those orphans still
advertise a `streamPort`, so a viewer picking "the newest session with a stream"
can dial a dead port and show nothing, and `status` lists sessions that do not
exist. `open` and `status` now drop session files whose pid is gone.

**Stale plaintext profile copies are removed too.** `<name>.work` is the
UNSEALED profile — cookies on disk, outside the vault. A clean close wipes it;
an abrupt death left it there indefinitely (weeks-old copies were found for
sessions long gone). Orphaned work dirs are now removed once they are old enough
that they cannot belong to a launch still in flight.
