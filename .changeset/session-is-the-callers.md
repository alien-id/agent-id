---
"@alien-id/agent-id-browser": minor
---

`auto-login` requires an open session instead of starting an unnamed one.

One browser is one user at a time, and which user is a `Session.start` name — a
profile directory under the browser's `--data`. This command is handed a port
and a credential, never a profile, so it can neither name the profile it wants
nor move a browser that is currently being somebody else. It used to start a
session anyway, unnamed, from back when a session had no profile to name;
against a browser that has them that call is simply an error, and the sign-in
failed reporting the browser "not reachable" — which sent callers looking for a
network fault instead of the session they had not opened.

Now `Session.state` deciding there is no session raises `NO_SESSION`, saying
that the caller chooses the profile a sign-in lands in and must open the session
before handing the port over. An already-active session is used exactly as
before.
