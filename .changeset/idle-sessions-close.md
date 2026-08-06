---
"@alien-id/agent-id-browser": minor
---

Unused sessions close themselves

A session holds a Chrome and a node process for as long as it lives, and nothing
ended one: an agent that opened a browser and moved on — or failed a login and
gave up — left it running until the container stopped. Sessions accumulated,
holding memory and making "which browser is this?" genuinely ambiguous, since
every host-side pick that falls back to "whichever started last" was choosing
between browsers nobody was using.

A session now closes itself after 20 minutes with no agent action, no viewer
input, and nobody watching. Closing is the safe direction: the existing shutdown
path reseals the profile into the vault first, so a signed-in session that times
out keeps its cookies and simply reopens next time.

A session with a viewer attached is never idle, however quiet it is — the owner
may be reading a page or part-way through a sign-in they were handed. Set
`AGENT_ID_BROWSER_IDLE_MS` to change the window, or `0` to disable it.
