---
"@alien-id/agent-id-core": minor
"@alien-id/agent-id-browser": minor
---

Tell a card closed for the browser from a card simply closed.

A card knows how to be answered and how to be dismissed, and the owner saying
"not here — I will sign in myself, where I can see it" has nowhere to live
between them. It arrives as a plain dismissal, so the agent reads a refusal,
leaves the sign-in alone, and reports it as not done — when what was asked for
was the browser.

The host now says how a card was closed, and a dismissal carrying `use_browser`
becomes its own outcome: `owner-will-drive`, escalating to the viewport the owner
just asked for, with a message that says in as many words they did not refuse.

Everything without a reason behaves exactly as before, which is what every client
that has not been taught the button keeps sending.
