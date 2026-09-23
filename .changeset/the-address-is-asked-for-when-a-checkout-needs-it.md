---
"@alien-id/agent-id-vault": minor
---

The billing address is asked for when a checkout needs it, not when the card is
stored.

`add --type card --form` raised the address screen right behind the card's,
with seven boxes the owner could not get past — and no way to tell, from a
checkout in Dubai that never asks, that none of it would be needed. The only
way out was the phone's Back, which declined the screen; the card was then
stored without an address and the caller was told nothing, so the agent could
neither know nor ask.

The card screen is now the whole of `add`. The address has a command of its
own, `set-address --card N --form`, for the agent to run once a form in front
of it asks for boxes the card cannot answer: an address the vault already holds
is linked to the card without a word (`source: "existing"`), a card that has one
is left alone (`"already"`), and only a vault with none puts the screen in front
of the owner (`"typed"`). `--replace` asks again regardless, for an address that
lacks a box a shop insists on. Every answer carries `fields` — the names a
checkout can now be filled with, never the values — and an owner who closes the
screen, or asks for the browser, ends the command the way `set-totp` is ended,
with the card untouched.

The state and the postal code are optional on that screen, alongside the second
street line: most countries have no states and some sixty issue no postal code,
so a required box there was a box the owner had to invent something for. A
checkout that insists on one refuses the fill for that box before anything is
spent, which is where the question belongs.
