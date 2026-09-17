---
"@alien-id/agent-id-vault": minor
---

A card asks whether to keep it, and its address is readable on its own.

The secure form for a card never carried the "Save to vault" box every other
credential offers, so a card was stored for good and the owner was told
nothing. It carries it now, with a window of its own: a sign-in is consumed at
a known moment and a purchase is not, so an unkept card lives a day rather than
the half hour an unkept sign-in gets.

Two readers join `read-card`, and neither hands a card over. `card-fields`
answers with the names of the fields this card can fill, so a caller can refuse
a box the card has no value for before it spends anything; `read-address`
answers with the address the card is billed to and nothing else, because a
delivery step asks for an address long before anything is paid.
