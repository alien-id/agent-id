---
"@alien-id/agent-id-vault": minor
---

The billing address a card is billed to.

A card-not-present payment is checked against the address the card is billed
to, so a stored card that has none cannot complete most checkouts. `address`
joins the credential types — eight fields, of which only the second street
line is optional — and it is asked for on a screen of its own, after the card,
so neither form is a wall of twelve boxes. Closing that second screen stores
the card without an address rather than losing it.

The address is a record in its own right, and the card holds a reference to
it, so a second card reuses the address the owner already typed. Its name
discloses nothing about where they live: `billing-1`, `billing-2`, matched by
value so the same address is never stored twice. Every field is in
`SECRET_FIELDS` — an address is personal data, and `show` seals it the way it
seals a card.

`read-card` resolves the reference, so whatever types a checkout form reads
one shape whether the address lives in its own record or inside the card. A
card stored before this reads back with no billing block, and a checkout that
asks for no address is filled exactly as before.
