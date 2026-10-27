---
"@alien-id/agent-id-vault": minor
---

Storing a card asks for its billing address on the same form. `add --type card --form` raises the card fields and the eight `billing*` fields together — a client draws them as two pages, the card and then its address — and stores the address with the card, so the first checkout that wants one already has it. The address is checked before anything is written: one the vault refuses (a country that is not an ISO 3166-1 alpha-2 code, say) leaves the card stored without it, and the answer carries `billingAddress: { stored: false, reason }`; a stored one reports `{ stored: true }`. `set-address --card N --form` stays for a card stored without an address, and now says when the vault refused the address instead of reporting an empty form. The Country box carries a `US` placeholder.
