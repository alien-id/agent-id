---
"@alien-id/agent-id-vault": minor
---

The credential card carries a "Save to vault" box, ticked by default. Unticked, `vault add --form` keeps the record for this sign-in only — marked `transient`, listed as such, and swept on the next open once its 30-minute window passes — and the result says `transient: true` so the caller knows not to plan a later sign-in around it.
