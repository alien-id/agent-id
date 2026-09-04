---
"@alien-id/agent-id-vault": minor
---

The credential card carries a "Save to vault" box, on by default, behind `AGENT_ID_SAVE_TO_VAULT_BOX=1` until the phone app that draws it has shipped. Turned off, `vault add --form` keeps the record for this sign-in only — marked `transient`, listed as such, dropped from every open once its 30-minute window passes and from disk on the next save — and the result says `transient: true` so the caller knows not to plan a later sign-in around it. Turning it off on a re-add of a credential the owner already keeps leaves that credential kept.
