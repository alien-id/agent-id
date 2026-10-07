---
"@alien-id/agent-id-vault": minor
---

A runtime can raise the credential card itself and hand the answer back. `vault form-spec` takes the flags `add` takes and prints the card `add --form` would raise (`title`, `description`, `fields`, `label`, `security`) without raising it or opening the vault, after the same shape checks `add` makes. `add --form --values-stdin` reads that card's values as a JSON object on stdin instead of raising the card, and stores them exactly as an answered card would, Save to vault included. Lethe uses the pair to open the sign-in card the moment the owner leaves a browser handover for it, rather than spawning `add --form` after the tap.
