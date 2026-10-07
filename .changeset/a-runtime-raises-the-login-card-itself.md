---
"@alien-id/agent-id-vault": minor
---

A caller can raise the credential card itself and hand the answer back. `vault form-spec` takes the flags `add` takes and prints the card `add --form` would raise (`title`, `description`, `fields`, `label`, `security`) without raising it or opening the vault, after the same shape checks `add` makes. `add --form --values-stdin` reads that card's values as a JSON object on stdin instead of raising the card, and stores them exactly as an answered card would, Save to vault included. A host that keeps its own secure-prompt channel can then show the card the moment the owner asks for it, rather than starting `add --form` first.
