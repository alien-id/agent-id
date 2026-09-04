---
"@alien-id/agent-id-vault": patch
---

`assertHostAllowed` throws with `code: "HOST_NOT_ALLOWED"` (and the offending
`host`), so a caller can tell a domain-allowlist refusal from a page fault
without reading the sentence.
