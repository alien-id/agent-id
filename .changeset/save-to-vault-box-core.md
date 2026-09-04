---
"@alien-id/agent-id-core": minor
---

Secure-input fields may declare `kind: "checkbox"` with a `default`; the local browser form and the tty prompt render it and answer with the string `"true"` / `"false"` (an unticked box posts nothing and reads as `"false"`, never as an absent field).
