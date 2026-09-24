---
"@alien-id/agent-id-vault": patch
---

Put the vault on the disk before renaming it into place, so a machine that loses power does not come back to a file of NUL bytes that no unlock can open.
