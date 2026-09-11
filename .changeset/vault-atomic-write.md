---
"@alien-id/agent-id-vault": patch
---

Write `vault.enc` atomically (temp file + rename) so a concurrent reader never sees a torn file.
