---
"@alien-id/agent-id-proxy": minor
---

Self-reopen for unattended deployments: when the vault was unlocked via the
agent-key slot, the proxy can reopen it without a restart — a credential
written after spawn is picked up on next use (one reopen + retry on a miss),
and an idle lock without the control plane recovers on the next request.
Consent/control-plane behavior is unchanged. A rotated OAuth refresh token is
now persisted through a vault handle re-read from disk, so the write no longer
erases credentials another process added since the proxy started; the replaced
handle is locked (no second decrypted copy in the heap) and its cached OAuth
tokens are dropped so a re-authorized credential's new refresh token wins.
