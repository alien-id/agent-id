---
"@alien-id/agent-id-proxy": minor
---

Self-reopen for unattended deployments: when the vault was unlocked via the
agent-key slot, the proxy can reopen it without a restart — a credential
written after spawn is picked up on next use (one reopen + retry on a miss),
and an idle lock without the control plane recovers on the next request.
Consent/control-plane behavior is unchanged. Every write to `vault.enc` — a
rotated OAuth refresh token, and phone pairing — now goes through a handle
re-read from disk, and is refused when the vault cannot be re-read, so a write
can no longer erase credentials another process added since the proxy started
(a refused rotation stays in the in-memory cache and is logged; a refused
pairing answers `409 vault_reread_unavailable`). The replaced handle is locked
(no second decrypted copy in the heap) and its cached OAuth refresh tokens are
dropped so a re-authorized credential's new refresh token wins, while still-valid
access tokens are kept — a reopen costs no extra token-endpoint round trips.
