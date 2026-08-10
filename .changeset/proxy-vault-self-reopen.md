---
"@alien-id/agent-id-proxy": minor
---

Self-reopen for unattended deployments: when the vault was unlocked via the
agent-key slot, the proxy can reopen it without a restart — a credential
written after spawn is picked up on next use (one reopen + retry on a miss),
and an idle lock without the control plane recovers on the next request.
Consent/control-plane behavior is unchanged.
