---
"@alien-id/agent-id-vault": minor
---

p2p vault sync (PoC): live, fully decentralized synchronization of credential
records between a user's devices. Signed op-log DAG inside the encrypted
payload (git-like causality, deterministic conflict tiebreak, local conflict
journal), TLS 1.3 channel with Ed25519-over-EKM identity binding, same-owner
verification via the v3 bundle plus one-time per-device approval, UDP beacon
discovery + explicit `--peer`. New CLI: `sync`, `sync --listen`, `sync status`,
`sync devices [add]`, `sync revoke`, `sync resolve`. `browser-profile` records
stay device-local. Master keys never leave a device.
