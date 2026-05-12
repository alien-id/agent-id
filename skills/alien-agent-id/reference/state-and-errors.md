# State directory, errors, security

## State directory

Default: `~/.agent-id`. Override with `--state-dir <path>` or `AGENT_ID_STATE_DIR`.

```
~/.agent-id/
├── keys/main.json             # Ed25519 keypair (mode 0600)
├── ssh/
│   ├── agent-id               # SSH private key (mode 0600)
│   ├── agent-id.pub           # SSH public key
│   └── allowed_signers        # For git signature verification
├── vault/
│   ├── github.json            # Encrypted credential (mode 0600)
│   └── ...
├── audit/operations.jsonl     # Hash-chained, signed operation log
├── owner-session.json         # SSO session — id_token IS the chain attestation (mode 0600) — NEVER commit
├── nonces.json                # Per-agent nonce tracking
├── sequence.json              # Sequence counter
```

## Error catalog

| Error | What to do |
|---|---|
| `No provider address` | Set `--provider-address`, `ALIEN_PROVIDER_ADDRESS`, or place an address in `default-provider.txt` next to `cli.mjs`. |
| `No pending auth found` | Run `auth` first (or `bootstrap` from the top). |
| `Alien SSO authorization session expired` | Restart the flow with `bootstrap` / `auth`. |
| `User rejected Alien SSO authorization` | Ask the user to retry. |
| `Timed out waiting` | Restart `bootstrap`; remind the user to scan promptly. |
| `No agent keypair` | Run `init` (or `bootstrap` from the top). |
| `No bound session with access_token` | Run `bind` (or `bootstrap` from the top). |
| `--url is required …` | DPoP binds to `(method, URL)`. Re-invoke with `--url <U> --method <V>`. |
| `No credential stored for "..."` | Ask the user for the credential, then `vault-store` — see [vault.md](vault.md). |
| `Manifest fetch failed: …` | The target is not Alien-aware (or the manifest is malformed). Fall back to standard browsing. |

## Security guarantees

- Private keys stored with mode 0600 — never transmitted.
- Vault credentials encrypted with AES-256-GCM; key derived via HKDF from the agent's Ed25519 key.
- PKCE prevents authorization-code interception.
- Access tokens are short-lived (≤5 minutes).
- Hash-chained audit log — any tampering breaks the chain.
- Ed25519 SSH signatures on commits provide non-repudiation.
- Never expose `owner-session.json` or any file under `vault/`.
