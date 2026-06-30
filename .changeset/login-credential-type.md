---
"@alien-id/agent-id-core": minor
"@alien-id/agent-id-vault": minor
---

Add a direct `login` credential type and a `set-totp` command, so a user can hand
the vault a service login + password once and have an agent log in later (driven
by `agent-id-browser auto-login`).

- **vault**: new `login` type (username, password, `otp: none|totp|interactive`,
  optional `totpSecret`, `loginUrl`, `profile`, `selectors`/`recipe`), kept
  distinct from HTTP `basic`. `domains` is advisory for this type (browser-driven,
  not proxy-injected) and defaults to the `loginUrl` host. `add --type login
  --form` captures username/password (and the 2FA seed when `--otp totp`) through
  the secure prompt, so they never enter the agent's transcript.
- **vault**: new `set-totp --name N [--form]` attaches or updates a 2FA seed on an
  existing `login` (or `totp`) credential — for the common case where 2FA is
  enabled *after* the login was first stored. It accepts a raw base32 secret or a
  full `otpauth://` URI, entered out-of-band via the secure prompt.
- **vault**: `add --form` now routes through the secure-prompt resolver, so it
  works where no GUI browser is present (falls back to `/dev/tty` or a hosted
  harness form).
- **core**: `totp.mjs` gains `validateBase32Secret`, `parseOtpauthUri`, and
  `normalizeTotpInput` (raw secret or `otpauth://` → normalized seed). The
  secure-prompt resolver gains an `AGENT_ID_SECURE_PROMPT=browser|tty|hosted`
  operator override to pin a backend.
