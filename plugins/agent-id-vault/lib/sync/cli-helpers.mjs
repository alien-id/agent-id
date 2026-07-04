// Pure helpers for the vault sync CLI, kept out of bin/cli.mjs so the
// entrypoint has no reason to guard its top-level dispatch behind
// `import.meta.main` just to be importable from tests.

import { SECRET_FIELDS } from "../store.mjs";

// Redact every secret-bearing field on a credential record before it is printed.
// Used by `sync resolve` (no --restore) so the journaled *losing* record can be
// inspected without leaking refreshToken/clientSecret/accessToken (oauth2),
// password/totpSecret (login), privateKey (evm), secretSeed (solana), etc.
// Pure: returns a shallow copy; the input is left untouched.
export function redactSecretFields(rec) {
  const redacted = { ...rec };
  for (const f of SECRET_FIELDS) {
    if (redacted[f] != null) redacted[f] = "(redacted — use --restore)";
  }
  return redacted;
}

// Validate the --listen --port flag. parseFlags yields boolean `true` for a bare
// flag (last, or followed by another --flag); Number(true) === 1 would silently
// bind port 1, so a boolean or non-digit value must be rejected. Returns 0 when
// absent (ephemeral OS-assigned port). Throws Error (message names --port) so
// the caller can outputError.
export function parseListenPort(flags) {
  if (flags.port == null) return 0;
  if (typeof flags.port !== "string" || !/^[0-9]+$/.test(flags.port)) {
    throw new Error("--port must be a number (0–65535)");
  }
  const port = Number(flags.port);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error("--port must be a number (0–65535)");
  }
  return port;
}
