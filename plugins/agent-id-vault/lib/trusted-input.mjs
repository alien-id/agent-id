// Alien Agent ID — back-compat re-export.
//
// The trusted-input channel (/dev/tty echo-off prompt) moved to core
// (@alien-id/agent-id-core/lib/trusted-input.mjs) so non-vault plugins and the
// core secure-prompt resolver can share it. This shim preserves the historical
// import path (`../lib/trusted-input.mjs` from the vault CLI; the proxy CLI's
// `@alien-id/agent-id-vault/lib/trusted-input.mjs`).
//
// It MUST re-export (never redefine) `TrustedInputUnavailable`: the vault CLI
// catches `err instanceof TrustedInputUnavailable`, which only holds if both
// sides reference the one class object from core.

export * from "@alien-id/agent-id-core/lib/trusted-input.mjs";
