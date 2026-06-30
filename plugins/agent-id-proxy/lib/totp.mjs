// Alien Agent ID — back-compat re-export.
//
// The RFC 6238 TOTP generator moved to core
// (@alien-id/agent-id-core/lib/totp.mjs) so the browser plugin can generate
// stored-TOTP codes during auto-login. This shim keeps the proxy's relative
// `./totp.mjs` imports (rewrite.mjs, stub.mjs) working unchanged.

export * from "@alien-id/agent-id-core/lib/totp.mjs";
