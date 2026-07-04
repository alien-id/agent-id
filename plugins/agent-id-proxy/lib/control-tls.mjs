// Moved to agent-id-core (lib/tls-cert.mjs) so vault p2p sync can mint certs
// without importing from the proxy (dependency direction is proxy → vault →
// core). This shim keeps existing proxy imports working.
export * from "@alien-id/agent-id-core/lib/tls-cert.mjs";
