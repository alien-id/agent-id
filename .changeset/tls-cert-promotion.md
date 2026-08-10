---
"@alien-id/agent-id-core": minor
---

Add `lib/tls-cert.mjs`: the self-signed TLS certificate minter
(`generateControlCert`, `fingerprintOfCertPem`, `normalizeFingerprint`),
promoted from the proxy plugin so other plugins (vault p2p sync) can mint
ephemeral certs. The proxy re-exports it unchanged.
