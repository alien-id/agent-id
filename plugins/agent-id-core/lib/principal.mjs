// Canonical authorization principal for an Alien Agent ID key.
//
// Capability policies treat principals as opaque strings, but every local
// transport needs to derive the SAME value from the agent's public key. Keep
// that derivation in one pure helper so a later Frame service can reproduce it
// without depending on local state layout.

import { ed25519PublicKeyToJwk, jwkThumbprint } from "./crypto.mjs";

export function agentPrincipalFromPublicKeyPem(publicKeyPem) {
  return `agent:jkt:${jwkThumbprint(ed25519PublicKeyToJwk(publicKeyPem))}`;
}

