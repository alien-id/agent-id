// Alien Agent ID — Passkey ceremony drivers (CLI side).
//
// Run the WebAuthn PRF ceremony through the secure form and hand back the bits the
// vault needs. The browser does the actual WebAuthn (Touch ID / Face ID / security
// key); this process only ever receives the PRF secret (the key-derivation input)
// over the loopback form, never the authenticator itself.

import { collectViaForm } from "@alien-id/agent-id-core/lib/secure-form.mjs";
import { generatePasskeyPrfSalt } from "./format.mjs";

const REG_SECURITY =
  "Your authenticator returns a secret only after you verify (biometric); the vault key is derived " +
  "from it via <code>HKDF-SHA256</code> and the agent never sees it.";
const AUTH_SECURITY =
  "Your authenticator releases the key-derivation secret only after you verify; the agent never sees it.";

// Enroll a new passkey. Opens the form, runs create() (+ a get() if the
// authenticator only evaluates PRF on assertion), and returns everything needed
// to build a passkey slot. `prfSecret` is a Buffer; the rest are stored in the slot.
export async function registerPasskey({ deviceLabel = null, userName = "vault" } = {}) {
  const prfSalt = generatePasskeyPrfSalt();
  const { values } = await collectViaForm({
    title: "Create a passkey for your vault",
    description: "Touch ID / Face ID / security key — unlocks the vault without a password.",
    security: REG_SECURITY,
    submitLabel: "Create passkey",
    label: "create a vault passkey",
    webauthn: { mode: "register", rpName: "Alien Vault", userName, prfSalt },
  });
  if (!values.prfSecret || !values.credentialId) {
    throw new Error("passkey registration returned no PRF secret (authenticator lacks passkey-PRF support?)");
  }
  return {
    prfSecret: Buffer.from(values.prfSecret, "hex"),
    credentialId: values.credentialId,
    rpId: values.rpId || "localhost",
    prfSalt,
    deviceLabel,
  };
}

// Unlock with an existing passkey slot (its descriptor from readPasskeyChallenges).
// Opens the form, runs get(), returns the PRF secret (Buffer) to unwrap the slot.
export async function authenticatePasskey(challenge) {
  const { values } = await collectViaForm({
    title: "Unlock your vault",
    description: "Verify with Touch ID / Face ID / your security key.",
    security: AUTH_SECURITY,
    submitLabel: "Unlock vault",
    label: "unlock the vault with your passkey",
    webauthn: {
      mode: "authenticate",
      credentialId: challenge.credentialId,
      rpId: challenge.rpId,
      prfSalt: challenge.prfSalt,
    },
  });
  if (!values.prfSecret) throw new Error("passkey unlock returned no PRF secret");
  return Buffer.from(values.prfSecret, "hex");
}
