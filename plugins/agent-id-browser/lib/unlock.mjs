// Alien Agent ID — Owner-approval ("approve in the Alien app") vault unlock.
//
// Lets a CLI unlock the vault the same way the proxy does for a locked request —
// by driving the owner-approval SSO pull flow — WITHOUT needing a control-plane
// server (the proxy only needs one because it parks inbound HTTP requests; a CLI
// can talk to the SSO and open the vault directly):
//
//   readOwnerApprovalChallenge → owner session (SignatureEngine) →
//   requestUnlockSecret (prompts the Alien app, polls) →
//   recoverMasterKeyViaOwnerApproval → openVaultWithMasterKey
//
// (Mobile-slot unlock is intentionally NOT here: the phone POSTs the sealed
// master key to a control plane, which only the long-running proxy exposes.)

import { SignatureEngine } from "@alien-id/agent-id-core/lib/signature-engine.mjs";
import { requestUnlockSecret } from "@alien-id/agent-id-vault/lib/owner-approval.mjs";
import {
  readOwnerApprovalChallenge,
  recoverMasterKeyViaOwnerApproval,
  openVaultWithMasterKey,
} from "@alien-id/agent-id-vault/lib/vault.mjs";

// Cheap check (no unlock): does the vault have an owner-approval slot?
export async function hasOwnerApproval(stateDir) {
  return (await readOwnerApprovalChallenge(stateDir)) != null;
}

// Drive the app approval and return an unlocked vault handle. Throws (with a
// code) if no slot / no agent key / no owner session / approval failed/timed out.
export async function unlockViaOwnerApproval({ stateDir, onPrompt }) {
  const challenge = await readOwnerApprovalChallenge(stateDir);
  if (!challenge) {
    const e = new Error("vault has no owner-approval slot");
    e.code = "NO_OWNER_APPROVAL";
    throw e;
  }

  const engine = new SignatureEngine({ baseDir: stateDir });
  const main = await engine.ensureMainKey().catch(() => null);
  if (!main?.privateKeyPem) {
    const e = new Error("no agent key — run `agent-id-core bootstrap`");
    e.code = "NO_AGENT_KEY";
    throw e;
  }

  const session = await engine.ensureValidSession().catch(() => null);
  if (!session?.accessToken) {
    const e = new Error("no valid owner session — run `agent-id-core auth`");
    e.code = "NO_OWNER_SESSION";
    throw e;
  }

  // SECURITY: pin the SSO to the locally-trusted owner session, never the vault
  // slot's ssoBaseUrl (slot fields are cleartext outside the AEAD wrap). Mirrors
  // the proxy's owner-approval approver.
  const ssoBaseUrl = session.ssoBaseUrl || session.issuer;
  if (!ssoBaseUrl) {
    const e = new Error("owner session has no SSO URL");
    e.code = "NO_SSO_URL";
    throw e;
  }

  let secret = null;
  try {
    ({ secret } = await requestUnlockSecret({
      ssoBaseUrl,
      accessToken: session.accessToken,
      agentPrivateKeyPem: main.privateKeyPem,
      keyRef: challenge.keyRef,
      onPrompt,
    }));
    const masterKey = await recoverMasterKeyViaOwnerApproval(stateDir, secret);
    // openVaultWithMasterKey takes ownership of masterKey (held in the handle and
    // zeroed by vault.lock()); do NOT zero it here.
    return await openVaultWithMasterKey({ stateDir, masterKey });
  } finally {
    if (secret) secret.fill(0);
  }
}
