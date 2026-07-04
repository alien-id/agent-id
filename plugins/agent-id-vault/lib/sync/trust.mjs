// Alien Agent ID — Vault sync trust layer.
//
// WHO a peer is: its agent Ed25519 key, proven live by a signature over the
// TLS session's exported keying material (RFC 5705) — a MITM terminating two
// TLS legs sees two different EKMs, so a relayed hello never verifies.
// WHETHER it may sync: it must be pinned in this device's trust list. The
// first contact requires the peer to be bound to the SAME owner (v3 bundle,
// SSO id_token, cnf.jkt) plus a one-time human approval; after pinning, the
// key alone authenticates and no SSO/JWKS access is needed (offline path).

import os from "node:os";

import {
  canonicalJSONString,
  ed25519PublicKeyToJwk,
  jwkThumbprint,
  nowMs,
  signEd25519Base64Url,
  verifyEd25519Base64Url,
} from "@alien-id/agent-id-core/lib/crypto.mjs";
import { buildV3Bundle, parseBundle, verifyBundle } from "@alien-id/agent-id-core/lib/bundle.mjs";
import { parseJwt } from "@alien-id/agent-id-core/lib/oidc.mjs";
import { readJsonFile, statePaths } from "@alien-id/agent-id-core/lib/state.mjs";

import { jwkToPublicKeyPem } from "./oplog.mjs";

export const SYNC_EKM_LABEL = "agent-id-vault-sync-v1";

function codedError(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

// ─── Sync metadata inside the encrypted payload ─────────────────────────────────

export function ensureSyncMeta(payload) {
  if (!payload.sync || typeof payload.sync !== "object") payload.sync = {};
  const sync = payload.sync;
  if (!Array.isArray(sync.oplog)) sync.oplog = [];
  if (!Array.isArray(sync.devices)) sync.devices = [];
  if (!Array.isArray(sync.conflicts)) sync.conflicts = [];
  return sync;
}

export function findDevice(sync, jkt) {
  return sync.devices.find((d) => d.deviceJkt === jkt) || null;
}

// Pin (or complete) a trusted device. A headless preapproval pins the jkt
// alone (agentJwk null); the jwk is filled in on the next verified hello.
export function pinDevice(sync, { deviceJkt, agentJwk = null, label = null, ownerSub = null, now = nowMs() }) {
  const existing = findDevice(sync, deviceJkt);
  if (existing) {
    if (!existing.agentJwk && agentJwk) existing.agentJwk = agentJwk;
    if (!existing.label && label) existing.label = label;
    if (!existing.ownerSub && ownerSub) existing.ownerSub = ownerSub;
    return existing;
  }
  const device = { deviceJkt, agentJwk, label, ownerSub, addedAt: now };
  sync.devices.push(device);
  return device;
}

export function revokeDevice(sync, jkt) {
  const before = sync.devices.length;
  sync.devices = sync.devices.filter((d) => d.deviceJkt !== jkt);
  return sync.devices.length !== before;
}

// ─── Local identity ─────────────────────────────────────────────────────────────

export async function loadSyncIdentity(stateDir, { label = os.hostname() } = {}) {
  const paths = statePaths(stateDir);
  const key = await readJsonFile(paths.mainKey, null);
  if (!key?.privateKeyPem || !key?.publicKeyPem) {
    throw codedError("SYNC_NO_AGENT_KEY", "No agent keypair. Run `agent-id-core bootstrap` first.");
  }
  const session = await readJsonFile(paths.ownerSession, null);
  if (!session?.idToken) {
    throw codedError(
      "SYNC_NOT_BOUND",
      "vault sync requires an owner binding (L1+) — run `agent-id-core auth` first",
    );
  }
  let ownerSub = null;
  try {
    ownerSub = parseJwt(session.idToken).payload?.sub || null;
  } catch {
    ownerSub = null;
  }
  if (!ownerSub) {
    throw codedError("SYNC_NOT_BOUND", "owner session id_token has no sub claim");
  }
  const agentJwk = ed25519PublicKeyToJwk(key.publicKeyPem);
  return {
    privateKeyPem: key.privateKeyPem,
    agentJwk,
    jkt: jwkThumbprint(agentJwk),
    idToken: session.idToken,
    ownerSub,
    label,
  };
}

// ─── Hello (identity handshake message) ─────────────────────────────────────────

// Both sides sign their OWN view of the channel: EKM + own role + the nonce
// the PEER sent. The verifier reconstructs it from its own EKM export, the
// peer's expected role, and the nonce it generated.
function helloSigningPayload({ ekmHex, role, nonce }) {
  return canonicalJSONString({ v: 1, purpose: SYNC_EKM_LABEL, ekm: ekmHex, role, nonce });
}

export function buildHello({ identity, ekm, role, peerNonce, label = null }) {
  const bundle = buildV3Bundle({ idToken: identity.idToken, agentJwk: identity.agentJwk });
  const sig = signEd25519Base64Url(
    helloSigningPayload({ ekmHex: ekm.toString("hex"), role, nonce: peerNonce }),
    identity.privateKeyPem,
  );
  return { t: "hello", label, bundle, sig };
}

export async function verifyHello({
  hello,
  ekm,
  peerRole,
  ownNonce,
  ownJkt,
  ownOwnerSub,
  sync,
  verifyIdToken,
}) {
  const parsed = parseBundle(hello.bundle);
  const agentJwk = parsed.agent_jwk;
  const jkt = jwkThumbprint(agentJwk);

  const expected = helloSigningPayload({ ekmHex: ekm.toString("hex"), role: peerRole, nonce: ownNonce });
  let sigOk = false;
  try {
    sigOk = verifyEd25519Base64Url(expected, hello.sig, jwkToPublicKeyPem(agentJwk));
  } catch {
    sigOk = false;
  }
  if (!sigOk) {
    throw codedError(
      "SYNC_HELLO_BAD_SIG",
      "peer hello signature does not match this TLS session's channel binding",
    );
  }
  if (jkt === ownJkt) {
    throw codedError("SYNC_SELF_CONNECT", "peer presented this device's own agent key");
  }

  const pinned = findDevice(sync, jkt);
  if (pinned && pinned.agentJwk) {
    return { jkt, agentJwk, label: hello.label || pinned.label || null, pinned: true, preapproved: false };
  }

  // First contact (or a jkt-only preapproval): full owner-binding check. This
  // is the only path that may touch the network (SSO JWKS) — routine syncs
  // between pinned devices never reach here.
  const verified = await verifyBundle(parsed, { verifyIdToken });
  if (!verified.ownerSub) {
    throw codedError("SYNC_PEER_UNBOUND", "peer agent has no owner binding (L0) — sync requires L1+");
  }
  if (verified.ownerSub !== ownOwnerSub) {
    throw codedError("SYNC_OWNER_MISMATCH", "peer is bound to a different owner");
  }
  return {
    jkt,
    agentJwk,
    label: hello.label || null,
    pinned: false,
    preapproved: Boolean(pinned),
    ownerSub: verified.ownerSub,
    level: verified.level,
  };
}
