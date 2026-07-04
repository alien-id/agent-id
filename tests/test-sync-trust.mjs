#!/usr/bin/env node

// Tests for sync trust: device pinning, hello channel-binding signature,
// owner-match verification, approval preconditions.
// Run: node --test tests/test-sync-trust.mjs

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import {
  ed25519PublicKeyToJwk,
  generateEd25519PemPair,
  jwkThumbprint,
} from "../plugins/agent-id-core/lib/crypto.mjs";
import {
  buildHello,
  ensureSyncMeta,
  findDevice,
  pinDevice,
  revokeDevice,
  verifyHello,
} from "../plugins/agent-id-vault/lib/sync/trust.mjs";

// A "bound" test identity: fake id_token whose payload carries sub + cnf.jkt.
// verifyBundle receives our injected verifyIdToken, so no real SSO/JWKS is hit.
function identity(sub, label) {
  const pair = generateEd25519PemPair();
  const agentJwk = ed25519PublicKeyToJwk(pair.publicKeyPem);
  const jkt = jwkThumbprint(agentJwk);
  const payload = { iss: "https://sso.test", sub, cnf: { jkt } };
  const idToken = ["e30", Buffer.from(JSON.stringify(payload)).toString("base64url"), "sig"].join(".");
  return { privateKeyPem: pair.privateKeyPem, agentJwk, jkt, idToken, ownerSub: sub, label };
}

// Injected verifier: trusts the token body (signature is out of scope here —
// verifyBundle's structural checks + cnf.jkt binding still run for real).
const fakeVerifyIdToken = async ({ idToken }) => {
  const payload = JSON.parse(Buffer.from(idToken.split(".")[1], "base64url").toString("utf8"));
  return { signatureValid: true, issuer: payload.iss, payload, header: { alg: "RS256" } };
};

function freshSync() {
  return ensureSyncMeta({ version: 1, credentials: [] });
}

describe("sync trust", () => {
  it("ensureSyncMeta creates and preserves the sync section", () => {
    const payload = { version: 1, credentials: [] };
    const sync = ensureSyncMeta(payload);
    assert.deepEqual(sync, { oplog: [], devices: [], conflicts: [] });
    sync.devices.push({ deviceJkt: "x" });
    assert.equal(ensureSyncMeta(payload).devices.length, 1);
  });

  it("pinDevice / findDevice / revokeDevice round-trip; pin fills a preapproved stub", () => {
    const sync = freshSync();
    pinDevice(sync, { deviceJkt: "j1" }); // headless preapproval: jkt only
    assert.equal(findDevice(sync, "j1").agentJwk, null);
    pinDevice(sync, { deviceJkt: "j1", agentJwk: { kty: "OKP" }, label: "mba" });
    assert.deepEqual(findDevice(sync, "j1").agentJwk, { kty: "OKP" });
    assert.equal(sync.devices.length, 1);
    assert.equal(revokeDevice(sync, "j1"), true);
    assert.equal(findDevice(sync, "j1"), null);
  });

  it("hello round-trips against the same EKM and fails on a different EKM (MITM)", async () => {
    const a = identity("owner-1", "dev-a");
    const ekm = randomBytes(32);
    const nonce = "n-from-b";
    const hello = buildHello({ identity: a, ekm, role: "initiator", peerNonce: nonce, label: a.label });
    const sync = freshSync();
    const peer = await verifyHello({
      hello, ekm, peerRole: "initiator", ownNonce: nonce,
      ownJkt: "not-a", ownOwnerSub: "owner-1", sync, verifyIdToken: fakeVerifyIdToken,
    });
    assert.equal(peer.jkt, a.jkt);
    assert.equal(peer.pinned, false);
    assert.equal(peer.ownerSub, "owner-1");
    await assert.rejects(
      () => verifyHello({
        hello, ekm: randomBytes(32), peerRole: "initiator", ownNonce: nonce,
        ownJkt: "not-a", ownOwnerSub: "owner-1", sync, verifyIdToken: fakeVerifyIdToken,
      }),
      (err) => err.code === "SYNC_HELLO_BAD_SIG",
    );
  });

  it("rejects owner mismatch and self-connection", async () => {
    const a = identity("owner-1", "dev-a");
    const ekm = randomBytes(32);
    const hello = buildHello({ identity: a, ekm, role: "listener", peerNonce: "n", label: a.label });
    await assert.rejects(
      () => verifyHello({
        hello, ekm, peerRole: "listener", ownNonce: "n",
        ownJkt: "x", ownOwnerSub: "owner-OTHER", sync: freshSync(), verifyIdToken: fakeVerifyIdToken,
      }),
      (err) => err.code === "SYNC_OWNER_MISMATCH",
    );
    await assert.rejects(
      () => verifyHello({
        hello, ekm, peerRole: "listener", ownNonce: "n",
        ownJkt: a.jkt, ownOwnerSub: "owner-1", sync: freshSync(), verifyIdToken: fakeVerifyIdToken,
      }),
      (err) => err.code === "SYNC_SELF_CONNECT",
    );
  });

  it("rejects an unbound (L0) peer", async () => {
    const pair = generateEd25519PemPair();
    const l0 = {
      privateKeyPem: pair.privateKeyPem,
      agentJwk: ed25519PublicKeyToJwk(pair.publicKeyPem),
      jkt: jwkThumbprint(ed25519PublicKeyToJwk(pair.publicKeyPem)),
      idToken: null, ownerSub: null, label: "l0",
    };
    const ekm = randomBytes(32);
    const hello = buildHello({ identity: l0, ekm, role: "initiator", peerNonce: "n", label: "l0" });
    await assert.rejects(
      () => verifyHello({
        hello, ekm, peerRole: "initiator", ownNonce: "n",
        ownJkt: "x", ownOwnerSub: "owner-1", sync: freshSync(), verifyIdToken: fakeVerifyIdToken,
      }),
      (err) => err.code === "SYNC_PEER_UNBOUND",
    );
  });

  it("a pinned peer skips id_token verification entirely (offline path)", async () => {
    const a = identity("owner-1", "dev-a");
    const ekm = randomBytes(32);
    const hello = buildHello({ identity: a, ekm, role: "initiator", peerNonce: "n", label: a.label });
    const sync = freshSync();
    pinDevice(sync, { deviceJkt: a.jkt, agentJwk: a.agentJwk, label: "dev-a", ownerSub: "owner-1" });
    let called = false;
    const peer = await verifyHello({
      hello, ekm, peerRole: "initiator", ownNonce: "n",
      ownJkt: "x", ownOwnerSub: "owner-1", sync,
      verifyIdToken: async () => { called = true; throw new Error("network"); },
    });
    assert.equal(peer.pinned, true);
    assert.equal(called, false);
  });
});
