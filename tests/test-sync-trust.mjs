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
import { fakeVerifyIdToken, makeIdentity as identity } from "./sync-test-helpers.mjs";

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
    pinDevice(sync, { deviceJkt: "j1", agentJwk: { kty: "OKP" }, label: "mba", ownerSub: "owner-1" });
    assert.deepEqual(findDevice(sync, "j1").agentJwk, { kty: "OKP" });
    assert.equal(findDevice(sync, "j1").ownerSub, "owner-1");
    assert.equal(sync.devices.length, 1);
    assert.equal(revokeDevice(sync, "j1"), true);
    assert.equal(findDevice(sync, "j1"), null);
  });

  it("pinDevice re-pin with a new ownerSub UPDATES the existing device (re-bind invariant)", () => {
    const sync = freshSync();
    const addedAt = 1000;
    pinDevice(sync, {
      deviceJkt: "j1",
      agentJwk: { kty: "OKP", x: "old" },
      label: "old-label",
      ownerSub: "owner-1",
      now: addedAt,
    });
    pinDevice(sync, {
      deviceJkt: "j1",
      agentJwk: { kty: "OKP", x: "new" },
      label: "new-label",
      ownerSub: "owner-2",
      now: 2000,
    });
    const device = findDevice(sync, "j1");
    assert.equal(device.ownerSub, "owner-2");
    assert.equal(device.label, "new-label");
    assert.deepEqual(device.agentJwk, { kty: "OKP", x: "new" });
    assert.equal(device.addedAt, addedAt, "addedAt must stay stable across re-pin");
    assert.equal(sync.devices.length, 1);
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

  it("rejects an expired id_token at first contact", async () => {
    const pastExp = Math.floor(Date.now() / 1000) - 3600;
    const a = identity("owner-1", "dev-a", { exp: pastExp });
    const ekm = randomBytes(32);
    const hello = buildHello({ identity: a, ekm, role: "initiator", peerNonce: "n", label: a.label });
    await assert.rejects(
      () => verifyHello({
        hello, ekm, peerRole: "initiator", ownNonce: "n",
        ownJkt: "x", ownOwnerSub: "owner-1", sync: freshSync(), verifyIdToken: fakeVerifyIdToken,
      }),
      (err) => err.code === "SYNC_PEER_TOKEN_EXPIRED",
    );
  });

  it("accepts a future-exp id_token at first contact", async () => {
    const futureExp = Math.floor(Date.now() / 1000) + 3600;
    const a = identity("owner-1", "dev-a", { exp: futureExp });
    const ekm = randomBytes(32);
    const hello = buildHello({ identity: a, ekm, role: "initiator", peerNonce: "n", label: a.label });
    const peer = await verifyHello({
      hello, ekm, peerRole: "initiator", ownNonce: "n",
      ownJkt: "x", ownOwnerSub: "owner-1", sync: freshSync(), verifyIdToken: fakeVerifyIdToken,
    });
    assert.equal(peer.ownerSub, "owner-1");
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
