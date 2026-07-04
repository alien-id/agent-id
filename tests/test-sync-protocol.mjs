#!/usr/bin/env node

// In-process end-to-end tests of the sync protocol over a real loopback TLS
// channel: pairing with approval, bidirectional op transfer, convergence,
// tombstones, conflict journaling, refusal paths, and the vault lock.
// Run: node --test tests/test-sync-protocol.mjs

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";

import { connectToPeer, startSyncServer } from "../plugins/agent-id-vault/lib/sync/channel.mjs";
import { buildHello, ensureSyncMeta } from "../plugins/agent-id-vault/lib/sync/trust.mjs";
import { createOp, findHeads } from "../plugins/agent-id-vault/lib/sync/oplog.mjs";
import { runSyncSession } from "../plugins/agent-id-vault/lib/sync/protocol.mjs";
import { withVaultLock } from "../plugins/agent-id-vault/lib/sync/lock.mjs";
import { fakeVerifyIdToken, makeDevice, openDevice } from "./sync-test-helpers.mjs";

// One full sync between two devices over loopback TLS. approve defaults to yes.
async function syncOnce(devA, devB, { approveA = async () => true, approveB = async () => true } = {}) {
  const a = await openDevice(devA);
  const b = await openDevice(devB);
  let listenerResult;
  const listenerDone = new Promise((resolve, reject) => {
    listenerResult = { resolve, reject };
  });
  listenerDone.catch(() => {}); // refusal tests reject this after the initiator throws
  const srv = await startSyncServer({
    host: "127.0.0.1",
    onSession: (session) => {
      runSyncSession({ session, vault: a.vault, identity: a.identity, approvePeer: approveA, verifyIdToken: fakeVerifyIdToken })
        .then(listenerResult.resolve, listenerResult.reject);
    },
  });
  try {
    const session = await connectToPeer({ host: "127.0.0.1", port: srv.port });
    const initiatorSummary = await runSyncSession({
      session, vault: b.vault, identity: b.identity, approvePeer: approveB, verifyIdToken: fakeVerifyIdToken,
    });
    const listenerSummary = await listenerDone;
    return { initiatorSummary, listenerSummary };
  } finally {
    await srv.close();
  }
}

async function credNames(device) {
  const { vault } = await openDevice(device);
  return vault.list().map((c) => c.name).sort();
}

describe("sync protocol", () => {
  let devA, devB;
  before(async () => {
    devA = await makeDevice("owner-1", "dev-a");
    devB = await makeDevice("owner-1", "dev-b");
  });
  after(async () => {
    for (const d of [devA, devB]) await fs.rm(d.stateDir, { recursive: true, force: true });
  });

  it("first sync pairs both devices and transfers divergent records both ways", async () => {
    {
      const { vault } = await openDevice(devA);
      vault.add({ name: "gh-pat", type: "bearer", value: "tok-a", domains: ["api.github.com"] });
      await vault.save();
    }
    {
      const { vault } = await openDevice(devB);
      vault.add({ name: "npm-token", type: "bearer", value: "tok-b", domains: ["registry.npmjs.org"] });
      await vault.save();
    }
    const { initiatorSummary } = await syncOnce(devA, devB);
    assert.ok(initiatorSummary.received >= 1);
    assert.deepEqual(await credNames(devA), ["gh-pat", "npm-token"]);
    assert.deepEqual(await credNames(devB), ["gh-pat", "npm-token"]);
  });

  it("a remove on one device tombstones on the other", async () => {
    {
      const { vault } = await openDevice(devA);
      vault.remove("npm-token");
      await vault.save();
    }
    await syncOnce(devA, devB);
    assert.deepEqual(await credNames(devB), ["gh-pat"]);
  });

  it("concurrent edits of one record converge and journal the loser", async () => {
    {
      const { vault } = await openDevice(devA);
      vault.add({ name: "gh-pat", type: "bearer", value: "from-A", domains: ["api.github.com"] });
      await vault.save();
    }
    {
      const { vault } = await openDevice(devB);
      vault.add({ name: "gh-pat", type: "bearer", value: "from-B", domains: ["api.github.com"] });
      await vault.save();
    }
    await syncOnce(devA, devB);
    const a = await openDevice(devA);
    const b = await openDevice(devB);
    assert.equal(a.vault.get("gh-pat").value, b.vault.get("gh-pat").value);
    const journal = a.vault.payload().sync.conflicts;
    assert.equal(journal.length, 1);
    assert.equal(journal[0].name, "gh-pat");
    const winner = a.vault.get("gh-pat").value;
    assert.equal(journal[0].losingRecord.value, winner === "from-A" ? "from-B" : "from-A");
  });

  it("an unapproved peer is refused with approval-required and nothing changes", async () => {
    const devC = await makeDevice("owner-1", "dev-c");
    try {
      await assert.rejects(
        () => syncOnce(devA, devC, { approveA: async () => false }),
        (err) => err.code === "approval-required",
      );
      assert.deepEqual(await credNames(devC), []);
    } finally {
      await fs.rm(devC.stateDir, { recursive: true, force: true });
    }
  });

  it("a different-owner peer is refused with SYNC_OWNER_MISMATCH", async () => {
    const devX = await makeDevice("owner-EVIL", "dev-x");
    try {
      await assert.rejects(
        () => syncOnce(devA, devX),
        (err) => err.code === "SYNC_OWNER_MISMATCH" || err.code === "peer-error",
      );
    } finally {
      await fs.rm(devX.stateDir, { recursive: true, force: true });
    }
  });

  it("withVaultLock serializes and reports VAULT_BUSY when exhausted", async () => {
    await withVaultLock(devA.stateDir, async () => {
      await assert.rejects(
        () => withVaultLock(devA.stateDir, async () => {}, { retries: 1, delayMs: 10 }),
        (err) => err.code === "VAULT_BUSY",
      );
    });
    // lock released → works again
    await withVaultLock(devA.stateDir, async () => {});
  });

  // F7: the listener must verify the initiator BEFORE disclosing its own hello.
  // A hello embeds the full SSO id_token (owner sub, issuer, all OIDC claims),
  // so a peer that fails verification must never receive the listener's hello.
  it("listener refuses an unverifiable peer WITHOUT disclosing its own hello", async () => {
    // dev-evil has a different owner → the listener's verifyHello throws
    // SYNC_OWNER_MISMATCH and must write {t:"error"} before ever sending hello.
    const devEvil = await makeDevice("owner-EVIL", "dev-evil");
    try {
      const a = await openDevice(devA); // listener, our real owner
      const evil = await openDevice(devEvil); // manual initiator
      let resolveListener, rejectListener;
      const listenerDone = new Promise((resolve, reject) => { resolveListener = resolve; rejectListener = reject; });
      listenerDone.catch(() => {}); // we assert its rejection below; pre-attach to avoid an unhandled-rejection warning
      const srv = await startSyncServer({
        host: "127.0.0.1",
        onSession: (session) => {
          runSyncSession({ session, vault: a.vault, identity: a.identity, verifyIdToken: fakeVerifyIdToken })
            .then(resolveListener, rejectListener);
        },
      });
      try {
        const session = await connectToPeer({ host: "127.0.0.1", port: srv.port });
        const { io, ekm } = session;
        // Drive the initiator side of the handshake manually so we can observe
        // exactly what frames the listener sends back after our hello.
        const ownNonce = "aa".repeat(16);
        io.write({ t: "nonce", nonce: ownNonce });
        const peerNonce = String((await io.read()).nonce || "");
        io.write(buildHello({ identity: evil.identity, ekm, role: "initiator", peerNonce, label: "dev-evil" }));

        // Collect every subsequent frame until the socket closes. The listener
        // must send {t:"error"} and MUST NOT send a {t:"hello"}.
        const frames = [];
        try {
          // read() rejects when the connection closes; loop until then.
          // eslint-disable-next-line no-constant-condition
          while (true) frames.push(await io.read());
        } catch { /* connection closed by the listener after error */ }

        assert.ok(
          frames.some((f) => f.t === "error"),
          "listener must send {t:'error'} to the unverified peer",
        );
        assert.ok(
          !frames.some((f) => f.t === "hello"),
          "listener must NOT disclose its hello (id_token) to an unverified peer",
        );
        await assert.rejects(listenerDone, (err) => err.code === "SYNC_OWNER_MISMATCH");
      } finally {
        await srv.close();
      }
    } finally {
      await fs.rm(devEvil.stateDir, { recursive: true, force: true });
    }
  });

  // F6: an incoming op carrying a schema-invalid record is refused with
  // 'invalid-record' before it can reach the vault — even though the op is
  // validly signed by a pinned device.
  it("refuses an incoming op with an invalid record and leaves the vault unchanged", async () => {
    const devP = await makeDevice("owner-1", "dev-p"); // receiver
    const devQ = await makeDevice("owner-1", "dev-q"); // sender, injects a bad op
    try {
      // 1. Seed the receiver with a known credential and pin the two devices to
      //    each other via one clean sync (so dev-q's later op has an author).
      {
        const { vault } = await openDevice(devP);
        vault.add({ name: "keep-me", type: "bearer", value: "safe", domains: ["api.example.com"] });
        await vault.save();
      }
      await syncOnce(devP, devQ);
      const before = await credNames(devP);
      assert.ok(before.includes("keep-me"));

      // 2. On dev-q, forge a validly-SIGNED op whose record is schema-invalid
      //    (bearer with no `value`). createOp signs whatever it's given; it does
      //    not validate — the receiver's staging loop must catch this.
      {
        const { vault, identity } = await openDevice(devQ);
        const sync = ensureSyncMeta(vault.payload());
        const badOp = createOp({
          parents: findHeads(sync.oplog),
          device: identity.jkt,
          kind: "add",
          name: "evil-cred",
          record: { name: "evil-cred", type: "bearer", domains: ["api.example.com"] }, // no `value`
          privateKeyPem: identity.privateKeyPem,
        });
        sync.oplog.push(badOp);
        await vault.save();
      }

      // 3. Sync — the receiver must refuse the malformed op with 'invalid-record'.
      await assert.rejects(
        () => syncOnce(devP, devQ),
        (err) => err.code === "invalid-record" || err.code === "peer-error",
      );

      // 4. The receiver's credential set is unchanged: no evil-cred landed.
      const after = await credNames(devP);
      assert.deepEqual(after, before);
      assert.ok(!after.includes("evil-cred"));
    } finally {
      await fs.rm(devP.stateDir, { recursive: true, force: true });
      await fs.rm(devQ.stateDir, { recursive: true, force: true });
    }
  });
});
