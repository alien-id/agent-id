#!/usr/bin/env node

// End-to-end acceptance tests for vault p2p sync, per the spec's Testing §3-4:
//   - a legacy (pre-sync) vault migrates via genesis ops on first sync
//   - a 3-device full mesh converges
//   - revocation blocks a formerly trusted peer
// Uses the same in-process loopback harness as test-sync-protocol.mjs.
// Run: node --test tests/test-sync-e2e.mjs

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";

import { connectToPeer, startSyncServer } from "../plugins/agent-id-vault/lib/sync/channel.mjs";
import { revokeDevice, ensureSyncMeta } from "../plugins/agent-id-vault/lib/sync/trust.mjs";
import { runSyncSession } from "../plugins/agent-id-vault/lib/sync/protocol.mjs";
import { fakeVerifyIdToken, makeDevice, openDevice as open } from "./sync-test-helpers.mjs";

async function syncPair(listener, initiator) {
  const l = await open(listener);
  const i = await open(initiator);
  let settle;
  const done = new Promise((resolve, reject) => { settle = { resolve, reject }; });
  const srv = await startSyncServer({
    host: "127.0.0.1",
    onSession: (session) =>
      runSyncSession({ session, vault: l.vault, identity: l.identity, approvePeer: async () => true, verifyIdToken: fakeVerifyIdToken })
        .then(settle.resolve, settle.reject),
  });
  try {
    const session = await connectToPeer({ host: "127.0.0.1", port: srv.port });
    const initiatorSummary = await runSyncSession({
      session, vault: i.vault, identity: i.identity, approvePeer: async () => true, verifyIdToken: fakeVerifyIdToken,
    });
    return { initiatorSummary, listenerSummary: await done };
  } finally {
    await srv.close();
  }
}

async function names(device) {
  const { vault } = await open(device);
  return vault.list().map((c) => c.name).sort();
}

describe("sync e2e", () => {
  let a, b, c;
  before(async () => {
    a = await makeDevice("owner-1", "a");
    b = await makeDevice("owner-1", "b");
    c = await makeDevice("owner-1", "c");
  });
  after(async () => {
    for (const d of [a, b, c]) await fs.rm(d.stateDir, { recursive: true, force: true });
  });

  it("legacy vault contents migrate as genesis ops on first sync", async () => {
    // Populate A entirely through the NORMAL vault API — no sync code involved,
    // exactly like a vault that predates the sync feature.
    const opened = await open(a);
    opened.vault.add({ name: "legacy-1", type: "bearer", value: "v1", domains: ["x.com"] });
    opened.vault.add({ name: "legacy-2", type: "basic", username: "u", password: "p", domains: ["y.com"] });
    opened.vault.add({
      name: "local-browser", type: "browser-profile", domains: ["*"],
      dek: "a".repeat(64), profileFile: "p.enc",
    });
    await opened.vault.save();

    await syncPair(a, b);
    // Credentials crossed; the device-local browser-profile did NOT.
    assert.deepEqual(await names(b), ["legacy-1", "legacy-2"]);
    assert.deepEqual(await names(a), ["legacy-1", "legacy-2", "local-browser"]);
  });

  it("a 3-device full mesh converges", async () => {
    {
      const opened = await open(c);
      opened.vault.add({ name: "from-c", type: "bearer", value: "vc", domains: ["c.com"] });
      await opened.vault.save();
    }
    // Pairing order matters (full-mesh requirement): a device accepts a
    // RELAYED op only if its author is already pinned. So c must sync with a
    // DIRECTLY before any peer relays a-authored ops to it. Direct sessions
    // always pin the counterparty during the approval step, so a↔c first:
    await syncPair(a, c); // pairs a↔c; c gets a-authored ops, a gets from-c
    await syncPair(b, c); // pairs b↔c; b gets from-c (c-authored, pinned in-session)
    await syncPair(a, b); // no-op convergence check
    const [na, nb, nc] = await Promise.all([names(a), names(b), names(c)]);
    assert.deepEqual(nb, nc);
    assert.deepEqual(na.filter((n) => n !== "local-browser"), nb);
    assert.ok(nb.includes("from-c") && nb.includes("legacy-1"));
  });

  it("a revoked device is refused", async () => {
    {
      const opened = await open(a);
      revokeDevice(ensureSyncMeta(opened.vault.payload()), c.jkt);
      await opened.vault.save();
    }
    // c is unpinned on a → approval gate fires; refuse it.
    const l = await open(a);
    let settle;
    const done = new Promise((resolve, reject) => { settle = { resolve, reject }; });
    done.catch(() => {}); // rejection is asserted below, after the initiator throws
    const srv = await startSyncServer({
      host: "127.0.0.1",
      onSession: (session) =>
        runSyncSession({ session, vault: l.vault, identity: l.identity, approvePeer: async () => false, verifyIdToken: fakeVerifyIdToken })
          .then(settle.resolve, settle.reject),
    });
    try {
      const i = await open(c);
      const session = await connectToPeer({ host: "127.0.0.1", port: srv.port });
      await assert.rejects(
        () => runSyncSession({ session, vault: i.vault, identity: i.identity, approvePeer: async () => true, verifyIdToken: fakeVerifyIdToken }),
        (err) => err.code === "approval-required" || err.code === "peer-error",
      );
      await assert.rejects(() => done, (err) => err.code === "approval-required");
    } finally {
      await srv.close();
    }
  });
});
