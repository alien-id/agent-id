#!/usr/bin/env node

// Tests for the vault sync op-log: hashing, signatures, DAG heads, merge,
// deterministic fold (causal LWW + concurrent tiebreak + conflicts).
// Run: node --test tests/test-sync-oplog.mjs

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  ed25519PublicKeyToJwk,
  generateEd25519PemPair,
} from "../plugins/agent-id-core/lib/crypto.mjs";
import {
  applyView,
  createOp,
  findHeads,
  foldView,
  mergeOps,
  opHash,
  reconcileLocalOps,
  recordsEqual,
  verifyOp,
} from "../plugins/agent-id-vault/lib/sync/oplog.mjs";
import { wipePayload } from "../plugins/agent-id-vault/lib/store.mjs";

function device(name) {
  const pair = generateEd25519PemPair();
  return { name, ...pair, jwk: ed25519PublicKeyToJwk(pair.publicKeyPem) };
}

const rec = (name, value) => ({
  name, type: "bearer", value, domains: ["api.example.com"],
  createdAt: 1, updatedAt: 1,
});

describe("sync oplog", () => {
  it("createOp produces a self-consistent signed op", () => {
    const d = device("a");
    const op = createOp({
      parents: [], device: "jkt-a", ts: 100, kind: "add",
      name: "gh", record: rec("gh", "tok"), privateKeyPem: d.privateKeyPem,
    });
    assert.equal(op.h, opHash(op));
    assert.ok(verifyOp(op, d.jwk));
  });

  it("verifyOp rejects a tampered record and a foreign key", () => {
    const d = device("a"), e = device("b");
    const op = createOp({
      parents: [], device: "jkt-a", ts: 100, kind: "add",
      name: "gh", record: rec("gh", "tok"), privateKeyPem: d.privateKeyPem,
    });
    assert.equal(verifyOp(op, e.jwk), false);
    const tampered = { ...op, op: { ...op.op, record: rec("gh", "EVIL") } };
    assert.equal(verifyOp(tampered, d.jwk), false);
    const badParents = { ...op, parents: ["ff"] };
    assert.equal(verifyOp(badParents, d.jwk), false);
  });

  it("findHeads returns ops nothing points to", () => {
    const d = device("a");
    const o1 = createOp({ parents: [], device: "a", ts: 1, kind: "add", name: "x", record: rec("x", "1"), privateKeyPem: d.privateKeyPem });
    const o2 = createOp({ parents: [o1.h], device: "a", ts: 2, kind: "update", name: "x", record: rec("x", "2"), privateKeyPem: d.privateKeyPem });
    assert.deepEqual(findHeads([o1, o2]), [o2.h]);
  });

  it("mergeOps dedupes by hash and reports added", () => {
    const d = device("a");
    const o1 = createOp({ parents: [], device: "a", ts: 1, kind: "add", name: "x", record: rec("x", "1"), privateKeyPem: d.privateKeyPem });
    const o2 = createOp({ parents: [o1.h], device: "a", ts: 2, kind: "update", name: "x", record: rec("x", "2"), privateKeyPem: d.privateKeyPem });
    const { log, added } = mergeOps([o1], [o1, o2]);
    assert.equal(log.length, 2);
    assert.deepEqual(added.map((o) => o.h), [o2.h]);
  });

  it("fold: causally-later op wins regardless of ts", () => {
    const d = device("a");
    const o1 = createOp({ parents: [], device: "a", ts: 999, kind: "add", name: "x", record: rec("x", "old"), privateKeyPem: d.privateKeyPem });
    // ts is EARLIER but causally later — must win (clock-skew independence).
    const o2 = createOp({ parents: [o1.h], device: "a", ts: 5, kind: "update", name: "x", record: rec("x", "new"), privateKeyPem: d.privateKeyPem });
    const { records, conflicts } = foldView([o1, o2]);
    assert.equal(records.get("x").value, "new");
    assert.equal(conflicts.length, 0);
  });

  it("fold: concurrent edits pick a deterministic winner and journal the loser", () => {
    const a = device("a"), b = device("b");
    const base = createOp({ parents: [], device: "a", ts: 1, kind: "add", name: "x", record: rec("x", "base"), privateKeyPem: a.privateKeyPem });
    const fromA = createOp({ parents: [base.h], device: "a", ts: 10, kind: "update", name: "x", record: rec("x", "A"), privateKeyPem: a.privateKeyPem });
    const fromB = createOp({ parents: [base.h], device: "b", ts: 10, kind: "update", name: "x", record: rec("x", "B"), privateKeyPem: b.privateKeyPem });
    const r1 = foldView([base, fromA, fromB]);
    const r2 = foldView([base, fromB, fromA]);
    // Equal ts → lexicographically greater hash wins; same on both sides.
    const expected = fromA.h > fromB.h ? "A" : "B";
    assert.equal(r1.records.get("x").value, expected);
    assert.equal(r2.records.get("x").value, expected);
    assert.equal(r1.conflicts.length, 1);
    assert.equal(r1.conflicts[0].name, "x");
    assert.equal(r1.conflicts[0].winnerHash, expected === "A" ? fromA.h : fromB.h);
    assert.equal(r1.conflicts[0].losingRecord.value, expected === "A" ? "B" : "A");
  });

  it("fold: remove produces a tombstone (null)", () => {
    const d = device("a");
    const o1 = createOp({ parents: [], device: "a", ts: 1, kind: "add", name: "x", record: rec("x", "1"), privateKeyPem: d.privateKeyPem });
    const o2 = createOp({ parents: [o1.h], device: "a", ts: 2, kind: "remove", name: "x", record: null, privateKeyPem: d.privateKeyPem });
    const { records } = foldView([o1, o2]);
    assert.equal(records.get("x"), null);
  });

  it("fold converges under any application order (property)", () => {
    const a = device("a"), b = device("b");
    const ops = [];
    let heads = [];
    for (let i = 0; i < 8; i++) {
      const d = i % 2 ? a : b;
      const op = createOp({
        parents: heads, device: d.name, ts: 100 - i, kind: i === 5 ? "remove" : "update",
        name: `cred-${i % 3}`, record: i === 5 ? null : rec(`cred-${i % 3}`, `v${i}`),
        privateKeyPem: d.privateKeyPem,
      });
      ops.push(op);
      heads = i % 3 === 0 ? heads.concat(op.h) : [op.h]; // occasionally fork
    }
    const baseline = foldView(ops);
    for (let trial = 0; trial < 10; trial++) {
      const shuffled = [...ops].sort(() => (trial % 2 ? 1 : -1) * 0.5);
      shuffled.reverse();
      const alt = foldView(shuffled);
      assert.deepEqual([...alt.records.entries()].sort(), [...baseline.records.entries()].sort());
    }
  });
});

describe("sync reconcile + applyView", () => {
  function payloadWith(creds) {
    return { version: 1, credentials: creds, sync: { oplog: [], devices: [], conflicts: [] } };
  }

  it("genesis: reconcile turns existing records into a chained op per record", () => {
    const d = device("a");
    const payload = payloadWith([rec("one", "1"), rec("two", "2")]);
    const ops = reconcileLocalOps({ payload, device: "jkt-a", privateKeyPem: d.privateKeyPem });
    assert.equal(ops.length, 2);
    assert.deepEqual(ops[0].parents, []);
    assert.deepEqual(ops[1].parents, [ops[0].h]); // chained, single head
    const { records } = foldView(payload.sync.oplog);
    assert.equal(records.get("one").value, "1");
    assert.equal(records.get("two").value, "2");
  });

  it("reconcile emits update and remove ops for drift, and nothing when clean", () => {
    const d = device("a");
    const payload = payloadWith([rec("one", "1")]);
    reconcileLocalOps({ payload, device: "jkt-a", privateKeyPem: d.privateKeyPem });
    // no drift → no ops
    assert.equal(reconcileLocalOps({ payload, device: "jkt-a", privateKeyPem: d.privateKeyPem }).length, 0);
    // update + remove drift
    payload.credentials = [ { ...rec("one", "CHANGED"), updatedAt: 9 } ];
    const ops2 = reconcileLocalOps({ payload, device: "jkt-a", privateKeyPem: d.privateKeyPem });
    assert.deepEqual(ops2.map((o) => o.op.kind).sort(), ["update"]);
    payload.credentials = [];
    const ops3 = reconcileLocalOps({ payload, device: "jkt-a", privateKeyPem: d.privateKeyPem });
    assert.deepEqual(ops3.map((o) => o.op.kind), ["remove"]);
    assert.equal(foldView(payload.sync.oplog).records.get("one"), null);
  });

  it("reconcile ignores lastUsedAt-only drift and browser-profile records", () => {
    const d = device("a");
    const payload = payloadWith([rec("one", "1")]);
    reconcileLocalOps({ payload, device: "jkt-a", privateKeyPem: d.privateKeyPem });
    payload.credentials[0].lastUsedAt = 123456;
    assert.equal(reconcileLocalOps({ payload, device: "jkt-a", privateKeyPem: d.privateKeyPem }).length, 0);
    payload.credentials.push({
      name: "chrome", type: "browser-profile", domains: ["*"],
      dek: "a".repeat(64), profileFile: "p.enc", createdAt: 1, updatedAt: 1,
    });
    assert.equal(reconcileLocalOps({ payload, device: "jkt-a", privateKeyPem: d.privateKeyPem }).length, 0);
  });

  it("applyView writes the fold, preserves local lastUsedAt, keeps browser-profile", () => {
    const local = { ...rec("one", "1"), lastUsedAt: 777 };
    const bp = {
      name: "chrome", type: "browser-profile", domains: ["*"],
      dek: "a".repeat(64), profileFile: "p.enc", createdAt: 1, updatedAt: 1,
    };
    const payload = payloadWith([local, bp]);
    const view = new Map([
      ["one", rec("one", "1")],          // same content → keep local object
      ["two", rec("two", "2")],          // new from remote
      ["gone", null],                     // tombstone
    ]);
    applyView(payload, view);
    const names = payload.credentials.map((c) => c.name).sort();
    assert.deepEqual(names, ["chrome", "one", "two"]);
    assert.equal(payload.credentials.find((c) => c.name === "one").lastUsedAt, 777);
  });

  it("recordsEqual ignores lastUsedAt but not values", () => {
    assert.ok(recordsEqual({ ...rec("x", "1"), lastUsedAt: 1 }, { ...rec("x", "1"), lastUsedAt: 2 }));
    assert.ok(!recordsEqual(rec("x", "1"), rec("x", "2")));
  });
});

describe("sync payload wipe", () => {
  it("wipePayload scrubs secrets inside oplog records and conflict journal", () => {
    const payload = {
      version: 1,
      credentials: [rec("one", "s3cret")],
      sync: {
        oplog: [{ h: "x", parents: [], device: "d", ts: 1,
                  op: { kind: "add", name: "one", record: rec("one", "s3cret") }, sig: "s" }],
        devices: [],
        conflicts: [{ name: "one", losingRecord: rec("one", "l0ser"), losingHash: "y", winnerHash: "x", decidedAt: 1 }],
      },
    };
    wipePayload(payload);
    assert.equal(payload.credentials.length, 0);
    assert.equal(payload.sync.oplog.length, 0);
    assert.equal(payload.sync.conflicts.length, 0);
  });
});
