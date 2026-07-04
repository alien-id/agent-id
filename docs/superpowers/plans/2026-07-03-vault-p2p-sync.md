# Vault p2p sync (PoC) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Live, fully decentralized p2p sync of vault credential records between a user's PCs, per the approved spec `docs/superpowers/specs/2026-07-03-vault-p2p-sync-design.md`.

**Architecture:** Each device keeps its own fully self-contained vault (own master key, own slots). Every credential mutation is represented as a signed operation in a hash-DAG op-log stored inside the encrypted payload; `credentials` is a deterministic fold of that DAG. Devices talk over TLS 1.3 with ephemeral self-signed certs; identity is an Ed25519 signature over the RFC 5705 exported keying material, verified against the peer's v3 bundle (same SSO owner) and a locally pinned device list.

**Tech Stack:** Plain ESM `.mjs`, `node:crypto` / `node:tls` / `node:dgram` only (zero new npm deps), `node --test` for tests, existing `@alien-id/agent-id-core` primitives (`crypto.mjs`, `bundle.mjs`, `oidc.mjs`, `state.mjs`, `cli-runtime.mjs`).

## Global Constraints

- Plain ESM `.mjs`; **no TypeScript**, no build step.
- **Zero new npm dependencies** — `node:*` builtins only.
- Cross-plugin imports use bare specifiers `@alien-id/agent-id-core/lib/*.mjs`, never relative sibling paths.
- Dependency direction: proxy → vault → core. Vault must never import from proxy.
- Tests: `tests/test-*.mjs`, run with `node --test tests/test-<name>.mjs`; full suite `bun run test`.
- Master key never leaves a device; op-log and conflict journal live INSIDE the AEAD-encrypted payload.
- `browser-profile` records never sync (device-local), and the agent identity/key never syncs.
- Records synced at L1+ only: sync requires an owner binding (`owner-session.json` with `idToken`).
- EKM label (channel binding): `"agent-id-vault-sync-v1"`, 32 bytes.
- Work on the current branch `explore-agent-id-plugins`; conventional commits with gitmoji (match `git log` style); PR targets `main`.
- Changesets required: `@alien-id/agent-id-core` minor (cert-minter promotion), `@alien-id/agent-id-vault` minor (sync feature). Private plugins need none.

---

### Task 1: Promote the self-signed cert minter from proxy to core

**Files:**
- Create: `plugins/agent-id-core/lib/tls-cert.mjs` (moved content)
- Modify: `plugins/agent-id-proxy/lib/control-tls.mjs` (becomes a re-export shim)
- Modify: `tests/test-control-tls.mjs:22` (import path)
- Create: `.changeset/tls-cert-promotion.md`

**Interfaces:**
- Consumes: nothing new.
- Produces: `generateControlCert({cn, days, now, serial}) → {certPem, keyPem, fingerprint}`, `fingerprintOfCertPem(certPem) → hex`, `normalizeFingerprint(fp) → hex` importable from `@alien-id/agent-id-core/lib/tls-cert.mjs`. Task 6 depends on `generateControlCert`.

- [ ] **Step 1: Move the module**

```bash
git mv plugins/agent-id-proxy/lib/control-tls.mjs plugins/agent-id-core/lib/tls-cert.mjs
```

Then edit the header comment of `plugins/agent-id-core/lib/tls-cert.mjs`: replace the first line

```js
// Alien Agent ID — Self-signed certificate for the control plane.
```

with

```js
// Alien Agent ID — Self-signed TLS certificate minting (shared).
//
// Used by the proxy control plane and by vault p2p sync. The cert is a pinned
// (or, for sync, ephemeral) key carrier: no CA, hostname/CA validation is
// intentionally bypassed by consumers.
```

Keep every export name unchanged (`normalizeFingerprint`, `fingerprintOfCertPem`, `generateControlCert`).

- [ ] **Step 2: Create the proxy shim**

Create `plugins/agent-id-proxy/lib/control-tls.mjs` with exactly:

```js
// Moved to agent-id-core (lib/tls-cert.mjs) so vault p2p sync can mint certs
// without importing from the proxy (dependency direction is proxy → vault →
// core). This shim keeps existing proxy imports working.
export * from "@alien-id/agent-id-core/lib/tls-cert.mjs";
```

- [ ] **Step 3: Update the test import**

In `tests/test-control-tls.mjs` change

```js
} from "../plugins/agent-id-proxy/lib/control-tls.mjs";
```

to

```js
} from "../plugins/agent-id-core/lib/tls-cert.mjs";
```

- [ ] **Step 4: Run the affected tests**

Run: `node --test tests/test-control-tls.mjs tests/test-proxy-control-auth.mjs`
Expected: PASS (the shim keeps `plugins/agent-id-proxy/lib/proxy.mjs:50` and `bin/cli.mjs:54` working).

- [ ] **Step 5: Add the core changeset**

Create `.changeset/tls-cert-promotion.md`:

```md
---
"@alien-id/agent-id-core": minor
---

Add `lib/tls-cert.mjs`: the self-signed TLS certificate minter
(`generateControlCert`, `fingerprintOfCertPem`, `normalizeFingerprint`),
promoted from the proxy plugin so other plugins (vault p2p sync) can mint
ephemeral certs. The proxy re-exports it unchanged.
```

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "refactor(core): :recycle: promote self-signed cert minter to core lib/tls-cert.mjs"
```

---

### Task 2: Op-log core — create, verify, heads, merge, fold

**Files:**
- Create: `plugins/agent-id-vault/lib/sync/oplog.mjs`
- Test: `tests/test-sync-oplog.mjs`

**Interfaces:**
- Consumes: `canonicalJSONString`, `nowMs`, `sha256Hex`, `signEd25519Base64Url`, `verifyEd25519Base64Url`, `generateEd25519PemPair`, `ed25519PublicKeyToJwk` from `@alien-id/agent-id-core/lib/crypto.mjs`.
- Produces (used by Tasks 3, 5, 7):
  - `jwkToPublicKeyPem(jwk) → pem`
  - `opHash(op) → hex`
  - `createOp({parents, device, ts?, kind, name, record?, privateKeyPem}) → op`
  - `verifyOp(op, authorJwk) → boolean`
  - `findHeads(log) → [hash]`
  - `mergeOps(log, incoming) → {log, added}`
  - `foldView(log) → {records: Map<name, record|null>, conflicts: [{name, losingRecord, losingHash, winnerHash}]}`

- [ ] **Step 1: Write the failing tests**

Create `tests/test-sync-oplog.mjs`:

```js
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
  createOp,
  findHeads,
  foldView,
  mergeOps,
  opHash,
  verifyOp,
} from "../plugins/agent-id-vault/lib/sync/oplog.mjs";

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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test tests/test-sync-oplog.mjs`
Expected: FAIL — `Cannot find module .../lib/sync/oplog.mjs`

- [ ] **Step 3: Implement the module**

Create `plugins/agent-id-vault/lib/sync/oplog.mjs`:

```js
// Alien Agent ID — Vault sync op-log.
//
// Every credential mutation is a signed operation in an append-only hash DAG
// (git-like causality: parents = DAG heads at creation time). The vault's
// `credentials` array is a deterministic fold of this log, so any two devices
// holding the same op set converge to the same view without trusting clocks.
//
//   { h, parents: [h...], device: <author jkt>, ts,
//     op: { kind: add|update|remove, name, record|null },
//     sig: Ed25519(h) by the author device's agent key }
//
// Causally-latest op per name wins; true concurrency (neither op an ancestor
// of the other) is resolved by the deterministic tiebreak "greater ts, then
// lexicographically greater h" and the loser goes to the conflict journal.

import { createPublicKey } from "node:crypto";

import {
  canonicalJSONString,
  nowMs,
  sha256Hex,
  signEd25519Base64Url,
  verifyEd25519Base64Url,
} from "@alien-id/agent-id-core/lib/crypto.mjs";

export function jwkToPublicKeyPem(jwk) {
  return createPublicKey({ key: jwk, format: "jwk" })
    .export({ type: "spki", format: "pem" });
}

// The signed/hashed body — everything except h and sig, parents sorted so
// hashing is order-independent.
function opBody(op) {
  return {
    parents: [...op.parents].sort(),
    device: op.device,
    ts: op.ts,
    op: op.op,
  };
}

export function opHash(op) {
  return sha256Hex(canonicalJSONString(opBody(op)));
}

export function createOp({ parents, device, ts = nowMs(), kind, name, record = null, privateKeyPem }) {
  const base = { parents: [...parents].sort(), device, ts, op: { kind, name, record } };
  const h = opHash(base);
  return { ...base, h, sig: signEd25519Base64Url(h, privateKeyPem) };
}

export function verifyOp(op, authorJwk) {
  try {
    if (opHash(op) !== op.h) return false;
    return verifyEd25519Base64Url(op.h, op.sig, jwkToPublicKeyPem(authorJwk));
  } catch {
    return false;
  }
}

export function findHeads(log) {
  const referenced = new Set(log.flatMap((o) => o.parents));
  return log.filter((o) => !referenced.has(o.h)).map((o) => o.h);
}

export function mergeOps(log, incoming) {
  const have = new Set(log.map((o) => o.h));
  const added = [];
  for (const op of incoming) {
    if (have.has(op.h)) continue;
    have.add(op.h);
    added.push(op);
  }
  return { log: [...log, ...added], added };
}

// Memoized transitive-ancestor computation over the whole DAG. Logs are small
// in the PoC (compaction is phase 2), so O(ops²) worst case is acceptable.
function makeAncestorLookup(byHash) {
  const memo = new Map();
  function walk(h) {
    if (memo.has(h)) return memo.get(h);
    const out = new Set();
    memo.set(h, out); // set before recursing — cycle guard
    const op = byHash.get(h);
    if (!op) return out; // dangling parent: treated as no further ancestry
    for (const p of op.parents) {
      out.add(p);
      for (const a of walk(p)) out.add(a);
    }
    return out;
  }
  return walk;
}

// Deterministic fold of the DAG into { name → record|null(tombstone) } plus
// the conflicts produced by concurrent maximal ops.
export function foldView(log) {
  const byHash = new Map(log.map((o) => [o.h, o]));
  const ancestors = makeAncestorLookup(byHash);
  const byName = new Map();
  for (const op of log) {
    const list = byName.get(op.op.name) || [];
    list.push(op);
    byName.set(op.op.name, list);
  }

  const records = new Map();
  const conflicts = [];
  for (const [name, ops] of byName) {
    // Maximal ops for this name: not an ancestor of any other op on the name.
    const maximal = ops.filter(
      (o) => !ops.some((other) => other !== o && ancestors(other.h).has(o.h)),
    );
    // Winner first: greater ts, then lexicographically greater hash.
    maximal.sort((a, b) => (b.ts - a.ts) || (a.h < b.h ? 1 : a.h > b.h ? -1 : 0));
    const winner = maximal[0];
    for (const loser of maximal.slice(1)) {
      if (loser.op.record != null) {
        conflicts.push({
          name,
          losingRecord: loser.op.record,
          losingHash: loser.h,
          winnerHash: winner.h,
        });
      }
    }
    records.set(name, winner.op.kind === "remove" ? null : winner.op.record);
  }
  return { records, conflicts };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test tests/test-sync-oplog.mjs`
Expected: PASS (all `sync oplog` tests)

- [ ] **Step 5: Commit**

```bash
git add plugins/agent-id-vault/lib/sync/oplog.mjs tests/test-sync-oplog.mjs
git commit -m "feat(vault): :sparkles: sync op-log core (signed hash DAG, deterministic fold)"
```

---

### Task 3: Reconcile local changes and apply the folded view

**Files:**
- Modify: `plugins/agent-id-vault/lib/sync/oplog.mjs` (append functions)
- Test: `tests/test-sync-oplog.mjs` (append describe block)

**Interfaces:**
- Consumes: Task 2 exports.
- Produces (used by Task 7):
  - `reconcileLocalOps({payload, device, privateKeyPem, now?}) → [appended ops]` — diffs `payload.credentials` against the folded oplog and appends signed ops for any drift (this is also the legacy-vault genesis migration: empty log + N records → N ops).
  - `applyView(payload, records) → void` — replaces `payload.credentials` with the folded view, preserving local `lastUsedAt` and keeping device-local `browser-profile` records.
  - `recordsEqual(a, b) → boolean` (ignores `lastUsedAt`).

- [ ] **Step 1: Write the failing tests**

Append to `tests/test-sync-oplog.mjs` (add `applyView`, `reconcileLocalOps`, `recordsEqual` to the existing import from `oplog.mjs`):

```js
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test tests/test-sync-oplog.mjs`
Expected: FAIL — `reconcileLocalOps is not a function` (or import error)

- [ ] **Step 3: Implement**

Append to `plugins/agent-id-vault/lib/sync/oplog.mjs`:

```js
// ─── Local reconcile + view application ─────────────────────────────────────────

// Record types that never sync — device-local by design (the vault holds only
// a DEK; the sealed profile sidecar can't travel with the record).
const LOCAL_ONLY_TYPES = new Set(["browser-profile"]);

// lastUsedAt is volatile bookkeeping, not content — it must neither generate
// ops nor be clobbered by an incoming winner.
function stableRecord(rec) {
  const copy = { ...rec };
  delete copy.lastUsedAt;
  return copy;
}

export function recordsEqual(a, b) {
  return canonicalJSONString(stableRecord(a)) === canonicalJSONString(stableRecord(b));
}

// Diff payload.credentials against the folded oplog and append signed ops for
// any drift. This single mechanism covers every local writer (CLI add/remove,
// proxy, browser) with zero changes to their code paths — AND the genesis
// migration of a pre-sync vault (empty log + N records → N chained add ops).
export function reconcileLocalOps({ payload, device, privateKeyPem, now = nowMs() }) {
  const sync = payload.sync;
  const { records } = foldView(sync.oplog);
  const appended = [];
  const currentHeads = () => findHeads(sync.oplog);

  for (const rec of payload.credentials) {
    if (LOCAL_ONLY_TYPES.has(rec.type)) continue;
    const folded = records.get(rec.name);
    if (folded != null && recordsEqual(folded, rec)) continue;
    const kind = records.has(rec.name) ? "update" : "add";
    const op = createOp({
      parents: currentHeads(), device, ts: rec.updatedAt || now,
      kind, name: rec.name, record: stableRecord(rec), privateKeyPem,
    });
    sync.oplog.push(op);
    appended.push(op);
  }

  const present = new Set(payload.credentials.map((c) => c.name));
  for (const [name, folded] of records) {
    if (folded == null || LOCAL_ONLY_TYPES.has(folded.type)) continue;
    if (present.has(name)) continue;
    const op = createOp({
      parents: currentHeads(), device, ts: now,
      kind: "remove", name, record: null, privateKeyPem,
    });
    sync.oplog.push(op);
    appended.push(op);
  }
  return appended;
}

// Replace payload.credentials with the folded view. Local record objects are
// kept when content matches (preserving lastUsedAt); device-local types are
// carried over untouched; tombstones drop records.
export function applyView(payload, records) {
  const localByName = new Map(payload.credentials.map((c) => [c.name, c]));
  const next = [];
  for (const [name, rec] of records) {
    if (rec == null) continue; // tombstone
    const local = localByName.get(name);
    if (local && recordsEqual(local, rec)) {
      next.push(local);
      continue;
    }
    const merged = { ...rec };
    if (local?.lastUsedAt && (!merged.lastUsedAt || local.lastUsedAt > merged.lastUsedAt)) {
      merged.lastUsedAt = local.lastUsedAt;
    }
    next.push(merged);
  }
  for (const c of payload.credentials) {
    if (LOCAL_ONLY_TYPES.has(c.type)) next.push(c);
  }
  payload.credentials = next;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test tests/test-sync-oplog.mjs`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add plugins/agent-id-vault/lib/sync/oplog.mjs tests/test-sync-oplog.mjs
git commit -m "feat(vault): :sparkles: sync reconcile (diff-driven local ops) and view application"
```

---

### Task 4: Payload plumbing — wipe sync secrets on lock, expose payload handle

**Files:**
- Modify: `plugins/agent-id-vault/lib/store.mjs:385-402` (`wipePayload`)
- Modify: `plugins/agent-id-vault/lib/vault.mjs` (`buildVaultHandle` — add `payload()` accessor after `raw()`)
- Test: `tests/test-sync-oplog.mjs` (append describe block)

**Interfaces:**
- Consumes: `SECRET_FIELDS` (existing, `store.mjs`).
- Produces: `vault.payload()` accessor (used by Task 7 and the CLI); `wipePayload` now also scrubs `payload.sync.oplog[].op.record` and `payload.sync.conflicts[].losingRecord`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test-sync-oplog.mjs`:

```js
import { wipePayload } from "../plugins/agent-id-vault/lib/store.mjs";

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test tests/test-sync-oplog.mjs`
Expected: FAIL — oplog/conflicts still hold entries after `wipePayload`

- [ ] **Step 3: Implement**

In `plugins/agent-id-vault/lib/store.mjs`, refactor `wipePayload` — extract the per-record scrub into a helper and add the sync section (replace the existing function body):

```js
function scrubRecordSecrets(cred) {
  if (!cred || typeof cred !== "object") return;
  for (const f of SECRET_FIELDS) {
    const v = cred[f];
    if (Buffer.isBuffer(v)) v.fill(0);
    if (f in cred) delete cred[f];
  }
}

export function wipePayload(payload) {
  if (!payload || !Array.isArray(payload.credentials)) return;
  for (const cred of payload.credentials) scrubRecordSecrets(cred);
  payload.credentials.length = 0;
  // The sync section embeds full credential records too (op-log entries and
  // journaled conflict losers) — same scrub, same reason.
  if (payload.sync) {
    for (const op of payload.sync.oplog || []) scrubRecordSecrets(op?.op?.record);
    for (const c of payload.sync.conflicts || []) scrubRecordSecrets(c?.losingRecord);
    if (Array.isArray(payload.sync.oplog)) payload.sync.oplog.length = 0;
    if (Array.isArray(payload.sync.conflicts)) payload.sync.conflicts.length = 0;
  }
}
```

(The original comment about not recursing into aliased nested objects stays valid — keep it on `scrubRecordSecrets`.)

In `plugins/agent-id-vault/lib/vault.mjs`, inside `buildVaultHandle`'s returned object, after the `raw()` method add:

```js
    // Direct payload access for the sync engine (oplog + syncMeta live inside
    // the encrypted payload). Mutations become durable on the next save().
    payload() {
      assertOpen();
      return state.payload;
    },
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test tests/test-sync-oplog.mjs && bun run test`
Expected: PASS (the new wipe test, and no regressions across the existing suite)

- [ ] **Step 5: Commit**

```bash
git add plugins/agent-id-vault/lib/store.mjs plugins/agent-id-vault/lib/vault.mjs tests/test-sync-oplog.mjs
git commit -m "feat(vault): :sparkles: expose payload handle and wipe sync secrets on lock"
```

---

### Task 5: Trust — device pinning, identity loading, hello build/verify

**Files:**
- Create: `plugins/agent-id-vault/lib/sync/trust.mjs`
- Test: `tests/test-sync-trust.mjs`

**Interfaces:**
- Consumes: `buildV3Bundle`, `parseBundle`, `verifyBundle` from core `bundle.mjs`; `canonicalJSONString`, `jwkThumbprint`, `nowMs`, `signEd25519Base64Url`, `verifyEd25519Base64Url`, `ed25519PublicKeyToJwk` from core `crypto.mjs`; `parseJwt` from core `oidc.mjs`; `readJsonFile`, `statePaths` from core `state.mjs`; `jwkToPublicKeyPem` from `./oplog.mjs`.
- Produces (used by Tasks 7, 9):
  - `SYNC_EKM_LABEL = "agent-id-vault-sync-v1"`
  - `ensureSyncMeta(payload) → sync` (creates `{oplog, devices, conflicts}`)
  - `findDevice(sync, jkt)`, `pinDevice(sync, {deviceJkt, agentJwk?, label?, ownerSub?, now?})`, `revokeDevice(sync, jkt) → boolean`
  - `loadSyncIdentity(stateDir, {label?}) → {privateKeyPem, agentJwk, jkt, idToken, ownerSub, label}` (throws `SYNC_NO_AGENT_KEY` / `SYNC_NOT_BOUND`)
  - `buildHello({identity, ekm, role, peerNonce, label}) → hello msg`
  - `verifyHello({hello, ekm, peerRole, ownNonce, ownJkt, ownOwnerSub, sync, verifyIdToken}) → {jkt, agentJwk, label, pinned, preapproved, ownerSub?, level?}` (throws coded errors)

- [ ] **Step 1: Write the failing tests**

Create `tests/test-sync-trust.mjs`:

```js
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test tests/test-sync-trust.mjs`
Expected: FAIL — `Cannot find module .../lib/sync/trust.mjs`

- [ ] **Step 3: Implement**

Create `plugins/agent-id-vault/lib/sync/trust.mjs`:

```js
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test tests/test-sync-trust.mjs`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add plugins/agent-id-vault/lib/sync/trust.mjs tests/test-sync-trust.mjs
git commit -m "feat(vault): :sparkles: sync trust layer (device pinning, EKM-bound hello, owner match)"
```

---

### Task 6: Channel — TLS server/client with EKM and JSON-lines framing

**Files:**
- Create: `plugins/agent-id-vault/lib/sync/channel.mjs`
- Test: `tests/test-sync-channel.mjs`

**Interfaces:**
- Consumes: `generateControlCert` from `@alien-id/agent-id-core/lib/tls-cert.mjs` (Task 1); `SYNC_EKM_LABEL` from `./trust.mjs`.
- Produces (used by Tasks 7, 9):
  - `makeLineIO(socket) → {write(msg), read() → Promise<msg>, expect(type) → Promise<msg>}`
  - `startSyncServer({host?, port?, onSession}) → {server, port, close()}` — `onSession({socket, ekm, io, role: "listener"})`
  - `connectToPeer({host, port, timeoutMs?}) → {socket, ekm, io, role: "initiator"}`

- [ ] **Step 1: Write the failing tests**

Create `tests/test-sync-channel.mjs`:

```js
#!/usr/bin/env node

// Tests for the sync TLS channel: EKM agreement between the two real ends,
// JSON-lines framing, and the MITM property (a TLS-terminating relay yields
// different EKMs, so a forwarded hello fails verification).
// Run: node --test tests/test-sync-channel.mjs

import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import {
  connectToPeer,
  startSyncServer,
} from "../plugins/agent-id-vault/lib/sync/channel.mjs";
import {
  buildHello,
  ensureSyncMeta,
  verifyHello,
} from "../plugins/agent-id-vault/lib/sync/trust.mjs";
import {
  ed25519PublicKeyToJwk,
  generateEd25519PemPair,
  jwkThumbprint,
} from "../plugins/agent-id-core/lib/crypto.mjs";

const closers = [];
after(async () => { for (const c of closers.reverse()) await c(); });

function identity(sub) {
  const pair = generateEd25519PemPair();
  const agentJwk = ed25519PublicKeyToJwk(pair.publicKeyPem);
  const jkt = jwkThumbprint(agentJwk);
  const payload = { iss: "https://sso.test", sub, cnf: { jkt } };
  const idToken = ["e30", Buffer.from(JSON.stringify(payload)).toString("base64url"), "sig"].join(".");
  return { privateKeyPem: pair.privateKeyPem, agentJwk, jkt, idToken, ownerSub: sub, label: "t" };
}
const fakeVerifyIdToken = async ({ idToken }) => {
  const payload = JSON.parse(Buffer.from(idToken.split(".")[1], "base64url").toString("utf8"));
  return { signatureValid: true, issuer: payload.iss, payload, header: {} };
};

describe("sync channel", () => {
  it("both ends export the same EKM and can exchange framed JSON", async () => {
    let serverSide;
    const gotSession = new Promise((r) => { serverSide = r; });
    const srv = await startSyncServer({ host: "127.0.0.1", onSession: serverSide });
    closers.push(srv.close);
    const client = await connectToPeer({ host: "127.0.0.1", port: srv.port });
    closers.push(async () => client.socket.destroy());
    const session = await gotSession;
    closers.push(async () => session.socket.destroy());

    assert.equal(session.ekm.toString("hex"), client.ekm.toString("hex"));
    assert.equal(session.role, "listener");
    assert.equal(client.role, "initiator");

    client.io.write({ t: "ping", n: 1 });
    client.io.write({ t: "ping", n: 2 });
    assert.deepEqual(await session.io.expect("ping"), { t: "ping", n: 1 });
    assert.deepEqual(await session.io.read(), { t: "ping", n: 2 });
    session.io.write({ t: "pong" });
    assert.equal((await client.io.expect("pong")).t, "pong");
  });

  it("expect() surfaces a peer error line as a coded throw", async () => {
    let serverSide;
    const gotSession = new Promise((r) => { serverSide = r; });
    const srv = await startSyncServer({ host: "127.0.0.1", onSession: serverSide });
    closers.push(srv.close);
    const client = await connectToPeer({ host: "127.0.0.1", port: srv.port });
    closers.push(async () => client.socket.destroy());
    const session = await gotSession;
    session.io.write({ t: "error", code: "approval-required" });
    await assert.rejects(() => client.io.expect("hello"), (err) => err.code === "approval-required");
  });

  it("a TLS-terminating MITM relay produces mismatched EKMs → hello fails", async () => {
    const a = identity("owner-1");
    // Real endpoint B.
    let bSide;
    const gotB = new Promise((r) => { bSide = r; });
    const realServer = await startSyncServer({ host: "127.0.0.1", onSession: bSide });
    closers.push(realServer.close);

    // MITM: terminates TLS from A, dials B itself, forwards hello verbatim.
    let mitmInbound;
    const gotMitm = new Promise((r) => { mitmInbound = r; });
    const mitm = await startSyncServer({ host: "127.0.0.1", onSession: mitmInbound });
    closers.push(mitm.close);

    const aConn = await connectToPeer({ host: "127.0.0.1", port: mitm.port });
    closers.push(async () => aConn.socket.destroy());
    const aToMitm = await gotMitm;
    const mitmToB = await connectToPeer({ host: "127.0.0.1", port: realServer.port });
    closers.push(async () => mitmToB.socket.destroy());
    const bSession = await gotB;

    // A signs over ITS channel's EKM (A↔MITM); MITM forwards to B unchanged.
    const nonceFromB = randomBytes(16).toString("hex");
    const hello = buildHello({ identity: a, ekm: aConn.ekm, role: "initiator", peerNonce: nonceFromB });
    mitmToB.io.write(hello);
    const forwarded = await bSession.io.expect("hello");

    await assert.rejects(
      () => verifyHello({
        hello: forwarded, ekm: bSession.ekm, peerRole: "initiator", ownNonce: nonceFromB,
        ownJkt: "b-jkt", ownOwnerSub: "owner-1",
        sync: ensureSyncMeta({ credentials: [] }), verifyIdToken: fakeVerifyIdToken,
      }),
      (err) => err.code === "SYNC_HELLO_BAD_SIG",
    );
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test tests/test-sync-channel.mjs`
Expected: FAIL — `Cannot find module .../lib/sync/channel.mjs`

- [ ] **Step 3: Implement**

Create `plugins/agent-id-vault/lib/sync/channel.mjs`:

```js
// Alien Agent ID — Vault sync transport.
//
// TLS 1.3 with ephemeral self-signed P-256 certs on BOTH ends. The certs are
// pure key carriers: CA/hostname validation is disabled and nothing is pinned
// — identity lives entirely in the Ed25519 signature over the RFC 5705
// exported keying material (see trust.mjs), so cert rotation is a non-event
// and an active MITM is structurally excluded.
//
// Framing: one JSON object per LF-terminated line.

import tls from "node:tls";

import { generateControlCert } from "@alien-id/agent-id-core/lib/tls-cert.mjs";
import { SYNC_EKM_LABEL } from "./trust.mjs";

const EKM_BYTES = 32;
const MAX_BUFFERED = 16 * 1024 * 1024; // ops carry full credential records

export function makeLineIO(socket) {
  let buffered = "";
  const queue = [];
  const waiters = [];
  let finished = null;

  const fail = (err) => {
    if (finished) return;
    finished = err || new Error("sync connection closed");
    for (const w of waiters.splice(0)) w.reject(finished);
  };

  socket.setEncoding("utf8");
  socket.on("data", (chunk) => {
    buffered += chunk;
    if (buffered.length > MAX_BUFFERED) {
      socket.destroy(new Error("sync frame too large"));
      return;
    }
    let idx;
    while ((idx = buffered.indexOf("\n")) >= 0) {
      const line = buffered.slice(0, idx);
      buffered = buffered.slice(idx + 1);
      if (!line.trim()) continue;
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        socket.destroy(new Error("malformed sync frame"));
        return;
      }
      const waiter = waiters.shift();
      if (waiter) waiter.resolve(msg);
      else queue.push(msg);
    }
  });
  socket.on("error", fail);
  socket.on("close", () => fail());

  return {
    write(msg) {
      socket.write(JSON.stringify(msg) + "\n");
    },
    read() {
      if (queue.length) return Promise.resolve(queue.shift());
      if (finished) return Promise.reject(finished);
      return new Promise((resolve, reject) => waiters.push({ resolve, reject }));
    },
    async expect(type) {
      const msg = await this.read();
      if (msg.t === "error") {
        const err = new Error(`peer refused: ${msg.code || "unknown"}`);
        err.code = msg.code || "peer-error";
        throw err;
      }
      if (msg.t !== type) {
        throw new Error(`sync protocol error: expected "${type}", got "${String(msg.t)}"`);
      }
      return msg;
    },
  };
}

export async function startSyncServer({ host = "0.0.0.0", port = 0, onSession }) {
  const { certPem, keyPem } = generateControlCert({ cn: "agent-id-vault-sync" });
  const server = tls.createServer(
    {
      cert: certPem,
      key: keyPem,
      minVersion: "TLSv1.3",
      requestCert: true,
      rejectUnauthorized: false, // peer cert is a key carrier, not an identity
    },
    (socket) => {
      const ekm = socket.exportKeyingMaterial(EKM_BYTES, SYNC_EKM_LABEL);
      onSession({ socket, ekm, io: makeLineIO(socket), role: "listener" });
    },
  );
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, resolve);
  });
  return {
    server,
    port: server.address().port,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

export async function connectToPeer({ host, port, timeoutMs = 10_000 }) {
  const { certPem, keyPem } = generateControlCert({ cn: "agent-id-vault-sync" });
  const socket = tls.connect({
    host,
    port,
    cert: certPem,
    key: keyPem,
    minVersion: "TLSv1.3",
    rejectUnauthorized: false,
  });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`sync connect timeout to ${host}:${port}`));
    }, timeoutMs);
    socket.once("secureConnect", () => { clearTimeout(timer); resolve(); });
    socket.once("error", (err) => { clearTimeout(timer); reject(err); });
  });
  const ekm = socket.exportKeyingMaterial(EKM_BYTES, SYNC_EKM_LABEL);
  return { socket, ekm, io: makeLineIO(socket), role: "initiator" };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test tests/test-sync-channel.mjs`
Expected: PASS (including the MITM test)

- [ ] **Step 5: Commit**

```bash
git add plugins/agent-id-vault/lib/sync/channel.mjs tests/test-sync-channel.mjs
git commit -m "feat(vault): :sparkles: sync TLS channel with EKM channel binding and line framing"
```

---

### Task 7: Protocol — the symmetric sync session + vault lock

**Files:**
- Create: `plugins/agent-id-vault/lib/sync/protocol.mjs`
- Create: `plugins/agent-id-vault/lib/sync/lock.mjs`
- Test: `tests/test-sync-protocol.mjs`

**Interfaces:**
- Consumes: Tasks 2–6 exports; `nowMs` from core crypto.
- Produces (used by Task 9):
  - `runSyncSession({session, vault, identity, approvePeer?, verifyIdToken}) → {peer, sent, received, conflicts}` — full symmetric session over an established channel; throws `SyncRefusal` (`.code` ∈ `approval-required | unknown-author | bad-op-signature | dangling-parent | ...`).
  - `withVaultLock(stateDir, fn, {retries?, delayMs?, staleMs?})` from `lock.mjs` (throws `.code === "VAULT_BUSY"`).

- [ ] **Step 1: Write the failing tests**

Create `tests/test-sync-protocol.mjs`:

```js
#!/usr/bin/env node

// In-process end-to-end tests of the sync protocol over a real loopback TLS
// channel: pairing with approval, bidirectional op transfer, convergence,
// tombstones, conflict journaling, refusal paths, and the vault lock.
// Run: node --test tests/test-sync-protocol.mjs

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import {
  ed25519PublicKeyToJwk,
  generateEd25519PemPair,
  jwkThumbprint,
} from "../plugins/agent-id-core/lib/crypto.mjs";
import { ensureDir, statePaths, writeJsonFile } from "../plugins/agent-id-core/lib/state.mjs";
import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { connectToPeer, startSyncServer } from "../plugins/agent-id-vault/lib/sync/channel.mjs";
import { loadSyncIdentity } from "../plugins/agent-id-vault/lib/sync/trust.mjs";
import { runSyncSession } from "../plugins/agent-id-vault/lib/sync/protocol.mjs";
import { withVaultLock } from "../plugins/agent-id-vault/lib/sync/lock.mjs";

const fakeVerifyIdToken = async ({ idToken }) => {
  const payload = JSON.parse(Buffer.from(idToken.split(".")[1], "base64url").toString("utf8"));
  return { signatureValid: true, issuer: payload.iss, payload, header: {} };
};

// A full simulated device: stateDir + agent key + owner session + vault.
async function makeDevice(sub, label) {
  const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), `sync-${label}-`));
  const pair = generateEd25519PemPair();
  const agentJwk = ed25519PublicKeyToJwk(pair.publicKeyPem);
  const jkt = jwkThumbprint(agentJwk);
  const paths = statePaths(stateDir);
  await ensureDir(path.dirname(paths.mainKey));
  await writeJsonFile(paths.mainKey, { agentId: "main", ...pair });
  const idPayload = { iss: "https://sso.test", sub, cnf: { jkt } };
  const idToken = ["e30", Buffer.from(JSON.stringify(idPayload)).toString("base64url"), "sig"].join(".");
  await writeJsonFile(paths.ownerSession, { idToken });
  await initVault({ stateDir, privateKeyPem: pair.privateKeyPem, agentId: "main" });
  return { stateDir, pair, label };
}

async function openDevice(device) {
  const vault = await openVault({ stateDir: device.stateDir, privateKeyPem: device.pair.privateKeyPem });
  const identity = await loadSyncIdentity(device.stateDir, { label: device.label });
  return { vault, identity };
}

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
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test tests/test-sync-protocol.mjs`
Expected: FAIL — `Cannot find module .../lib/sync/protocol.mjs`

- [ ] **Step 3: Implement the lock**

Create `plugins/agent-id-vault/lib/sync/lock.mjs`:

```js
// Alien Agent ID — advisory vault write lock.
//
// Guards the read-reconcile-merge-save window of a sync against a concurrent
// CLI writer on the same stateDir. Best-effort `wx` lockfile with stale
// takeover; both sides fail EXPLICITLY rather than corrupt the vault.

import fs from "node:fs/promises";

import { statePaths } from "@alien-id/agent-id-core/lib/state.mjs";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function withVaultLock(stateDir, fn, { retries = 50, delayMs = 100, staleMs = 60_000 } = {}) {
  const lockPath = statePaths(stateDir).vaultFile + ".lock";
  for (let attempt = 0; ; attempt++) {
    try {
      const handle = await fs.open(lockPath, "wx");
      await handle.write(String(process.pid));
      await handle.close();
      break;
    } catch (err) {
      if (err?.code !== "EEXIST") throw err;
      const stat = await fs.stat(lockPath).catch(() => null);
      if (stat && Date.now() - stat.mtimeMs > staleMs) {
        await fs.unlink(lockPath).catch(() => {});
        continue;
      }
      if (attempt >= retries) {
        const busy = new Error(`vault is locked by another process (${lockPath})`);
        busy.code = "VAULT_BUSY";
        throw busy;
      }
      await sleep(delayMs);
    }
  }
  try {
    return await fn();
  } finally {
    await fs.unlink(lockPath).catch(() => {});
  }
}
```

- [ ] **Step 4: Implement the protocol**

Create `plugins/agent-id-vault/lib/sync/protocol.mjs`:

```js
// Alien Agent ID — the sync session state machine.
//
// Fully symmetric over a full-duplex channel; both sides run the same code:
//
//   nonce ⇄  hello ⇄  [approval]  heads ⇄  want ⇄  ops ⇄  done ⇄  apply
//
// Incoming ops are STAGED and verified (author pinned, signature, parent
// connectivity) before anything mutates; the vault is then re-folded and
// written once. A failure at any point leaves the vault untouched — ops are
// idempotent by hash, so the next sync simply starts over.

import { randomBytes } from "node:crypto";

import { nowMs } from "@alien-id/agent-id-core/lib/crypto.mjs";

import {
  applyView,
  findHeads,
  foldView,
  mergeOps,
  reconcileLocalOps,
  verifyOp,
} from "./oplog.mjs";
import { buildHello, ensureSyncMeta, findDevice, pinDevice, verifyHello } from "./trust.mjs";

export class SyncRefusal extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

export async function runSyncSession({ session, vault, identity, approvePeer = null, verifyIdToken }) {
  const { io, ekm, role, socket } = session;
  const payload = vault.payload();
  const sync = ensureSyncMeta(payload);
  // Self-registration: our own ops must verify against a pinned key locally too.
  pinDevice(sync, {
    deviceJkt: identity.jkt, agentJwk: identity.agentJwk,
    label: identity.label, ownerSub: identity.ownerSub,
  });

  try {
    // 1. Nonce exchange (feeds the peer's hello signature).
    const ownNonce = randomBytes(16).toString("hex");
    io.write({ t: "nonce", nonce: ownNonce });
    const peerNonce = String((await io.expect("nonce")).nonce || "");

    // 2. Hello exchange — each side signs its own EKM view + role + peer nonce.
    io.write(buildHello({ identity, ekm, role, peerNonce, label: identity.label }));
    const hello = await io.expect("hello");
    const peerRole = role === "initiator" ? "listener" : "initiator";
    let peer;
    try {
      peer = await verifyHello({
        hello, ekm, peerRole, ownNonce,
        ownJkt: identity.jkt, ownOwnerSub: identity.ownerSub, sync, verifyIdToken,
      });
    } catch (err) {
      io.write({ t: "error", code: err.code || "hello-rejected" });
      throw err;
    }

    // 3. Authorization: pinned, or approved right now (ceremony / preapproval).
    if (!peer.pinned) {
      const approved = peer.preapproved || (approvePeer ? await approvePeer(peer) : false);
      if (!approved) {
        io.write({ t: "error", code: "approval-required" });
        throw new SyncRefusal(
          "approval-required",
          `peer ${peer.jkt} (${peer.label || "unlabelled"}) is not approved — ` +
            `approve interactively or run: agent-id-vault sync devices add --jkt ${peer.jkt}`,
        );
      }
      pinDevice(sync, {
        deviceJkt: peer.jkt, agentJwk: peer.agentJwk,
        label: peer.label, ownerSub: peer.ownerSub || null,
      });
    }

    // 4. Capture local drift (CLI adds/removes since last sync; genesis on first run).
    reconcileLocalOps({ payload, device: identity.jkt, privateKeyPem: identity.privateKeyPem });

    // 5. Difference by full hash-set exchange (PoC; DAG-walk narrowing is phase 2).
    const ownHashes = sync.oplog.map((o) => o.h);
    io.write({ t: "heads", heads: findHeads(sync.oplog), all: ownHashes });
    const theirs = await io.expect("heads");
    const ownSet = new Set(ownHashes);
    io.write({ t: "want", hashes: (theirs.all || []).filter((h) => !ownSet.has(h)) });
    const theirWant = new Set((await io.expect("want")).hashes || []);
    const byHash = new Map(sync.oplog.map((o) => [o.h, o]));
    io.write({ t: "ops", ops: [...theirWant].map((h) => byHash.get(h)).filter(Boolean) });
    const incoming = (await io.expect("ops")).ops || [];
    io.write({ t: "done" });
    await io.expect("done");

    // 6. Stage → verify → merge → fold → single save.
    for (const op of incoming) {
      const author = findDevice(sync, op.device);
      if (!author?.agentJwk) {
        throw new SyncRefusal("unknown-author", `op ${op.h} authored by unpinned device ${op.device}`);
      }
      if (!verifyOp(op, author.agentJwk)) {
        throw new SyncRefusal("bad-op-signature", `op ${op.h} failed signature verification`);
      }
    }
    const { log, added } = mergeOps(sync.oplog, incoming);
    const known = new Set(log.map((o) => o.h));
    for (const op of added) {
      for (const parent of op.parents) {
        if (!known.has(parent)) {
          throw new SyncRefusal("dangling-parent", `op ${op.h} references missing parent ${parent}`);
        }
      }
    }
    sync.oplog = log;

    const { records, conflicts } = foldView(sync.oplog);
    const journaled = [];
    for (const conflict of conflicts) {
      if (!sync.conflicts.some((j) => j.losingHash === conflict.losingHash)) {
        const entry = { ...conflict, decidedAt: nowMs() };
        sync.conflicts.push(entry);
        journaled.push(entry);
      }
    }
    applyView(payload, records);
    await vault.save();

    return {
      peer: { jkt: peer.jkt, label: peer.label || null },
      sent: theirWant.size,
      received: added.length,
      conflicts: journaled,
    };
  } finally {
    socket.end();
  }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `node --test tests/test-sync-protocol.mjs`
Expected: PASS (all 6 tests; the owner-mismatch case may surface on either side, hence the two accepted codes)

- [ ] **Step 6: Run the whole suite for regressions**

Run: `bun run test`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add plugins/agent-id-vault/lib/sync/protocol.mjs plugins/agent-id-vault/lib/sync/lock.mjs tests/test-sync-protocol.mjs
git commit -m "feat(vault): :sparkles: sync protocol (symmetric session, staged atomic apply) and vault lock"
```

---

### Task 8: Discovery — UDP multicast beacon

**Files:**
- Create: `plugins/agent-id-vault/lib/sync/discovery.mjs`
- Test: `tests/test-sync-discovery.mjs`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces (used by Task 9):
  - `announceBeacon({deviceJkt, tcpPort, intervalMs?, group?, port?}) → {stop()}`
  - `listenForBeacons({timeoutMs?, ownJkt?, group?, port?}) → Promise<[{host, port, deviceJkt}]>`

- [ ] **Step 1: Write the failing test**

Create `tests/test-sync-discovery.mjs`:

```js
#!/usr/bin/env node

// Loopback test of the sync discovery beacon. Multicast on CI loopback can be
// flaky, so announce+listen share one high, randomized port and the assertions
// tolerate the beacon simply not arriving ONLY by skipping (never failing) —
// the mechanism is exercised for real when it does arrive.
// Run: node --test tests/test-sync-discovery.mjs

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  announceBeacon,
  listenForBeacons,
} from "../plugins/agent-id-vault/lib/sync/discovery.mjs";

describe("sync discovery", () => {
  it("a listener hears an announcer and filters its own jkt", async () => {
    const port = 40000 + Math.floor(Math.random() * 20000);
    const ann = announceBeacon({ deviceJkt: "jkt-A", tcpPort: 7777, intervalMs: 200, port });
    const annSelf = announceBeacon({ deviceJkt: "jkt-ME", tcpPort: 8888, intervalMs: 200, port });
    try {
      const peers = await listenForBeacons({ timeoutMs: 1200, ownJkt: "jkt-ME", port });
      if (peers.length === 0) {
        // Multicast unavailable in this environment — mechanism untestable here.
        return;
      }
      assert.ok(peers.every((p) => p.deviceJkt !== "jkt-ME"));
      const a = peers.find((p) => p.deviceJkt === "jkt-A");
      assert.ok(a);
      assert.equal(a.port, 7777);
      assert.ok(a.host);
    } finally {
      ann.stop();
      annSelf.stop();
    }
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test tests/test-sync-discovery.mjs`
Expected: FAIL — `Cannot find module .../lib/sync/discovery.mjs`

- [ ] **Step 3: Implement**

Create `plugins/agent-id-vault/lib/sync/discovery.mjs`:

```js
// Alien Agent ID — sync peer discovery.
//
// A deliberately tiny UDP multicast beacon (NOT full mDNS/DNS-SD — phase 2).
// Beacons are unsigned and carry no secrets: a beacon is only an invitation
// to open a TLS connection, where the real mutual authentication happens
// (trust.mjs). The worst a forged beacon can cause is a failed handshake.

import dgram from "node:dgram";

export const BEACON_GROUP = "239.83.7.71";
export const BEACON_PORT = 48338;
const BEACON_MAGIC = "agent-id-vault-sync";

export function announceBeacon({
  deviceJkt,
  tcpPort,
  intervalMs = 2000,
  group = BEACON_GROUP,
  port = BEACON_PORT,
}) {
  const socket = dgram.createSocket({ type: "udp4", reuseAddr: true });
  const message = Buffer.from(JSON.stringify({ magic: BEACON_MAGIC, v: 1, deviceJkt, tcpPort }));
  let timer = null;
  socket.on("error", () => { /* discovery is best-effort */ });
  socket.bind(() => {
    try { socket.setMulticastTTL(1); } catch { /* not fatal */ }
    const send = () => socket.send(message, port, group);
    send();
    timer = setInterval(send, intervalMs);
    timer.unref?.();
  });
  return {
    stop() {
      if (timer) clearInterval(timer);
      try { socket.close(); } catch { /* already closed */ }
    },
  };
}

export function listenForBeacons({
  timeoutMs = 2500,
  ownJkt = null,
  group = BEACON_GROUP,
  port = BEACON_PORT,
} = {}) {
  return new Promise((resolve) => {
    const socket = dgram.createSocket({ type: "udp4", reuseAddr: true });
    const peers = new Map();
    const finish = () => {
      try { socket.close(); } catch { /* already closed */ }
      resolve([...peers.values()]);
    };
    socket.on("error", finish);
    socket.on("message", (buf, rinfo) => {
      try {
        const msg = JSON.parse(buf.toString("utf8"));
        if (msg.magic !== BEACON_MAGIC || !Number.isInteger(msg.tcpPort)) return;
        if (ownJkt && msg.deviceJkt === ownJkt) return;
        peers.set(`${rinfo.address}:${msg.tcpPort}`, {
          host: rinfo.address,
          port: msg.tcpPort,
          deviceJkt: msg.deviceJkt || null,
        });
      } catch { /* ignore malformed beacons */ }
    });
    socket.bind(port, () => {
      try { socket.addMembership(group); } catch { /* no multicast here */ }
      setTimeout(finish, timeoutMs).unref?.();
    });
  });
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test tests/test-sync-discovery.mjs`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add plugins/agent-id-vault/lib/sync/discovery.mjs tests/test-sync-discovery.mjs
git commit -m "feat(vault): :sparkles: sync peer discovery via UDP multicast beacon"
```

---

### Task 9: CLI — `sync` command family

**Files:**
- Modify: `plugins/agent-id-vault/bin/cli.mjs` (new imports, `cmdSync*` handlers, command table entry, help text)

**Interfaces:**
- Consumes: everything from Tasks 5–8 plus `withVaultLock`; `verifyIdTokenSignatureOnly` from core `oidc.mjs`; existing CLI helpers (`openWithFlags`, `resolveStateDir`, `outputJson`, `outputError`, `stderr`); `hasTty` from `../lib/trusted-input.mjs`; `createInterface` from `node:readline`.
- Produces: user-facing commands —
  - `agent-id-vault sync [--peer host:port] [--label L] [--timeout-ms N]` (one-shot)
  - `agent-id-vault sync --listen [--port N] [--host H]` (resident)
  - `agent-id-vault sync status`
  - `agent-id-vault sync devices` / `sync devices add --jkt <jkt> [--label L]`
  - `agent-id-vault sync revoke --jkt <jkt>`
  - `agent-id-vault sync resolve --name <N> [--restore]`
  - Test-only escape hatch: env `AGENT_ID_SYNC_AUTOAPPROVE=1` approves any same-owner peer without a prompt (documented as test-only).

- [ ] **Step 1: Add imports**

In `plugins/agent-id-vault/bin/cli.mjs`, after the existing imports add:

```js
import { createInterface } from "node:readline";

import { verifyIdTokenSignatureOnly } from "@alien-id/agent-id-core/lib/oidc.mjs";
import { connectToPeer, startSyncServer } from "../lib/sync/channel.mjs";
import { announceBeacon, listenForBeacons } from "../lib/sync/discovery.mjs";
import { withVaultLock } from "../lib/sync/lock.mjs";
import { runSyncSession } from "../lib/sync/protocol.mjs";
import { ensureSyncMeta, loadSyncIdentity, pinDevice, revokeDevice } from "../lib/sync/trust.mjs";
```

- [ ] **Step 2: Add the handlers**

Add before the `printHelp` function:

```js
// ─── sync ───────────────────────────────────────────────────────────────────────

function promptApproval(peer) {
  if (process.env.AGENT_ID_SYNC_AUTOAPPROVE === "1") return Promise.resolve(true);
  if (!hasTty()) return Promise.resolve(false); // headless → approval-required path
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  const q =
    `\nNew sync peer:\n` +
    `  device : ${peer.label || "(unlabelled)"}\n` +
    `  agent  : ${peer.jkt}\n` +
    `  owner  : verified — same as this device (L${peer.level ?? "?"})\n` +
    `Trust this device and sync credentials with it? [y/N] `;
  return new Promise((resolve) => {
    rl.question(q, (answer) => {
      rl.close();
      resolve(/^y(es)?$/i.test(answer.trim()));
    });
  });
}

async function syncWith(stateDir, vault, identity, session) {
  return withVaultLock(stateDir, () =>
    runSyncSession({
      session,
      vault,
      identity,
      approvePeer: promptApproval,
      verifyIdToken: verifyIdTokenSignatureOnly,
    }),
  );
}

function describeSummary(summary) {
  return {
    peer: summary.peer,
    sent: summary.sent,
    received: summary.received,
    conflicts: summary.conflicts.map((c) => ({ name: c.name, winnerHash: c.winnerHash })),
  };
}

async function cmdSyncRun(flags) {
  const stateDir = resolveStateDir(flags);
  const identity = await loadSyncIdentity(stateDir, flags.label ? { label: String(flags.label) } : {});
  const vault = await openWithFlags(flags);

  if (flags.listen) {
    const srv = await startSyncServer({
      host: flags.host ? String(flags.host) : "0.0.0.0",
      port: flags.port ? Number(flags.port) : 0,
      onSession: async (session) => {
        try {
          const summary = await syncWith(stateDir, vault, identity, session);
          stderr(`✓ synced with ${summary.peer.label || summary.peer.jkt}: +${summary.received} / -${summary.sent} ops` +
            (summary.conflicts.length ? `, ${summary.conflicts.length} conflict(s) journaled` : ""));
        } catch (err) {
          stderr(`✗ sync refused: ${err.message}`);
        }
      },
    });
    const beacon = announceBeacon({ deviceJkt: identity.jkt, tcpPort: srv.port });
    stderr(`Sync listener on port ${srv.port} (device ${identity.jkt}, label "${identity.label}"). Ctrl-C to stop.`);
    await new Promise((resolve) => {
      process.once("SIGINT", resolve);
      process.once("SIGTERM", resolve);
    });
    beacon.stop();
    await srv.close();
    return;
  }

  // One-shot: explicit --peer wins; otherwise listen for beacons briefly.
  let peers = [];
  if (flags.peer) {
    const [host, port] = String(flags.peer).split(":");
    if (!host || !port) return outputError("--peer must be host:port");
    peers = [{ host, port: Number(port) }];
  } else {
    stderr("Discovering peers on the local network…");
    peers = await listenForBeacons({
      timeoutMs: flags["timeout-ms"] ? Number(flags["timeout-ms"]) : 2500,
      ownJkt: identity.jkt,
    });
    if (peers.length === 0) {
      return outputError("no sync peers found — is the other device running `agent-id-vault sync --listen`? (or pass --peer host:port)");
    }
  }

  const results = [];
  for (const peer of peers) {
    try {
      const session = await connectToPeer({ host: peer.host, port: peer.port });
      const summary = await syncWith(stateDir, vault, identity, session);
      results.push({ ok: true, ...describeSummary(summary) });
    } catch (err) {
      results.push({ ok: false, peer: `${peer.host}:${peer.port}`, error: err.message, code: err.code || null });
    }
  }
  outputJson({ ok: results.every((r) => r.ok), results });
}

async function cmdSyncStatus(flags) {
  const vault = await openWithFlags(flags);
  const sync = ensureSyncMeta(vault.payload());
  outputJson({
    ok: true,
    ops: sync.oplog.length,
    devices: sync.devices.map((d) => ({ jkt: d.deviceJkt, label: d.label, ownerSub: d.ownerSub, addedAt: d.addedAt, complete: Boolean(d.agentJwk) })),
    conflicts: sync.conflicts.map((c) => ({ name: c.name, winnerHash: c.winnerHash, decidedAt: c.decidedAt })),
  });
}

async function cmdSyncDevices(flags) {
  const vault = await openWithFlags(flags);
  const sync = ensureSyncMeta(vault.payload());
  if (flags._sub2 === "add") {
    if (!flags.jkt) return outputError("sync devices add requires --jkt <thumbprint> (from the other device's approval-required log)");
    pinDevice(sync, { deviceJkt: String(flags.jkt), label: flags.label ? String(flags.label) : null });
    await vault.save();
    stderr(`Preapproved device ${flags.jkt} — its key is pinned on first verified contact.`);
    return outputJson({ ok: true, jkt: String(flags.jkt) });
  }
  outputJson({ ok: true, devices: sync.devices.map((d) => ({ jkt: d.deviceJkt, label: d.label, complete: Boolean(d.agentJwk) })) });
}

async function cmdSyncRevoke(flags) {
  if (!flags.jkt) return outputError("sync revoke requires --jkt <thumbprint>");
  const vault = await openWithFlags(flags);
  const sync = ensureSyncMeta(vault.payload());
  const removed = revokeDevice(sync, String(flags.jkt));
  if (removed) await vault.save();
  outputJson({ ok: removed, ...(removed ? {} : { error: "device not found" }) });
}

async function cmdSyncResolve(flags) {
  if (!flags.name) return outputError("sync resolve requires --name <credential>");
  const vault = await openWithFlags(flags);
  const sync = ensureSyncMeta(vault.payload());
  const entries = sync.conflicts.filter((c) => c.name === flags.name);
  if (entries.length === 0) return outputError(`no journaled conflicts for "${flags.name}"`);
  const latest = entries[entries.length - 1];
  if (!flags.restore) {
    return outputJson({
      ok: true, name: latest.name, winnerHash: latest.winnerHash,
      current: vault.get(String(flags.name)) ? "present" : "removed",
      losingRecord: { ...latest.losingRecord, ...(latest.losingRecord.value ? { value: "(redacted — use --restore)" } : {}) },
      hint: "re-run with --restore to reinstate the losing version as a new edit",
    });
  }
  // Reinstating = a NEW causally-later edit; it wins everywhere on next sync.
  vault.add({ ...latest.losingRecord });
  sync.conflicts = sync.conflicts.filter((c) => c !== latest);
  await vault.save();
  stderr(`Restored the journaled version of "${flags.name}". It will propagate on the next sync.`);
  outputJson({ ok: true, restored: flags.name });
}

// `sync` takes an optional sub-verb as its first positional arg (like rekey).
function makeSyncHandler() {
  return async (flags) => {
    const argv = process.argv.slice(2);
    const idx = argv.indexOf("sync");
    const sub = idx >= 0 && argv[idx + 1] && !argv[idx + 1].startsWith("--") ? argv[idx + 1] : null;
    const sub2 = sub && argv[idx + 2] && !argv[idx + 2].startsWith("--") ? argv[idx + 2] : null;
    if (sub === "status") return cmdSyncStatus(flags);
    if (sub === "devices") return cmdSyncDevices({ ...flags, _sub2: sub2 });
    if (sub === "revoke") return cmdSyncRevoke(flags);
    if (sub === "resolve") return cmdSyncResolve(flags);
    if (sub) return outputError(`Unknown sync subcommand: ${sub}`);
    return cmdSyncRun(flags);
  };
}
```

- [ ] **Step 3: Register the command and extend help**

In the `commands` table add (after `migrate: cmdMigrate,`):

```js
  sync: makeSyncHandler(),
```

In `printHelp`'s usage text, after the `migrate` line add:

```
      "  sync [--peer H:P] [--listen [--port N] [--host H]] [--label L]",
      "  sync status | devices [add --jkt J] | revoke --jkt J | resolve --name N [--restore]",
```

- [ ] **Step 4: Smoke-test the CLI manually**

```bash
STATE=$(mktemp -d)
node plugins/agent-id-core/bin/cli.mjs bootstrap --state-dir "$STATE" 2>/dev/null || true
node plugins/agent-id-vault/bin/cli.mjs sync --state-dir "$STATE" 2>&1 | head -3
```

Expected: a clean coded error about the missing owner binding (`sync requires an owner binding (L1+)`) or missing vault — NOT a stack trace.

Then verify help renders: `node plugins/agent-id-vault/bin/cli.mjs help | grep sync`
Expected: the two new usage lines.

- [ ] **Step 5: Run the full suite**

Run: `bun run test`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add plugins/agent-id-vault/bin/cli.mjs
git commit -m "feat(vault): :sparkles: sync CLI (one-shot, listen, status, devices, revoke, resolve)"
```

---

### Task 10: End-to-end integration test — three devices, migration, revocation

**Files:**
- Test: `tests/test-sync-e2e.mjs`

**Interfaces:**
- Consumes: everything above (this is the acceptance test for the spec's Testing section, items 3–4).

- [ ] **Step 1: Write the test**

Create `tests/test-sync-e2e.mjs`:

```js
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
import os from "node:os";
import path from "node:path";

import {
  ed25519PublicKeyToJwk,
  generateEd25519PemPair,
  jwkThumbprint,
} from "../plugins/agent-id-core/lib/crypto.mjs";
import { ensureDir, statePaths, writeJsonFile } from "../plugins/agent-id-core/lib/state.mjs";
import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { connectToPeer, startSyncServer } from "../plugins/agent-id-vault/lib/sync/channel.mjs";
import { loadSyncIdentity, revokeDevice, ensureSyncMeta } from "../plugins/agent-id-vault/lib/sync/trust.mjs";
import { runSyncSession } from "../plugins/agent-id-vault/lib/sync/protocol.mjs";

const fakeVerifyIdToken = async ({ idToken }) => {
  const payload = JSON.parse(Buffer.from(idToken.split(".")[1], "base64url").toString("utf8"));
  return { signatureValid: true, issuer: payload.iss, payload, header: {} };
};

async function makeDevice(sub, label) {
  const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), `sync-e2e-${label}-`));
  const pair = generateEd25519PemPair();
  const agentJwk = ed25519PublicKeyToJwk(pair.publicKeyPem);
  const jkt = jwkThumbprint(agentJwk);
  const paths = statePaths(stateDir);
  await ensureDir(path.dirname(paths.mainKey));
  await writeJsonFile(paths.mainKey, { agentId: "main", ...pair });
  const idPayload = { iss: "https://sso.test", sub, cnf: { jkt } };
  const idToken = ["e30", Buffer.from(JSON.stringify(idPayload)).toString("base64url"), "sig"].join(".");
  await writeJsonFile(paths.ownerSession, { idToken });
  await initVault({ stateDir, privateKeyPem: pair.privateKeyPem, agentId: "main" });
  return { stateDir, pair, label, jkt };
}

async function open(device) {
  const vault = await openVault({ stateDir: device.stateDir, privateKeyPem: device.pair.privateKeyPem });
  const identity = await loadSyncIdentity(device.stateDir, { label: device.label });
  return { vault, identity };
}

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
```

- [ ] **Step 2: Run the test**

Run: `node --test tests/test-sync-e2e.mjs`
Expected: PASS. If the mesh test fails on `unknown-author`: that means op relay hit an unpinned author — re-check the pairing order comment in the test; the full-mesh requirement is by design (spec: "full-mesh pairing required for 3+ devices").

- [ ] **Step 3: Run the whole suite**

Run: `bun run test`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add tests/test-sync-e2e.mjs
git commit -m "test(vault): :white_check_mark: sync e2e — genesis migration, 3-device mesh, revocation"
```

---

### Task 11: Docs, changeset, final verification

**Files:**
- Modify: `plugins/agent-id-vault/skills/agent-id-vault/SKILL.md` (add sync section)
- Modify: `plugins/agent-id-vault/skills/agent-id-vault/reference.md` (add sync command reference)
- Create: `.changeset/vault-p2p-sync.md`

**Interfaces:** none (documentation + release intent).

- [ ] **Step 1: Add the changeset**

Create `.changeset/vault-p2p-sync.md`:

```md
---
"@alien-id/agent-id-vault": minor
---

p2p vault sync (PoC): live, fully decentralized synchronization of credential
records between a user's devices. Signed op-log DAG inside the encrypted
payload (git-like causality, deterministic conflict tiebreak, local conflict
journal), TLS 1.3 channel with Ed25519-over-EKM identity binding, same-owner
verification via the v3 bundle plus one-time per-device approval, UDP beacon
discovery + explicit `--peer`. New CLI: `sync`, `sync --listen`, `sync status`,
`sync devices [add]`, `sync revoke`, `sync resolve`. `browser-profile` records
stay device-local. Master keys never leave a device.
```

- [ ] **Step 2: Document in the plugin skill**

In `plugins/agent-id-vault/skills/agent-id-vault/SKILL.md`, add a section (match the file's existing heading style — read it first, then append near the other command workflows):

```md
## Sync between devices (p2p)

Both devices need an owner binding (`agent-id-core auth`) to the SAME owner.

1. On device A: `agent-id-vault sync --listen`
2. On device B: `agent-id-vault sync` (same LAN) or `agent-id-vault sync --peer <hostA>:<port>`
3. First contact prompts on both sides to trust the peer (one-time). Headless
   side: approve later with `agent-id-vault sync devices add --jkt <jkt>` using
   the thumbprint from its log.
4. Afterwards sync is automatic between pinned devices — no prompts, no SSO.

Conflicts (same credential edited on two devices while apart) resolve
deterministically; the losing version is journaled — inspect with
`sync status`, restore with `sync resolve --name <N> --restore`.
Revoke a device with `sync revoke --jkt <jkt>` (repeat on each device).
Note: `browser-profile` records and the agent identity never sync.
```

In `plugins/agent-id-vault/skills/agent-id-vault/reference.md`, append a
command-reference section (match the file's existing per-command formatting):

```md
## sync — p2p synchronization between the owner's devices

    agent-id-vault sync [--peer HOST:PORT] [--label LABEL] [--timeout-ms N]
    agent-id-vault sync --listen [--port N] [--host H] [--label LABEL]
    agent-id-vault sync status
    agent-id-vault sync devices
    agent-id-vault sync devices add --jkt THUMBPRINT [--label LABEL]
    agent-id-vault sync revoke --jkt THUMBPRINT
    agent-id-vault sync resolve --name CREDENTIAL [--restore]

- One-shot `sync` discovers LAN peers via UDP beacon (or dials `--peer`),
  exchanges signed op-log entries over TLS 1.3, applies atomically, exits.
- `--listen` stays resident: announces a beacon and serves incoming syncs.
- Requires an owner binding (L1+) on both devices, bound to the same owner.
- First contact per device pair triggers a one-time trust prompt; headless
  hosts log the peer's jkt and expect `sync devices add --jkt <jkt>` instead.
- `resolve --restore` reinstates a conflict-journaled version as a new edit.
- Never synced: `browser-profile` records (+ sealed profile sidecars), the
  agent identity/key, the trust list, the conflict journal.
- Env: `AGENT_ID_SYNC_AUTOAPPROVE=1` skips the trust prompt (tests only).
```

- [ ] **Step 3: Full-suite + release-tooling verification**

Run: `bun run test && bun test scripts/tests && bun run sync-plugin-versions 2>/dev/null || true`
Expected: test suites PASS. (`sync-plugin-versions` needs no changes — versions are bumped by the release bot, not by this PR.)

- [ ] **Step 4: Commit**

```bash
git add .changeset/vault-p2p-sync.md plugins/agent-id-vault/skills/agent-id-vault/
git commit -m "docs(vault): :memo: sync skill docs + release changeset"
```

- [ ] **Step 5: Wrap up the branch**

Rebase on main, push, and open the PR per repo convention (squash-merge target `main`):

```bash
git pull --rebase origin main
git push -u origin explore-agent-id-plugins
```

Then open the PR with the `/pr` skill if available (fall back to `gh pr create --base main`), titled `feat(vault): p2p vault sync PoC`, body summarizing the spec link `docs/superpowers/specs/2026-07-03-vault-p2p-sync-design.md`, and noting the two changesets (core minor, vault minor).

---

## Spec coverage map (self-review)

| Spec section | Task(s) |
| --- | --- |
| Cert-minter promotion to core | 1 |
| Operation format / DAG / fold / tiebreak / conflicts | 2 |
| Materialized view, genesis migration, `browser-profile` exclusion | 3 |
| Oplog + journal under AEAD, wiped on lock | 4 |
| Trust store, pinning, revocation, owner-binding auth, L0 rejection, offline pinned path | 5 |
| TLS 1.3 + ephemeral certs + EKM channel binding + MITM exclusion | 6 |
| Wire protocol, staged atomic apply, advisory lock, self-registration | 7 |
| UDP beacon discovery | 8 |
| CLI: one-shot / --listen / --peer / status / devices / revoke / resolve, approval ceremony, headless preapproval | 9 |
| E2E: migration, 3-device mesh (full-mesh pairing), revocation | 10 |
| Changesets (core minor + vault minor), skill docs | 1, 11 |

Known intentional deviations from the spec text (documented in code comments):
- For **pinned** peers the id_token is not re-verified per connection — the pinned key + EKM signature is the identity. This implements the spec's "no SSO call at sync time" more strongly than a JWKS cache would.
- The spec's `want` line lists hashes; the difference source is the full hash set carried on the `heads` line (`all`), exactly as the spec's "difference is computed by exchanging full op-hash sets" prescribes.
