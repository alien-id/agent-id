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
