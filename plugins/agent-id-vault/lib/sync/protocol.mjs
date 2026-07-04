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
