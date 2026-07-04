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
import { fakeVerifyIdToken, makeIdentity as identity } from "./sync-test-helpers.mjs";

const closers = [];
after(async () => { for (const c of closers.reverse()) await c(); });

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
    assert.equal(srv.server.maxConnections, 32);

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
