#!/usr/bin/env node

import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";

import { startDevPhoneSimulator } from "../plugins/agent-id-proxy/lib/dev-phone.mjs";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(predicate, message) {
  for (let i = 0; i < 100; i++) {
    if (predicate()) return;
    await sleep(5);
  }
  assert.fail(message);
}

function startControl({ pending, token = "control-token" }) {
  const posts = [];
  let pendingReads = 0;
  const server = http.createServer((req, res) => {
    assert.equal(req.headers.authorization, `Bearer ${token}`);
    if (req.method === "GET" && req.url === "/pending") {
      pendingReads++;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, pending }));
      return;
    }
    if (req.method === "POST" && (req.url === "/approve" || req.url === "/deny")) {
      const chunks = [];
      req.on("data", (chunk) => chunks.push(chunk));
      req.on("end", () => {
        posts.push({ path: req.url, body: JSON.parse(Buffer.concat(chunks).toString("utf8")) });
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end('{"ok":true}');
      });
      return;
    }
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end('{"ok":false,"error":"not_found"}');
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () =>
      resolve({
        server,
        port: server.address().port,
        posts,
        get pendingReads() {
          return pendingReads;
        },
      }),
    );
  });
}

describe("development phone simulator", () => {
  const cleanup = [];

  afterEach(async () => {
    while (cleanup.length) await cleanup.pop()();
  });

  it("approves only capability entries and echoes the exact digest with once scope", async () => {
    const control = await startControl({
      pending: [
        { id: "unlock-1", action: "unlock" },
        { id: "authorize-1", action: "authorize" },
        { id: "cap-1", action: "capability", actionDigest: "sha256:exact-request" },
      ],
    });
    cleanup.push(() => new Promise((resolve) => control.server.close(resolve)));

    const phone = startDevPhoneSimulator({
      controlPort: control.port,
      controlToken: "control-token",
      decision: "approve",
      pollIntervalMs: 5,
    });
    cleanup.push(() => phone.stop());

    await waitFor(() => control.posts.length === 1, "simulator did not approve capability");
    assert.deepEqual(control.posts, [
      {
        path: "/approve",
        body: {
          id: "cap-1",
          actionDigest: "sha256:exact-request",
          scope: "once",
        },
      },
    ]);

    // The fake server intentionally keeps returning every entry. A successful
    // capability approval is still submitted once, and unlock/authorize never are.
    await sleep(30);
    assert.equal(control.posts.length, 1);
    assert.equal(phone.handledCount, 1);
  });

  it("denies a capability through /deny with the same exact binding", async () => {
    const control = await startControl({
      pending: [{ id: "cap-deny", action: "capability", actionDigest: "digest-deny" }],
    });
    cleanup.push(() => new Promise((resolve) => control.server.close(resolve)));

    const phone = startDevPhoneSimulator({
      controlPort: control.port,
      controlToken: "control-token",
      decision: "deny",
      pollIntervalMs: 5,
    });
    cleanup.push(() => phone.stop());

    await waitFor(() => control.posts.length === 1, "simulator did not deny capability");
    assert.deepEqual(control.posts[0], {
      path: "/deny",
      body: { id: "cap-deny", actionDigest: "digest-deny", scope: "once" },
    });
  });

  it("ignores malformed capability entries without an exact digest", async () => {
    const control = await startControl({
      pending: [{ id: "cap-no-digest", action: "capability" }],
    });
    cleanup.push(() => new Promise((resolve) => control.server.close(resolve)));

    const phone = startDevPhoneSimulator({
      controlPort: control.port,
      controlToken: "control-token",
      pollIntervalMs: 5,
    });
    cleanup.push(() => phone.stop());

    await waitFor(() => control.pendingReads >= 2, "simulator did not poll control plane");
    assert.deepEqual(control.posts, []);
    assert.equal(phone.handledCount, 0);
  });

  it("refuses non-loopback control hosts", () => {
    assert.throws(
      () =>
        startDevPhoneSimulator({
          controlHost: "192.168.1.20",
          controlPort: 48772,
          controlToken: "token",
        }),
      /loopback/,
    );
  });

  it("stops cleanly while a poll is in flight", async () => {
    const sockets = new Set();
    const server = http.createServer(() => {
      // Deliberately leave the response open until stop() destroys the request.
    });
    server.on("connection", (socket) => {
      sockets.add(socket);
      socket.on("close", () => sockets.delete(socket));
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    cleanup.push(
      () =>
        new Promise((resolve) => {
          for (const socket of sockets) socket.destroy();
          server.close(resolve);
        }),
    );

    const phone = startDevPhoneSimulator({
      controlPort: server.address().port,
      controlToken: "control-token",
      pollIntervalMs: 5,
    });
    await waitFor(() => sockets.size > 0, "simulator never began polling");
    await phone.stop();
    assert.equal(phone.handledCount, 0);
  });
});

