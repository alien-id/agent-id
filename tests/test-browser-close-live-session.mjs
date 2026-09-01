#!/usr/bin/env node

// closeLiveSession (lib/session-server.mjs): the guard every profile-sealing
// command runs first. A fake daemon stands in for the real one — a TCP server
// that answers `close` and then removes its session file the way finalize()
// does after re-sealing — so the ordering contract is tested without a browser.
//
// Run: node --test tests/test-browser-close-live-session.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { closeLiveSession, sessionFilePath } from "../plugins/agent-id-browser/lib/session-server.mjs";

async function tmpStateDir() {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "aib-close-live-"));
  await fs.mkdir(path.join(dir, "browser-sessions"), { recursive: true });
  return dir;
}

// A daemon that acknowledges `close`, then (after `resealMs`) removes its
// session file — the observable end of finalize()'s reseal.
async function fakeDaemon(stateDir, name, { resealMs = 300 } = {}) {
  const token = "t0k";
  const received = [];
  const server = net.createServer((sock) => {
    let buf = "";
    sock.on("data", (d) => {
      buf += d.toString("utf8");
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      const msg = JSON.parse(buf.slice(0, nl));
      received.push(msg);
      if (msg.token !== token) {
        sock.end(JSON.stringify({ ok: false, error: "bad token" }) + "\n");
        return;
      }
      sock.end(JSON.stringify({ ok: true, closed: true }) + "\n");
      setTimeout(() => {
        fs.rm(sessionFilePath(stateDir, name), { force: true }).then(() => server.close());
      }, resealMs).unref();
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  await fs.writeFile(
    sessionFilePath(stateDir, name),
    JSON.stringify({ port, token, pid: process.pid, headless: true, startedAt: 1 }),
  );
  return { received, server };
}

test("closeLiveSession: no session file → false, nothing to do", async () => {
  const stateDir = await tmpStateDir();
  assert.equal(await closeLiveSession(stateDir, "main"), false);
});

test("closeLiveSession: sends close and returns only after the session file is gone", async () => {
  const stateDir = await tmpStateDir();
  const daemon = await fakeDaemon(stateDir, "main", { resealMs: 400 });
  const logs = [];
  const t0 = Date.now();
  const closed = await closeLiveSession(stateDir, "main", { log: (m) => logs.push(m) });
  assert.equal(closed, true);
  assert.equal(daemon.received.length, 1);
  assert.equal(daemon.received[0].action, "close");
  // Returned after the file was removed (the reseal), not on the ack.
  assert.ok(Date.now() - t0 >= 350, "waited for the daemon's reseal to finish");
  await assert.rejects(fs.access(sessionFilePath(stateDir, "main")));
  assert.ok(logs.some((m) => m.includes("Closing the open 'main' session")));
});

test("closeLiveSession: a stale session file (daemon gone) is removed and reports false", async () => {
  const stateDir = await tmpStateDir();
  // Grab a port that nothing listens on.
  const probe = net.createServer();
  await new Promise((r) => probe.listen(0, "127.0.0.1", r));
  const { port } = probe.address();
  await new Promise((r) => probe.close(r));
  await fs.writeFile(
    sessionFilePath(stateDir, "main"),
    JSON.stringify({ port, token: "x", pid: 1, headless: true, startedAt: 1 }),
  );
  assert.equal(await closeLiveSession(stateDir, "main"), false);
  await assert.rejects(fs.access(sessionFilePath(stateDir, "main")));
});

test("closeLiveSession: a daemon that never finishes closing is an error, not a silent race", async () => {
  const stateDir = await tmpStateDir();
  const daemon = await fakeDaemon(stateDir, "main", { resealMs: 60_000 });
  await assert.rejects(closeLiveSession(stateDir, "main", { timeoutMs: 600 }), (err) => err.code === "SESSION_BUSY");
  daemon.server.close();
});
