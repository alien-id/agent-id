#!/usr/bin/env node

// Auto-lock on idle: after `idleTimeoutMs` with no traffic, the proxy must
// zero its master key and refuse subsequent requests with 401 vault_locked.
//
// We drive the clock with an injected `now()` so the test runs in
// milliseconds, not 12 hours.

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { createProxy } from "../plugins/agent-id-proxy/lib/proxy.mjs";
import { readJsonl } from "../plugins/agent-id-core/lib/state.mjs";

function startUpstream() {
  return new Promise((resolve) => {
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"ok":true}');
    });
    server.listen(0, "127.0.0.1", () => {
      const a = server.address();
      resolve({ server, url: `http://${a.address}:${a.port}` });
    });
  });
}

function proxyRequest({ port, target, headers = {} }) {
  return new Promise((resolve, reject) => {
    const url = new URL(target);
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        method: "GET",
        path: target,
        headers: { Host: url.host, ...headers },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf8"),
          })
        );
      }
    );
    req.on("error", reject);
    req.end();
  });
}

describe("proxy idle auto-lock", () => {
  let stateDir;
  let upstream;
  let vault;
  let proxy;
  let proxyPort;
  let clock = 0;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-idle-"));
    await initVault({ stateDir, passphrase: "p" });
    vault = await openVault({ stateDir, passphrase: "p" });

    upstream = await startUpstream();
    const upstreamHost = new URL(upstream.url).hostname;
    vault.add({
      name: "tok",
      type: "bearer",
      domains: [upstreamHost],
      value: "SECRET",
    });
    await vault.save();

    // Re-open so the credentials we just added are present in `vault`.
    vault.lock();
    vault = await openVault({ stateDir, passphrase: "p" });

    // 100 ms idle timeout, but we control `now()` directly so we don't
    // actually wait — we advance the clock past the threshold and then
    // pump the event loop so the interval tick runs.
    clock = 1_000_000;
    proxy = createProxy({
      vault,
      logPath: path.join(stateDir, "proxy.log"),
      idleTimeoutMs: 50,
      now: () => clock,
    });
    const addr = await proxy.listen();
    proxyPort = addr.port;
  });

  after(async () => {
    await proxy?.close();
    upstream?.server.close();
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("serves while active", async () => {
    const r = await proxyRequest({
      port: proxyPort,
      target: `${upstream.url}/x`,
      headers: { Authorization: "AgentVault tok" },
    });
    assert.equal(r.status, 200);
    assert.equal(proxy.locked, false);
  });

  it("force-lock drops the master key and returns 401 vault_locked", async () => {
    proxy.forceLock("test");
    assert.equal(proxy.locked, true);
    const r = await proxyRequest({
      port: proxyPort,
      target: `${upstream.url}/y`,
      headers: { Authorization: "AgentVault tok" },
    });
    assert.equal(r.status, 401);
    const body = JSON.parse(r.body);
    assert.equal(body.error, "vault_locked");
    assert.equal(r.headers["x-agentvault-proxy-error"], "vault_locked");
  });

  it("subsequent requests stay locked (no auto-relock)", async () => {
    const r = await proxyRequest({
      port: proxyPort,
      target: `${upstream.url}/z`,
      headers: { Authorization: "AgentVault tok" },
    });
    assert.equal(r.status, 401);
  });
});

describe("proxy idle ticker", () => {
  let stateDir;
  let vault;
  let proxy;
  let upstream;
  let proxyPort;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-idle-tick-"));
    await initVault({ stateDir, passphrase: "p" });
    vault = await openVault({ stateDir, passphrase: "p" });
    upstream = await startUpstream();
    vault.add({
      name: "tok",
      type: "bearer",
      domains: [new URL(upstream.url).hostname],
      value: "SECRET",
    });
    await vault.save();
    vault.lock();
    vault = await openVault({ stateDir, passphrase: "p" });
  });

  after(async () => {
    await proxy?.close();
    upstream?.server.close();
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("ticker locks after idleTimeoutMs of inactivity", async () => {
    // Advance the clock via a controllable now(). Tick interval = min(60s, idle).
    // With idle=20ms the ticker runs every 20ms; we wait ~150ms for it to fire.
    let clock = 0;
    proxy = createProxy({
      vault,
      logPath: path.join(stateDir, "proxy.log"),
      idleTimeoutMs: 20,
      now: () => clock,
    });
    const addr = await proxy.listen();
    proxyPort = addr.port;

    // First request: clock at 0, lastRequestAt becomes 0, not locked.
    const r1 = await proxyRequest({
      port: proxyPort,
      target: `${upstream.url}/a`,
      headers: { Authorization: "AgentVault tok" },
    });
    assert.equal(r1.status, 200);

    // Move the clock far past the idle window; the tick (running every 20ms
    // real time) will observe `now() - lastRequestAt > 20` and lock.
    clock = 10_000;
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(proxy.locked, true);
  });
});

describe("proxy idle auto-lock — self-reopen (agent-key mode)", () => {
  let stateDir;
  let logPath;
  let upstream;
  let proxy;
  let proxyPort;
  let clock = 0;
  let reopenCalls;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-idle-reopen-"));
    logPath = path.join(stateDir, "proxy.log");
    await initVault({ stateDir, passphrase: "p" });
    let vault = await openVault({ stateDir, passphrase: "p" });

    upstream = await startUpstream();
    vault.add({
      name: "tok",
      type: "bearer",
      domains: [new URL(upstream.url).hostname],
      value: "SECRET",
    });
    await vault.save();
    vault.lock();
    vault = await openVault({ stateDir, passphrase: "p" });

    clock = 1_000_000;
    reopenCalls = 0;
    proxy = createProxy({
      vault,
      logPath,
      idleTimeoutMs: 50,
      now: () => clock,
      // Mirrors the CLI's agent-key path: a fresh open, no human involved.
      reopenVault: async () => {
        reopenCalls += 1;
        return openVault({ stateDir, passphrase: "p" });
      },
    });
    const addr = await proxy.listen();
    proxyPort = addr.port;
  });

  after(async () => {
    await proxy?.close();
    upstream?.server.close();
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("idle-locks the same as without a reopenVault callback", async () => {
    proxy.forceLock("test");
    assert.equal(proxy.locked, true);
  });

  it("recovers on the next request instead of staying locked", async () => {
    const r = await proxyRequest({
      port: proxyPort,
      target: `${upstream.url}/after-reopen`,
      headers: { Authorization: "AgentVault tok" },
    });
    assert.equal(r.status, 200);
    assert.equal(proxy.locked, false);
    assert.equal(reopenCalls, 1);

    // logAccess is fire-and-forget (see doLock's vault_locked write for the
    // same pattern), so the response can land slightly before the append
    // finishes — poll briefly instead of asserting on the first read.
    let reopened;
    for (let i = 0; i < 20 && !reopened; i++) {
      const entries = await readJsonl(logPath);
      reopened = entries.find((e) => e.event === "vault_reopened");
      if (!reopened) await new Promise((res) => setTimeout(res, 25));
    }
    assert.ok(reopened, "expected a vault_reopened log entry");
    assert.equal(reopened.reason, "idle_lock");
  });

  it("locks again on the next idle period and reopens again on the next request", async () => {
    clock += 1000; // past the 50ms idle window again
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(proxy.locked, true);

    const r = await proxyRequest({
      port: proxyPort,
      target: `${upstream.url}/again`,
      headers: { Authorization: "AgentVault tok" },
    });
    assert.equal(r.status, 200);
    assert.equal(proxy.locked, false);
    assert.equal(reopenCalls, 2);
  });
});
