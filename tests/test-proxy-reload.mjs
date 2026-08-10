#!/usr/bin/env node

// Self-reopen (issue #103): a proxy given a `reopenVault` callback can recover
// a credential written to `vault.enc` by another process after it started —
// no restart, no port churn. Mirrors the setup/request helpers in
// test-proxy-idle-lock.mjs.

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { createProxy } from "../plugins/agent-id-proxy/lib/proxy.mjs";

function startUpstream() {
  return new Promise((resolve) => {
    const requests = [];
    const server = http.createServer((req, res) => {
      requests.push({ authorization: req.headers.authorization || null });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"ok":true}');
    });
    server.listen(0, "127.0.0.1", () => {
      const a = server.address();
      resolve({ server, url: `http://${a.address}:${a.port}`, requests });
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
          }),
        );
      },
    );
    req.on("error", reject);
    req.end();
  });
}

describe("proxy self-reopen: credential added after start", () => {
  let stateDir;
  let upstream;
  let proxy;
  let proxyPort;
  let upstreamHost;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-reload-"));
    await initVault({ stateDir, passphrase: "p" });

    upstream = await startUpstream();
    upstreamHost = new URL(upstream.url).hostname;

    const vault = await openVault({ stateDir, passphrase: "p" });
    proxy = createProxy({
      vault,
      logPath: path.join(stateDir, "proxy.log"),
      // Reopens from disk exactly the way the agent-key path does — a fresh
      // open, not a reference to any in-memory vault the test already holds.
      reopenVault: async () => openVault({ stateDir, passphrase: "p" }),
    });
    const addr = await proxy.listen();
    proxyPort = addr.port;
  });

  after(async () => {
    await proxy?.close();
    upstream?.server.close();
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("404s a credential that does not exist yet", async () => {
    const r = await proxyRequest({
      port: proxyPort,
      target: `${upstream.url}/x`,
      headers: { Authorization: "AgentVault tok" },
    });
    assert.equal(r.status, 400);
    const body = JSON.parse(r.body);
    assert.equal(body.error, "credential_not_found");
  });

  it("injects it once another process adds it to the vault on disk, without a proxy restart", async () => {
    // "Another process" — a separate open/save, exactly like the vault CLI
    // running after an out-of-band OAuth flow.
    const writer = await openVault({ stateDir, passphrase: "p" });
    writer.add({
      name: "tok",
      type: "bearer",
      domains: [upstreamHost],
      value: "SECRET-FROM-DISK",
    });
    await writer.save();
    writer.lock();

    const r = await proxyRequest({
      port: proxyPort,
      target: `${upstream.url}/y`,
      headers: { Authorization: "AgentVault tok" },
    });
    assert.equal(r.status, 200);
    assert.equal(upstream.requests.at(-1).authorization, "Bearer SECRET-FROM-DISK");
  });
});

describe("proxy self-reopen: single-flight", () => {
  let stateDir;
  let upstream;
  let proxy;
  let proxyPort;
  let reopenCalls;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-reload-sf-"));
    await initVault({ stateDir, passphrase: "p" });

    upstream = await startUpstream();
    const upstreamHost = new URL(upstream.url).hostname;

    const vault = await openVault({ stateDir, passphrase: "p" });
    reopenCalls = 0;
    proxy = createProxy({
      vault,
      logPath: path.join(stateDir, "proxy.log"),
      reopenVault: async () => {
        reopenCalls += 1;
        // Add the credential to the SAME on-disk vault the first time we're
        // asked, so every concurrent caller's retry finds it — a real
        // reopen would already see it, since another process wrote it first.
        const writer = await openVault({ stateDir, passphrase: "p" });
        if (!writer.get("tok")) {
          writer.add({
            name: "tok",
            type: "bearer",
            domains: [upstreamHost],
            value: "SECRET-SF",
          });
          await writer.save();
        }
        writer.lock();
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

  it("fires the reopen exactly once for 5 concurrent misses", async () => {
    const results = await Promise.all(
      Array.from({ length: 5 }, () =>
        proxyRequest({
          port: proxyPort,
          target: `${upstream.url}/z`,
          headers: { Authorization: "AgentVault tok" },
        }),
      ),
    );
    for (const r of results) assert.equal(r.status, 200);
    assert.equal(reopenCalls, 1);
  });
});
