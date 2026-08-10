#!/usr/bin/env node

// Self-reopen (issue #103): a proxy given a `reopenVault` callback can recover
// a credential written to `vault.enc` by another process after it started —
// no restart, no port churn. Mirrors the setup/request helpers in
// test-proxy-idle-lock.mjs.

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

import { generateEd25519PemPair } from "../plugins/agent-id-core/lib/crypto.mjs";
import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { createProxy } from "../plugins/agent-id-proxy/lib/proxy.mjs";

function startUpstream() {
  return new Promise((resolve) => {
    const requests = [];
    const server = http.createServer((req, res) => {
      req.resume();
      requests.push({ method: req.method, authorization: req.headers.authorization || null });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"ok":true}');
    });
    server.listen(0, "127.0.0.1", () => {
      const a = server.address();
      resolve({ server, url: `http://${a.address}:${a.port}`, requests });
    });
  });
}

// Fake oauth2 token endpoint: mints incrementing access tokens and records the
// refresh token each exchange presented. `cfg.rotateTo` makes it rotate.
function startTokenEndpoint() {
  const stats = { count: 0, refreshTokens: [] };
  const cfg = { rotateTo: null };
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        stats.count += 1;
        const form = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
        stats.refreshTokens.push(form.get("refresh_token"));
        const body = {
          access_token: `at-${stats.count}`,
          expires_in: 3600,
          token_type: "Bearer",
        };
        if (cfg.rotateTo) body.refresh_token = cfg.rotateTo;
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(body));
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const a = server.address();
      resolve({ server, url: `http://${a.address}:${a.port}/token`, stats, cfg });
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

// URL-rewrite mode: /<credname>/<host>/<path>.
function proxyPathRequest({ port, path: reqPath, method = "GET" }) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, method, path: reqPath }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () =>
        resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString("utf8") }),
      );
    });
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

  it("400s a credential that does not exist yet", async () => {
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

describe("proxy self-reopen: URL-rewrite mode", () => {
  let stateDir;
  let upstream;
  let proxy;
  let proxyPort;
  let upstreamHost;
  let upstreamAuthority;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-reload-rw-"));
    await initVault({ stateDir, passphrase: "p" });

    upstream = await startUpstream();
    upstreamHost = new URL(upstream.url).hostname;
    upstreamAuthority = new URL(upstream.url).host;

    const vault = await openVault({ stateDir, passphrase: "p" });
    proxy = createProxy({
      vault,
      logPath: path.join(stateDir, "proxy.log"),
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

  it("400s a credential that does not exist yet", async () => {
    const r = await proxyPathRequest({
      port: proxyPort,
      path: `/tok/${upstreamAuthority}/x`,
    });
    assert.equal(r.status, 400);
    assert.equal(JSON.parse(r.body).error, "credential_not_found");
  });

  it("injects it once another process adds it to the vault on disk", async () => {
    const writer = await openVault({ stateDir, passphrase: "p" });
    writer.add({
      name: "tok",
      type: "bearer",
      domains: [upstreamHost],
      upstreamScheme: "http",
      value: "SECRET-REWRITE",
    });
    await writer.save();
    writer.lock();

    const r = await proxyPathRequest({
      port: proxyPort,
      path: `/tok/${upstreamAuthority}/y`,
    });
    assert.equal(r.status, 200);
    assert.equal(upstream.requests.at(-1).authorization, "Bearer SECRET-REWRITE");
  });
});

describe("proxy self-reopen: reopen failures fall back to the plain miss", () => {
  let stateDir;
  let upstream;
  let upstreamAuthority;
  const proxies = [];

  async function startProxy(reopenVault) {
    const vault = await openVault({ stateDir, passphrase: "p" });
    const proxy = createProxy({
      vault,
      logPath: path.join(stateDir, "proxy.log"),
      reopenVault,
    });
    const addr = await proxy.listen();
    proxies.push(proxy);
    return addr.port;
  }

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-reload-fail-"));
    await initVault({ stateDir, passphrase: "p" });
    upstream = await startUpstream();
    upstreamAuthority = new URL(upstream.url).host;

    const seed = await openVault({ stateDir, passphrase: "p" });
    seed.add({
      name: "present",
      type: "bearer",
      domains: [new URL(upstream.url).hostname],
      upstreamScheme: "http",
      value: "SECRET-PRESENT",
    });
    await seed.save();
    seed.lock();
  });

  after(async () => {
    for (const p of proxies) await p.close();
    upstream?.server.close();
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("answers the normal credential_not_found when reopenVault rejects", async () => {
    const port = await startProxy(async () => {
      throw new Error("agent key unavailable");
    });
    const r = await proxyPathRequest({ port, path: `/tok/${upstreamAuthority}/x` });
    assert.equal(r.status, 400);
    assert.equal(JSON.parse(r.body).error, "credential_not_found");

    const stub = await proxyRequest({
      port,
      target: `${upstream.url}/x`,
      headers: { Authorization: "AgentVault tok" },
    });
    assert.equal(stub.status, 400);
    assert.equal(JSON.parse(stub.body).error, "credential_not_found");
  });

  it("answers the normal credential_not_found when reopenVault resolves nothing", async () => {
    for (const nothing of [async () => null, async () => undefined]) {
      const port = await startProxy(nothing);
      const r = await proxyPathRequest({ port, path: `/tok/${upstreamAuthority}/x` });
      assert.equal(r.status, 400);
      assert.equal(JSON.parse(r.body).error, "credential_not_found");

      // The failed reopen must not have displaced the working vault handle.
      const ok = await proxyPathRequest({ port, path: `/present/${upstreamAuthority}/x` });
      assert.equal(ok.status, 200);
      assert.equal(upstream.requests.at(-1).authorization, "Bearer SECRET-PRESENT");
    }
  });
});

describe("proxy self-reopen: an oauth2 rotation must not erase another writer's credential", () => {
  let stateDir;
  let upstream;
  let token;
  let proxy;
  let proxyPort;
  let upstreamAuthority;
  const clock = 1_700_000_000_000;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-reload-oauth-"));
    await initVault({ stateDir, passphrase: "p" });

    upstream = await startUpstream();
    token = await startTokenEndpoint();
    upstreamAuthority = new URL(upstream.url).host;

    const seed = await openVault({ stateDir, passphrase: "p" });
    seed.add({
      name: "api",
      type: "oauth2",
      domains: [new URL(upstream.url).hostname],
      upstreamScheme: "http",
      tokenEndpoint: token.url,
      clientId: "cid",
      clientSecret: "cs",
      refreshToken: "rt-1",
    });
    await seed.save();
    seed.lock();

    // The proxy's handle is opened here — before the second process writes —
    // so its in-memory payload is exactly the pre-write snapshot.
    const vault = await openVault({ stateDir, passphrase: "p" });
    proxy = createProxy({
      vault,
      stateDir,
      logPath: path.join(stateDir, "proxy.log"),
      now: () => clock,
      reopenVault: async () => openVault({ stateDir, passphrase: "p" }),
    });
    const addr = await proxy.listen();
    proxyPort = addr.port;
  });

  after(async () => {
    await proxy?.close();
    upstream?.server.close();
    token?.server.close();
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("keeps a credential written after start and still persists the rotated token", async () => {
    // "Another process" — e.g. the vault CLI after an out-of-band OAuth flow.
    const writer = await openVault({ stateDir, passphrase: "p" });
    writer.add({
      name: "added-later",
      type: "bearer",
      domains: ["example.test"],
      value: "SECRET-LATER",
    });
    await writer.save();
    writer.lock();

    token.cfg.rotateTo = "rt-2";
    const r = await proxyPathRequest({ port: proxyPort, path: `/api/${upstreamAuthority}/v1/x` });
    assert.equal(r.status, 200);
    assert.equal(upstream.requests.at(-1).authorization, "Bearer at-1");
    assert.deepEqual(token.stats.refreshTokens, ["rt-1"]);

    const disk = await openVault({ stateDir, passphrase: "p" });
    assert.ok(disk.get("added-later"), "the other process's credential survived the rotation save");
    assert.equal(disk.get("api").refreshToken, "rt-2");
    disk.lock();
  });
});

describe("proxy self-reopen: the oauth2 token cache does not outlive the vault handle", () => {
  let stateDir;
  let upstream;
  let token;
  let proxy;
  let proxyPort;
  let upstreamAuthority;
  let clock = 1_700_000_000_000;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-reload-cache-"));
    await initVault({ stateDir, passphrase: "p" });

    upstream = await startUpstream();
    token = await startTokenEndpoint();
    upstreamAuthority = new URL(upstream.url).host;

    const seed = await openVault({ stateDir, passphrase: "p" });
    seed.add({
      name: "api",
      type: "oauth2",
      domains: [new URL(upstream.url).hostname],
      upstreamScheme: "http",
      tokenEndpoint: token.url,
      clientId: "cid",
      clientSecret: "cs",
      refreshToken: "rt-1",
    });
    await seed.save();
    seed.lock();

    const vault = await openVault({ stateDir, passphrase: "p" });
    proxy = createProxy({
      vault,
      stateDir,
      logPath: path.join(stateDir, "proxy.log"),
      now: () => clock,
      reopenVault: async () => openVault({ stateDir, passphrase: "p" }),
    });
    const addr = await proxy.listen();
    proxyPort = addr.port;
  });

  after(async () => {
    await proxy?.close();
    upstream?.server.close();
    token?.server.close();
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("refreshes with the re-authorized refresh token after a reopen", async () => {
    const first = await proxyPathRequest({
      port: proxyPort,
      path: `/api/${upstreamAuthority}/v1/a`,
    });
    assert.equal(first.status, 200);
    assert.deepEqual(token.stats.refreshTokens, ["rt-1"]);

    // The owner re-authorizes out of band: a new refresh token lands on disk.
    const writer = await openVault({ stateDir, passphrase: "p" });
    writer.get("api").refreshToken = "rt-2";
    await writer.save();
    writer.lock();

    clock += 3600 * 1000 + 1; // the cached access token has expired

    // A miss on an unrelated name is what makes the proxy re-read the vault.
    const miss = await proxyPathRequest({
      port: proxyPort,
      path: `/ghost/${upstreamAuthority}/v1/b`,
    });
    assert.equal(miss.status, 400);

    const second = await proxyPathRequest({
      port: proxyPort,
      path: `/api/${upstreamAuthority}/v1/c`,
    });
    assert.equal(second.status, 200);
    assert.equal(
      token.stats.refreshTokens.at(-1),
      "rt-2",
      "the refresh used the record's token, not the cached pre-reopen one",
    );
  });
});

describe("proxy self-reopen: the displaced vault handle is locked", () => {
  let stateDir;
  let upstream;
  let proxy;
  let proxyPort;
  let upstreamAuthority;
  let initialVault;
  let opened;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-reload-wipe-"));
    await initVault({ stateDir, passphrase: "p" });

    upstream = await startUpstream();
    upstreamAuthority = new URL(upstream.url).host;

    initialVault = await openVault({ stateDir, passphrase: "p" });
    opened = [];
    proxy = createProxy({
      vault: initialVault,
      logPath: path.join(stateDir, "proxy.log"),
      reopenVault: async () => {
        const v = await openVault({ stateDir, passphrase: "p" });
        opened.push(v);
        return v;
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

  it("locks each handle it replaces, keeping only the live one usable", async () => {
    const first = await proxyPathRequest({ port: proxyPort, path: `/tok/${upstreamAuthority}/x` });
    assert.equal(first.status, 400);
    assert.equal(opened.length, 1);
    assert.throws(() => initialVault.list(), /locked/i, "the startup handle was locked");

    const second = await proxyPathRequest({ port: proxyPort, path: `/tok/${upstreamAuthority}/y` });
    assert.equal(second.status, 400);
    assert.equal(opened.length, 2);
    assert.throws(() => opened[0].list(), /locked/i, "the first reopened handle was locked");
    assert.doesNotThrow(() => opened[1].list(), "the live handle still serves lookups");
  });
});

describe("proxy self-reopen: an in-flight request keeps the credential it resolved", () => {
  let stateDir;
  let upstream;
  let proxy;
  let proxyPort;
  let upstreamAuthority;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-reload-inflight-"));
    await initVault({ stateDir, passphrase: "p" });

    upstream = await startUpstream();
    upstreamAuthority = new URL(upstream.url).host;

    const seed = await openVault({ stateDir, passphrase: "p" });
    seed.add({
      name: "ro-tok",
      type: "bearer",
      domains: [new URL(upstream.url).hostname],
      upstreamScheme: "http",
      access: "ro",
      value: "SECRET-INFLIGHT",
    });
    await seed.save();
    seed.lock();

    const vault = await openVault({ stateDir, passphrase: "p" });
    proxy = createProxy({
      vault,
      logPath: path.join(stateDir, "proxy.log"),
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

  it("injects the resolved value even when a concurrent miss swaps the vault mid-request", async () => {
    // An "ro" credential buffers a POST body before deciding, so this request
    // sits awaiting its body with the credential already resolved.
    const slow = http.request({
      host: "127.0.0.1",
      port: proxyPort,
      method: "POST",
      path: `/ro-tok/${upstreamAuthority}/graphql`,
      headers: { "Content-Type": "application/json" },
    });
    const answered = new Promise((resolve, reject) => {
      slow.on("response", (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode));
      });
      slow.on("error", reject);
    });
    slow.write('{"query":"query ');
    await new Promise((r) => setTimeout(r, 100));

    const miss = await proxyPathRequest({ port: proxyPort, path: `/ghost/${upstreamAuthority}/x` });
    assert.equal(miss.status, 400);

    slow.end('{ me { id } }"}');
    assert.equal(await answered, 200);
    assert.equal(upstream.requests.at(-1).method, "POST");
    assert.equal(upstream.requests.at(-1).authorization, "Bearer SECRET-INFLIGHT");
  });
});

describe("proxy CLI: the idle-lock notice matches what can re-unlock the vault", () => {
  const CLI = new URL("../plugins/agent-id-proxy/bin/cli.mjs", import.meta.url).pathname;
  const dirs = [];

  function freePort() {
    return new Promise((resolve) => {
      const s = net.createServer();
      s.listen(0, "127.0.0.1", () => {
        const { port } = s.address();
        s.close(() => resolve(port));
      });
    });
  }

  // Run a proxy until its idle lock fires, then return the lock line.
  async function lockNotice(extraArgs, stateDir) {
    const port = await freePort();
    const child = spawn(
      "node",
      [
        CLI,
        "start",
        "--no-control",
        "--idle-timeout",
        "200ms",
        "--port",
        String(port),
        "--state-dir",
        stateDir,
        ...extraArgs,
      ],
      { env: { ...process.env, AGENT_ID_NO_BROWSER: "1" } },
    );
    let stderrBuf = "";
    child.stderr.on("data", (d) => (stderrBuf += d));
    try {
      return await new Promise((resolve, reject) => {
        const timer = setTimeout(
          () => reject(new Error(`timeout waiting for the lock notice\n${stderrBuf}`)),
          10_000,
        );
        const onData = () => {
          const m = stderrBuf.match(/^Vault locked \(idle_timeout\)\..*$/m);
          if (!m) return;
          clearTimeout(timer);
          child.stderr.off("data", onData);
          resolve(m[0]);
        };
        child.stderr.on("data", onData);
        child.on("exit", () => reject(new Error(`proxy exited early\n${stderrBuf}`)));
      });
    } finally {
      child.kill("SIGTERM");
      await new Promise((r) => child.on("exit", r));
    }
  }

  after(async () => {
    for (const d of dirs) await fs.rm(d, { recursive: true, force: true });
  });

  it("says the proxy re-opens the vault itself when it unlocked via the agent key", async () => {
    const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-reload-cli-key-"));
    dirs.push(stateDir);
    const { privateKeyPem, publicKeyPem } = generateEd25519PemPair();
    await fs.mkdir(path.join(stateDir, "keys"), { recursive: true });
    await fs.writeFile(
      path.join(stateDir, "keys", "main.json"),
      JSON.stringify({ privateKeyPem, publicKeyPem }),
      { mode: 0o600 },
    );
    await initVault({ stateDir, privateKeyPem });

    const notice = await lockNotice([], stateDir);
    assert.match(notice, /agent key/i);
    assert.doesNotMatch(notice, /restart/i);
  });

  it("still says restart when the vault needed a human to unlock", async () => {
    const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-reload-cli-pass-"));
    dirs.push(stateDir);
    await initVault({ stateDir, passphrase: "p" });
    const passFile = path.join(stateDir, "pass.txt");
    await fs.writeFile(passFile, "p", { mode: 0o600 });

    const notice = await lockNotice(["--passphrase-file", passFile], stateDir);
    assert.match(notice, /restart/i);
  });
});
