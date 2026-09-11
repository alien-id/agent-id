#!/usr/bin/env node

// Reload in place: a supervisor that manages the proxy can make a running
// daemon re-read the vault and the oauth secrets file without restarting it,
// so the port never moves. Covers the in-process `reload()` contract (what a
// removal, a re-add, a refresh in flight and a rotated secrets file do to the
// caches) and the `reload` subcommand that drives it over SIGHUP.
//
// Run: node --test --test-force-exit tests/test-proxy-reload-signal.mjs

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";

import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { writeJsonFile, statePaths } from "../plugins/agent-id-core/lib/state.mjs";
import { fingerprintPublicKeyPem } from "../plugins/agent-id-core/lib/crypto.mjs";
import { createProxy } from "../plugins/agent-id-proxy/lib/proxy.mjs";
import { loadOauthSecretsFile } from "../plugins/agent-id-proxy/lib/oauth.mjs";

const CLI = new URL("../plugins/agent-id-proxy/bin/cli.mjs", import.meta.url).pathname;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function startUpstream() {
  return new Promise((resolve) => {
    const requests = [];
    const server = http.createServer((req, res) => {
      req.resume();
      requests.push({
        method: req.method,
        url: req.url,
        authorization: req.headers.authorization || null,
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"ok":true}');
    });
    server.listen(0, "127.0.0.1", () => {
      const a = server.address();
      resolve({ server, url: `http://${a.address}:${a.port}`, requests });
    });
  });
}

// Fake oauth2 token endpoint. Mints a distinct access token per exchange and
// records what each exchange presented. `cfg.expiresIn` 0 makes every request
// re-exchange (no usable cache); `cfg.hold` parks the response until resolved.
function startTokenEndpoint() {
  const stats = { count: 0, refreshTokens: [], clientSecrets: [] };
  const cfg = { expiresIn: 3600, hold: null };
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", async () => {
        stats.count += 1;
        const form = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
        stats.refreshTokens.push(form.get("refresh_token"));
        stats.clientSecrets.push(form.get("client_secret"));
        const n = stats.count;
        if (cfg.hold) await cfg.hold;
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            access_token: `at-${n}`,
            expires_in: cfg.expiresIn,
            token_type: "Bearer",
          }),
        );
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const a = server.address();
      resolve({ server, url: `http://${a.address}:${a.port}/token`, stats, cfg });
    });
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

// Stub-injection mode: absolute-URI request line, `AgentVault <name>` markers.
function proxyStubRequest({ port, target, headers = {} }) {
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
          resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString("utf8") }),
        );
      },
    );
    req.on("error", reject);
    req.end();
  });
}

async function readAccessLog(logPath) {
  const raw = await fs.readFile(logPath, "utf8").catch(() => "");
  return raw
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l));
}

// Log writes are fire-and-forget, so an entry can land after the response.
async function waitForLogEvent(logPath, event, timeoutMs = 2000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const entries = await readAccessLog(logPath);
    const hit = entries.find((e) => e.event === event);
    if (hit) return hit;
    if (Date.now() > deadline) {
      throw new Error(
        `no '${event}' in the access log (saw: ${entries.map((e) => e.event).join(",") || "nothing"})`,
      );
    }
    await sleep(20);
  }
}

function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

function pidAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function waitForSpawn(child) {
  await new Promise((resolve, reject) => {
    child.once("spawn", resolve);
    child.once("error", reject);
  });
}

// An agent-key vault: the one unlock path a spawned proxy can walk with no
// human, so the CLI reaches "listening" — and the one that makes it reloadable.
async function makeAgentKeyVault(stateDir) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
  const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  await writeJsonFile(statePaths(stateDir).mainKey, {
    version: 1,
    agentId: "main",
    keyNonce: 0,
    createdAt: 1,
    publicKeyPem,
    privateKeyPem,
    fingerprint: fingerprintPublicKeyPem(publicKeyPem),
  });
  await initVault({ stateDir, privateKeyPem, agentId: "main" });
  const v = await openVault({ stateDir, privateKeyPem });
  await v.save();
  v.lock();
}

function spawnCli(args) {
  const child = spawn("node", [CLI, ...args], {
    env: { ...process.env, AGENT_ID_NO_BROWSER: "1" },
  });
  const out = { stdout: "", stderr: "" };
  child.stdout.on("data", (d) => (out.stdout += d));
  child.stderr.on("data", (d) => (out.stderr += d));
  return { child, out };
}

function waitForStderr({ child, out }, re, ms) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`timeout waiting for ${re}\n${out.stderr}\n${out.stdout}`)),
      ms,
    );
    const check = () => {
      const m = out.stderr.match(re);
      if (m) {
        clearTimeout(timer);
        resolve(m[0]);
      }
    };
    child.stderr.on("data", check);
    child.on("exit", () => {
      clearTimeout(timer);
      reject(new Error(`proxy exited early\n${out.stderr}\n${out.stdout}`));
    });
    check();
  });
}

function waitForExit({ child, out }, ms = 15000) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      resolve({ code: "still-running", ...out });
    }, ms);
    child.on("exit", (code) => {
      clearTimeout(timer);
      resolve({ code, ...out });
    });
  });
}

describe("reload: a credential another process removed stops being served", () => {
  let stateDir;
  let upstream;
  let proxy;
  let proxyPort;
  let upstreamAuthority;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-reload-sig-rm-"));
    await initVault({ stateDir, passphrase: "p" });
    upstream = await startUpstream();
    upstreamAuthority = new URL(upstream.url).host;

    const seed = await openVault({ stateDir, passphrase: "p" });
    seed.add({
      name: "tok",
      type: "bearer",
      domains: [new URL(upstream.url).hostname],
      upstreamScheme: "http",
      value: "SECRET-A",
    });
    await seed.save();
    seed.lock();

    proxy = createProxy({
      vault: await openVault({ stateDir, passphrase: "p" }),
      stateDir,
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

  it("serves it, then refuses it after a reload", async () => {
    const before = await proxyPathRequest({
      port: proxyPort,
      path: `/tok/${upstreamAuthority}/a`,
    });
    assert.equal(before.status, 200);
    assert.equal(upstream.requests.at(-1).authorization, "Bearer SECRET-A");

    const writer = await openVault({ stateDir, passphrase: "p" });
    writer.remove("tok");
    await writer.save();
    writer.lock();

    const result = await proxy.reload({ reason: "test" });
    assert.equal(result.ok, true);
    assert.equal(result.credentials, 0);

    const after = await proxyPathRequest({
      port: proxyPort,
      path: `/tok/${upstreamAuthority}/b`,
    });
    assert.equal(after.status, 400);
    assert.equal(JSON.parse(after.body).error, "credential_not_found");
  });
});

describe("reload: a credential another process added needs no credential-miss reopen", () => {
  let stateDir;
  let logPath;
  let upstream;
  let proxy;
  let proxyPort;
  let upstreamAuthority;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-reload-sig-add-"));
    logPath = path.join(stateDir, "proxy.log");
    await initVault({ stateDir, passphrase: "p" });
    upstream = await startUpstream();
    upstreamAuthority = new URL(upstream.url).host;

    proxy = createProxy({
      vault: await openVault({ stateDir, passphrase: "p" }),
      stateDir,
      logPath,
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

  it("serves it straight after the reload", async () => {
    const writer = await openVault({ stateDir, passphrase: "p" });
    writer.add({
      name: "later",
      type: "bearer",
      domains: [new URL(upstream.url).hostname],
      upstreamScheme: "http",
      value: "SECRET-LATER",
    });
    await writer.save();
    writer.lock();

    const result = await proxy.reload({ reason: "test" });
    assert.equal(result.ok, true);
    assert.equal(result.credentials, 1);

    const r = await proxyPathRequest({ port: proxyPort, path: `/later/${upstreamAuthority}/a` });
    assert.equal(r.status, 200);
    assert.equal(upstream.requests.at(-1).authorization, "Bearer SECRET-LATER");

    const entries = await readAccessLog(logPath);
    assert.equal(
      entries.some((e) => e.event === "vault_reopened" && e.reason === "cred_miss"),
      false,
      "the reload must have adopted the new vault — the request should never have missed",
    );
  });
});

describe("reload: a re-added credential is served from a fresh exchange", () => {
  let stateDir;
  let upstream;
  let token;
  let proxy;
  let proxyPort;
  let upstreamAuthority;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-reload-sig-readd-"));
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

    proxy = createProxy({
      vault: await openVault({ stateDir, passphrase: "p" }),
      stateDir,
      logPath: path.join(stateDir, "proxy.log"),
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

  it("does not keep serving the token minted from the credential it replaced", async () => {
    const first = await proxyPathRequest({ port: proxyPort, path: `/api/${upstreamAuthority}/a` });
    assert.equal(first.status, 200);
    assert.equal(upstream.requests.at(-1).authorization, "Bearer at-1");
    assert.deepEqual(token.stats.refreshTokens, ["rt-1"]);

    // The owner re-authorized out of band: same name, a different grant.
    await sleep(5); // the record's epoch is a millisecond timestamp
    const writer = await openVault({ stateDir, passphrase: "p" });
    writer.remove("api");
    writer.add({
      name: "api",
      type: "oauth2",
      domains: [new URL(upstream.url).hostname],
      upstreamScheme: "http",
      tokenEndpoint: token.url,
      clientId: "cid",
      clientSecret: "cs",
      refreshToken: "rt-2",
    });
    await writer.save();
    writer.lock();

    const result = await proxy.reload({ reason: "test" });
    assert.equal(result.ok, true);
    assert.equal(result.purged.tokens, 1);

    const second = await proxyPathRequest({ port: proxyPort, path: `/api/${upstreamAuthority}/b` });
    assert.equal(second.status, 200);
    assert.equal(token.stats.count, 2, "the cached access token must not have survived the re-add");
    assert.equal(token.stats.refreshTokens.at(-1), "rt-2");
    assert.equal(upstream.requests.at(-1).authorization, "Bearer at-2");
  });
});

describe("reload: reports what it purged", () => {
  let stateDir;
  let upstream;
  let token;
  let proxy;
  let proxyPort;
  let upstreamAuthority;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-reload-sig-purge-"));
    await initVault({ stateDir, passphrase: "p" });
    upstream = await startUpstream();
    token = await startTokenEndpoint();
    upstreamAuthority = new URL(upstream.url).host;

    const seed = await openVault({ stateDir, passphrase: "p" });
    for (const name of ["api1", "api2"]) {
      seed.add({
        name,
        type: "oauth2",
        domains: [new URL(upstream.url).hostname],
        upstreamScheme: "http",
        tokenEndpoint: token.url,
        clientId: "cid",
        clientSecret: "cs",
        refreshToken: `rt-${name}`,
      });
    }
    await seed.save();
    seed.lock();

    proxy = createProxy({
      vault: await openVault({ stateDir, passphrase: "p" }),
      stateDir,
      logPath: path.join(stateDir, "proxy.log"),
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

  it("counts exactly the caches the removed credential owned", async () => {
    for (const name of ["api1", "api2"]) {
      const r = await proxyPathRequest({ port: proxyPort, path: `/${name}/${upstreamAuthority}/a` });
      assert.equal(r.status, 200);
    }
    assert.equal(token.stats.count, 2);

    const writer = await openVault({ stateDir, passphrase: "p" });
    writer.remove("api1");
    await writer.save();
    writer.lock();

    const result = await proxy.reload({ reason: "test" });
    assert.equal(result.ok, true);
    assert.deepEqual(result.purged, { tokens: 1, grants: 0 });
    assert.equal(result.credentials, 1);

    const gone = await proxyPathRequest({ port: proxyPort, path: `/api1/${upstreamAuthority}/b` });
    assert.equal(gone.status, 400);

    // The credential that survived keeps its still-valid access token.
    const kept = await proxyPathRequest({ port: proxyPort, path: `/api2/${upstreamAuthority}/b` });
    assert.equal(kept.status, 200);
    assert.equal(token.stats.count, 2);
  });
});

describe("reload: a refresh in flight across it is not cached", () => {
  let stateDir;
  let logPath;
  let upstream;
  let token;
  let proxy;
  let proxyPort;
  let upstreamAuthority;
  let release;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-reload-sig-inflight-"));
    logPath = path.join(stateDir, "proxy.log");
    await initVault({ stateDir, passphrase: "p" });
    upstream = await startUpstream();
    token = await startTokenEndpoint();
    upstreamAuthority = new URL(upstream.url).host;
    token.cfg.hold = new Promise((resolve) => {
      release = resolve;
    });

    const seed = await openVault({ stateDir, passphrase: "p" });
    seed.add({
      name: "slow",
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

    proxy = createProxy({
      vault: await openVault({ stateDir, passphrase: "p" }),
      stateDir,
      logPath,
      reopenVault: async () => openVault({ stateDir, passphrase: "p" }),
    });
    const addr = await proxy.listen();
    proxyPort = addr.port;
  });

  after(async () => {
    release?.();
    await proxy?.close();
    upstream?.server.close();
    token?.server.close();
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("discards the token an exchange returns for a credential that is gone", async () => {
    const pending = proxyPathRequest({ port: proxyPort, path: `/slow/${upstreamAuthority}/a` });
    const deadline = Date.now() + 5000;
    while (token.stats.count === 0 && Date.now() < deadline) await sleep(10);
    assert.equal(token.stats.count, 1, "the token exchange should be on the wire");

    const writer = await openVault({ stateDir, passphrase: "p" });
    writer.remove("slow");
    await writer.save();
    writer.lock();

    const reloaded = await proxy.reload({ reason: "test" });
    assert.equal(reloaded.ok, true);

    release();
    token.cfg.hold = null;
    const answered = await pending;
    assert.equal(answered.status, 200, "the request that paid for the exchange still gets served");

    const discarded = await waitForLogEvent(logPath, "oauth_refresh_discarded");
    assert.equal(discarded.reason, "credential_changed");

    const second = await proxy.reload({ reason: "test" });
    assert.equal(
      second.purged.tokens,
      0,
      "the in-flight exchange must not have left a cache entry behind",
    );

    // Re-added, the credential mints its own token from its own grant.
    await sleep(5);
    const readd = await openVault({ stateDir, passphrase: "p" });
    readd.add({
      name: "slow",
      type: "oauth2",
      domains: [new URL(upstream.url).hostname],
      upstreamScheme: "http",
      tokenEndpoint: token.url,
      clientId: "cid",
      clientSecret: "cs",
      refreshToken: "rt-2",
    });
    await readd.save();
    readd.lock();
    assert.equal((await proxy.reload({ reason: "test" })).ok, true);

    const after = await proxyPathRequest({ port: proxyPort, path: `/slow/${upstreamAuthority}/b` });
    assert.equal(after.status, 200);
    assert.equal(token.stats.count, 2);
    assert.equal(token.stats.refreshTokens.at(-1), "rt-2");
  });
});

describe("reload: re-reads the oauth secrets file", () => {
  let stateDir;
  let secretsFile;
  let upstream;
  let token;
  let proxy;
  let proxyPort;
  let upstreamAuthority;

  async function writeSecrets(map, mode = 0o600) {
    await fs.writeFile(secretsFile, JSON.stringify(map), { encoding: "utf8", mode });
    await fs.chmod(secretsFile, mode);
  }

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-reload-sig-secrets-"));
    secretsFile = path.join(stateDir, "oauth-secrets.json");
    await initVault({ stateDir, passphrase: "p" });
    upstream = await startUpstream();
    token = await startTokenEndpoint();
    upstreamAuthority = new URL(upstream.url).host;
    // Never cacheable, so every request re-runs the exchange and shows which
    // secret is in force right now.
    token.cfg.expiresIn = 0;
    await writeSecrets({ cid: "S1" });

    const seed = await openVault({ stateDir, passphrase: "p" });
    seed.add({
      name: "api",
      type: "oauth2",
      domains: [new URL(upstream.url).hostname],
      upstreamScheme: "http",
      tokenEndpoint: token.url,
      clientId: "cid",
      refreshToken: "rt-1",
    });
    await seed.save();
    seed.lock();

    proxy = createProxy({
      vault: await openVault({ stateDir, passphrase: "p" }),
      stateDir,
      logPath: path.join(stateDir, "proxy.log"),
      reopenVault: async () => openVault({ stateDir, passphrase: "p" }),
      oauthClientSecrets: await loadOauthSecretsFile(secretsFile),
      reloadOauthSecrets: async () => loadOauthSecretsFile(secretsFile),
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

  it("uses the rotated secret after a reload", async () => {
    const first = await proxyPathRequest({ port: proxyPort, path: `/api/${upstreamAuthority}/a` });
    assert.equal(first.status, 200);
    assert.equal(token.stats.clientSecrets.at(-1), "S1");

    await writeSecrets({ cid: "S2" });
    const result = await proxy.reload({ reason: "test" });
    assert.equal(result.ok, true);

    const second = await proxyPathRequest({ port: proxyPort, path: `/api/${upstreamAuthority}/b` });
    assert.equal(second.status, 200);
    assert.equal(token.stats.clientSecrets.at(-1), "S2");
  });

  it("keeps the previous secrets when the file is no longer private", async () => {
    await writeSecrets({ cid: "S3" }, 0o644);

    const result = await proxy.reload({ reason: "test" });
    assert.equal(result.ok, false);
    assert.equal(result.error, "secrets_reload_failed");
    assert.equal(result.vaultReloaded, true);

    const third = await proxyPathRequest({ port: proxyPort, path: `/api/${upstreamAuthority}/c` });
    assert.equal(third.status, 200);
    assert.equal(
      token.stats.clientSecrets.at(-1),
      "S2",
      "a refused re-read must leave the working secrets in force",
    );
  });
});

describe("reload: a failed vault reopen is not silent", () => {
  let stateDir;
  let logPath;
  let upstream;
  let proxy;
  let proxyPort;
  let upstreamAuthority;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-reload-sig-fail-"));
    logPath = path.join(stateDir, "proxy.log");
    await initVault({ stateDir, passphrase: "p" });
    upstream = await startUpstream();
    upstreamAuthority = new URL(upstream.url).host;

    const seed = await openVault({ stateDir, passphrase: "p" });
    seed.add({
      name: "tok",
      type: "bearer",
      domains: [new URL(upstream.url).hostname],
      upstreamScheme: "http",
      value: "SECRET-KEEP",
    });
    await seed.save();
    seed.lock();

    proxy = createProxy({
      vault: await openVault({ stateDir, passphrase: "p" }),
      stateDir,
      logPath,
      reopenVault: async () => {
        const err = new Error("cannot reopen");
        err.code = "EACCES";
        throw err;
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

  it("logs the failure and keeps the open vault serving", async () => {
    const miss = await proxyPathRequest({ port: proxyPort, path: `/ghost/${upstreamAuthority}/x` });
    assert.equal(miss.status, 400);

    const entry = await waitForLogEvent(logPath, "vault_reopen_failed");
    assert.equal(entry.reason, "cred_miss");
    assert.equal(entry.error, "EACCES");

    const served = await proxyPathRequest({ port: proxyPort, path: `/tok/${upstreamAuthority}/y` });
    assert.equal(served.status, 200);
    assert.equal(upstream.requests.at(-1).authorization, "Bearer SECRET-KEEP");
  });
});

describe("stub mode: a credential that vanishes before the access gate is refused", () => {
  let stateDir;
  let logPath;
  let upstream;
  let proxy;
  let proxyPort;
  let upstreamHost;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-reload-sig-stub-"));
    logPath = path.join(stateDir, "proxy.log");
    await initVault({ stateDir, passphrase: "p" });
    upstream = await startUpstream();
    upstreamHost = new URL(upstream.url).hostname;

    const seed = await openVault({ stateDir, passphrase: "p" });
    seed.add({
      name: "qtok",
      type: "query",
      domains: [upstreamHost],
      paramName: "k",
      value: "QSECRET",
    });
    await seed.save();
    seed.lock();

    // The reopen this request triggers is what removes the credential the URL
    // step already resolved — the vault swaps between resolution and the gate.
    let swapped = false;
    proxy = createProxy({
      vault: await openVault({ stateDir, passphrase: "p" }),
      stateDir,
      logPath,
      reopenVault: async () => {
        if (!swapped) {
          swapped = true;
          const writer = await openVault({ stateDir, passphrase: "p" });
          writer.remove("qtok");
          writer.add({
            name: "btok",
            type: "bearer",
            domains: [upstreamHost],
            value: "SECRET-B",
          });
          await writer.save();
          writer.lock();
        }
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

  it("answers 403 credential_not_found and forwards nothing", async () => {
    const r = await proxyStubRequest({
      port: proxyPort,
      target: `${upstream.url}/p?k=AgentVault%20qtok`,
      headers: { Authorization: "AgentVault btok" },
    });
    assert.equal(r.status, 403);
    const body = JSON.parse(r.body);
    assert.equal(body.ok, false);
    assert.equal(body.error, "credential_not_found");
    assert.equal(upstream.requests.length, 0, "nothing may reach the upstream");

    const denied = await waitForLogEvent(logPath, "access_denied");
    assert.equal(denied.credential, "qtok");
    assert.equal(denied.reason, "credential_gone");
  });
});

describe("reload subcommand: drives the running daemon", () => {
  let dir;
  let proc;

  before(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-reload-sig-cli-"));
    await makeAgentKeyVault(dir);
    const port = await freePort();
    proc = spawnCli([
      "start",
      "--no-control",
      "--idle-timeout",
      "never",
      "--port",
      String(port),
      "--state-dir",
      dir,
    ]);
    await waitForStderr(proc, /agent-id-proxy listening on/, 15000);
  });

  after(async () => {
    if (proc?.child.exitCode === null) proc.child.kill("SIGKILL");
    if (dir) await fs.rm(dir, { recursive: true, force: true });
  });

  it("reports the reload and bumps reloadSeq in proxy.json, keeping the pid", async () => {
    const stateBefore = JSON.parse(await fs.readFile(statePaths(dir).proxyState, "utf8"));
    assert.equal(stateBefore.reloadable, true);
    assert.equal(stateBefore.reloadSeq, 0);
    assert.equal(stateBefore.reloadedAt, null);

    const first = await waitForExit(spawnCli(["reload", "--state-dir", dir]), 10000);
    assert.notEqual(first.code, "still-running", `reload hung: ${first.stderr}`);
    assert.equal(first.code, 0, `reload failed: ${first.stdout}${first.stderr}`);
    const firstJson = JSON.parse(first.stdout);
    assert.equal(firstJson.ok, true);
    assert.equal(firstJson.reloaded, true);
    assert.equal(firstJson.pid, proc.child.pid);

    const afterFirst = JSON.parse(await fs.readFile(statePaths(dir).proxyState, "utf8"));
    assert.equal(afterFirst.reloadSeq, 1);
    assert.equal(typeof afterFirst.reloadedAt, "number");
    assert.equal(afterFirst.lastReload.ok, true);
    assert.equal(pidAlive(proc.child.pid), true, "the daemon must survive its own reload");

    const second = await waitForExit(spawnCli(["reload", "--state-dir", dir]), 10000);
    assert.equal(JSON.parse(second.stdout).ok, true);
    const afterSecond = JSON.parse(await fs.readFile(statePaths(dir).proxyState, "utf8"));
    assert.equal(afterSecond.reloadSeq, 2);
  });
});

describe("reload subcommand: refuses a daemon that cannot reload", () => {
  let dir;
  let foreign;

  before(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-reload-sig-gate-"));
    foreign = spawn("sleep", ["30"]);
    await waitForSpawn(foreign);
    await writeJsonFile(statePaths(dir).proxyState, {
      pid: foreign.pid,
      host: "127.0.0.1",
      port: 1234,
      startedAt: Date.now(),
      reloadable: false,
      reloadSeq: 0,
      reloadedAt: null,
      lastReload: null,
    });
  });

  after(async () => {
    if (foreign && pidAlive(foreign.pid)) foreign.kill("SIGKILL");
    if (dir) await fs.rm(dir, { recursive: true, force: true });
  });

  it("answers not_reloadable without signalling it", async () => {
    const result = await waitForExit(spawnCli(["reload", "--state-dir", dir]), 10000);
    assert.notEqual(result.code, "still-running", `reload hung: ${result.stderr}`);
    assert.equal(result.code, 1);
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.ok, false);
    assert.equal(parsed.error, "not_reloadable");
    assert.equal(parsed.pid, foreign.pid);
    // A process that does not handle SIGHUP dies of it — its being alive is the
    // proof that nothing was sent.
    await sleep(200);
    assert.equal(pidAlive(foreign.pid), true, "a non-reloadable daemon must never be signalled");
  });

  it("answers no_proxy when there is no state file", async () => {
    const empty = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-reload-sig-none-"));
    try {
      const result = await waitForExit(spawnCli(["reload", "--state-dir", empty]), 10000);
      assert.equal(result.code, 1);
      assert.deepEqual(JSON.parse(result.stdout), { ok: false, error: "no_proxy" });
    } finally {
      await fs.rm(empty, { recursive: true, force: true });
    }
  });
});
