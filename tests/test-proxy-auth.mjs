#!/usr/bin/env node

// Opt-in data-plane authentication (issue #104). Loopback possession alone
// must not be enough to make the proxy attach a credential wherever the
// network namespace is shared. The token check runs before the vault, and the
// token itself never reaches an upstream. CORS preflights are refused locally
// in both modes.

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { createProxy, PROXY_AUTH_HEADER } from "../plugins/agent-id-proxy/lib/proxy.mjs";
import { prepareUpstreamHeaders } from "../plugins/agent-id-proxy/lib/rewrite.mjs";

const TOKEN = "s3cret-proxy-token";

function startUpstream() {
  return new Promise((resolve) => {
    const requests = [];
    const server = http.createServer((req, res) => {
      requests.push({
        url: req.url,
        method: req.method,
        authorization: req.headers.authorization || null,
        headers: { ...req.headers },
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

// Absolute-URI target → legacy stub mode; a "/cred/host/path" target → the
// URL-rewrite mode. Host is only defaulted for the former.
function proxyRequest({ port, target, method = "GET", headers = {} }) {
  return new Promise((resolve, reject) => {
    const absolute = /^https?:\/\//i.test(target);
    const baseHeaders = absolute ? { Host: new URL(target).host } : {};
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        method,
        path: target,
        headers: { ...baseHeaders, ...headers },
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

async function setupVault(stateDir, upstreamHost) {
  await initVault({ stateDir, passphrase: "p" });
  const writer = await openVault({ stateDir, passphrase: "p" });
  writer.add({
    name: "tok",
    type: "bearer",
    domains: [upstreamHost],
    value: "SECRET-VALUE",
    upstreamScheme: "http",
  });
  await writer.save();
  writer.lock();
  return openVault({ stateDir, passphrase: "p" });
}

describe("upstream header preparation (unit)", () => {
  it("drops the proxy auth token alongside origin/referer", () => {
    const out = prepareUpstreamHeaders({
      incoming: {
        [PROXY_AUTH_HEADER]: TOKEN,
        origin: "http://127.0.0.1:1",
        referer: "http://127.0.0.1:1/x",
        accept: "application/json",
      },
      upstreamHost: "api.example.com",
    });
    assert.equal(out[PROXY_AUTH_HEADER], undefined);
    assert.equal(out.origin, undefined);
    assert.equal(out.accept, "application/json");
    assert.equal(out.host, "api.example.com");
  });
});

describe("data-plane auth: stub-injection mode", () => {
  let stateDir;
  let upstream;
  let proxy;
  let proxyPort;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-auth-stub-"));
    upstream = await startUpstream();
    const vault = await setupVault(stateDir, new URL(upstream.url).hostname);
    proxy = createProxy({
      vault,
      logPath: path.join(stateDir, "proxy.log"),
      authToken: TOKEN,
    });
    proxyPort = (await proxy.listen()).port;
  });

  after(async () => {
    await proxy?.close();
    upstream?.server.close();
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("refuses a request with no token and never contacts the upstream", async () => {
    const before = upstream.requests.length;
    const r = await proxyRequest({
      port: proxyPort,
      target: `${upstream.url}/a`,
      headers: { Authorization: "AgentVault tok" },
    });
    assert.equal(r.status, 401);
    assert.equal(JSON.parse(r.body).error, "unauthorized");
    assert.equal(upstream.requests.length, before);
  });

  it("refuses a wrong token and never contacts the upstream", async () => {
    const before = upstream.requests.length;
    const r = await proxyRequest({
      port: proxyPort,
      target: `${upstream.url}/b`,
      headers: { Authorization: "AgentVault tok", [PROXY_AUTH_HEADER]: `${TOKEN}x` },
    });
    assert.equal(r.status, 401);
    assert.equal(JSON.parse(r.body).error, "unauthorized");
    assert.equal(upstream.requests.length, before);
  });

  it("refuses an empty token", async () => {
    const before = upstream.requests.length;
    const r = await proxyRequest({
      port: proxyPort,
      target: `${upstream.url}/b2`,
      headers: { Authorization: "AgentVault tok", [PROXY_AUTH_HEADER]: "" },
    });
    assert.equal(r.status, 401);
    assert.equal(upstream.requests.length, before);
  });

  it("injects the credential on a correct token, and the upstream never sees the token", async () => {
    const r = await proxyRequest({
      port: proxyPort,
      target: `${upstream.url}/c`,
      headers: { Authorization: "AgentVault tok", [PROXY_AUTH_HEADER]: TOKEN },
    });
    assert.equal(r.status, 200);
    const seen = upstream.requests.at(-1);
    assert.equal(seen.authorization, "Bearer SECRET-VALUE");
    assert.equal(seen.headers[PROXY_AUTH_HEADER], undefined);
  });

  // Auth runs first, so with a token configured an unauthenticated preflight is
  // an auth failure, not a CORS one — the refusal must not tell an unauthorized
  // caller anything more specific than "unauthorized".
  it("answers an unauthenticated preflight with 401, not the CORS refusal", async () => {
    const before = upstream.requests.length;
    const r = await proxyRequest({
      port: proxyPort,
      target: `${upstream.url}/c`,
      method: "OPTIONS",
      headers: {
        Origin: "https://evil.example",
        "Access-Control-Request-Method": "GET",
      },
    });
    assert.equal(r.status, 401);
    assert.equal(JSON.parse(r.body).error, "unauthorized");
    assert.equal(r.headers["access-control-allow-origin"], undefined);
    assert.equal(upstream.requests.length, before);
  });

  it("refuses an authenticated CORS preflight locally", async () => {
    const before = upstream.requests.length;
    const r = await proxyRequest({
      port: proxyPort,
      target: `${upstream.url}/c`,
      method: "OPTIONS",
      headers: {
        Origin: "https://evil.example",
        "Access-Control-Request-Method": "GET",
        [PROXY_AUTH_HEADER]: TOKEN,
      },
    });
    assert.equal(r.status, 403);
    assert.equal(JSON.parse(r.body).error, "cross_origin_refused");
    assert.equal(r.headers["access-control-allow-origin"], undefined);
    assert.equal(upstream.requests.length, before);
  });
});

describe("data-plane auth: URL-rewrite mode", () => {
  let stateDir;
  let upstream;
  let proxy;
  let proxyPort;
  let upstreamAuthority;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-auth-rewrite-"));
    upstream = await startUpstream();
    upstreamAuthority = new URL(upstream.url).host;
    const vault = await setupVault(stateDir, new URL(upstream.url).hostname);
    proxy = createProxy({
      vault,
      logPath: path.join(stateDir, "proxy.log"),
      authToken: TOKEN,
    });
    proxyPort = (await proxy.listen()).port;
  });

  after(async () => {
    await proxy?.close();
    upstream?.server.close();
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("refuses a request with no token and never contacts the upstream", async () => {
    const before = upstream.requests.length;
    const r = await proxyRequest({
      port: proxyPort,
      target: `/tok/${upstreamAuthority}/a`,
    });
    assert.equal(r.status, 401);
    assert.equal(JSON.parse(r.body).error, "unauthorized");
    assert.equal(upstream.requests.length, before);
  });

  it("injects the credential on a correct token, and the upstream never sees the token", async () => {
    const r = await proxyRequest({
      port: proxyPort,
      target: `/tok/${upstreamAuthority}/c`,
      headers: { [PROXY_AUTH_HEADER]: TOKEN },
    });
    assert.equal(r.status, 200);
    const seen = upstream.requests.at(-1);
    assert.equal(seen.url, "/c");
    assert.equal(seen.authorization, "Bearer SECRET-VALUE");
    assert.equal(seen.headers[PROXY_AUTH_HEADER], undefined);
  });
});

describe("data-plane auth precedes vault state", () => {
  let stateDir;
  let upstream;
  let proxy;
  let proxyPort;
  let reopenCalls;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-auth-locked-"));
    upstream = await startUpstream();
    const vault = await setupVault(stateDir, new URL(upstream.url).hostname);
    reopenCalls = 0;
    proxy = createProxy({
      vault,
      logPath: path.join(stateDir, "proxy.log"),
      authToken: TOKEN,
      reopenVault: async () => {
        reopenCalls += 1;
        return openVault({ stateDir, passphrase: "p" });
      },
    });
    proxyPort = (await proxy.listen()).port;
    proxy.forceLock("test");
  });

  after(async () => {
    await proxy?.close();
    upstream?.server.close();
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("answers unauthorized — not vault_locked — and never attempts a reopen", async () => {
    const r = await proxyRequest({
      port: proxyPort,
      target: `${upstream.url}/a`,
      headers: { Authorization: "AgentVault tok" },
    });
    assert.equal(r.status, 401);
    assert.equal(JSON.parse(r.body).error, "unauthorized");
    assert.equal(reopenCalls, 0);
    assert.equal(upstream.requests.length, 0);
  });

  it("still reaches the locked vault once the token is correct", async () => {
    const r = await proxyRequest({
      port: proxyPort,
      target: `${upstream.url}/a`,
      headers: { Authorization: "AgentVault tok", [PROXY_AUTH_HEADER]: TOKEN },
    });
    assert.equal(r.status, 200);
    assert.equal(reopenCalls, 1);
  });
});

describe("auth_failed logging is bounded", () => {
  let stateDir;
  let upstream;
  let proxy;
  let proxyPort;
  let logFile;
  let clock;

  const BURST = 30;

  async function flood(tag) {
    for (let i = 0; i < BURST; i++) {
      const r = await proxyRequest({ port: proxyPort, target: `${upstream.url}/${tag}${i}` });
      assert.equal(r.status, 401);
    }
    // logAccess is fire-and-forget on the request path — let the writes settle.
    await new Promise((r) => setTimeout(r, 200));
  }

  async function authFailedLines() {
    return (await fs.readFile(logFile, "utf8"))
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l))
      .filter((e) => e.event === "auth_failed");
  }

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-auth-flood-"));
    upstream = await startUpstream();
    logFile = path.join(stateDir, "proxy.log");
    clock = Date.now();
    proxy = createProxy({
      vault: await setupVault(stateDir, new URL(upstream.url).hostname),
      logPath: logFile,
      authToken: TOKEN,
      now: () => clock,
    });
    proxyPort = (await proxy.listen()).port;
  });

  after(async () => {
    await proxy?.close();
    upstream?.server.close();
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("coalesces a flood of rejected requests instead of a line per request", async () => {
    await flood("flood");
    const lines = await authFailedLines();
    assert.ok(lines.length >= 1, "the refusals must leave at least one record");
    assert.ok(
      lines.length <= 3,
      `expected the ${BURST} refusals to coalesce, got ${lines.length} lines`,
    );
  });

  it("reports how many refusals were suppressed once the window rolls over", async () => {
    const before = (await authFailedLines()).length;
    clock += 10 * 60 * 1000;
    await flood("flood2");
    const lines = await authFailedLines();
    assert.ok(
      lines.length <= before + 3,
      `expected the second burst to coalesce, got ${lines.length - before} new lines`,
    );
    const rolled = lines[before];
    assert.ok(rolled, "the rolled-over window must emit a line");
    assert.ok(
      rolled.suppressed >= BURST - 2,
      `expected the suppressed count of the first burst, got ${rolled.suppressed}`,
    );
  });
});

describe("no authToken configured", () => {
  let stateDir;
  let upstream;
  let proxy;
  let proxyPort;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-auth-off-"));
    upstream = await startUpstream();
    const vault = await setupVault(stateDir, new URL(upstream.url).hostname);
    proxy = createProxy({ vault, logPath: path.join(stateDir, "proxy.log") });
    proxyPort = (await proxy.listen()).port;
  });

  after(async () => {
    await proxy?.close();
    upstream?.server.close();
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("serves a tokenless request exactly as before", async () => {
    const r = await proxyRequest({
      port: proxyPort,
      target: `${upstream.url}/a`,
      headers: { Authorization: "AgentVault tok" },
    });
    assert.equal(r.status, 200);
    assert.equal(upstream.requests.at(-1).authorization, "Bearer SECRET-VALUE");
  });

  it("still refuses a CORS preflight locally", async () => {
    const before = upstream.requests.length;
    const r = await proxyRequest({
      port: proxyPort,
      target: `${upstream.url}/a`,
      method: "OPTIONS",
      headers: {
        Origin: "https://evil.example",
        "Access-Control-Request-Method": "POST",
      },
    });
    assert.equal(r.status, 403);
    assert.equal(JSON.parse(r.body).error, "cross_origin_refused");
    assert.equal(r.headers["access-control-allow-origin"], undefined);
    assert.equal(upstream.requests.length, before);
  });

  it("strips a stray token header before the upstream even when auth is off", async () => {
    const r = await proxyRequest({
      port: proxyPort,
      target: `${upstream.url}/a`,
      headers: { Authorization: "AgentVault tok", [PROXY_AUTH_HEADER]: "leftover" },
    });
    assert.equal(r.status, 200);
    assert.equal(upstream.requests.at(-1).headers[PROXY_AUTH_HEADER], undefined);
  });
});
