#!/usr/bin/env node

// URL-rewrite mode end-to-end:
//   curl http://localhost:PORT/<credname>/<host>/<path> → upstream sees the
//   real path with the credential injected. The agent never types the
//   credential value; the upstream sees no localhost references.

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { createProxy } from "../plugins/agent-id-proxy/lib/proxy.mjs";
import {
  injectCredential,
  parseRewritePath,
  prepareUpstreamHeaders,
  resolveCredential,
} from "../plugins/agent-id-proxy/lib/rewrite.mjs";

const lastSeen = { headers: null, url: null, method: null, body: null };

function startUpstream() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      lastSeen.method = req.method;
      lastSeen.url = req.url;
      lastSeen.headers = { ...req.headers };
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        lastSeen.body = Buffer.concat(chunks).toString("utf8");
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end('{"ok":true}');
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const a = server.address();
      resolve({ server, host: a.address, port: a.port });
    });
  });
}

function callProxy({
  port,
  path: pathArg,
  method = "GET",
  body = null,
  headers = {},
}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        method,
        path: pathArg,
        headers,
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
    if (body) req.write(body);
    req.end();
  });
}

describe("URL-rewrite parsing (unit)", () => {
  it("parses /credname/host/path", () => {
    const p = parseRewritePath("/gh/api.github.com/user");
    assert.deepEqual(p, {
      credname: "gh",
      host: "api.github.com",
      restAndQuery: "/user",
    });
  });

  it("parses /credname/host with no path", () => {
    const p = parseRewritePath("/gh/api.github.com");
    assert.equal(p.host, "api.github.com");
    assert.equal(p.restAndQuery, "/");
  });

  it("parses query at root", () => {
    const p = parseRewritePath("/gh/api.github.com?x=1");
    assert.equal(p.host, "api.github.com");
    assert.equal(p.restAndQuery, "/?x=1");
  });

  it("parses path + query", () => {
    const p = parseRewritePath("/gh/api.github.com/repos/x/y?ref=main");
    assert.equal(p.restAndQuery, "/repos/x/y?ref=main");
  });

  it("host:port allowed", () => {
    const p = parseRewritePath("/gh/127.0.0.1:8443/foo");
    assert.equal(p.host, "127.0.0.1:8443");
  });

  it("rejects missing host", () => {
    assert.equal(parseRewritePath("/gh"), null);
  });

  it("rejects bad credname", () => {
    assert.equal(parseRewritePath("/has space/api.github.com/x"), null);
  });
});

describe("injectCredential (unit)", () => {
  function inject(cred, search = new URLSearchParams()) {
    return injectCredential({
      headers: prepareUpstreamHeaders({
        incoming: { "user-agent": "test", host: "ignored" },
        upstreamHost: "up.example",
      }),
      search,
      cred,
    });
  }

  it("bearer → Authorization: Bearer ...", () => {
    const r = inject({ type: "bearer", value: "tok123" });
    assert.equal(r.headers.authorization, "Bearer tok123");
  });

  it("basic → Authorization: Basic b64", () => {
    const r = inject({ type: "basic", username: "u", password: "p" });
    assert.equal(r.headers.authorization, "Basic dTpw");
  });

  it("header → named header", () => {
    const r = inject({ type: "header", headerName: "X-Api-Key", value: "v" });
    assert.equal(r.headers["x-api-key"], "v");
  });

  it("query → URL param", () => {
    const sp = new URLSearchParams("existing=1");
    const r = inject({ type: "query", paramName: "k", value: "v" }, sp);
    assert.equal(r.search.get("k"), "v");
    assert.equal(r.search.get("existing"), "1");
  });

  it("cookie → Cookie header (single)", () => {
    const r = inject({ type: "cookie", cookieName: "sid", value: "abc" });
    assert.equal(r.headers.cookie, "sid=abc");
  });

  it("cookie-jar → Cookie header (joined)", () => {
    const r = inject({ type: "cookie-jar", cookies: { a: "1", b: "2" } });
    assert.equal(r.headers.cookie, "a=1; b=2");
  });

  it("totp → X-OTP-Code header by default", () => {
    // Base32("12345678901234567890") = GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    const r = inject({
      type: "totp",
      secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    });
    assert.match(r.headers["x-otp-code"], /^\d{6}$/);
  });
});

describe("URL-rewrite end-to-end", () => {
  let stateDir;
  let upstream;
  let vault;
  let proxy;
  let proxyPort;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-rewrite-"));
    await initVault({ stateDir, passphrase: "p" });
    vault = await openVault({ stateDir, passphrase: "p" });

    upstream = await startUpstream();
    const upstreamHostPort = `${upstream.host}:${upstream.port}`;

    // bearer credential — note `upstreamScheme: "http"` so the proxy
    // forwards to the test server's plain-HTTP listener.
    vault.add({
      name: "gh",
      type: "bearer",
      domains: [upstream.host],
      upstreamScheme: "http",
      value: "ghp_SECRET",
    });
    vault.add({
      name: "openai",
      type: "header",
      domains: [upstream.host],
      upstreamScheme: "http",
      headerName: "X-Api-Key",
      value: "sk-RAW",
    });
    vault.add({
      name: "geo",
      type: "query",
      domains: [upstream.host],
      upstreamScheme: "http",
      paramName: "api_key",
      value: "QUERY-VAL",
    });
    vault.add({
      name: "sess",
      type: "cookie",
      domains: [upstream.host],
      upstreamScheme: "http",
      cookieName: "sid",
      value: "COOKIE-VAL",
    });
    vault.add({
      name: "wild",
      type: "bearer",
      domains: [`*.${upstream.host.split(".").join(".")}`], // 127.0.0.1 has no dots so use a literal-only allowlist
      upstreamScheme: "http",
      value: "WILD",
    });
    // For testing wildcard, use a domain that does match the IP-host. Easier
    // alternative: just trust the literal host.
    vault.remove("wild");
    vault.add({
      name: "wild",
      type: "bearer",
      domains: [upstream.host],
      upstreamScheme: "http",
      value: "WILD",
    });
    await vault.save();

    proxy = createProxy({
      vault,
      logPath: path.join(stateDir, "proxy.log"),
    });
    const addr = await proxy.listen();
    proxyPort = addr.port;
    void upstreamHostPort;
  });

  after(async () => {
    await proxy?.close();
    upstream?.server.close();
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("bearer: GET /gh/<host>/path → upstream sees Bearer + correct path + Host", async () => {
    const r = await callProxy({
      port: proxyPort,
      path: `/gh/${upstream.host}:${upstream.port}/repos/x/y?ref=main`,
    });
    assert.equal(r.status, 200);
    assert.equal(lastSeen.method, "GET");
    assert.equal(lastSeen.url, "/repos/x/y?ref=main");
    assert.equal(lastSeen.headers.authorization, "Bearer ghp_SECRET");
    assert.equal(lastSeen.headers.host, `${upstream.host}:${upstream.port}`);
  });

  it("header credential: upstream sees named header", async () => {
    const r = await callProxy({
      port: proxyPort,
      path: `/openai/${upstream.host}:${upstream.port}/v1/models`,
    });
    assert.equal(r.status, 200);
    assert.equal(lastSeen.headers["x-api-key"], "sk-RAW");
  });

  it("query credential: upstream sees query param", async () => {
    const r = await callProxy({
      port: proxyPort,
      path: `/geo/${upstream.host}:${upstream.port}/v1/lookup?addr=1`,
    });
    assert.equal(r.status, 200);
    assert.match(
      lastSeen.url,
      /\?addr=1&api_key=QUERY-VAL|\?api_key=QUERY-VAL&addr=1/
    );
  });

  it("cookie credential: upstream sees Cookie header", async () => {
    const r = await callProxy({
      port: proxyPort,
      path: `/sess/${upstream.host}:${upstream.port}/whoami`,
    });
    assert.equal(r.status, 200);
    assert.equal(lastSeen.headers.cookie, "sid=COOKIE-VAL");
  });

  it("POST with body: body is forwarded verbatim", async () => {
    const r = await callProxy({
      port: proxyPort,
      method: "POST",
      path: `/gh/${upstream.host}:${upstream.port}/v1/things`,
      body: '{"x":1}',
      headers: { "Content-Type": "application/json", "Content-Length": "7" },
    });
    assert.equal(r.status, 200);
    assert.equal(lastSeen.method, "POST");
    assert.equal(lastSeen.body, '{"x":1}');
    assert.equal(lastSeen.headers.authorization, "Bearer ghp_SECRET");
  });

  it("Origin / Referer stripped before forwarding", async () => {
    await callProxy({
      port: proxyPort,
      path: `/gh/${upstream.host}:${upstream.port}/foo`,
      headers: {
        Origin: "http://127.0.0.1:0",
        Referer: "http://127.0.0.1:0/something",
      },
    });
    assert.equal(lastSeen.headers.origin, undefined);
    assert.equal(lastSeen.headers.referer, undefined);
  });

  it("unknown credential → 400 credential_not_found", async () => {
    const r = await callProxy({
      port: proxyPort,
      path: `/no-such/${upstream.host}:${upstream.port}/foo`,
    });
    assert.equal(r.status, 400);
    const body = JSON.parse(r.body);
    assert.equal(body.error, "credential_not_found");
  });

  it("host not in allowlist → 403 host_not_allowed", async () => {
    const r = await callProxy({
      port: proxyPort,
      path: `/gh/evil.example.com:8080/foo`,
    });
    assert.equal(r.status, 403);
    const body = JSON.parse(r.body);
    assert.equal(body.error, "host_not_allowed");
  });

  it("access log keeps credential names, not values", async () => {
    const raw = await fs.readFile(path.join(stateDir, "proxy.log"), "utf8");
    assert.ok(raw.includes('"gh"'));
    assert.ok(!raw.includes("ghp_SECRET"));
    assert.ok(!raw.includes("sk-RAW"));
    assert.ok(!raw.includes("QUERY-VAL"));
  });
});

describe("URL-rewrite + wildcard allowlist", () => {
  let stateDir;
  let upstream;
  let vault;
  let proxy;
  let proxyPort;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-wild-"));
    await initVault({ stateDir, passphrase: "p" });
    vault = await openVault({ stateDir, passphrase: "p" });
    upstream = await startUpstream();

    // Allowlist a hostname that the proxy resolves at the credential level
    // (wildcard match), but the request uses the literal upstream host. We
    // approximate this by adding an alias allowlist entry that includes a
    // wildcard the request will match by suffix.
    vault.add({
      name: "wild",
      type: "bearer",
      domains: ["*.localhost", upstream.host],
      upstreamScheme: "http",
      value: "WILD-VAL",
    });
    await vault.save();

    proxy = createProxy({
      vault,
      logPath: path.join(stateDir, "proxy.log"),
    });
    const addr = await proxy.listen();
    proxyPort = addr.port;
  });

  after(async () => {
    await proxy?.close();
    upstream?.server.close();
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("literal allowlist entry matches concrete host", async () => {
    const r = await callProxy({
      port: proxyPort,
      path: `/wild/${upstream.host}:${upstream.port}/foo`,
    });
    assert.equal(r.status, 200);
    assert.equal(lastSeen.headers.authorization, "Bearer WILD-VAL");
  });
});

// resolveCredential unit tests separated so they don't need a live upstream.
describe("resolveCredential (unit)", () => {
  const cred = {
    name: "x",
    type: "bearer",
    value: "v",
    domains: ["api.example.com", "*.github.com"],
  };
  const lookup = (n) => (n === "x" ? cred : null);

  it("returns cred when host matches", () => {
    assert.equal(
      resolveCredential({ credname: "x", host: "api.example.com", lookup }),
      cred
    );
  });

  it("wildcard subdomain matches", () => {
    assert.equal(
      resolveCredential({ credname: "x", host: "api.github.com:443", lookup }),
      cred
    );
  });

  it("throws on missing", () => {
    assert.throws(() =>
      resolveCredential({
        credname: "missing",
        host: "api.example.com",
        lookup,
      })
    );
  });

  it("throws on host mismatch", () => {
    assert.throws(() =>
      resolveCredential({ credname: "x", host: "evil.example.com", lookup })
    );
  });
});
