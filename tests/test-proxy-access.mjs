#!/usr/bin/env node

// End-to-end access-level enforcement in the proxy: an `access: "ro"`
// credential lets reads through and refuses writes with a structured 403, in
// both URL-rewrite and legacy stub-injection modes.
//
// Run: node --test tests/test-proxy-access.mjs

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { createProxy } from "../plugins/agent-id-proxy/lib/proxy.mjs";

const upstreamSeen = { value: null };

function startUpstream() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        upstreamSeen.value = {
          method: req.method,
          url: req.url,
          auth: req.headers.authorization || null,
          body: Buffer.concat(chunks).toString("utf8"),
        };
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const a = server.address();
      resolve({ server, host: a.address, port: a.port });
    });
  });
}

// URL-rewrite mode request: /<credname>/<host:port>/<path>. A body is sent with
// an explicit Content-Length (as real JSON clients do) rather than chunked —
// Node's own http client mis-reports the status when the server closes the
// connection mid-chunked-upload, which is a client quirk, not proxy behavior.
function rewriteRequest({
  proxyPort,
  credname,
  upstream,
  pathq,
  method = "GET",
  body = null,
}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port: proxyPort,
        method,
        path: `/${credname}/${upstream.host}:${upstream.port}${pathq}`,
        headers:
          body != null
            ? {
                "Content-Type": "application/json",
                "Content-Length": Buffer.byteLength(body),
              }
            : {},
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode,
            body: Buffer.concat(chunks).toString("utf8"),
          })
        );
      }
    );
    req.on("error", reject);
    req.end(body != null ? body : undefined);
  });
}

// Legacy stub mode request: absolute URI + AgentVault marker header.
function stubRequest({ proxyPort, target, method = "GET", headers = {} }) {
  return new Promise((resolve, reject) => {
    const url = new URL(target);
    const req = http.request(
      {
        host: "127.0.0.1",
        port: proxyPort,
        method,
        path: target,
        headers: { Host: url.host, ...headers },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode,
            body: Buffer.concat(chunks).toString("utf8"),
          })
        );
      }
    );
    req.on("error", reject);
    req.end();
  });
}

describe("proxy access-level enforcement", () => {
  let stateDir;
  let upstream;
  let vault;
  let proxy;
  let proxyPort;
  let logPath;

  before(async () => {
    stateDir = await fs.mkdtemp(
      path.join(os.tmpdir(), "agent-id-access-test-")
    );
    await initVault({ stateDir, passphrase: "test-pass-1234" });
    vault = await openVault({ stateDir, passphrase: "test-pass-1234" });

    upstream = await startUpstream();

    vault.add({
      name: "mail-ro",
      type: "bearer",
      domains: [upstream.host],
      upstreamScheme: "http",
      access: "ro",
      value: "tok_READONLY",
    });
    vault.add({
      name: "mail-rw",
      type: "bearer",
      domains: [upstream.host],
      upstreamScheme: "http",
      value: "tok_READWRITE",
    });
    vault.add({
      name: "ro-with-rules",
      type: "bearer",
      domains: [upstream.host],
      upstreamScheme: "http",
      access: "ro",
      accessRules: [
        { effect: "allow", methods: ["POST"], path: "/search" },
        { effect: "deny", methods: ["GET"], path: "/admin/*" },
      ],
      value: "tok_RULES",
    });
    await vault.save();

    logPath = path.join(stateDir, "proxy.log");
    proxy = createProxy({ vault, logPath });
    const addr = await proxy.listen();
    proxyPort = addr.port;
  });

  after(async () => {
    await proxy.close();
    upstream.server.close();
    await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("ro: GET passes and injects", async () => {
    upstreamSeen.value = null;
    const r = await rewriteRequest({
      proxyPort,
      credname: "mail-ro",
      upstream,
      pathq: "/v1/messages",
    });
    assert.equal(r.status, 200);
    assert.equal(upstreamSeen.value.auth, "Bearer tok_READONLY");
  });

  it("ro: POST is refused with a structured 403 and the upstream is never hit", async () => {
    upstreamSeen.value = null;
    const r = await rewriteRequest({
      proxyPort,
      credname: "mail-ro",
      upstream,
      pathq: "/v1/messages/send",
      method: "POST",
      body: JSON.stringify({ to: "victim@example.com" }),
    });
    assert.equal(r.status, 403);
    const err = JSON.parse(r.body);
    assert.equal(err.error, "access_denied");
    assert.equal(err.access, "ro");
    assert.equal(
      upstreamSeen.value,
      null,
      "upstream must not see the blocked write"
    );
  });

  it("ro: a GraphQL query POST is classified as a read and passes", async () => {
    upstreamSeen.value = null;
    const r = await rewriteRequest({
      proxyPort,
      credname: "mail-ro",
      upstream,
      pathq: "/graphql",
      method: "POST",
      body: JSON.stringify({ query: "query { inbox { subject } }" }),
    });
    assert.equal(r.status, 200);
    assert.ok(
      upstreamSeen.value.body.includes("inbox"),
      "body forwarded intact"
    );
  });

  it("ro: a DELETE with a read-shaped body is still blocked (only POST tunnels reads)", async () => {
    upstreamSeen.value = null;
    const r = await rewriteRequest({
      proxyPort,
      credname: "mail-ro",
      upstream,
      pathq: "/v1/messages/42",
      method: "DELETE",
      body: JSON.stringify({ query: "{ __typename }" }),
    });
    assert.equal(r.status, 403);
    assert.equal(JSON.parse(r.body).error, "access_denied");
    assert.equal(
      upstreamSeen.value,
      null,
      "the DELETE must never reach upstream"
    );
  });

  it("ro: a GraphQL mutation POST is blocked", async () => {
    upstreamSeen.value = null;
    const r = await rewriteRequest({
      proxyPort,
      credname: "mail-ro",
      upstream,
      pathq: "/graphql",
      method: "POST",
      body: JSON.stringify({ query: "mutation { sendMail }" }),
    });
    assert.equal(r.status, 403);
    assert.equal(upstreamSeen.value, null);
  });

  it("rules: an allow rule opens a specific POST; a deny rule closes a GET", async () => {
    const ok = await rewriteRequest({
      proxyPort,
      credname: "ro-with-rules",
      upstream,
      pathq: "/search",
      method: "POST",
      body: '{"q":"hello"}',
    });
    assert.equal(ok.status, 200);

    const denied = await rewriteRequest({
      proxyPort,
      credname: "ro-with-rules",
      upstream,
      pathq: "/admin/keys",
    });
    assert.equal(denied.status, 403);
    assert.equal(JSON.parse(denied.body).error, "access_denied");
  });

  it("rw (default) is unaffected", async () => {
    const r = await rewriteRequest({
      proxyPort,
      credname: "mail-rw",
      upstream,
      pathq: "/v1/messages/send",
      method: "POST",
      body: "{}",
    });
    assert.equal(r.status, 200);
    assert.equal(upstreamSeen.value.auth, "Bearer tok_READWRITE");
  });

  it("stub mode: ro blocks non-read methods, allows GET", async () => {
    const target = `http://${upstream.host}:${upstream.port}/v1/messages`;
    const okGet = await stubRequest({
      proxyPort,
      target,
      headers: { Authorization: "AgentVault mail-ro" },
    });
    assert.equal(okGet.status, 200);
    assert.equal(upstreamSeen.value.auth, "Bearer tok_READONLY");

    upstreamSeen.value = null;
    const denied = await stubRequest({
      proxyPort,
      target,
      method: "POST",
      headers: { Authorization: "AgentVault mail-ro" },
    });
    assert.equal(denied.status, 403);
    assert.equal(JSON.parse(denied.body).error, "access_denied");
    assert.equal(upstreamSeen.value, null);
  });

  it("denials are audited, and the secret never reaches the log", async () => {
    const log = await fs.readFile(logPath, "utf8");
    assert.ok(
      log.includes('"event":"access_denied"'),
      "access_denied event logged"
    );
    assert.ok(log.includes('"credential":"mail-ro"'));
    assert.ok(!log.includes("tok_READONLY"), "log leaked the secret");
  });
});
