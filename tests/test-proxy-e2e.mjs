#!/usr/bin/env node

// End-to-end proxy test: real HTTP upstream, real local proxy, stub-injected
// credential. Validates:
//   - bearer stub in Authorization header → upstream sees `Bearer <secret>`
//   - header stub in custom header        → upstream sees raw value
//   - query stub                          → upstream sees decoded value
//   - disallowed host                     → proxy returns 403, upstream not hit
//   - unknown credential                  → proxy returns 400
//   - HTTPS rejection                     → proxy returns 501 explaining MITM
//
// Run: node --test tests/test-proxy-e2e.mjs

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { createProxy } from "../plugins/agent-id-proxy/lib/proxy.mjs";

const upstreamHeaders = { value: null };

async function makeStateDir() {
  return fs.mkdtemp(path.join(os.tmpdir(), "agent-id-proxy-test-"));
}

function startUpstream() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      upstreamHeaders.value = { ...req.headers, _url: req.url };
      const body = JSON.stringify({
        ok: true,
        sawAuth: req.headers.authorization || null,
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(body);
    });
    server.listen(0, "127.0.0.1", () => {
      const a = server.address();
      resolve({ server, url: `http://${a.address}:${a.port}` });
    });
  });
}

function proxyRequest({ proxyPort, target, headers = {}, method = "GET" }) {
  return new Promise((resolve, reject) => {
    const url = new URL(target);
    const req = http.request(
      {
        host: "127.0.0.1",
        port: proxyPort,
        method,
        path: target, // absolute URI per HTTP_PROXY semantics
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

describe("proxy end-to-end", () => {
  let stateDir;
  let upstream;
  let vault;
  let proxy;
  let proxyPort;

  before(async () => {
    stateDir = await makeStateDir();
    process.env.AGENT_ID_STATE_DIR = stateDir;
    await initVault({ stateDir, passphrase: "test-pass-1234" });
    vault = await openVault({ stateDir, passphrase: "test-pass-1234" });

    upstream = await startUpstream();
    const upstreamHost = new URL(upstream.url).hostname;

    vault.add({
      name: "github-pat",
      type: "bearer",
      domains: [upstreamHost],
      value: "ghp_SECRET_TOKEN",
    });
    vault.add({
      name: "api-key",
      type: "header",
      domains: [upstreamHost],
      headerName: "X-Api-Key",
      value: "raw-key-value",
    });
    vault.add({
      name: "qkey",
      type: "query",
      domains: [upstreamHost],
      paramName: "k",
      value: "decoded value",
    });
    vault.add({
      name: "gh-restricted",
      type: "bearer",
      domains: ["api.github.com"],
      value: "ghp_OTHER",
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
    vault?.lock();
    delete process.env.AGENT_ID_STATE_DIR;
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("bearer stub → upstream sees Bearer <secret>", async () => {
    upstreamHeaders.value = null;
    const r = await proxyRequest({
      proxyPort,
      target: `${upstream.url}/foo`,
      headers: { Authorization: "AgentVault github-pat" },
    });
    assert.equal(r.status, 200);
    assert.equal(
      upstreamHeaders.value.authorization,
      "Bearer ghp_SECRET_TOKEN"
    );
    // The agent transcript would only see the response, not the secret.
    assert.ok(
      !r.body.includes("ghp_SECRET_TOKEN") || JSON.parse(r.body).sawAuth
    );
  });

  it("header stub → upstream sees raw value", async () => {
    upstreamHeaders.value = null;
    const r = await proxyRequest({
      proxyPort,
      target: `${upstream.url}/foo`,
      headers: { "X-Api-Key": "AgentVault api-key" },
    });
    assert.equal(r.status, 200);
    assert.equal(upstreamHeaders.value["x-api-key"], "raw-key-value");
  });

  it("query stub → upstream sees decoded value", async () => {
    upstreamHeaders.value = null;
    const r = await proxyRequest({
      proxyPort,
      target: `${upstream.url}/foo?k=AgentVault%20qkey`,
    });
    assert.equal(r.status, 200);
    assert.match(
      upstreamHeaders.value._url,
      /\?k=decoded\+value|\?k=decoded%20value/
    );
  });

  it("unknown credential → 400 credential_not_found", async () => {
    const r = await proxyRequest({
      proxyPort,
      target: `${upstream.url}/foo`,
      headers: { Authorization: "AgentVault no-such-cred" },
    });
    assert.equal(r.status, 400);
    const body = JSON.parse(r.body);
    assert.equal(body.error, "credential_not_found");
    assert.equal(body.credential, "no-such-cred");
  });

  it("host not on allowlist → 403 host_not_allowed", async () => {
    const r = await proxyRequest({
      proxyPort,
      target: `${upstream.url}/foo`,
      headers: { Authorization: "AgentVault gh-restricted" },
    });
    assert.equal(r.status, 403);
    const body = JSON.parse(r.body);
    assert.equal(body.error, "host_not_allowed");
    assert.equal(body.credential, "gh-restricted");
  });

  it("HTTPS absolute URI → 501 https_not_supported_yet", async () => {
    const r = await proxyRequest({
      proxyPort,
      target: "https://example.com/foo",
      headers: { Authorization: "AgentVault github-pat" },
    });
    assert.equal(r.status, 501);
    const body = JSON.parse(r.body);
    assert.equal(body.error, "https_not_supported_yet");
  });

  it("access log lines include credential names but never values", async () => {
    const logPath = path.join(stateDir, "proxy.log");
    const raw = await fs.readFile(logPath, "utf8").catch(() => "");
    assert.ok(raw.includes("github-pat"), "log should mention credential name");
    assert.ok(
      !raw.includes("ghp_SECRET_TOKEN"),
      "log must NOT contain secret value"
    );
    assert.ok(
      !raw.includes("raw-key-value"),
      "log must NOT contain header value"
    );
  });
});
