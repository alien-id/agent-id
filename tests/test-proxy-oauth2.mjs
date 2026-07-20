#!/usr/bin/env node

// oauth2 credential type: the proxy refreshes a short-lived access token from a
// vault-stored refresh token at injection time, caches it, re-refreshes on
// expiry, persists a rotated refresh token, and never exposes any of it to the
// agent — which only ever names the credential.
//
// A fake token endpoint (loopback http) stands in for Google's oauth2 endpoint;
// a fake upstream echoes the Authorization header the proxy injected. A mock
// clock (createProxy `now`) lets us drive token expiry deterministically.
//
// Run: node --test tests/test-proxy-oauth2.mjs

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { createProxy } from "../plugins/agent-id-proxy/lib/proxy.mjs";
import {
  loadOauthSecretsFile,
  refreshAccessToken,
  OAuthError,
} from "../plugins/agent-id-proxy/lib/oauth.mjs";

// ── Fake upstream: records the Authorization header it received ────────────────
function startUpstream() {
  const seen = { authorization: null, count: 0 };
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      seen.authorization = req.headers.authorization || null;
      seen.count += 1;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"ok":true}');
    });
    server.listen(0, "127.0.0.1", () => {
      const a = server.address();
      resolve({ server, host: `${a.address}:${a.port}`, seen });
    });
  });
}

// ── Fake token endpoint: mints incrementing access tokens; configurable mode ──
function startTokenEndpoint() {
  const stats = { count: 0, lastBody: null };
  const cfg = { mode: "ok", rotateTo: null };
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        stats.count += 1;
        stats.lastBody = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
        if (cfg.mode === "invalid_grant") {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end('{"error":"invalid_grant","error_description":"Token revoked"}');
          return;
        }
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

function callProxy({ port, path: p }) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, method: "GET", path: p }, (res) => {
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

describe("oauth.refreshAccessToken (unit)", () => {
  let token;
  before(async () => {
    token = await startTokenEndpoint();
  });
  after(() => token.server.close());

  it("exchanges a refresh token for an access token + expiry", async () => {
    const res = await refreshAccessToken({
      tokenEndpoint: token.url,
      clientId: "cid",
      clientSecret: "csecret",
      refreshToken: "rt-1",
      scope: "gmail.readonly",
    });
    assert.match(res.accessToken, /^at-\d+$/);
    assert.equal(res.expiresInSec, 3600);
    // Request carried the RFC 6749 §6 grant.
    assert.equal(token.stats.lastBody.get("grant_type"), "refresh_token");
    assert.equal(token.stats.lastBody.get("refresh_token"), "rt-1");
    assert.equal(token.stats.lastBody.get("client_id"), "cid");
    assert.equal(token.stats.lastBody.get("client_secret"), "csecret");
    assert.equal(token.stats.lastBody.get("scope"), "gmail.readonly");
  });

  it("surfaces invalid_grant as an OAuthError with the code", async () => {
    token.cfg.mode = "invalid_grant";
    await assert.rejects(
      () =>
        refreshAccessToken({
          tokenEndpoint: token.url,
          clientId: "cid",
          refreshToken: "rt-bad",
        }),
      (err) => err instanceof OAuthError && err.oauthError === "invalid_grant",
    );
    token.cfg.mode = "ok";
  });
});

describe("oauth2 credential through the proxy", () => {
  let stateDir, upstream, token, proxy, proxyPort;
  let clock = 1_000_000_000_000; // fixed start; advanced by tests

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "agentid-oauth2-"));
    upstream = await startUpstream();
    token = await startTokenEndpoint();

    await initVault({ stateDir, passphrase: "test-pass" });
    const vault = await openVault({ stateDir, passphrase: "test-pass" });
    vault.add({
      name: "gmail",
      type: "oauth2",
      domains: [upstream.host.split(":")[0]],
      upstreamScheme: "http",
      tokenEndpoint: token.url,
      clientId: "cid",
      clientSecret: "csecret",
      refreshToken: "rt-1",
      scope: "gmail.readonly",
    });
    await vault.save();

    proxy = createProxy({
      vault,
      stateDir,
      logPath: path.join(stateDir, "proxy.log"),
      now: () => clock,
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

  it("first use refreshes and injects Authorization: Bearer <access token>", async () => {
    const r = await callProxy({ port: proxyPort, path: `/gmail/${upstream.host}/v1/messages` });
    assert.equal(r.status, 200);
    assert.equal(token.stats.count, 1, "token endpoint hit once");
    assert.equal(upstream.seen.authorization, "Bearer at-1");
  });

  it("second use within expiry serves the cached token (no refresh)", async () => {
    const r = await callProxy({ port: proxyPort, path: `/gmail/${upstream.host}/v1/labels` });
    assert.equal(r.status, 200);
    assert.equal(token.stats.count, 1, "still one refresh — cache hit");
    assert.equal(upstream.seen.authorization, "Bearer at-1");
  });

  it("re-refreshes once the access token has expired", async () => {
    clock += 3600 * 1000 + 1; // past expires_in
    const r = await callProxy({ port: proxyPort, path: `/gmail/${upstream.host}/v1/messages` });
    assert.equal(r.status, 200);
    assert.equal(token.stats.count, 2, "expiry triggered a second refresh");
    assert.equal(upstream.seen.authorization, "Bearer at-2");
  });

  it("persists a rotated refresh token back to the vault", async () => {
    token.cfg.rotateTo = "rt-2";
    clock += 3600 * 1000 + 1;
    const r = await callProxy({ port: proxyPort, path: `/gmail/${upstream.host}/v1/messages` });
    assert.equal(r.status, 200);
    assert.equal(token.stats.lastBody.get("refresh_token"), "rt-1", "used the old token to refresh");

    // Re-open the vault from disk: the rotated token was saved.
    const reopened = await openVault({ stateDir, passphrase: "test-pass" });
    assert.equal(reopened.get("gmail").refreshToken, "rt-2");
    reopened.lock();
    token.cfg.rotateTo = null;
  });

  it("invalid_grant from the token endpoint surfaces as 401", async () => {
    token.cfg.mode = "invalid_grant";
    clock += 3600 * 1000 + 1;
    const r = await callProxy({ port: proxyPort, path: `/gmail/${upstream.host}/v1/messages` });
    assert.equal(r.status, 401);
    assert.equal(JSON.parse(r.body).error, "oauth_refresh_token_invalid");
    token.cfg.mode = "ok";
  });
});

describe("loadOauthSecretsFile (unit)", () => {
  let dir;
  before(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "agentid-oauth-secrets-"));
  });
  after(async () => {
    if (dir) await fs.rm(dir, { recursive: true, force: true });
  });

  async function write(name, content, mode) {
    const p = path.join(dir, name);
    await fs.writeFile(p, content, { mode });
    return p;
  }

  it("loads a 0600 JSON object keyed by clientId", async () => {
    const p = await write("ok.json", '{"cid-1":"secret-1","cid-2":"secret-2"}', 0o600);
    const secrets = await loadOauthSecretsFile(p);
    assert.equal(secrets["cid-1"], "secret-1");
    assert.equal(secrets["cid-2"], "secret-2");
  });

  it(
    "refuses a group/world-accessible file",
    { skip: process.platform === "win32" },
    async () => {
      const p = await write("loose.json", '{"cid":"s"}', 0o644);
      await assert.rejects(() => loadOauthSecretsFile(p), /chmod 600/);
    },
  );

  it("refuses non-object JSON and non-string values", async () => {
    const arr = await write("arr.json", '["cid"]', 0o600);
    await assert.rejects(() => loadOauthSecretsFile(arr), /JSON object/);
    const bad = await write("bad.json", '{"cid":42}', 0o600);
    await assert.rejects(() => loadOauthSecretsFile(bad), /non-empty string/);
    const garbled = await write("garbled.json", "not json", 0o600);
    await assert.rejects(() => loadOauthSecretsFile(garbled), /not valid JSON/);
  });

  it("does not resolve secrets through the prototype chain", async () => {
    const p = await write("proto.json", '{"cid":"s"}', 0o600);
    const secrets = await loadOauthSecretsFile(p);
    assert.equal(secrets["toString"], undefined);
    assert.equal(secrets["__proto__"], undefined);
  });
});

describe("config-supplied client secret (platform connectors)", () => {
  let stateDir, upstream, token, proxy, proxyPort;
  const clock = 2_000_000_000_000;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "agentid-oauth2-cfg-"));
    upstream = await startUpstream();
    token = await startTokenEndpoint();

    await initVault({ stateDir, passphrase: "test-pass" });
    const vault = await openVault({ stateDir, passphrase: "test-pass" });
    const base = {
      type: "oauth2",
      domains: [upstream.host.split(":")[0]],
      upstreamScheme: "http",
      tokenEndpoint: token.url,
      refreshToken: "rt-1",
    };
    // Platform-seeded: no clientSecret on the cred — the config supplies it.
    vault.add({ ...base, name: "platform", clientId: "cid-platform" });
    // Personal: the cred's own secret must keep winning over the config.
    vault.add({
      ...base,
      name: "personal",
      clientId: "cid-personal",
      clientSecret: "personal-secret",
    });
    // No secret anywhere: refresh proceeds without client_secret (public client).
    vault.add({ ...base, name: "bare", clientId: "cid-bare" });
    await vault.save();

    proxy = createProxy({
      vault,
      stateDir,
      logPath: path.join(stateDir, "proxy.log"),
      now: () => clock,
      oauthClientSecrets: {
        "cid-platform": "config-secret",
        "cid-personal": "config-should-lose",
      },
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

  it("a cred without clientSecret refreshes with the config-supplied secret", async () => {
    const r = await callProxy({ port: proxyPort, path: `/platform/${upstream.host}/v1/a` });
    assert.equal(r.status, 200);
    assert.equal(token.stats.lastBody.get("client_id"), "cid-platform");
    assert.equal(token.stats.lastBody.get("client_secret"), "config-secret");
  });

  it("a cred with its own clientSecret behaves exactly as today (cred wins)", async () => {
    const r = await callProxy({ port: proxyPort, path: `/personal/${upstream.host}/v1/b` });
    assert.equal(r.status, 200);
    assert.equal(token.stats.lastBody.get("client_id"), "cid-personal");
    assert.equal(token.stats.lastBody.get("client_secret"), "personal-secret");
  });

  it("no secret on the cred or in the config sends none (current behavior)", async () => {
    const r = await callProxy({ port: proxyPort, path: `/bare/${upstream.host}/v1/c` });
    assert.equal(r.status, 200);
    assert.equal(token.stats.lastBody.get("client_id"), "cid-bare");
    assert.equal(token.stats.lastBody.get("client_secret"), null);
  });
});
