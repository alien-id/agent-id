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
import { randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { createProxy } from "../plugins/agent-id-proxy/lib/proxy.mjs";
import { refreshAccessToken, OAuthError } from "../plugins/agent-id-proxy/lib/oauth.mjs";
import { fileLockPrefix } from "../plugins/agent-id-core/lib/file-lock.mjs";

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
  const stats = { count: 0, lastBody: null, active: 0, maxActive: 0 };
  const cfg = {
    mode: "ok",
    rotateTo: null,
    rotateSequence: null,
    validRefreshToken: null,
  };
  let nextResponseGate = null;
  function holdNextResponse() {
    if (nextResponseGate) throw new Error("a token response is already held");
    let markArrived;
    let releaseResponse;
    const arrived = new Promise((resolve) => {
      markArrived = resolve;
    });
    const released = new Promise((resolve) => {
      releaseResponse = resolve;
    });
    nextResponseGate = { markArrived, released };
    return { arrived, release: releaseResponse };
  }
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", async () => {
        stats.count += 1;
        stats.active += 1;
        stats.maxActive = Math.max(stats.maxActive, stats.active);
        res.once("finish", () => {
          stats.active -= 1;
        });
        stats.lastBody = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
        const gate = nextResponseGate;
        nextResponseGate = null;
        if (gate) {
          gate.markArrived();
          await gate.released;
        }
        if (
          cfg.mode === "invalid_grant" ||
          (cfg.validRefreshToken &&
            stats.lastBody.get("refresh_token") !== cfg.validRefreshToken)
        ) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end('{"error":"invalid_grant","error_description":"Token revoked"}');
          return;
        }
        const body = {
          access_token: `at-${stats.count}`,
          expires_in: 3600,
          token_type: "Bearer",
        };
        const rotated = Array.isArray(cfg.rotateSequence)
          ? cfg.rotateSequence.shift() || null
          : cfg.rotateTo;
        if (rotated) {
          body.refresh_token = rotated;
          if (cfg.validRefreshToken) cfg.validRefreshToken = rotated;
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(body));
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const a = server.address();
      resolve({
        server,
        url: `http://${a.address}:${a.port}/token`,
        stats,
        cfg,
        holdNextResponse,
      });
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
  let stateDir, upstream, token, proxy, proxyPort, vault;
  let clock = 1_000_000_000_000; // fixed start; advanced by tests

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "agentid-oauth2-"));
    upstream = await startUpstream();
    token = await startTokenEndpoint();

    await initVault({ stateDir, passphrase: "test-pass" });
    vault = await openVault({ stateDir, passphrase: "test-pass" });
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

  it("persists token rotation across a concurrent metadata-only edit", async () => {
    token.cfg.rotateTo = "rt-after-metadata-edit";
    clock += 3600 * 1000 + 1;
    const gate = token.holdNextResponse();
    const pending = callProxy({
      port: proxyPort,
      path: `/gmail/${upstream.host}/v1/messages`,
    });
    await gate.arrived;

    const editor = await openVault({ stateDir, passphrase: "test-pass" });
    editor.add({
      ...editor.get("gmail"),
      description: "owner-updated description while refresh was in flight",
    });
    await editor.save();
    editor.lock();
    await vault.reload();

    gate.release();
    const response = await pending;
    assert.equal(response.status, 409, "the old request retries under the new revision");

    const reopened = await openVault({ stateDir, passphrase: "test-pass" });
    assert.equal(reopened.get("gmail").refreshToken, "rt-after-metadata-edit");
    assert.match(reopened.get("gmail").description, /owner-updated/);
    reopened.lock();
    token.cfg.rotateTo = null;
  });

  it("invalidates the OAuth cache when the owner replaces a seeded access token", async () => {
    const beforeRefreshes = token.stats.count;
    const editor = await openVault({ stateDir, passphrase: "test-pass" });
    editor.add({
      ...editor.get("gmail"),
      accessToken: "owner-seed-b",
      accessTokenExpiresAt: clock + 3600 * 1000,
    });
    await editor.save();
    editor.lock();

    const response = await callProxy({
      port: proxyPort,
      path: `/gmail/${upstream.host}/v1/messages`,
    });
    assert.equal(response.status, 200);
    assert.equal(upstream.seen.authorization, "Bearer owner-seed-b");
    assert.equal(token.stats.count, beforeRefreshes, "fresh owner seed needs no refresh");
  });

  it("merges rotation but never publishes an old refresh result over a new seed", async () => {
    clock += 3600 * 1000 + 1;
    token.cfg.rotateTo = "rt-after-seed-race";
    const gate = token.holdNextResponse();
    const pending = callProxy({
      port: proxyPort,
      path: `/gmail/${upstream.host}/v1/messages`,
    });
    await gate.arrived;

    const editor = await openVault({ stateDir, passphrase: "test-pass" });
    editor.add({
      ...editor.get("gmail"),
      accessToken: "owner-seed-c",
      accessTokenExpiresAt: clock + 3600 * 1000,
    });
    await editor.save();
    editor.lock();
    await vault.reload();

    gate.release();
    const stale = await pending;
    assert.equal(stale.status, 409);
    assert.equal(JSON.parse(stale.body).error, "oauth_credential_changed");

    const reopened = await openVault({ stateDir, passphrase: "test-pass" });
    assert.equal(reopened.get("gmail").refreshToken, "rt-after-seed-race");
    assert.equal(reopened.get("gmail").accessToken, "owner-seed-c");
    reopened.lock();

    const beforeRefreshes = token.stats.count;
    const current = await callProxy({
      port: proxyPort,
      path: `/gmail/${upstream.host}/v1/messages`,
    });
    assert.equal(current.status, 200);
    assert.equal(upstream.seen.authorization, "Bearer owner-seed-c");
    assert.equal(token.stats.count, beforeRefreshes);
    token.cfg.rotateTo = null;
  });

  it("serializes single-use refresh tokens across broker processes", async () => {
    clock += 3600 * 1000 + 1;
    const currentVault = await openVault({ stateDir, passphrase: "test-pass" });
    const startingRefreshToken = currentVault.get("gmail").refreshToken;
    currentVault.lock();
    token.cfg.validRefreshToken = startingRefreshToken;
    token.cfg.rotateSequence = ["cross-process-r2", "cross-process-r3"];
    token.stats.maxActive = 0;
    const beforeRefreshes = token.stats.count;

    const secondVault = await openVault({ stateDir, passphrase: "test-pass" });
    const secondProxy = createProxy({
      vault: secondVault,
      stateDir,
      logPath: path.join(stateDir, "proxy-second.log"),
      now: () => clock,
    });
    const secondPort = (await secondProxy.listen()).port;
    try {
      const [first, second] = await Promise.all([
        callProxy({ port: proxyPort, path: `/gmail/${upstream.host}/v1/messages` }),
        callProxy({ port: secondPort, path: `/gmail/${upstream.host}/v1/messages` }),
      ]);
      assert.deepEqual([first.status, second.status], [200, 200]);
      assert.equal(token.stats.count, beforeRefreshes + 2);
      assert.equal(token.stats.maxActive, 1, "provider exchanges must never overlap");

      const reopened = await openVault({ stateDir, passphrase: "test-pass" });
      assert.equal(reopened.get("gmail").refreshToken, "cross-process-r3");
      reopened.lock();
    } finally {
      await secondProxy.close();
    }

    // The next refresh must start from the tail of the chain, not replay the
    // invalidated predecessor used by either concurrent broker.
    clock += 3600 * 1000 + 1;
    token.cfg.rotateSequence = ["cross-process-r4"];
    const next = await callProxy({
      port: proxyPort,
      path: `/gmail/${upstream.host}/v1/messages`,
    });
    assert.equal(next.status, 200);
    assert.equal(token.stats.lastBody.get("refresh_token"), "cross-process-r3");
    token.cfg.rotateSequence = null;
    token.cfg.validRefreshToken = null;
  });

  it("does not persist or inject an old refresh result after credential replacement", async () => {
    token.cfg.rotateTo = "rt-from-old-account";
    clock += 3600 * 1000 + 1;
    const gate = token.holdNextResponse();
    const pending = callProxy({
      port: proxyPort,
      path: `/gmail/${upstream.host}/v1/messages`,
    });
    await gate.arrived;

    const editor = await openVault({ stateDir, passphrase: "test-pass" });
    editor.add({
      ...editor.get("gmail"),
      clientId: "replacement-client",
      refreshToken: "rt-replacement-account",
    });
    await editor.save();
    editor.lock();
    await vault.reload();

    const beforeUpstream = upstream.seen.count;
    gate.release();
    const response = await pending;
    assert.equal(response.status, 409);
    assert.equal(JSON.parse(response.body).error, "oauth_credential_changed");
    assert.equal(upstream.seen.count, beforeUpstream, "stale access token was not injected");

    const reopened = await openVault({ stateDir, passphrase: "test-pass" });
    assert.equal(reopened.get("gmail").clientId, "replacement-client");
    assert.equal(reopened.get("gmail").refreshToken, "rt-replacement-account");
    reopened.lock();
    token.cfg.rotateTo = null;
  });

  it("reaps a dead OAuth refresh contender without a canonical-lock ABA race", async () => {
    clock += 3600 * 1000 + 1;
    const lockDir = path.join(stateDir, "locks");
    await fs.mkdir(lockDir, { recursive: true });
    const prefix = fileLockPrefix("oauth:gmail");
    const lockPath = path.join(
      lockDir,
      `${prefix}.ticket.1.99999999.${randomUUID()}`,
    );
    await fs.writeFile(lockPath, "99999999\n", { mode: 0o600 });

    const response = await callProxy({
      port: proxyPort,
      path: `/gmail/${upstream.host}/v1/messages`,
    });
    assert.equal(response.status, 200);
    await assert.rejects(fs.stat(lockPath), (err) => err?.code === "ENOENT");
  });

  it("discards an OAuth refresh response that completes after vault lock", async () => {
    clock += 3600 * 1000 + 1;
    token.cfg.rotateTo = "rt-rotated-during-lock";
    const gate = token.holdNextResponse();
    const pending = callProxy({
      port: proxyPort,
      path: `/gmail/${upstream.host}/v1/messages`,
    });
    await gate.arrived;
    const beforeUpstream = upstream.seen.count;

    proxy.forceLock("oauth_refresh_test");
    gate.release();
    const response = await pending;
    assert.equal(response.status, 409);
    assert.equal(JSON.parse(response.body).error, "oauth_refresh_stale");
    assert.equal(upstream.seen.count, beforeUpstream, "post-lock token was not injected");

    const reopened = await openVault({ stateDir, passphrase: "test-pass" });
    assert.equal(
      reopened.get("gmail").refreshToken,
      "rt-rotated-during-lock",
      "provider rotation must be durable even though the data plane locked",
    );
    reopened.lock();
    token.cfg.rotateTo = null;
  });
});
