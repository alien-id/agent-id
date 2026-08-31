#!/usr/bin/env node

// Control-plane auth: the credential-bearing routes (/pending, /approve, /deny,
// /register) require the bearer token; /status stays open for liveness. This is
// the gate that makes a co-resident process or LAN host unable to drive an
// approval even when it can reach the control port.
//
// Run: node --test tests/test-proxy-control-auth.mjs

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { createProxy } from "../plugins/agent-id-proxy/lib/proxy.mjs";
import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";

function req(port, p, { method = "GET", token = null } = {}) {
  return new Promise((resolve, reject) => {
    const r = http.request(
      {
        host: "127.0.0.1",
        port,
        path: p,
        method,
        headers: token ? { Authorization: `Bearer ${token}` } : {},
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
    r.on("error", reject);
    r.end();
  });
}

describe("control-plane auth", () => {
  let proxy;
  let stateDir;
  let controlPort;
  let token;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "ctl-auth-"));
    await initVault({ stateDir, passphrase: "p" });
    const vault = await openVault({ stateDir, passphrase: "p" });
    proxy = createProxy({
      vault,
      stateDir,
      logPath: path.join(stateDir, "proxy.log"),
      idleTimeoutMs: Infinity,
      control: {
        listen: { port: 0, host: "127.0.0.1" },
        approvalTimeoutMs: 5000,
      },
    });
    await proxy.listen();
    controlPort = proxy.controlAddress.port;
    token = proxy.controlToken;
  });

  after(async () => {
    if (proxy) await proxy.close();
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("generates a control token", () => {
    assert.equal(typeof token, "string");
    assert.ok(token.length >= 32);
  });

  it("/status is reachable without a token (liveness)", async () => {
    const r = await req(controlPort, "/status");
    assert.equal(r.status, 200);
  });

  it("/pending without a token is 401", async () => {
    const r = await req(controlPort, "/pending");
    assert.equal(r.status, 401);
    assert.match(r.body, /control_unauthorized/);
  });

  it("/pending with the token succeeds", async () => {
    const r = await req(controlPort, "/pending", { token });
    assert.equal(r.status, 200);
  });

  it("/approve without a token is 401 (cannot drive an approval)", async () => {
    const r = await req(controlPort, "/approve", { method: "POST" });
    assert.equal(r.status, 401);
  });

  it("/register without a token is 401 (cannot pair a rogue device)", async () => {
    const r = await req(controlPort, "/register", { method: "POST" });
    assert.equal(r.status, 401);
  });

  it("a wrong token is rejected", async () => {
    const r = await req(controlPort, "/pending", { token: "not-the-token" });
    assert.equal(r.status, 401);
  });
});
