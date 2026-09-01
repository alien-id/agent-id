#!/usr/bin/env node

// SSRF guard: blocked-address classification, the connect-time lookup, and the
// proxy returning 403 upstream_blocked for a link-local / metadata target.
//
// Run: node --test tests/test-ssrf.mjs

import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { blockedAddressReason, makeUpstreamLookup } from "../plugins/agent-id-proxy/lib/ssrf.mjs";
import { createProxy } from "../plugins/agent-id-proxy/lib/proxy.mjs";
import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";

describe("blockedAddressReason", () => {
  it("always blocks cloud-metadata / link-local / unspecified / multicast", () => {
    assert.ok(blockedAddressReason("169.254.169.254"));
    assert.ok(blockedAddressReason("169.254.0.1"));
    assert.ok(blockedAddressReason("0.0.0.0"));
    assert.ok(blockedAddressReason("224.0.0.1"));
    assert.ok(blockedAddressReason("fe80::1"));
    assert.ok(blockedAddressReason("::"));
    assert.ok(blockedAddressReason("ff02::1"));
    // IPv4-mapped IPv6 form of the metadata IP is unwrapped and blocked.
    assert.ok(blockedAddressReason("::ffff:169.254.169.254"));
  });

  it("allows public addresses", () => {
    assert.equal(blockedAddressReason("8.8.8.8"), null);
    assert.equal(blockedAddressReason("140.82.121.3"), null);
    assert.equal(blockedAddressReason("2606:4700:4700::1111"), null);
  });

  it("loopback/private only blocked under blockPrivate", () => {
    for (const ip of ["127.0.0.1", "10.0.0.5", "172.16.0.1", "192.168.1.1", "100.64.0.1", "::1", "fd00::1"]) {
      assert.equal(blockedAddressReason(ip), null, `${ip} default-allowed`);
      assert.ok(blockedAddressReason(ip, { blockPrivate: true }), `${ip} blocked under blockPrivate`);
    }
  });
});

describe("makeUpstreamLookup", () => {
  it("errors with ESSRFBLOCKED for a blocked literal IP", (t, done) => {
    makeUpstreamLookup()("169.254.169.254", {}, (err) => {
      assert.ok(err);
      assert.equal(err.code, "ESSRFBLOCKED");
      done();
    });
  });

  it("resolves a normal loopback literal by default", (t, done) => {
    makeUpstreamLookup()("127.0.0.1", {}, (err, address) => {
      assert.equal(err, null);
      assert.equal(address, "127.0.0.1");
      done();
    });
  });

  it("blocks loopback under blockPrivate", (t, done) => {
    makeUpstreamLookup({ blockPrivate: true })("127.0.0.1", {}, (err) => {
      assert.ok(err);
      assert.equal(err.code, "ESSRFBLOCKED");
      done();
    });
  });
});

describe("proxy refuses a link-local upstream (403 upstream_blocked)", () => {
  let proxy;
  let stateDir;

  after(async () => {
    if (proxy) await proxy.close();
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("returns 403 for a credential pointed at 169.254.169.254", async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "ssrf-"));
    await initVault({ stateDir, passphrase: "p" });
    const vault = await openVault({ stateDir, passphrase: "p" });
    // A deliberately mis-scoped credential allowlisting the metadata service.
    vault.add({
      name: "leaky",
      type: "bearer",
      domains: ["169.254.169.254"],
      upstreamScheme: "http",
      value: "SECRET",
    });
    await vault.save();

    proxy = createProxy({
      vault,
      stateDir,
      logPath: path.join(stateDir, "proxy.log"),
      idleTimeoutMs: Infinity,
    });
    const { port } = await proxy.listen();

    const res = await new Promise((resolve, reject) => {
      const req = http.request(
        { host: "127.0.0.1", port, method: "GET", path: "/leaky/169.254.169.254/latest/meta-data/" },
        (r) => {
          const chunks = [];
          r.on("data", (c) => chunks.push(c));
          r.on("end", () => resolve({ status: r.statusCode, body: Buffer.concat(chunks).toString("utf8") }));
        },
      );
      req.on("error", reject);
      req.end();
    });

    assert.equal(res.status, 403);
    assert.match(res.body, /upstream_blocked/);
  });
});
