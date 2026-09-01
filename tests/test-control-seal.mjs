#!/usr/bin/env node

// The control plane never accepts a cleartext master key: an approver seals the
// master key to the proxy's per-run control-plane public key (pinned by the
// approver out-of-band, via the pairing QR), and /approve only accepts that
// sealed form. This keeps the master key confidential even over a plain-HTTP
// control plane on a LAN.
//
// Run: node --test tests/test-control-seal.mjs

import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createECDH, randomBytes } from "node:crypto";

import {
  buildMobileSlot,
  deviceUnsealMasterKey,
  sealToPublicKey,
  unsealFromPublicKey,
} from "../plugins/agent-id-vault/lib/format.mjs";
import { createProxy } from "../plugins/agent-id-proxy/lib/proxy.mjs";
import { initVault, openVault, readMobileSlotChallenges } from "../plugins/agent-id-vault/lib/vault.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

describe("control-plane sealed box (crypto)", () => {
  it("round-trips a master key to the recipient and back", () => {
    const recip = createECDH("prime256v1");
    recip.generateKeys();
    const mk = randomBytes(32);
    const box = sealToPublicKey(mk, recip.getPublicKey().toString("hex"));
    assert.deepEqual(unsealFromPublicKey(box, recip.getPrivateKey()), mk);
  });

  it("carries no plaintext of the master key", () => {
    const recip = createECDH("prime256v1");
    recip.generateKeys();
    const mk = randomBytes(32);
    const box = sealToPublicKey(mk, recip.getPublicKey().toString("hex"));
    assert.ok(!JSON.stringify(box).includes(mk.toString("hex")));
  });

  it("a different recipient key cannot unseal", () => {
    const recip = createECDH("prime256v1");
    recip.generateKeys();
    const box = sealToPublicKey(randomBytes(32), recip.getPublicKey().toString("hex"));
    const wrong = createECDH("prime256v1");
    wrong.generateKeys();
    assert.throws(() => unsealFromPublicKey(box, wrong.getPrivateKey()));
  });

  it("rejects a malformed box", () => {
    const recip = createECDH("prime256v1");
    recip.generateKeys();
    assert.throws(() => unsealFromPublicKey({}, recip.getPrivateKey()), /malformed/);
  });
});

function controlGet(port, p, token) {
  return new Promise((resolve, reject) => {
    http
      .get({ host: "127.0.0.1", port, path: p, headers: { Authorization: `Bearer ${token}` } }, (res) => {
        const c = [];
        res.on("data", (x) => c.push(x));
        res.on("end", () => resolve(JSON.parse(Buffer.concat(c).toString("utf8"))));
      })
      .on("error", reject);
  });
}

function controlPost(port, p, body, token) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        path: p,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload),
          Authorization: `Bearer ${token}`,
        },
      },
      (res) => {
        const c = [];
        res.on("data", (x) => c.push(x));
        res.on("end", () =>
          resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(c).toString("utf8")) }),
        );
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}

function rewriteRequest(port, cred, upstream) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, method: "GET", path: `/${cred}/${upstream}/x` },
      (res) => {
        const c = [];
        res.on("data", (x) => c.push(x));
        res.on("end", () => resolve({ status: res.statusCode }));
      },
    );
    req.on("error", reject);
    req.end();
  });
}

describe("/approve requires a sealed master key", () => {
  let proxy;
  let stateDir;
  let upstreamServer;

  after(async () => {
    if (proxy) await proxy.close();
    if (upstreamServer) upstreamServer.close();
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("rejects a cleartext masterKey and accepts only the sealed form", async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "seal-approve-"));
    await initVault({ stateDir, passphrase: "p" });

    const record = { value: null };
    upstreamServer = http.createServer((req, res) => {
      record.value = req.headers;
      res.writeHead(200);
      res.end("{}");
    });
    const upstreamHost = await new Promise((r) =>
      upstreamServer.listen(0, "127.0.0.1", () => r(`127.0.0.1:${upstreamServer.address().port}`)),
    );

    const vault = await openVault({ stateDir, passphrase: "p" });
    vault.add({ name: "tok", type: "bearer", domains: ["127.0.0.1"], upstreamScheme: "http", value: "S" });
    const device = createECDH("prime256v1");
    device.generateKeys();
    vault.addMobileSlot(device.getPublicKey().toString("hex"), "phone");
    await vault.save();
    vault.lock();

    proxy = createProxy({
      stateDir,
      logPath: path.join(stateDir, "proxy.log"),
      idleTimeoutMs: Infinity,
      control: { listen: { port: 0, host: "127.0.0.1" }, approvalTimeoutMs: 5000 },
    });
    const dataPort = (await proxy.listen()).port;
    const controlPort = proxy.controlAddress.port;
    const token = proxy.controlToken;
    assert.equal(proxy.locked, true);

    // Fire a request — it parks awaiting unlock.
    const pending = rewriteRequest(dataPort, "tok", upstreamHost);

    // Wait for the unlock entry to appear.
    let entry = null;
    for (let i = 0; i < 100 && !entry; i++) {
      const { pending: list } = await controlGet(controlPort, "/pending", token);
      entry = (list || []).find((e) => e.action === "unlock");
      if (!entry) await sleep(10);
    }
    assert.ok(entry, "unlock request should park");

    // Recover the master key the way the phone does.
    const mk = deviceUnsealMasterKey({ ...entry.challenges[0], type: "mobile" }, device.getPrivateKey());

    // A cleartext masterKey is refused.
    const plain = await controlPost(controlPort, "/approve", { id: entry.id, masterKey: mk.toString("hex") }, token);
    assert.equal(plain.status, 400);
    assert.equal(plain.body.error, "sealed_master_key_required");
    assert.equal(proxy.locked, true);

    // The sealed form unlocks and the parked request completes.
    const sealed = sealToPublicKey(mk, proxy.controlPublicKey);
    const ok = await controlPost(controlPort, "/approve", { id: entry.id, sealedMasterKey: sealed }, token);
    assert.equal(ok.status, 200);
    const res = await pending;
    assert.equal(res.status, 200);
    assert.equal(proxy.locked, false);
  });
});
