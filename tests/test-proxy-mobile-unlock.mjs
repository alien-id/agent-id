#!/usr/bin/env node

// Phone-approved unlock + per-credential consent over the control plane.
//
// A Node P-256 keypair stands in for the iOS Secure-Enclave key: we add a
// `mobile` slot sealed to its public key, then drive the proxy's control plane
// exactly as the phone would —
//   1. poll  GET  /pending
//   2. for an `unlock` request, ECDH-unseal the master key and POST it to
//      /approve  (deviceUnsealMasterKey is the canonical client reference)
//   3. for an `authorize` request, POST /approve (or /deny)
//
// Validates: locked-start → request parks → phone unlocks → request completes;
// idle force-lock → next request re-unlocks; consent approve and deny; and that
// a granted (cred,host) pair is not re-prompted within its TTL.
//
// Run: node --test tests/test-proxy-mobile-unlock.mjs

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createECDH } from "node:crypto";

import {
  initVault,
  openVault,
  openVaultWithMasterKey,
} from "../plugins/agent-id-vault/lib/vault.mjs";
import {
  buildMobileSlot,
  deviceUnsealMasterKey,
  sealToPublicKey,
} from "../plugins/agent-id-vault/lib/format.mjs";
import { createProxy } from "../plugins/agent-id-proxy/lib/proxy.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function startUpstream(record) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      record.value = { ...req.headers, _url: req.url };
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"ok":true}');
    });
    server.listen(0, "127.0.0.1", () => {
      const a = server.address();
      resolve({ server, host: `${a.address}:${a.port}` });
    });
  });
}

// URL-rewrite request: /<cred>/<upstream-host>/<path>. Returns the response.
function rewriteRequest({ port, cred, upstream, path: p = "/x" }) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, method: "GET", path: `/${cred}/${upstream}${p}` },
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

function controlGet(port, p, token) {
  return new Promise((resolve, reject) => {
    http
      .get(
        { host: "127.0.0.1", port, path: p, headers: token ? { Authorization: `Bearer ${token}` } : {} },
        (res) => {
          const chunks = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))));
        },
      )
      .on("error", reject);
  });
}

function controlPost(port, p, body, token) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const headers = { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) };
    if (token) headers.Authorization = `Bearer ${token}`;
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        path: p,
        method: "POST",
        headers,
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString("utf8")) }),
        );
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}

// Background "phone": handles each pending request once.
function startPhone({ port, devicePrivRaw, denyAuthorize = false, token, controlPubKey }) {
  const state = { stop: false, handled: { unlock: 0, authorize: 0 }, seen: new Set() };
  (async function loop() {
    while (!state.stop) {
      try {
        const { pending } = await controlGet(port, "/pending", token);
        for (const entry of pending) {
          if (state.seen.has(entry.id)) continue;
          state.seen.add(entry.id);
          if (entry.action === "unlock") {
            const ch = entry.challenges[0];
            const mk = deviceUnsealMasterKey({ ...ch, type: "mobile" }, devicePrivRaw);
            // Seal the master key to the proxy's control key (pinned via the
            // pairing QR) — never POST it in cleartext.
            const sealedMasterKey = sealToPublicKey(mk, controlPubKey);
            await controlPost(port, "/approve", { id: entry.id, sealedMasterKey }, token);
            state.handled.unlock++;
          } else if (entry.action === "authorize") {
            if (denyAuthorize) {
              await controlPost(port, "/deny", { id: entry.id, reason: "consent_denied" }, token);
            } else {
              await controlPost(port, "/approve", { id: entry.id }, token);
            }
            state.handled.authorize++;
          }
        }
      } catch {
        // control server may be momentarily unavailable; retry
      }
      await sleep(5);
    }
  })();
  return state;
}

// ── Setup: a vault with one http credential + a mobile slot ──────────────────
async function setupVault({ requireConsent }) {
  const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-mobile-"));
  await initVault({ stateDir, passphrase: "p" });

  const record = { value: null };
  const upstream = await startUpstream(record);

  let vault = await openVault({ stateDir, passphrase: "p" });
  vault.add({
    name: "tok",
    type: "bearer",
    domains: [upstream.host.split(":")[0]],
    upstreamScheme: "http",
    value: "SECRET-TOKEN",
  });

  // Node P-256 key stands in for the phone's Secure-Enclave key.
  const device = createECDH("prime256v1");
  device.generateKeys();
  const devicePubHex = device.getPublicKey().toString("hex");
  const devicePrivRaw = device.getPrivateKey();
  vault.addMobileSlot(devicePubHex, "test-phone");
  await vault.save();
  vault.lock();

  return { stateDir, upstream, record, devicePrivRaw, requireConsent };
}

describe("format: mobile slot seals and unseals the master key", () => {
  it("round-trips via ECDH + HKDF", () => {
    const masterKey = Buffer.alloc(32, 7);
    const device = createECDH("prime256v1");
    device.generateKeys();
    const slot = buildMobileSlot(2, masterKey, device.getPublicKey().toString("hex"), "dev");
    assert.equal(slot.type, "mobile");
    assert.equal(slot.alg, "ecdh-p256-hkdf-sha256-aes256gcm");
    const recovered = deviceUnsealMasterKey(slot, device.getPrivateKey());
    assert.deepEqual(recovered, masterKey);
  });

  it("a different device key cannot unseal", () => {
    const masterKey = Buffer.alloc(32, 9);
    const device = createECDH("prime256v1");
    device.generateKeys();
    const slot = buildMobileSlot(2, masterKey, device.getPublicKey().toString("hex"));
    const wrong = createECDH("prime256v1");
    wrong.generateKeys();
    assert.throws(() => deviceUnsealMasterKey(slot, wrong.getPrivateKey()));
  });

  it("openVaultWithMasterKey opens the payload with the recovered key", async () => {
    const { stateDir, devicePrivRaw } = await setupVault({ requireConsent: false });
    const challenges = await import("../plugins/agent-id-vault/lib/vault.mjs").then((m) =>
      m.readMobileSlotChallenges(stateDir),
    );
    const mk = deviceUnsealMasterKey({ ...challenges[0], type: "mobile" }, devicePrivRaw);
    const vault = await openVaultWithMasterKey({ stateDir, masterKey: mk });
    assert.equal(vault.get("tok").value, "SECRET-TOKEN");
    vault.lock();
    await fs.rm(stateDir, { recursive: true, force: true });
  });
});

describe("proxy: phone-approved unlock", () => {
  let ctx;
  let proxy;
  let dataPort;
  let controlPort;
  let phone;

  before(async () => {
    ctx = await setupVault({ requireConsent: false });
    proxy = createProxy({
      stateDir: ctx.stateDir,
      logPath: path.join(ctx.stateDir, "proxy.log"),
      idleTimeoutMs: Infinity,
      control: { listen: { port: 0, host: "127.0.0.1" }, approvalTimeoutMs: 5000 },
    });
    dataPort = (await proxy.listen()).port;
    controlPort = proxy.controlAddress.port;
    phone = startPhone({ port: controlPort, devicePrivRaw: ctx.devicePrivRaw, token: proxy.controlToken, controlPubKey: proxy.controlPublicKey });
  });

  after(async () => {
    phone.stop = true;
    await proxy?.close();
    ctx.upstream.server.close();
    await fs.rm(ctx.stateDir, { recursive: true, force: true });
  });

  it("starts locked, awaiting mobile unlock", () => {
    assert.equal(proxy.locked, true);
  });

  it("a request parks until the phone unlocks, then completes with the credential injected", async () => {
    ctx.record.value = null;
    const r = await rewriteRequest({ port: dataPort, cred: "tok", upstream: ctx.upstream.host });
    assert.equal(r.status, 200);
    assert.equal(proxy.locked, false);
    assert.equal(ctx.record.value.authorization, "Bearer SECRET-TOKEN");
    assert.equal(phone.handled.unlock, 1);
  });

  it("once unlocked, further requests do not re-prompt", async () => {
    const before = phone.handled.unlock;
    const r = await rewriteRequest({ port: dataPort, cred: "tok", upstream: ctx.upstream.host });
    assert.equal(r.status, 200);
    assert.equal(phone.handled.unlock, before);
  });

  it("after idle force-lock, the next request re-unlocks via the phone", async () => {
    proxy.forceLock("test_idle");
    assert.equal(proxy.locked, true);
    const before = phone.handled.unlock;
    const r = await rewriteRequest({ port: dataPort, cred: "tok", upstream: ctx.upstream.host });
    assert.equal(r.status, 200);
    assert.equal(proxy.locked, false);
    assert.equal(phone.handled.unlock, before + 1);
  });
});

describe("proxy: self-registration (no rekey)", () => {
  it("registers a device over the control plane, then that device unlocks after idle", async () => {
    const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-reg-"));
    await initVault({ stateDir, passphrase: "p" });
    const record = { value: null };
    const upstream = await startUpstream(record);

    // Vault with a credential but NO mobile slot yet.
    let vault = await openVault({ stateDir, passphrase: "p" });
    vault.add({
      name: "tok",
      type: "bearer",
      domains: [upstream.host.split(":")[0]],
      upstreamScheme: "http",
      value: "SECRET-TOKEN",
    });
    await vault.save();
    vault.lock();

    // Proxy starts UNLOCKED via passphrase (stands in for the agent-key path).
    vault = await openVault({ stateDir, passphrase: "p" });
    const proxy = createProxy({
      vault,
      stateDir,
      logPath: path.join(stateDir, "proxy.log"),
      idleTimeoutMs: Infinity,
      control: { listen: { port: 0, host: "127.0.0.1" }, approvalTimeoutMs: 5000 },
    });
    const dataPort = (await proxy.listen()).port;
    const controlPort = proxy.controlAddress.port;
    assert.equal(proxy.locked, false);

    // This device's key.
    const device = createECDH("prime256v1");
    device.generateKeys();
    const devicePubHex = device.getPublicKey().toString("hex");
    const devicePrivRaw = device.getPrivateKey();

    // Pair over the control plane — no CLI rekey.
    const reg = await controlPost(controlPort, "/register", {
      devicePubKey: devicePubHex,
      deviceId: "ios-demo",
    }, proxy.controlToken);
    assert.equal(reg.status, 200);
    assert.equal(reg.body.ok, true);

    // Idempotent.
    const reg2 = await controlPost(controlPort, "/register", { devicePubKey: devicePubHex }, proxy.controlToken);
    assert.equal(reg2.body.alreadyPaired, true);

    // /status now lists the paired device.
    const status = await controlGet(controlPort, "/status");
    assert.ok(status.devices.some((d) => d.devicePubKey === devicePubHex));

    // Idle lock, then the registered device unlocks on the next request.
    proxy.forceLock("test_idle");
    const phone = startPhone({ port: controlPort, devicePrivRaw, token: proxy.controlToken, controlPubKey: proxy.controlPublicKey });
    record.value = null;
    const r = await rewriteRequest({ port: dataPort, cred: "tok", upstream: upstream.host });
    assert.equal(r.status, 200);
    assert.equal(record.value.authorization, "Bearer SECRET-TOKEN");

    phone.stop = true;
    await proxy.close();
    upstream.server.close();
    await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("refuses to register while locked", async () => {
    const ctx = await setupVault({ requireConsent: false });
    const proxy = createProxy({
      stateDir: ctx.stateDir,
      logPath: path.join(ctx.stateDir, "proxy.log"),
      idleTimeoutMs: Infinity,
      control: { listen: { port: 0, host: "127.0.0.1" }, approvalTimeoutMs: 5000 },
    });
    await proxy.listen();
    const controlPort = proxy.controlAddress.port;
    assert.equal(proxy.locked, true);

    const device = createECDH("prime256v1");
    device.generateKeys();
    const reg = await controlPost(controlPort, "/register", {
      devicePubKey: device.getPublicKey().toString("hex"),
      deviceId: "late",
    }, proxy.controlToken);
    assert.equal(reg.status, 409);
    assert.equal(reg.body.error, "vault_locked");

    await proxy.close();
    ctx.upstream.server.close();
    await fs.rm(ctx.stateDir, { recursive: true, force: true });
  });
});

describe("proxy: per-credential consent", () => {
  it("approves first use, then caches the grant for the TTL", async () => {
    const ctx = await setupVault({ requireConsent: true });
    const proxy = createProxy({
      stateDir: ctx.stateDir,
      logPath: path.join(ctx.stateDir, "proxy.log"),
      idleTimeoutMs: Infinity,
      requireConsent: true,
      grantTtlMs: 60_000,
      control: { listen: { port: 0, host: "127.0.0.1" }, approvalTimeoutMs: 5000 },
    });
    const dataPort = (await proxy.listen()).port;
    const controlPort = proxy.controlAddress.port;
    const phone = startPhone({ port: controlPort, devicePrivRaw: ctx.devicePrivRaw, token: proxy.controlToken, controlPubKey: proxy.controlPublicKey });

    const r1 = await rewriteRequest({ port: dataPort, cred: "tok", upstream: ctx.upstream.host });
    assert.equal(r1.status, 200);
    assert.equal(phone.handled.unlock, 1);
    assert.equal(phone.handled.authorize, 1);

    // Second request to the same (cred,host): grant cached, no new prompt.
    const r2 = await rewriteRequest({ port: dataPort, cred: "tok", upstream: ctx.upstream.host });
    assert.equal(r2.status, 200);
    assert.equal(phone.handled.authorize, 1);

    phone.stop = true;
    await proxy.close();
    ctx.upstream.server.close();
    await fs.rm(ctx.stateDir, { recursive: true, force: true });
  });

  it("denied consent returns 403 and does not reach upstream", async () => {
    const ctx = await setupVault({ requireConsent: true });
    const proxy = createProxy({
      stateDir: ctx.stateDir,
      logPath: path.join(ctx.stateDir, "proxy.log"),
      idleTimeoutMs: Infinity,
      requireConsent: true,
      control: { listen: { port: 0, host: "127.0.0.1" }, approvalTimeoutMs: 5000 },
    });
    const dataPort = (await proxy.listen()).port;
    const controlPort = proxy.controlAddress.port;
    const phone = startPhone({ port: controlPort, devicePrivRaw: ctx.devicePrivRaw, denyAuthorize: true, token: proxy.controlToken, controlPubKey: proxy.controlPublicKey });

    ctx.record.value = null;
    const r = await rewriteRequest({ port: dataPort, cred: "tok", upstream: ctx.upstream.host });
    assert.equal(r.status, 403);
    assert.equal(ctx.record.value, null); // upstream never hit
    assert.equal(proxy.locked, false); // unlock still succeeded

    phone.stop = true;
    await proxy.close();
    ctx.upstream.server.close();
    await fs.rm(ctx.stateDir, { recursive: true, force: true });
  });
});
