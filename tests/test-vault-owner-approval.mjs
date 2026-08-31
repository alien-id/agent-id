#!/usr/bin/env node

// Tests for the owner-approval vault slot + the SSO unlock client.
//
// Two layers:
//   1. Pure format/crypto round-trip (no network): the owner-approval slot
//      wraps and unwraps the master key with a 32-byte KEK; wrong KEK fails;
//      openVault opens via the ownerApprovalKek path.
//   2. End-to-end against the real examples/dev-sso.mjs fixture: obtain an
//      owner-session access token via the OIDC flow, enroll an owner-approval
//      KEK, then drive the start/poll unlock flow and recover the KEK. This
//      exercises the documented /vault/enroll + /vault/unlock/* contract,
//      including DPoP + access-token binding and single-use release.
//
// Run: node --test tests/test-vault-owner-approval.mjs

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import http from "node:http";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  buildOwnerApprovalSlot,
  findOwnerApprovalSlot,
  generateMasterKey,
  masterKeyEquals,
  newVaultFile,
  ownerApprovalKekBytes,
  sealToPublicKey,
  unwrapSlotWithOwnerApproval,
} from "../plugins/agent-id-vault/lib/format.mjs";
import {
  initVault,
  openVault,
  recoverMasterKeyViaOwnerApproval,
} from "../plugins/agent-id-vault/lib/vault.mjs";
import {
  enrollOwnerApproval,
  requestUnlockSecret,
} from "../plugins/agent-id-vault/lib/owner-approval.mjs";
import { createProxy } from "../plugins/agent-id-proxy/lib/proxy.mjs";
import { statePaths } from "../plugins/agent-id-core/lib/state.mjs";
import {
  beginOidcAuthorization,
  exchangeAuthorizationCode,
  pollForAuthorizationCode,
} from "../plugins/agent-id-core/lib/oidc.mjs";
import { generateEd25519PemPair } from "../plugins/agent-id-core/lib/crypto.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEV_SSO = path.join(HERE, "..", "examples", "dev-sso.mjs");
const PROVIDER = "dev-fixture-provider";

// ─── Layer 1: pure format round-trip ──────────────────────────────────────────

describe("owner-approval slot (format)", () => {
  it("round-trips the master key with the right KEK", () => {
    const mk = generateMasterKey();
    const kek = ownerApprovalKekBytes();
    const slot = buildOwnerApprovalSlot(2, mk, kek, {
      keyRef: "oa-abc",
      ssoBaseUrl: "https://sso.example",
    });
    const recovered = unwrapSlotWithOwnerApproval(slot, kek);
    assert.ok(masterKeyEquals(mk, recovered));
    assert.equal(slot.type, "owner-approval");
    assert.equal(slot.keyRef, "oa-abc");
    assert.equal(slot.ssoBaseUrl, "https://sso.example");
    // The slot must NOT carry the KEK.
    assert.equal(slot.kek, undefined);
    assert.equal(slot.secret, undefined);
  });

  it("rejects a different KEK", () => {
    const mk = generateMasterKey();
    const slot = buildOwnerApprovalSlot(2, mk, ownerApprovalKekBytes(), {
      keyRef: "oa-1",
    });
    assert.throws(() =>
      unwrapSlotWithOwnerApproval(slot, ownerApprovalKekBytes())
    );
  });

  it("requires a keyRef", () => {
    const mk = generateMasterKey();
    assert.throws(() =>
      buildOwnerApprovalSlot(2, mk, ownerApprovalKekBytes(), {})
    );
  });

  it("requires a 32-byte KEK", () => {
    const mk = generateMasterKey();
    assert.throws(() =>
      buildOwnerApprovalSlot(2, mk, Buffer.alloc(16), { keyRef: "oa-1" })
    );
  });

  it("openVault opens via the ownerApprovalKek path", async () => {
    const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "agent-id-oa-"));
    try {
      // Build a vault with a passphrase slot + an owner-approval slot sharing
      // the same master key, then confirm the KEK alone opens it.
      const mk = generateMasterKey();
      const kek = ownerApprovalKekBytes();
      const { buildPassphraseSlot } = await import(
        "../plugins/agent-id-vault/lib/format.mjs"
      );
      const slots = [
        buildPassphraseSlot(0, mk, "recovery-pass"),
        buildOwnerApprovalSlot(1, mk, kek, {
          keyRef: "oa-xyz",
          ssoBaseUrl: "https://sso.example",
        }),
      ];
      const file = newVaultFile({
        masterKey: mk,
        slots,
        payloadPlaintext: '{"version":1,"credentials":[]}',
      });
      assert.ok(findOwnerApprovalSlot(file.slots));
      const paths = (
        await import("../plugins/agent-id-core/lib/state.mjs")
      ).statePaths(stateDir);
      await fs.writeFile(
        paths.vaultFile,
        JSON.stringify(file, null, 2) + "\n",
        { mode: 0o600 }
      );

      const vault = await openVault({ stateDir, ownerApprovalKek: kek });
      assert.deepEqual(vault.list(), []);
      const oaSlot = vault.slots.find((s) => s.type === "owner-approval");
      assert.equal(oaSlot.keyRef, "oa-xyz");
      vault.lock();
    } finally {
      await fs.rm(stateDir, { recursive: true, force: true });
    }
  });
});

// ─── Layer 2: end-to-end against dev-sso ───────────────────────────────────────

async function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

function startDevSso(port) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [DEV_SSO, "--port", String(port)], {
      stdio: ["ignore", "ignore", "pipe"],
    });
    let buf = "";
    const onData = (chunk) => {
      buf += chunk.toString();
      if (buf.includes("listening on")) {
        child.stderr.off("data", onData);
        resolve(child);
      }
    };
    child.stderr.on("data", onData);
    child.once("error", reject);
    setTimeout(() => reject(new Error("dev-sso did not start in time")), 5000);
  });
}

// Run the OIDC authorize/poll/exchange flow against dev-sso (which auto-
// approves) and return a DPoP-bound owner-session access token.
async function getOwnerSession(ssoBaseUrl, keys) {
  const begin = await beginOidcAuthorization({
    ssoBaseUrl,
    providerAddress: PROVIDER,
    agentPublicKeyPem: keys.publicKeyPem,
  });
  const { authorizationCode } = await pollForAuthorizationCode({
    ssoBaseUrl,
    pollingCode: begin.pollingCode,
    timeoutSec: 5,
    pollIntervalMs: 50,
    expectedState: begin.state,
    expectedIssuer: begin.issuer,
  });
  const tokens = await exchangeAuthorizationCode({
    ssoBaseUrl,
    authorizationCode,
    providerAddress: PROVIDER,
    codeVerifier: begin.codeVerifier,
    agentPrivateKeyPem: keys.privateKeyPem,
  });
  return tokens.access_token;
}

describe("owner-approval unlock (e2e against dev-sso)", () => {
  let child;
  let ssoBaseUrl;
  let keys;
  let accessToken;

  before(async () => {
    const port = await freePort();
    ssoBaseUrl = `http://127.0.0.1:${port}`;
    child = await startDevSso(port);
    keys = generateEd25519PemPair();
    accessToken = await getOwnerSession(ssoBaseUrl, keys);
  });

  after(() => {
    if (child) child.kill("SIGTERM");
  });

  it("enroll → start → poll recovers the KEK and opens the vault", async () => {
    const stateDir = await fs.mkdtemp(
      path.join(os.tmpdir(), "agent-id-oa-e2e-")
    );
    try {
      await initVault({ stateDir, passphrase: "recovery-pass" });

      // Mimic `rekey add-owner-approval`: generate a KEK, enroll it, store the
      // owner-approval slot wrapped by that KEK.
      const kek = ownerApprovalKekBytes();
      const { keyRef } = await enrollOwnerApproval({
        ssoBaseUrl,
        accessToken,
        agentPrivateKeyPem: keys.privateKeyPem,
        secret: kek,
      });
      assert.match(keyRef, /^oa-/);

      const vault = await openVault({ stateDir, passphrase: "recovery-pass" });
      vault.add({
        name: "gh",
        type: "bearer",
        value: "secret-token",
        domains: ["api.github.com"],
      });
      vault.addOwnerApprovalSlot(kek, {
        keyRef,
        ssoBaseUrl,
        providerAddress: PROVIDER,
      });
      await vault.save();
      vault.lock();

      // Now drive the unlock flow: the SSO releases the same KEK after the
      // (auto-)approval, and it must open the slot.
      let prompted = null;
      const { secret } = await requestUnlockSecret({
        ssoBaseUrl,
        accessToken,
        agentPrivateKeyPem: keys.privateKeyPem,
        keyRef,
        pollIntervalMs: 50,
        timeoutSec: 5,
        onPrompt: (p) => {
          prompted = p;
        },
      });
      assert.ok(
        prompted && prompted.deepLink,
        "onPrompt should receive a deep link"
      );
      assert.ok(
        masterKeyEquals(secret, kek),
        "released secret must equal the enrolled KEK"
      );

      const reopened = await openVault({ stateDir, ownerApprovalKek: secret });
      const cred = reopened.get("gh");
      assert.equal(cred.value, "secret-token");
      reopened.lock();
    } finally {
      await fs.rm(stateDir, { recursive: true, force: true });
    }
  });

  it("a foreign agent key cannot unlock the slot (binding enforced)", async () => {
    const kek = ownerApprovalKekBytes();
    const { keyRef } = await enrollOwnerApproval({
      ssoBaseUrl,
      accessToken,
      agentPrivateKeyPem: keys.privateKeyPem,
      secret: kek,
    });
    // A different agent presenting its own (valid-looking) session must not be
    // able to drive the unlock for someone else's key_ref. Use a fresh key +
    // its own owner session; the SSO binds key_ref to the enrolling jkt.
    const otherKeys = generateEd25519PemPair();
    const otherToken = await getOwnerSession(ssoBaseUrl, otherKeys);
    await assert.rejects(
      requestUnlockSecret({
        ssoBaseUrl,
        accessToken: otherToken,
        agentPrivateKeyPem: otherKeys.privateKeyPem,
        keyRef,
        pollIntervalMs: 50,
        timeoutSec: 3,
      }),
      /403|forbidden|HTTP 403/i
    );
  });

  it("an unknown key_ref is rejected", async () => {
    await assert.rejects(
      requestUnlockSecret({
        ssoBaseUrl,
        accessToken,
        agentPrivateKeyPem: keys.privateKeyPem,
        keyRef: "oa-does-not-exist",
        pollIntervalMs: 50,
        timeoutSec: 3,
      }),
      /404|unknown_key_ref|HTTP 404/i
    );
  });
});

// ─── Layer 3: proxy control-plane re-unlock via owner-approval ─────────────────
//
// The proxy surfaces an owner-approval slot as an unlock method over its HTTP
// control plane (alongside mobile slots). An approver — here the agent itself,
// the role the proxy CLI plays for owner-approval vaults — polls /pending,
// drives the SSO release to recover the KEK, unwraps the master key, and POSTs
// it to /approve, exactly as the phone does after unsealing a mobile slot.

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

function rewriteRequest({ port, cred, upstream, path: p = "/x" }) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        method: "GET",
        path: `/${cred}/${upstream}${p}`,
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

function controlGet(port, p, token) {
  return new Promise((resolve, reject) => {
    http
      .get(
        {
          host: "127.0.0.1",
          port,
          path: p,
          headers: token ? { Authorization: `Bearer ${token}` } : {},
        },
        (res) => {
          const chunks = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () =>
            resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")))
          );
        }
      )
      .on("error", reject);
  });
}

function controlPost(port, p, body, token) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const headers = {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(payload),
    };
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
          resolve({
            status: res.statusCode,
            body: JSON.parse(Buffer.concat(chunks).toString("utf8")),
          })
        );
      }
    );
    req.on("error", reject);
    req.end(payload);
  });
}

// Background owner-approval approver: handles each pending unlock once by
// driving the SSO release and posting the recovered master key.
function startApprover({
  controlPort,
  stateDir,
  ssoBaseUrl,
  accessToken,
  agentPrivateKeyPem,
  controlToken,
  controlPublicKey,
}) {
  const state = { stop: false, handled: 0, prompts: 0, seen: new Set() };
  (async function loop() {
    while (!state.stop) {
      try {
        const { pending } = await controlGet(
          controlPort,
          "/pending",
          controlToken
        );
        for (const entry of pending) {
          if (state.seen.has(entry.id)) continue;
          if (entry.action !== "unlock" || !entry.ownerApproval) continue;
          state.seen.add(entry.id);
          const { secret } = await requestUnlockSecret({
            ssoBaseUrl,
            accessToken,
            agentPrivateKeyPem,
            keyRef: entry.ownerApproval.keyRef,
            pollIntervalMs: 50,
            timeoutSec: 5,
            onPrompt: () => {
              state.prompts++;
            },
          });
          let mk;
          try {
            mk = await recoverMasterKeyViaOwnerApproval(stateDir, secret);
            const sealedMasterKey = sealToPublicKey(mk, controlPublicKey);
            await controlPost(
              controlPort,
              "/approve",
              { id: entry.id, sealedMasterKey },
              controlToken
            );
            state.handled++;
          } finally {
            secret.fill(0);
            if (mk) mk.fill(0);
          }
        }
      } catch {
        // control server momentarily unavailable, or a stale pending id — retry
      }
      await sleep(10);
    }
  })();
  return state;
}

describe("proxy: owner-approval re-unlock over the control plane", () => {
  let child;
  let ssoBaseUrl;
  let keys;
  let accessToken;

  before(async () => {
    const port = await freePort();
    ssoBaseUrl = `http://127.0.0.1:${port}`;
    child = await startDevSso(port);
    keys = generateEd25519PemPair();
    accessToken = await getOwnerSession(ssoBaseUrl, keys);
  });

  after(() => {
    if (child) child.kill("SIGTERM");
  });

  it("a request to a locked proxy parks, unlocks via owner approval, then completes", async () => {
    const stateDir = await fs.mkdtemp(
      path.join(os.tmpdir(), "agent-id-oa-ctl-")
    );
    const record = { value: null };
    const upstream = await startUpstream(record);
    let proxy;
    let approver;
    try {
      await initVault({ stateDir, passphrase: "recovery-pass" });
      const kek = ownerApprovalKekBytes();
      const { keyRef } = await enrollOwnerApproval({
        ssoBaseUrl,
        accessToken,
        agentPrivateKeyPem: keys.privateKeyPem,
        secret: kek,
      });
      const vault = await openVault({ stateDir, passphrase: "recovery-pass" });
      vault.add({
        name: "tok",
        type: "bearer",
        domains: [upstream.host.split(":")[0]],
        upstreamScheme: "http",
        value: "SECRET-TOKEN",
      });
      vault.addOwnerApprovalSlot(kek, {
        keyRef,
        ssoBaseUrl,
        providerAddress: PROVIDER,
      });
      await vault.save();
      vault.lock();
      kek.fill(0);

      // Proxy starts LOCKED (no vault handle passed) — the owner-approval slot
      // is the only unlock method.
      proxy = createProxy({
        stateDir,
        logPath: statePaths(stateDir).proxyLog,
        idleTimeoutMs: Infinity,
        control: {
          listen: { port: 0, host: "127.0.0.1" },
          approvalTimeoutMs: 5000,
        },
      });
      const dataPort = (await proxy.listen()).port;
      const controlPort = proxy.controlAddress.port;
      assert.equal(proxy.locked, true);

      approver = startApprover({
        controlPort,
        stateDir,
        ssoBaseUrl,
        accessToken,
        agentPrivateKeyPem: keys.privateKeyPem,
        controlToken: proxy.controlToken,
        controlPublicKey: proxy.controlPublicKey,
      });

      const r = await rewriteRequest({
        port: dataPort,
        cred: "tok",
        upstream: upstream.host,
      });
      assert.equal(r.status, 200);
      assert.equal(proxy.locked, false);
      assert.equal(record.value.authorization, "Bearer SECRET-TOKEN");
      assert.ok(approver.handled >= 1, "approver should have unlocked once");
      assert.ok(
        approver.prompts >= 1,
        "approver should have received an SSO prompt"
      );
    } finally {
      if (approver) approver.stop = true;
      if (proxy) await proxy.close();
      upstream.server.close();
      await fs.rm(stateDir, { recursive: true, force: true });
    }
  });

  it("after idle force-lock, the next request re-unlocks via owner approval", async () => {
    const stateDir = await fs.mkdtemp(
      path.join(os.tmpdir(), "agent-id-oa-ctl2-")
    );
    const record = { value: null };
    const upstream = await startUpstream(record);
    let proxy;
    let approver;
    try {
      await initVault({ stateDir, passphrase: "recovery-pass" });
      const kek = ownerApprovalKekBytes();
      const { keyRef } = await enrollOwnerApproval({
        ssoBaseUrl,
        accessToken,
        agentPrivateKeyPem: keys.privateKeyPem,
        secret: kek,
      });
      let vault = await openVault({ stateDir, passphrase: "recovery-pass" });
      vault.add({
        name: "tok",
        type: "bearer",
        domains: [upstream.host.split(":")[0]],
        upstreamScheme: "http",
        value: "SECRET-TOKEN",
      });
      vault.addOwnerApprovalSlot(kek, {
        keyRef,
        ssoBaseUrl,
        providerAddress: PROVIDER,
      });
      await vault.save();
      kek.fill(0);

      // Proxy starts UNLOCKED via the passphrase-opened handle.
      proxy = createProxy({
        vault,
        stateDir,
        logPath: statePaths(stateDir).proxyLog,
        idleTimeoutMs: Infinity,
        control: {
          listen: { port: 0, host: "127.0.0.1" },
          approvalTimeoutMs: 5000,
        },
      });
      const dataPort = (await proxy.listen()).port;
      const controlPort = proxy.controlAddress.port;
      assert.equal(proxy.locked, false);

      approver = startApprover({
        controlPort,
        stateDir,
        ssoBaseUrl,
        accessToken,
        agentPrivateKeyPem: keys.privateKeyPem,
        controlToken: proxy.controlToken,
        controlPublicKey: proxy.controlPublicKey,
      });

      // Simulate an idle auto-lock; the next request must re-unlock.
      proxy.forceLock("idle_timeout");
      assert.equal(proxy.locked, true);

      const r = await rewriteRequest({
        port: dataPort,
        cred: "tok",
        upstream: upstream.host,
      });
      assert.equal(r.status, 200);
      assert.equal(proxy.locked, false);
      assert.equal(record.value.authorization, "Bearer SECRET-TOKEN");
      assert.ok(approver.handled >= 1);
    } finally {
      if (approver) approver.stop = true;
      if (proxy) await proxy.close();
      upstream.server.close();
      await fs.rm(stateDir, { recursive: true, force: true });
    }
  });
});
