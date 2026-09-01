#!/usr/bin/env node

// Control-plane TLS: when exposed beyond loopback the control plane runs over
// HTTPS with a self-signed cert, and the approver pins the cert's SHA-256
// fingerprint (learned out-of-band from the pairing QR) instead of trusting a
// CA. This closes the bearer-token-over-cleartext residual.
//
// Run: node --test tests/test-control-tls.mjs

import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import https from "node:https";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createECDH, X509Certificate } from "node:crypto";

import {
  generateControlCert,
  fingerprintOfCertPem,
  normalizeFingerprint,
} from "../plugins/agent-id-proxy/lib/control-tls.mjs";
import { deviceUnsealMasterKey, sealToPublicKey } from "../plugins/agent-id-vault/lib/format.mjs";
import { createProxy } from "../plugins/agent-id-proxy/lib/proxy.mjs";
import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Pinning needs the cert on every connection, so disable TLS session resumption
// (a resumed session doesn't re-send the cert → getPeerCertificate() is empty).
const pinAgent = new https.Agent({ maxCachedSessions: 0 });

describe("self-signed cert generation", () => {
  it("produces a cert whose fingerprint is stable across reads", () => {
    const { certPem, fingerprint } = generateControlCert();
    assert.match(fingerprint, /^[0-9a-f]{64}$/);
    assert.equal(fingerprintOfCertPem(certPem), fingerprint);
  });

  it("two certs have different fingerprints", () => {
    assert.notEqual(generateControlCert().fingerprint, generateControlCert().fingerprint);
  });

  // Regression: a serial that DER-encodes with a redundant leading zero byte
  // (leading 0x00 followed by a high-bit-clear byte) is illegal padding and made
  // strict parsers throw "asn1 …::illegal padding" — the ~1/512 flake in the TLS
  // tests below. The INTEGER encoder now emits minimal DER, so every serial edge
  // case must parse via the strict X509Certificate constructor.
  it("encodes every serial edge case as valid DER (no illegal padding)", () => {
    const serials = {
      "leading zero + high-bit-clear (the flake)": Buffer.from([0x00, 0x45, 0x9a, 0xbc]),
      "leading zero + high-bit-set (0x00 required)": Buffer.from([0x00, 0x80, 0x11, 0x22]),
      "two leading zeros": Buffer.from([0x00, 0x00, 0x33, 0x44]),
      "top bit set, no leading zero": Buffer.from([0xff, 0x11, 0x22]),
      "ordinary": Buffer.from([0x45, 0x11, 0x22]),
      "all zero": Buffer.from([0x00, 0x00]),
    };
    for (const [label, serial] of Object.entries(serials)) {
      const { certPem, fingerprint } = generateControlCert({ serial });
      // Throws on illegal padding — the exact failure we're regressing against.
      assert.doesNotThrow(() => new X509Certificate(certPem), `strict parse: ${label}`);
      assert.equal(fingerprintOfCertPem(certPem), fingerprint, `fingerprint stable: ${label}`);
    }
  });
});

// HTTPS request that pins `expectedFp` (no CA trust). Rejects on mismatch.
function pinnedRequest({ port, method = "GET", p, body = null, token, expectedFp }) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const headers = {};
    if (payload) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = Buffer.byteLength(payload);
    }
    if (token) headers.Authorization = `Bearer ${token}`;
    const req = https.request(
      {
        host: "127.0.0.1",
        port,
        path: p,
        method,
        headers,
        rejectUnauthorized: false, // self-signed; we pin the fingerprint instead
        agent: pinAgent,
      },
      (res) => {
        const peerFp = normalizeFingerprint(res.socket.getPeerCertificate().fingerprint256);
        if (expectedFp && peerFp !== normalizeFingerprint(expectedFp)) {
          res.destroy();
          return reject(new Error("fingerprint pin mismatch"));
        }
        const c = [];
        res.on("data", (x) => c.push(x));
        res.on("end", () =>
          resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(c).toString("utf8") || "{}") }),
        );
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}

function dataRequest(port, cred, upstream) {
  return new Promise((resolve, reject) => {
    import("node:http").then(({ default: http }) => {
      const req = http.request(
        { host: "127.0.0.1", port, method: "GET", path: `/${cred}/${upstream}/x` },
        (res) => {
          res.resume();
          res.on("end", () => resolve({ status: res.statusCode }));
        },
      );
      req.on("error", reject);
      req.end();
    });
  });
}

describe("control plane over TLS with fingerprint pinning", () => {
  let proxy;
  let stateDir;
  let upstreamServer;

  after(async () => {
    if (proxy) await proxy.close();
    if (upstreamServer) upstreamServer.close();
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("serves HTTPS, pins the fingerprint, and unlocks via a sealed approve", async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "ctl-tls-"));
    await initVault({ stateDir, passphrase: "p" });

    const record = { value: null };
    const http = (await import("node:http")).default;
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
      // Force TLS even on a loopback bind so the test exercises the HTTPS path.
      control: { listen: { port: 0, host: "127.0.0.1" }, approvalTimeoutMs: 5000, tls: true },
    });
    const dataPort = (await proxy.listen()).port;
    const controlPort = proxy.controlAddress.port;
    const token = proxy.controlToken;
    const fp = proxy.controlCertFingerprint;

    assert.equal(proxy.controlScheme, "https");
    assert.match(fp, /^[0-9a-f]{64}$/);

    // /status reachable over HTTPS with the pinned fingerprint.
    const status = await pinnedRequest({ port: controlPort, p: "/status", expectedFp: fp });
    assert.equal(status.status, 200);

    // A wrong pin is rejected by the client before trusting the connection.
    await assert.rejects(
      pinnedRequest({ port: controlPort, p: "/status", expectedFp: "00".repeat(32) }),
      /pin mismatch/,
    );

    // Park a data request; it awaits unlock.
    const pending = dataRequest(dataPort, "tok", upstreamHost);

    // Poll /pending over HTTPS (token-gated) until the unlock entry shows.
    let entry = null;
    for (let i = 0; i < 100 && !entry; i++) {
      const r = await pinnedRequest({ port: controlPort, p: "/pending", token, expectedFp: fp });
      entry = (r.body.pending || []).find((e) => e.action === "unlock");
      if (!entry) await sleep(10);
    }
    assert.ok(entry, "unlock should park");

    // Unseal (as the phone), re-seal to the proxy key, approve over HTTPS.
    const mk = deviceUnsealMasterKey({ ...entry.challenges[0], type: "mobile" }, device.getPrivateKey());
    const sealedMasterKey = sealToPublicKey(mk, proxy.controlPublicKey);
    const ok = await pinnedRequest({
      port: controlPort,
      method: "POST",
      p: "/approve",
      body: { id: entry.id, sealedMasterKey },
      token,
      expectedFp: fp,
    });
    assert.equal(ok.status, 200);

    const res = await pending;
    assert.equal(res.status, 200);
    assert.equal(proxy.locked, false);
  });
});
