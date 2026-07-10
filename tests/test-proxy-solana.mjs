#!/usr/bin/env node

// End-to-end Solana wallet test against a MOCK RPC upstream:
//
//   1. `agent-id-vault generate` (real CLI) creates a keypair inside the vault —
//      stdout carries ONLY the public address, never the seed.
//   2. `show` redacts the sealed seed; `list` exposes the public key.
//   3. The agent fetches a blockhash through the proxy (passthrough), builds an
//      UNSIGNED transfer, POSTs sendTransaction through the proxy — the mock
//      upstream receives a correctly SIGNED transaction (ed25519-verified
//      against the advertised address).
//   4. Negative paths: host not allowlisted, malformed tx, seed never appears
//      in any agent-visible artifact (responses, logs, CLI output).
//
// Run: node --test tests/test-proxy-solana.mjs

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { createProxy } from "../plugins/agent-id-proxy/lib/proxy.mjs";
import {
  base58Decode,
  base58Encode,
  buildSolanaTransferTx,
  decodeCompactU16,
  generateSolanaKeypair,
} from "../plugins/agent-id-core/lib/solana.mjs";

const execFileAsync = promisify(execFile);
const VAULT_CLI = new URL("../plugins/agent-id-vault/bin/cli.mjs", import.meta.url).pathname;
const PASSPHRASE = "test-pass-solana-1234";

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
function verifySignature(messageBytes, signatureBytes, rawPubkey32) {
  const pub = crypto.createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, rawPubkey32]),
    format: "der",
    type: "spki",
  });
  return crypto.verify(null, messageBytes, pub, signatureBytes);
}

// Mock Solana RPC: answers getLatestBlockhash; records + verifies sendTransaction.
const MOCK_BLOCKHASH = base58Encode(crypto.randomBytes(32));
const upstreamSeen = { value: null };

function startMockRpc() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf8");
        upstreamSeen.value = { headers: { ...req.headers }, body };
        let msg = {};
        try {
          msg = JSON.parse(body);
        } catch {
          // fall through
        }
        let result = null;
        if (msg.method === "getLatestBlockhash") {
          result = { context: { slot: 1 }, value: { blockhash: MOCK_BLOCKHASH, lastValidBlockHeight: 1000 } };
        } else if (msg.method === "sendTransaction") {
          const wire = Buffer.from(msg.params[0], "base64");
          const [numSigs, n] = decodeCompactU16(wire, 0);
          result = base58Encode(wire.subarray(n, n + 64)); // tx signature, like real RPC
          upstreamSeen.value.numSigs = numSigs;
          upstreamSeen.value.wire = wire;
        }
        const payload = JSON.stringify({ jsonrpc: "2.0", id: msg.id ?? null, result });
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(payload);
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const a = server.address();
      resolve({ server, host: `${a.address}:${a.port}`, hostname: a.address });
    });
  });
}

function rpcViaProxy({ proxyPort, credname, host, body, method = "POST" }) {
  return new Promise((resolve, reject) => {
    const payload = body == null ? null : Buffer.from(JSON.stringify(body));
    const req = http.request(
      {
        host: "127.0.0.1",
        port: proxyPort,
        method,
        path: `/${credname}/${host}/`,
        headers: {
          "content-type": "application/json",
          ...(payload ? { "content-length": payload.length } : {}),
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString("utf8") }),
        );
      },
    );
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

describe("solana wallet via vault + proxy (mock RPC)", () => {
  let stateDir;
  let passFile;
  let upstream;
  let vault;
  let proxy;
  let proxyPort;
  let walletAddress; // the ONLY thing the agent learns about the key

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "agent-id-solana-test-"));
    passFile = path.join(stateDir, "pass");
    await fs.writeFile(passFile, PASSPHRASE, { mode: 0o600 });
    await initVault({ stateDir, passphrase: PASSPHRASE });
    upstream = await startMockRpc();
  });

  after(async () => {
    await proxy?.close();
    upstream?.server.close();
    vault?.lock();
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("CLI generate: emits the address, never the seed", async () => {
    const { stdout, stderr } = await execFileAsync(process.execPath, [
      VAULT_CLI,
      "generate",
      "--name",
      "sol-hot",
      "--type",
      "solana-keypair",
      "--domains",
      upstream.hostname,
      "--state-dir",
      stateDir,
      "--passphrase-file",
      passFile,
    ]);
    const out = JSON.parse(stdout);
    assert.equal(out.ok, true);
    assert.equal(out.type, "solana-keypair");
    assert.equal(out.exportable, false);
    assert.equal(base58Decode(out.publicKey).length, 32);
    walletAddress = out.publicKey;

    // The seed must not appear in ANY CLI output channel.
    vault = await openVault({ stateDir, passphrase: PASSPHRASE });
    const rec = vault.get("sol-hot");
    assert.match(rec.secretSeed, /^[0-9a-f]{64}$/);
    assert.ok(!stdout.includes(rec.secretSeed), "stdout leaks seed");
    assert.ok(!stderr.includes(rec.secretSeed), "stderr leaks seed");
    assert.equal(rec.publicKey, walletAddress);
  });

  it("CLI add refuses solana-keypair (generate-only type)", async () => {
    await assert.rejects(
      execFileAsync(process.execPath, [
        VAULT_CLI,
        "add",
        "--name",
        "sneaky",
        "--type",
        "solana-keypair",
        "--domains",
        upstream.hostname,
        "--state-dir",
        stateDir,
        "--passphrase-file",
        passFile,
      ]),
      (err) => /generate/.test(err.stdout || ""), // CLI emits {ok:false, error} JSON on stdout
    );
  });

  it("CLI show: sealed seed is redacted", async () => {
    const { stdout } = await execFileAsync(process.execPath, [
      VAULT_CLI,
      "show",
      "--name",
      "sol-hot",
      "--state-dir",
      stateDir,
      "--passphrase-file",
      passFile,
    ]);
    const out = JSON.parse(stdout);
    assert.equal(out.sealed, true);
    assert.match(out.credential.secretSeed, /sealed/);
    assert.equal(out.credential.publicKey, walletAddress);
    const rec = vault.get("sol-hot");
    assert.ok(!stdout.includes(rec.secretSeed), "show leaked the seed");
  });

  it("CLI list: exposes the public address in metadata", async () => {
    const { stdout } = await execFileAsync(process.execPath, [
      VAULT_CLI,
      "list",
      "--state-dir",
      stateDir,
      "--passphrase-file",
      passFile,
    ]);
    const out = JSON.parse(stdout);
    const meta = out.credentials.find((c) => c.name === "sol-hot");
    assert.equal(meta.publicKey, walletAddress);
    assert.equal(meta.type, "solana-keypair");
  });

  it("proxy: blockhash passthrough, unsigned sendTransaction arrives SIGNED upstream", async () => {
    // The mock upstream speaks plain http on loopback.
    const rec = vault.get("sol-hot");
    rec.upstreamScheme = "http";
    rec.domains = [upstream.hostname];
    vault.add(rec);
    await vault.save();

    proxy = createProxy({ vault, logPath: path.join(stateDir, "proxy.log") });
    const addr = await proxy.listen();
    proxyPort = addr.port;

    // 1. Agent fetches a blockhash through the proxy (no signing involved).
    const bh = await rpcViaProxy({
      proxyPort,
      credname: "sol-hot",
      host: upstream.host,
      body: { jsonrpc: "2.0", id: 1, method: "getLatestBlockhash", params: [] },
    });
    assert.equal(bh.status, 200);
    const blockhash = JSON.parse(bh.body).result.value.blockhash;
    assert.equal(blockhash, MOCK_BLOCKHASH);
    assert.equal(
      JSON.parse(upstreamSeen.value.body).method,
      "getLatestBlockhash",
      "passthrough body intact",
    );

    // 2. Agent builds an UNSIGNED transfer from only public material.
    const dest = generateSolanaKeypair().publicKey;
    const unsigned = buildSolanaTransferTx({
      from: walletAddress,
      to: dest,
      lamports: 2_000_000,
      recentBlockhash: blockhash,
    });

    // 3. sendTransaction through the proxy.
    const sendRes = await rpcViaProxy({
      proxyPort,
      credname: "sol-hot",
      host: upstream.host,
      body: {
        jsonrpc: "2.0",
        id: 2,
        method: "sendTransaction",
        params: [unsigned.toString("base64"), { encoding: "base64" }],
      },
    });
    assert.equal(sendRes.status, 200);

    // 4. Upstream received a SIGNED transaction; signature verifies against
    //    the address the vault advertised.
    const wire = upstreamSeen.value.wire;
    const [numSigs, n] = decodeCompactU16(wire, 0);
    assert.equal(numSigs, 1);
    const sig = wire.subarray(n, n + 64);
    const message = wire.subarray(n + 64);
    assert.notDeepEqual(sig, Buffer.alloc(64), "signature filled in");
    assert.ok(
      verifySignature(message, sig, base58Decode(walletAddress)),
      "proxy signature verifies against the wallet address",
    );

    // 5. The RPC's result (tx signature) matches what the proxy injected.
    assert.equal(JSON.parse(sendRes.body).result, base58Encode(sig));
  });

  it("proxy: refuses to sign for a host not on the allowlist", async () => {
    const r = await rpcViaProxy({
      proxyPort,
      credname: "sol-hot",
      host: "evil.example.com",
      body: { jsonrpc: "2.0", id: 3, method: "sendTransaction", params: ["AAAA", { encoding: "base64" }] },
    });
    assert.equal(r.status, 403);
    assert.equal(JSON.parse(r.body).error, "host_not_allowed");
  });

  it("proxy: malformed transaction → 400 solana_sign_failed", async () => {
    const r = await rpcViaProxy({
      proxyPort,
      credname: "sol-hot",
      host: upstream.host,
      body: {
        jsonrpc: "2.0",
        id: 4,
        method: "sendTransaction",
        params: [Buffer.from("garbage").toString("base64"), { encoding: "base64" }],
      },
    });
    assert.equal(r.status, 400);
    const body = JSON.parse(r.body);
    assert.equal(body.error, "solana_sign_failed");
    assert.equal(body.credential, "sol-hot");
  });

  it("proxy: refuses a transaction whose signer is a different key", async () => {
    const stranger = generateSolanaKeypair();
    const unsigned = buildSolanaTransferTx({
      from: stranger.publicKey,
      to: walletAddress,
      lamports: 1,
      recentBlockhash: MOCK_BLOCKHASH,
    });
    const r = await rpcViaProxy({
      proxyPort,
      credname: "sol-hot",
      host: upstream.host,
      body: {
        jsonrpc: "2.0",
        id: 5,
        method: "sendTransaction",
        params: [unsigned.toString("base64"), { encoding: "base64" }],
      },
    });
    assert.equal(r.status, 400);
    assert.match(JSON.parse(r.body).message, /not among the required signers/);
  });

  it("log mentions the signing event + credential name but never the seed", async () => {
    // The access-log append is async; poll briefly so the read doesn't race the write.
    const logPath = path.join(stateDir, "proxy.log");
    let raw = "";
    for (let i = 0; i < 50; i++) {
      raw = await fs.readFile(logPath, "utf8").catch(() => "");
      if (raw.includes("solana_signed")) break;
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.ok(raw.includes("solana_signed"), "log records the signing event");
    assert.ok(raw.includes("sol-hot"), "log mentions credential name");
    const rec = vault.get("sol-hot");
    assert.ok(!raw.includes(rec.secretSeed), "log must NOT contain the seed");
  });
});
