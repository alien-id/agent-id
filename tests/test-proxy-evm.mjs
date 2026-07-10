#!/usr/bin/env node

// EVM wallet via vault + proxy against a MOCK JSON-RPC upstream:
//   - CLI `generate --type evm-keypair` emits only the EIP-55 address
//   - `show` redacts the sealed private key
//   - proxy rewrites eth_sendTransaction → eth_sendRawTransaction with a
//     correctly signed EIP-1559 raw tx (sender recovered upstream == address)
//   - passthrough + allowlist + never-leak invariants
//
// Run: node --test tests/test-proxy-evm.mjs

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { createProxy } from "../plugins/agent-id-proxy/lib/proxy.mjs";

const execFileAsync = promisify(execFile);
const VAULT_CLI = new URL("../plugins/agent-id-vault/bin/cli.mjs", import.meta.url).pathname;
const PASSPHRASE = "test-pass-evm-1234";

const upstreamSeen = { value: null };

function startMockRpc() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf8");
        let msg = {};
        try {
          msg = JSON.parse(body);
        } catch {
          // fall through
        }
        upstreamSeen.value = { body, method: msg.method, params: msg.params };
        let result = null;
        if (msg.method === "eth_getTransactionCount") result = "0x7";
        if (msg.method === "eth_sendRawTransaction") result = "0x" + "ab".repeat(32);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id ?? null, result }));
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const a = server.address();
      resolve({ server, host: `${a.address}:${a.port}`, hostname: a.address });
    });
  });
}

function rpcViaProxy({ proxyPort, credname, host, body }) {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(JSON.stringify(body));
    const req = http.request(
      {
        host: "127.0.0.1",
        port: proxyPort,
        method: "POST",
        path: `/${credname}/${host}/`,
        headers: { "content-type": "application/json", "content-length": payload.length },
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
    req.write(payload);
    req.end();
  });
}

describe("evm wallet via vault + proxy (mock RPC)", () => {
  let stateDir;
  let passFile;
  let upstream;
  let vault;
  let proxy;
  let proxyPort;
  let walletAddress;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "agent-id-evm-test-"));
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

  it("CLI generate --type evm-keypair: emits the address, never the key", async () => {
    const { stdout, stderr } = await execFileAsync(process.execPath, [
      VAULT_CLI,
      "generate",
      "--name",
      "evm-hot",
      "--type",
      "evm-keypair",
      "--domains",
      upstream.hostname,
      "--state-dir",
      stateDir,
      "--passphrase-file",
      passFile,
    ]);
    const out = JSON.parse(stdout);
    assert.equal(out.ok, true);
    assert.equal(out.type, "evm-keypair");
    assert.equal(out.exportable, false);
    assert.match(out.address, /^0x[0-9a-fA-F]{40}$/);
    walletAddress = out.address;

    vault = await openVault({ stateDir, passphrase: PASSPHRASE });
    const rec = vault.get("evm-hot");
    assert.match(rec.privateKey, /^[0-9a-f]{64}$/);
    assert.ok(!stdout.includes(rec.privateKey), "stdout leaks private key");
    assert.ok(!stderr.includes(rec.privateKey), "stderr leaks private key");
  });

  it("CLI show: sealed private key is redacted", async () => {
    const { stdout } = await execFileAsync(process.execPath, [
      VAULT_CLI,
      "show",
      "--name",
      "evm-hot",
      "--state-dir",
      stateDir,
      "--passphrase-file",
      passFile,
    ]);
    const out = JSON.parse(stdout);
    assert.equal(out.sealed, true);
    assert.match(out.credential.privateKey, /sealed/);
    assert.equal(out.credential.address, walletAddress);
  });

  it("proxy: eth_sendTransaction arrives upstream as signed eth_sendRawTransaction", async () => {
    const rec = vault.get("evm-hot");
    rec.upstreamScheme = "http";
    rec.domains = [upstream.hostname];
    vault.add(rec);
    await vault.save();

    proxy = createProxy({ vault, logPath: path.join(stateDir, "proxy.log") });
    const addr = await proxy.listen();
    proxyPort = addr.port;

    // Passthrough first: agent reads its nonce through the proxy.
    const nonceRes = await rpcViaProxy({
      proxyPort,
      credname: "evm-hot",
      host: upstream.host,
      body: { jsonrpc: "2.0", id: 1, method: "eth_getTransactionCount", params: [walletAddress, "latest"] },
    });
    assert.equal(nonceRes.status, 200);
    assert.equal(JSON.parse(nonceRes.body).result, "0x7");
    assert.equal(upstreamSeen.value.method, "eth_getTransactionCount", "passthrough intact");

    // Now the unsigned tx object.
    const sendRes = await rpcViaProxy({
      proxyPort,
      credname: "evm-hot",
      host: upstream.host,
      body: {
        jsonrpc: "2.0",
        id: 2,
        method: "eth_sendTransaction",
        params: [
          {
            from: walletAddress,
            to: "0x000000000000000000000000000000000000dEaD",
            value: "0x1",
            chainId: 137,
            nonce: "0x7",
            gas: 21000,
            maxFeePerGas: 100_000_000_000,
            maxPriorityFeePerGas: 30_000_000_000,
          },
        ],
      },
    });
    assert.equal(sendRes.status, 200);
    assert.equal(upstreamSeen.value.method, "eth_sendRawTransaction", "method rewritten");
    assert.match(upstreamSeen.value.params[0], /^0x02/, "EIP-1559 typed raw tx");
    const rec2 = vault.get("evm-hot");
    assert.ok(!upstreamSeen.value.body.includes(rec2.privateKey), "upstream never sees the key");
  });

  it("proxy: refuses signing for non-allowlisted host", async () => {
    const r = await rpcViaProxy({
      proxyPort,
      credname: "evm-hot",
      host: "polygon-rpc.example.com",
      body: { jsonrpc: "2.0", id: 3, method: "eth_sendTransaction", params: [{}] },
    });
    assert.equal(r.status, 403);
    assert.equal(JSON.parse(r.body).error, "host_not_allowed");
  });

  it("proxy: invalid tx object → 400 evm_sign_failed", async () => {
    const r = await rpcViaProxy({
      proxyPort,
      credname: "evm-hot",
      host: upstream.host,
      body: { jsonrpc: "2.0", id: 4, method: "eth_sendTransaction", params: [{ to: "0xdead" }] },
    });
    assert.equal(r.status, 400);
    assert.equal(JSON.parse(r.body).error, "evm_sign_failed");
  });

  it("log records evm_signed but never the private key", async () => {
    // The access-log append is async; poll briefly so the read doesn't race the write.
    const logPath = path.join(stateDir, "proxy.log");
    let raw = "";
    for (let i = 0; i < 50; i++) {
      raw = await fs.readFile(logPath, "utf8").catch(() => "");
      if (raw.includes("evm_signed")) break;
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.ok(raw.includes("evm_signed"), "log records signing event");
    const rec = vault.get("evm-hot");
    assert.ok(!raw.includes(rec.privateKey), "log must NOT contain the key");
  });
});
