#!/usr/bin/env node

// `agent-id-vault wallet-sign`: one signature from an in-vault EVM key, for the
// process that holds the vault and broadcasts on its own.
//   - a transaction answers the raw EIP-1559 transaction, byte-equal to the
//     eth-account vector test-evm-lib.mjs pins for the same key
//   - typed data answers the EIP-712 specification's own example signature
//   - the record's chain, recipient and typed-data rules refuse before signing
//   - a read-only wallet signs nothing, and the key is never printed
//
// Run: node --test tests/test-vault-wallet-sign.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm, readFile, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";

import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { writeJsonFile, statePaths } from "../plugins/agent-id-core/lib/state.mjs";
import { fingerprintPublicKeyPem } from "../plugins/agent-id-core/lib/crypto.mjs";
import { keccak256 } from "../plugins/agent-id-core/lib/evm.mjs";

const CLI = new URL("../plugins/agent-id-vault/bin/cli.mjs", import.meta.url).pathname;

// Throwaway keys — NOT real wallets. The EIP-155 example key, and the EIP-712
// specification's keccak256("cow").
const TX_KEY = "46".repeat(32);
const TX_ADDRESS = "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F";
const COW_KEY = keccak256(Buffer.from("cow")).toString("hex");
const COW = "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826";

const MAIL_DOMAIN = {
  name: "Ether Mail",
  version: "1",
  chainId: 1,
  verifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
};
const MAIL = {
  types: {
    Person: [
      { name: "name", type: "string" },
      { name: "wallet", type: "address" },
    ],
    Mail: [
      { name: "from", type: "Person" },
      { name: "to", type: "Person" },
      { name: "contents", type: "string" },
    ],
  },
  primaryType: "Mail",
  domain: MAIL_DOMAIN,
  message: {
    from: { name: "Cow", wallet: COW },
    to: { name: "Bob", wallet: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB" },
    contents: "Hello, Bob!",
  },
};
const MAIL_SIGNATURE =
  "0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d" +
  "07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b91562" +
  "1c";

const TRANSFER = {
  chainId: 137,
  nonce: 7,
  maxPriorityFeePerGas: 30_000_000_000,
  maxFeePerGas: 100_000_000_000,
  gas: 21000,
  to: "0x000000000000000000000000000000000000dEaD",
  value: "12345678901234567",
  data: "0x",
};
const TRANSFER_RAW =
  "0x02f8748189078506fc23ac0085174876e80082520894000000000000000000000000000000000000dead872bdc545d6b4b8780c001a08a237992595e001e45d6dd3d4e86e02ead894b0b377b74a4ff4da9bd7116ee17a07cda7d3fe4dea2b3d8d8f2749bfe34a65914168ead1f82207ca06b3ddf3472ce";
const TRANSFER_HASH = "0x0ee145f3ce3051c0e14fddb1b157c0f6955cba05a348c730c98bee4a4e24c23d";

async function makeVault(dir) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
  const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  await writeJsonFile(statePaths(dir).mainKey, {
    version: 1,
    agentId: "main",
    keyNonce: 0,
    createdAt: 1,
    publicKeyPem,
    privateKeyPem,
    fingerprint: fingerprintPublicKeyPem(publicKeyPem),
  });
  await initVault({ stateDir: dir, privateKeyPem, agentId: "main" });
}

// A wallet with a KNOWN key, written through the library the way `generate`
// writes one, so a signature can be compared with a reference value.
async function putWallet(dir, record) {
  const { privateKeyPem } = JSON.parse(await readFile(statePaths(dir).mainKey, "utf8"));
  const vault = await openVault({ stateDir: dir, privateKeyPem });
  vault.add({ type: "evm-keypair", domains: ["rpc.example.com"], exportable: false, ...record });
  await vault.save();
  vault.lock();
}

function sign(dir, name, kind, payload, extra = []) {
  return new Promise((resolve) => {
    const what = kind ? [kind] : [];
    const child = spawn("node", [CLI, "wallet-sign", "--name", name, ...what, ...extra, "--state-dir", dir]);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("exit", (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(payload === undefined ? "" : JSON.stringify(payload));
  });
}

test("wallet-sign", async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "walletsign-"));
  try {
    await makeVault(dir);
    await putWallet(dir, { name: "open", privateKey: TX_KEY, address: TX_ADDRESS });
    await putWallet(dir, {
      name: "bounded",
      privateKey: COW_KEY,
      address: COW,
      chainIdAllowlist: [1],
      toAllowlist: ["0x1111111111111111111111111111111111111111"],
      typedDataAllowlist: [{ primaryType: "Mail", domain: MAIL_DOMAIN }],
    });
    await putWallet(dir, { name: "frozen", privateKey: TX_KEY, address: TX_ADDRESS, access: "ro" });

    await t.test("a transaction answers the raw transaction eth-account produces", async () => {
      const r = await sign(dir, "open", "--transaction", TRANSFER);
      assert.equal(r.code, 0, r.stderr);
      const out = JSON.parse(r.stdout);
      assert.equal(out.raw, TRANSFER_RAW);
      assert.equal(out.hash, TRANSFER_HASH);
      assert.equal(out.from, TX_ADDRESS);
      assert.ok(!(r.stdout + r.stderr).includes(TX_KEY), "the key is never printed");
    });

    await t.test("the payload may come from a file", async () => {
      const file = path.join(dir, "tx.json");
      await writeFile(file, JSON.stringify(TRANSFER));
      const r = await sign(dir, "open", "--transaction", undefined, ["--payload-file", file]);
      assert.equal(r.code, 0, r.stderr);
      assert.equal(JSON.parse(r.stdout).raw, TRANSFER_RAW);
    });

    await t.test("typed data answers the specification's signature", async () => {
      const r = await sign(dir, "bounded", "--typed-data", MAIL);
      assert.equal(r.code, 0, r.stderr);
      const out = JSON.parse(r.stdout);
      assert.equal(out.signature, MAIL_SIGNATURE);
      assert.equal(out.digest, "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2");
      assert.equal(out.address, COW);
      assert.ok(!(r.stdout + r.stderr).includes(COW_KEY), "the key is never printed");
    });

    await t.test("a wallet without typed-data rules signs no typed data", async () => {
      const r = await sign(dir, "open", "--typed-data", MAIL);
      assert.notEqual(r.code, 0);
      assert.match(r.stderr + r.stdout, /not in this credential's typedDataAllowlist/);
    });

    await t.test("the record's chain and recipient rules refuse a transaction", async () => {
      const chain = await sign(dir, "bounded", "--transaction", TRANSFER);
      assert.notEqual(chain.code, 0);
      assert.match(chain.stderr + chain.stdout, /chainId 137 not in this credential's chainIdAllowlist/);

      const recipient = await sign(dir, "bounded", "--transaction", { ...TRANSFER, chainId: 1 });
      assert.notEqual(recipient.code, 0);
      assert.match(recipient.stderr + recipient.stdout, /not in this credential's toAllowlist/);
    });

    await t.test("a transaction that names another sender is refused", async () => {
      const r = await sign(dir, "open", "--transaction", { ...TRANSFER, from: COW });
      assert.notEqual(r.code, 0);
      assert.match(r.stderr + r.stdout, /does not match the credential address/);
    });

    await t.test("a read-only wallet signs nothing", async () => {
      const r = await sign(dir, "frozen", "--transaction", TRANSFER);
      assert.notEqual(r.code, 0);
      assert.match(r.stderr + r.stdout, /access level 'ro'/);
    });

    await t.test("it says what it needs when the request is incomplete", async () => {
      const neither = await sign(dir, "open", null, TRANSFER);
      assert.notEqual(neither.code, 0);
      assert.match(neither.stderr + neither.stdout, /exactly one of --transaction and --typed-data/);
      const noPayload = await sign(dir, "open", "--transaction", undefined);
      assert.notEqual(noPayload.code, 0);
      assert.match(noPayload.stderr + noPayload.stdout, /must be JSON/);
    });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
