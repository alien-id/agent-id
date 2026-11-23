#!/usr/bin/env node

// CLI-level tests for an EVM wallet's typed-data rules:
//   - a wallet is born signing no typed data
//   - `set-typed-data` ADDING a rule requires the OWNER to confirm via the
//     secure prompt; a wrong confirmation leaves the rules unchanged
//   - removing a rule, or all of them, needs no ceremony
//   - the rules apply to an evm-keypair only, and a malformed rule is refused
//     before the owner is asked anything
//
// Run: node --test tests/test-vault-set-typed-data.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";

import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { writeJsonFile, statePaths } from "../plugins/agent-id-core/lib/state.mjs";
import { fingerprintPublicKeyPem } from "../plugins/agent-id-core/lib/crypto.mjs";

const CLI = new URL("../plugins/agent-id-vault/bin/cli.mjs", import.meta.url).pathname;

const ORDER = {
  primaryType: "Order",
  domain: {
    name: "Test Exchange",
    version: "1",
    chainId: 137,
    verifyingContract: "0x1111111111111111111111111111111111111111",
  },
};
const AUTH = { primaryType: "Auth", domain: { name: "Test Exchange Auth", version: "1", chainId: 137 } };

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

function run(args, env = {}) {
  return new Promise((resolve) => {
    const child = spawn("node", [CLI, ...args], { env: { ...process.env, ...env } });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("exit", (code) => resolve({ code, stdout, stderr }));
  });
}

// Spawn the CLI and, when it prints the secure-form URL, submit `confirm` as
// the human would.
function runWithFormConfirm(args, confirm) {
  return new Promise((resolve, reject) => {
    const child = spawn("node", [CLI, ...args], {
      env: { ...process.env, AGENT_ID_NO_BROWSER: "1", AGENT_ID_SECURE_PROMPT: "browser" },
    });
    let stdout = "";
    let stderr = "";
    let submitted = false;
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", async (d) => {
      stderr += d;
      const m = stderr.match(/http:\/\/127\.0\.0\.1:\d+\/\?t=[a-f0-9]+/);
      if (m && !submitted) {
        submitted = true;
        try {
          const u = new URL(m[0]);
          await fetch(`http://127.0.0.1:${u.port}/submit`, {
            method: "POST",
            body: new URLSearchParams({ _token: u.searchParams.get("t"), confirm }),
          });
        } catch (err) {
          reject(err);
        }
      }
    });
    child.on("exit", (code) => resolve({ code, stdout, stderr }));
  });
}

async function rulesOf(dir, name) {
  const { privateKeyPem } = JSON.parse(await readFile(statePaths(dir).mainKey, "utf8"));
  const vault = await openVault({ stateDir: dir, privateKeyPem });
  const rec = vault.get(name);
  const rules = rec ? (rec.typedDataAllowlist ?? null) : undefined;
  const address = rec ? rec.address : null;
  vault.lock();
  return { rules, address };
}

test("an EVM wallet's typed-data rules via the CLI", async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "settyped-"));
  try {
    await makeVault(dir);
    const born = await run([
      "generate", "--name", "wallet", "--type", "evm-keypair",
      "--domains", "rpc.example.com", "--state-dir", dir,
    ]);
    assert.equal(born.code, 0, born.stderr);
    const { address } = await rulesOf(dir, "wallet");

    await t.test("a wallet is born signing no typed data", async () => {
      assert.equal((await rulesOf(dir, "wallet")).rules, null);
    });

    await t.test("a malformed rule is refused before the owner is asked", async () => {
      const r = await run([
        "set-typed-data", "--name", "wallet",
        "--rules", '[{"primaryType":"Order","domain":{"chainId":"137"}}]',
        "--state-dir", dir,
      ]);
      assert.notEqual(r.code, 0);
      assert.match(r.stderr + r.stdout, /chainId must be a positive integer/);
      assert.equal((await rulesOf(dir, "wallet")).rules, null);
    });

    await t.test("adding a rule with a WRONG confirmation is refused", async () => {
      const r = await runWithFormConfirm(
        ["set-typed-data", "--name", "wallet", "--rules", JSON.stringify([ORDER]), "--state-dir", dir],
        "not-the-name",
      );
      assert.notEqual(r.code, 0);
      assert.match(r.stderr + r.stdout, /did not match/);
      assert.equal((await rulesOf(dir, "wallet")).rules, null);
    });

    await t.test("adding rules with the owner's confirmation applies", async () => {
      const r = await runWithFormConfirm(
        ["set-typed-data", "--name", "wallet", "--rules", JSON.stringify([ORDER, AUTH]), "--state-dir", dir],
        "wallet",
      );
      assert.equal(r.code, 0, r.stderr);
      assert.deepEqual(JSON.parse(r.stdout).typedDataAllowlist, [ORDER, AUTH]);
      const after = await rulesOf(dir, "wallet");
      assert.deepEqual(after.rules, [ORDER, AUTH]);
      assert.equal(after.address, address, "changing the rules must not change the key");
    });

    await t.test("removing a rule needs no ceremony", async () => {
      const r = await run([
        "set-typed-data", "--name", "wallet", "--rules", JSON.stringify([ORDER]), "--state-dir", dir,
      ]);
      assert.equal(r.code, 0, r.stderr);
      assert.deepEqual((await rulesOf(dir, "wallet")).rules, [ORDER]);
    });

    await t.test("--clear needs no ceremony", async () => {
      const r = await run(["set-typed-data", "--name", "wallet", "--clear", "--state-dir", dir]);
      assert.equal(r.code, 0, r.stderr);
      assert.equal((await rulesOf(dir, "wallet")).rules, null);
    });

    await t.test("the rules apply to an evm-keypair only", async () => {
      const sol = await run([
        "generate", "--name", "sol", "--type", "solana-keypair",
        "--domains", "rpc.example.com", "--state-dir", dir,
      ]);
      assert.equal(sol.code, 0, sol.stderr);
      const r = await run([
        "set-typed-data", "--name", "sol", "--rules", JSON.stringify([ORDER]), "--state-dir", dir,
      ]);
      assert.notEqual(r.code, 0);
      assert.match(r.stderr + r.stdout, /apply to evm-keypair only/);
    });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
