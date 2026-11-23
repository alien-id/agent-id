#!/usr/bin/env node

// CLI-level tests for the settings an owner gives an EVM wallet:
//   - the accounts its funds may leave to (`set-withdrawal`)
//   - the most it may trade in a day (`set-daily-limit`)
//   - where funds sent in from another chain go back to (`set-refund`)
// All are typed by the OWNER on the secure prompt. No flag carries an address
// or a figure in, so an agent can raise the card and can take an entry away,
// and cannot put one there. The vault keeps the settings and lists them.
//
// Run: node --test tests/test-vault-wallet-settings.mjs

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

// Throwaway addresses in their EIP-55 form — nobody's accounts.
const LEDGER = "0x52908400098527886E0F7030069857D2E4169EE7";
const EXCHANGE = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359";
// EXCHANGE with one letter's case flipped: an address that fails its checksum.
const SLIPPED = "0xfb6916095ca1df60bB79Ce92cE3Ea74c37c5d359";

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
    const child = spawn("node", [CLI, ...args], {
      // A secure prompt that cannot open: a command that reaches for the owner
      // when it should have refused on its own would hang, not pass.
      env: { ...process.env, AGENT_ID_NO_BROWSER: "1", AGENT_ID_SECURE_PROMPT: "browser", ...env },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    const timer = setTimeout(() => child.kill(), 15_000);
    child.on("exit", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

// Spawn the CLI and, when it prints the secure-form URL, type `fields` into
// the form as the owner would.
function runAsOwnerTypes(args, fields) {
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
            body: new URLSearchParams({ _token: u.searchParams.get("t"), ...fields }),
          });
        } catch (err) {
          reject(err);
        }
      }
    });
    child.on("exit", (code) => resolve({ code, stdout, stderr, asked: submitted }));
  });
}

async function recordOf(dir, name) {
  const { privateKeyPem } = JSON.parse(await readFile(statePaths(dir).mainKey, "utf8"));
  const vault = await openVault({ stateDir: dir, privateKeyPem });
  const rec = vault.get(name);
  const copy = rec
    ? {
        address: rec.address,
        privateKey: rec.privateKey,
        withdrawalAllowlist: rec.withdrawalAllowlist ?? null,
        dailySpendLimitUsd: rec.dailySpendLimitUsd ?? null,
        refundAddresses: rec.refundAddresses ?? null,
      }
    : null;
  vault.lock();
  return copy;
}

async function listed(dir, name) {
  const r = await run(["list", "--state-dir", dir]);
  assert.equal(r.code, 0, r.stderr);
  return JSON.parse(r.stdout).credentials.find((c) => c.name === name);
}

test("the settings an owner gives an EVM wallet", async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "walletset-"));
  try {
    await makeVault(dir);
    const born = await run([
      "generate", "--name", "wallet", "--type", "evm-keypair",
      "--domains", "rpc.example.com", "--state-dir", dir,
    ]);
    assert.equal(born.code, 0, born.stderr);
    const atBirth = await recordOf(dir, "wallet");
    const withdrawal = (...more) => ["set-withdrawal", "--name", "wallet", "--state-dir", dir, ...more];
    const limit = (...more) => ["set-daily-limit", "--name", "wallet", "--state-dir", dir, ...more];

    await t.test("a wallet is born with no withdrawal account and no limit", async () => {
      assert.equal(atBirth.withdrawalAllowlist, null);
      assert.equal(atBirth.dailySpendLimitUsd, null);
      const meta = await listed(dir, "wallet");
      assert.equal(meta.withdrawalAllowlist, undefined);
      assert.equal(meta.dailySpendLimitUsd, undefined);
    });

    await t.test("no flag carries an address in: the owner is not even asked", async () => {
      for (const flag of ["--address", "--add", "--accounts"]) {
        const r = await run(withdrawal(flag, LEDGER));
        assert.notEqual(r.code, 0, flag);
        assert.match(r.stderr + r.stdout, /typed by the owner on the secure prompt/, flag);
        assert.doesNotMatch(r.stderr, /127\.0\.0\.1/, `${flag} raised the prompt`);
      }
      assert.equal((await recordOf(dir, "wallet")).withdrawalAllowlist, null);
    });

    await t.test("the owner types an address and a name, and it is listed", async () => {
      const r = await runAsOwnerTypes(withdrawal(), { address: LEDGER, label: "Ledger" });
      assert.equal(r.code, 0, r.stderr);
      const account = { address: LEDGER, label: "Ledger" };
      assert.deepEqual(JSON.parse(r.stdout).withdrawalAllowlist, [account]);
      assert.deepEqual((await recordOf(dir, "wallet")).withdrawalAllowlist, [account]);
      assert.deepEqual((await listed(dir, "wallet")).withdrawalAllowlist, [account]);
    });

    await t.test("an address typed in one case is kept in its checksum form, named by its ends", async () => {
      const r = await runAsOwnerTypes(withdrawal(), { address: ` ${EXCHANGE.toLowerCase()} ` });
      assert.equal(r.code, 0, r.stderr);
      assert.deepEqual((await recordOf(dir, "wallet")).withdrawalAllowlist[1], {
        address: EXCHANGE,
        label: "0xfB69…d359",
      });
    });

    await t.test("what is not a usable account is refused and nothing is added", async () => {
      const before = (await recordOf(dir, "wallet")).withdrawalAllowlist;
      const cases = [
        ["a slip of the hand", { address: SLIPPED, label: "Slip" }, /does not pass its own checksum/],
        ["not an address", { address: "ledger.eth", label: "Name" }, /not an EVM address/],
        ["the wallet itself", { address: atBirth.address, label: "Self" }, /own address is not a withdrawal account/],
        ["the zero address", { address: `0x${"0".repeat(40)}`, label: "Zero" }, /nobody's account/],
        ["an account listed already", { address: LEDGER.toLowerCase(), label: "Again" }, /listed twice/],
        ["a name used already", { address: "0x000000000000000000000000000000000000dEaD", label: "ledger" }, /both named/],
      ];
      for (const [name, typed, why] of cases) {
        const r = await runAsOwnerTypes(withdrawal(), typed);
        assert.notEqual(r.code, 0, name);
        assert.match(r.stderr + r.stdout, why, name);
        assert.deepEqual((await recordOf(dir, "wallet")).withdrawalAllowlist, before, name);
      }
    });

    await t.test("taking an account away needs no ceremony, by name or by address", async () => {
      const byLabel = await run(withdrawal("--remove", "LEDGER"));
      assert.equal(byLabel.code, 0, byLabel.stderr);
      assert.doesNotMatch(byLabel.stderr, /127\.0\.0\.1/);
      assert.deepEqual(
        (await recordOf(dir, "wallet")).withdrawalAllowlist.map((account) => account.address),
        [EXCHANGE],
      );
      const unknown = await run(withdrawal("--remove", LEDGER));
      assert.notEqual(unknown.code, 0);
      assert.match(unknown.stderr + unknown.stdout, /nothing was removed/);
      const byAddress = await run(withdrawal("--remove", EXCHANGE.toLowerCase()));
      assert.equal(byAddress.code, 0, byAddress.stderr);
      assert.equal((await recordOf(dir, "wallet")).withdrawalAllowlist, null);
      assert.equal((await listed(dir, "wallet")).withdrawalAllowlist, undefined);
    });

    await t.test("--clear empties the list without the owner", async () => {
      const add = await runAsOwnerTypes(withdrawal(), { address: LEDGER, label: "Ledger" });
      assert.equal(add.code, 0, add.stderr);
      const r = await run(withdrawal("--clear"));
      assert.equal(r.code, 0, r.stderr);
      assert.equal(JSON.parse(r.stdout).withdrawalAllowlist, null);
      assert.equal((await recordOf(dir, "wallet")).withdrawalAllowlist, null);
    });

    await t.test("no flag carries a limit in: the owner is not even asked", async () => {
      for (const flag of ["--limit", "--usd", "--amount"]) {
        const r = await run(limit(flag, "100000"));
        assert.notEqual(r.code, 0, flag);
        assert.match(r.stderr + r.stdout, /typed by the owner on the secure prompt/, flag);
        assert.doesNotMatch(r.stderr, /127\.0\.0\.1/, `${flag} raised the prompt`);
      }
      assert.equal((await recordOf(dir, "wallet")).dailySpendLimitUsd, null);
    });

    await t.test("the owner types the limit, in whole dollars", async () => {
      const first = await runAsOwnerTypes(limit(), { limit: "250" });
      assert.equal(first.code, 0, first.stderr);
      assert.equal(JSON.parse(first.stdout).dailySpendLimitUsd, 250);
      assert.equal((await listed(dir, "wallet")).dailySpendLimitUsd, 250);
      const grouped = await runAsOwnerTypes(limit(), { limit: " $1,500 " });
      assert.equal(grouped.code, 0, grouped.stderr);
      assert.equal((await recordOf(dir, "wallet")).dailySpendLimitUsd, 1500);
    });

    await t.test("a figure that could be read two ways is refused and the limit stays", async () => {
      for (const typed of ["2,50", "1.5", "0", "-5", "abc", "", "1e6", "99999999999"]) {
        const r = await runAsOwnerTypes(limit(), { limit: typed });
        assert.notEqual(r.code, 0, JSON.stringify(typed));
        assert.equal((await recordOf(dir, "wallet")).dailySpendLimitUsd, 1500, JSON.stringify(typed));
      }
    });

    await t.test("--clear leaves no limit, without the owner", async () => {
      const r = await run(limit("--clear"));
      assert.equal(r.code, 0, r.stderr);
      assert.equal(JSON.parse(r.stdout).dailySpendLimitUsd, null);
      assert.equal((await listed(dir, "wallet")).dailySpendLimitUsd, undefined);
    });

    const refund = (...more) => ["set-refund", "--name", "wallet", "--state-dir", dir, ...more];
    // Throwaway addresses in their chains' own spellings — nobody's wallets.
    const BTC = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    const SOL = "7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV";

    await t.test("no flag carries a refund address in: the owner is not even asked", async () => {
      for (const flag of ["--address", "--refund", "--to"]) {
        const r = await run(refund("--chain", "BTC", flag, BTC));
        assert.notEqual(r.code, 0, flag);
        assert.match(r.stderr + r.stdout, /typed by the owner on the secure prompt/, flag);
        assert.doesNotMatch(r.stderr, /127\.0\.0\.1/, `${flag} raised the prompt`);
      }
      const bare = await run(refund());
      assert.notEqual(bare.code, 0);
      assert.equal((await recordOf(dir, "wallet")).refundAddresses, null);
    });

    await t.test("the owner types a refund address for the chain the caller names", async () => {
      const first = await runAsOwnerTypes(refund("--chain", "btc"), { address: ` ${BTC} ` });
      assert.equal(first.code, 0, first.stderr);
      assert.deepEqual(JSON.parse(first.stdout).refundAddresses, [{ chain: "BTC", address: BTC }]);
      const second = await runAsOwnerTypes(refund("--chain", "SOL"), { address: SOL });
      assert.equal(second.code, 0, second.stderr);
      assert.deepEqual((await listed(dir, "wallet")).refundAddresses, [
        { chain: "BTC", address: BTC },
        { chain: "SOL", address: SOL },
      ]);
    });

    await t.test("a chain has one refund address: typing another replaces it", async () => {
      const other = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
      const r = await runAsOwnerTypes(refund("--chain", "BTC"), { address: other });
      assert.equal(r.code, 0, r.stderr);
      assert.deepEqual((await recordOf(dir, "wallet")).refundAddresses, [
        { chain: "SOL", address: SOL },
        { chain: "BTC", address: other },
      ]);
    });

    await t.test("an EVM refund address is held to its checksum and kept in that form", async () => {
      // Vitalik's public address, as EIP-55 writes it.
      const checksummed = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
      const before = (await recordOf(dir, "wallet")).refundAddresses;
      // One capital off: the address fails its own checksum, so it holds a typo.
      const typo = await runAsOwnerTypes(refund("--chain", "ETH"), {
        address: "0xD8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
      });
      assert.notEqual(typo.code, 0);
      assert.match(typo.stderr + typo.stdout, /does not pass its own checksum/);
      assert.deepEqual((await recordOf(dir, "wallet")).refundAddresses, before);

      // All in one case carries no checksum to fail; it is kept in the checksummed form.
      const lower = await runAsOwnerTypes(refund("--chain", "ETH"), { address: checksummed.toLowerCase() });
      assert.equal(lower.code, 0, lower.stderr);
      const kept = (await recordOf(dir, "wallet")).refundAddresses.find((entry) => entry.chain === "ETH");
      assert.equal(kept.address, checksummed);

      const exact = await runAsOwnerTypes(refund("--chain", "POL"), { address: checksummed });
      assert.equal(exact.code, 0, exact.stderr);
      const cleanup = await run(refund("--remove", "ETH"));
      assert.equal(cleanup.code, 0, cleanup.stderr);
      const cleanup2 = await run(refund("--remove", "POL"));
      assert.equal(cleanup2.code, 0, cleanup2.stderr);
      assert.deepEqual((await recordOf(dir, "wallet")).refundAddresses, before);
    });

    await t.test("what does not read as an address or a chain is refused and nothing is saved", async () => {
      const before = (await recordOf(dir, "wallet")).refundAddresses;
      for (const typed of ["short", "has a space in it 12345", "<script>alert(1)</script>", ""]) {
        const r = await runAsOwnerTypes(refund("--chain", "LTC"), { address: typed });
        assert.notEqual(r.code, 0, JSON.stringify(typed));
        assert.deepEqual((await recordOf(dir, "wallet")).refundAddresses, before, JSON.stringify(typed));
      }
      for (const chain of ["bitcoin mainnet", "B", "$BTC"]) {
        const r = await run(refund("--chain", chain));
        assert.notEqual(r.code, 0, chain);
        assert.doesNotMatch(r.stderr, /127\.0\.0\.1/, `${chain} raised the prompt`);
      }
    });

    await t.test("a refund address is taken away without the owner", async () => {
      const r = await run(refund("--remove", "sol"));
      assert.equal(r.code, 0, r.stderr);
      assert.deepEqual(
        (await recordOf(dir, "wallet")).refundAddresses.map((entry) => entry.chain),
        ["BTC"],
      );
      const unknown = await run(refund("--remove", "DOGE"));
      assert.notEqual(unknown.code, 0);
      const cleared = await run(refund("--clear"));
      assert.equal(cleared.code, 0, cleared.stderr);
      assert.equal((await recordOf(dir, "wallet")).refundAddresses, null);
    });

    await t.test("neither setting touches the key", async () => {
      const now = await recordOf(dir, "wallet");
      assert.equal(now.address, atBirth.address);
      assert.equal(now.privateKey, atBirth.privateKey);
    });

    await t.test("the settings apply to an evm-keypair only", async () => {
      const sol = await run([
        "generate", "--name", "sol", "--type", "solana-keypair",
        "--domains", "rpc.example.com", "--state-dir", dir,
      ]);
      assert.equal(sol.code, 0, sol.stderr);
      for (const command of ["set-withdrawal", "set-daily-limit", "set-refund"]) {
        const more = command === "set-refund" ? ["--chain", "BTC"] : [];
        const r = await run([command, "--name", "sol", "--state-dir", dir, ...more]);
        assert.notEqual(r.code, 0, command);
        assert.match(r.stderr + r.stdout, /apply to evm-keypair only/, command);
      }
    });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
