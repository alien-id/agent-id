#!/usr/bin/env node

// End-to-end test for the billing address a card is billed to, through the REAL CLI.
//
// The address is what the issuer checks: a card-not-present payment without one
// is declined by AVS long before anything we wrote gets a say. Two things can
// silently stop working and neither fails loudly, which is why they are tested
// from outside the module: the eight field names (a wire contract with the
// phone, exactly as the card's four are), and where the values end up — the
// owner's choice between an address kept for re-use and one that belongs to this
// card alone.
//
// Run: node --test tests/test-vault-address.mjs

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

const PAN = "4242424242424242";
const CARD = {
  cardNumber: PAN,
  cardExpiry: "1234",
  cardSecurityCode: "123",
  cardholderName: "Alien Owner",
};

// The names the phone keys its billing page off.
const ADDRESS = {
  billingFirstName: "Andrei",
  billingLastName: "Rybin",
  billingCountry: "US",
  billingAddressLine1: "1226 University Dr",
  billingAddressLine2: "Apt 4B",
  billingCity: "Menlo Park",
  billingState: "CA",
  billingPostalCode: "94025",
};

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

function waitForUrl(child) {
  return new Promise((resolve, reject) => {
    let buf = "";
    const onData = (d) => {
      buf += d.toString();
      const m = buf.match(/http:\/\/127\.0\.0\.1:\d+\/\?t=[a-f0-9]+/);
      if (m) {
        child.stderr.off("data", onData);
        resolve(m[0]);
      }
    };
    child.stderr.on("data", onData);
    child.on("exit", () => reject(new Error(`CLI exited before printing a URL:\n${buf}`)));
  });
}

function runCli(args, dir) {
  return new Promise((resolve) => {
    const child = spawn("node", [CLI, ...args, "--state-dir", dir]);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("exit", (code) => resolve({ code, stdout, stderr }));
  });
}

// Drives one `add --type card --form` to completion, answering the form with
// `values`. Returns the rendered form markup, so a test can also assert what the
// owner was asked for.
async function addCard(dir, name, values) {
  const child = spawn(
    "node",
    [CLI, "add", "--name", name, "--type", "card", "--form", "--state-dir", dir],
    {
      env: {
        ...process.env,
        AGENT_ID_NO_BROWSER: "1",
        AGENT_ID_SECURE_PROMPT: "browser",
        AGENT_ID_SAVE_TO_VAULT_BOX: "1",
      },
    },
  );
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (d) => (stdout += d));
  child.stderr.on("data", (d) => (stderr += d));
  try {
    const url = await waitForUrl(child);
    const u = new URL(url);
    const form = await (await fetch(url)).text();
    const res = await fetch(`http://127.0.0.1:${u.port}/submit`, {
      method: "POST",
      body: new URLSearchParams({ _token: u.searchParams.get("t"), ...values }),
    });
    assert.equal(res.status, 200);
    const code = await new Promise((r) => child.on("exit", r));
    assert.equal(code, 0, `CLI failed: ${stderr}`);
    return { form, stdout, stderr };
  } catch (error) {
    child.kill();
    throw error;
  }
}

test("the billing page is asked for under the names the phone draws it by", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-form-"));
  try {
    await makeVault(dir);
    const { form } = await addCard(dir, "visa", { ...CARD, ...ADDRESS });

    for (const field of Object.keys(ADDRESS)) {
      assert.ok(
        form.includes(`id="${field}" name="${field}" type="text"`),
        `${field} must be asked for, and in the clear — an address masked cannot be checked`,
      );
    }
    assert.ok(form.includes('name="saveBillingAddress"'), "the owner is offered the choice");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("an address the owner keeps becomes a credential the next card can name", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-kept-"));
  try {
    await makeVault(dir);
    await addCard(dir, "visa", { ...CARD, ...ADDRESS, saveBillingAddress: "true" });

    const { privateKeyPem } = JSON.parse(await readFile(statePaths(dir).mainKey, "utf8"));
    const vault = await openVault({ stateDir: dir, privateKeyPem });
    const card = vault.get("visa");
    const address = vault.get(card.billingAddress);
    assert.equal(address.type, "address");
    assert.equal(address.billingPostalCode, "94025");
    assert.deepEqual(address.domains, []);
    assert.equal(address.access, "ro");
    // The card names it rather than copying it, so the two cannot drift.
    for (const field of Object.keys(ADDRESS)) {
      assert.ok(!(field in card), `the card copied ${field} instead of naming the address`);
    }
    vault.lock();

    // And the one reader that hands values over resolves the name for its caller.
    const read = JSON.parse((await runCli(["read-card", "--name", "visa"], dir)).stdout);
    assert.deepEqual(read.card.billing, ADDRESS);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("an address the owner does not keep belongs to its card and to nothing else", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-once-"));
  try {
    await makeVault(dir);
    await addCard(dir, "visa", { ...CARD, ...ADDRESS, saveBillingAddress: "false" });

    const { privateKeyPem } = JSON.parse(await readFile(statePaths(dir).mainKey, "utf8"));
    const vault = await openVault({ stateDir: dir, privateKeyPem });
    assert.equal(vault.get("visa").billingAddress, undefined);
    assert.equal(
      vault.list().filter((c) => c.type === "address").length,
      0,
      "an address nobody asked to keep was kept anyway",
    );
    vault.lock();

    // Stored all the same: a card that cannot be billed cannot be paid with.
    const read = JSON.parse((await runCli(["read-card", "--name", "visa"], dir)).stdout);
    assert.deepEqual(read.card.billing, ADDRESS);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("two cards billed to the same address share the one record", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-shared-"));
  try {
    await makeVault(dir);
    await addCard(dir, "visa", { ...CARD, ...ADDRESS, saveBillingAddress: "true" });
    await addCard(dir, "mastercard", {
      ...CARD,
      cardNumber: "5555555555554444",
      ...ADDRESS,
      saveBillingAddress: "true",
    });

    const { privateKeyPem } = JSON.parse(await readFile(statePaths(dir).mainKey, "utf8"));
    const vault = await openVault({ stateDir: dir, privateKeyPem });
    const addresses = vault.list().filter((c) => c.type === "address");
    assert.equal(addresses.length, 1, "the same address was stored twice");
    assert.equal(vault.get("visa").billingAddress, addresses[0].name);
    assert.equal(vault.get("mastercard").billingAddress, addresses[0].name);
    vault.lock();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// The address is the owner's home, not an instrument — but `show` printing it is
// a leak of its own kind, so it is sealed exactly as the card is.
test("a stored address never comes back through the agent's own channel", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-sealed-"));
  try {
    await makeVault(dir);
    await addCard(dir, "visa", { ...CARD, ...ADDRESS, saveBillingAddress: "true" });

    const listed = JSON.parse((await runCli(["list"], dir)).stdout);
    const address = listed.credentials.find((c) => c.type === "address");
    const shown = JSON.parse((await runCli(["show", "--name", address.name], dir)).stdout);
    assert.equal(shown.sealed, true);
    for (const value of [ADDRESS.billingAddressLine1, ADDRESS.billingPostalCode]) {
      assert.ok(!JSON.stringify(shown).includes(value), `show returned ${value}`);
      assert.ok(!JSON.stringify(listed).includes(value), `list returned ${value}`);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// A card stored before any of this existed still reads, and still pays — the
// fill simply has nothing to type into a checkout's address boxes.
test("a card with no address reads as a card without one", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-absent-"));
  try {
    await makeVault(dir);
    await addCard(dir, "visa", CARD);

    const read = JSON.parse((await runCli(["read-card", "--name", "visa"], dir)).stdout);
    assert.equal(read.ok, true);
    assert.equal(read.card.cardNumber, PAN);
    assert.equal(read.card.billing, null);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
