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

// Drives one `add --type card --form` to completion. The card is asked for on
// its own screen and the billing address on a second one, so this answers two
// forms in a row and returns both markups — a test can assert what the owner was
// asked for on each.
async function addCard(dir, name, values, billing) {
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
  let exited = false;
  child.stdout.on("data", (d) => (stdout += d));
  child.stderr.on("data", (d) => (stderr += d));
  child.on("exit", () => (exited = true));

  // The URL is printed to stderr, and the second form's is printed the instant
  // the first is answered — before anything here could have started listening
  // for it. So the scan reads everything the child has said so far and skips
  // the URLs already answered, rather than racing a listener against a write.
  const answered = [];
  const nextUrl = async () => {
    const deadline = Date.now() + 30_000;
    for (;;) {
      const url = (stderr.match(/http:\/\/127\.0\.0\.1:\d+\/\?t=[a-f0-9]+/g) || []).find(
        (candidate) => !answered.includes(candidate),
      );
      if (url) {
        answered.push(url);
        return url;
      }
      if (exited) throw new Error(`CLI exited before printing a URL:\n${stderr}`);
      if (Date.now() > deadline) throw new Error(`no secure form in 30s:\n${stderr}`);
      await new Promise((tick) => setTimeout(tick, 20));
    }
  };

  const answer = async (fields) => {
    const url = await nextUrl();
    const u = new URL(url);
    const markup = await (await fetch(url)).text();
    const res = await fetch(`http://127.0.0.1:${u.port}/submit`, {
      method: "POST",
      body: new URLSearchParams({ _token: u.searchParams.get("t"), ...fields }),
    });
    assert.equal(res.status, 200);
    return markup;
  };
  try {
    const cardForm = await answer(values);
    const billingForm = billing === null ? null : await answer(billing ?? {});
    const code = await new Promise((r) => child.on("exit", r));
    assert.equal(code, 0, `CLI failed: ${stderr}`);
    return { cardForm, billingForm, stdout, stderr };
  } catch (error) {
    child.kill();
    throw error;
  }
}

test("the address is a second screen, under the names the phone draws it by", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-form-"));
  try {
    await makeVault(dir);
    const { cardForm, billingForm } = await addCard(dir, "visa", CARD, ADDRESS);

    // The card screen is what it always was: the card in hand, nothing else.
    for (const field of Object.keys(ADDRESS)) {
      assert.ok(!cardForm.includes(`name="${field}"`), `${field} was asked for on the card screen`);
    }
    for (const field of Object.keys(ADDRESS)) {
      assert.ok(
        billingForm.includes(`id="${field}" name="${field}" type="text"`),
        `${field} must be asked for, and in the clear — an address masked cannot be checked`,
      );
    }
    assert.ok(billingForm.includes('name="saveBillingAddress"'), "the owner is offered the choice");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// Closing the second screen is not a reason to throw away a card the owner has
// just finished typing: plenty of checkouts never ask for an address.
test("a card whose address screen is closed is stored without one", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-skipped-"));
  try {
    await makeVault(dir);
    await addCard(dir, "visa", CARD, {});

    const read = JSON.parse((await runCli(["read-card", "--name", "visa"], dir)).stdout);
    assert.equal(read.ok, true);
    assert.equal(read.card.cardNumber, PAN);
    assert.equal(read.card.billing, null);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("an address the owner keeps becomes a credential the next card can name", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-kept-"));
  try {
    await makeVault(dir);
    await addCard(dir, "visa", CARD, { ...ADDRESS, saveBillingAddress: "true" });

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
    await addCard(dir, "visa", CARD, { ...ADDRESS, saveBillingAddress: "false" });

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
    await addCard(dir, "visa", CARD, { ...ADDRESS, saveBillingAddress: "true" });
    await addCard(
      dir,
      "mastercard",
      { ...CARD, cardNumber: "5555555555554444" },
      { ...ADDRESS, saveBillingAddress: "true" },
    );

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
    await addCard(dir, "visa", CARD, { ...ADDRESS, saveBillingAddress: "true" });

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
    await addCard(dir, "visa", CARD, {});

    const read = JSON.parse((await runCli(["read-card", "--name", "visa"], dir)).stdout);
    assert.equal(read.ok, true);
    assert.equal(read.card.cardNumber, PAN);
    assert.equal(read.card.billing, null);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// The box the card screen never had. Every other credential asks whether it
// should outlive the thing it was typed for; the card — the one worth asking
// about twice — was stored for good without a word, and the owner reported it
// as a missing box rather than as a surprise, which is the good outcome only
// because they happened to look.
test("the card screen asks whether to keep the card", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-keepbox-"));
  try {
    await makeVault(dir);
    const { cardForm, billingForm } = await addCard(dir, "visa", CARD, ADDRESS);

    assert.ok(cardForm.includes('name="saveToVault"'), "the card screen offers no choice");
    // The clients find a box by its name, so the name is the login form's; the
    // wording is not, because "Save to vault" on a card screen says nothing
    // about where the number is going.
    assert.ok(cardForm.includes("Save card to Secure Vault"), "the card box is worded for a login");
    assert.ok(
      billingForm.includes('name="saveBillingAddress"'),
      "the address screen's own box was lost",
    );
    // Two names, not one: the clients find a box by its name, and a screen that
    // reused the other's would tick the wrong record.
    assert.ok(!cardForm.includes('name="saveBillingAddress"'));
    assert.ok(!billingForm.includes('name="saveToVault"'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// A sign-in is consumed at a known moment and a purchase is not, so the two
// windows cannot be the same one. Half an hour would take the card out from
// under a checkout the owner is still approving from their phone.
test("a card the owner does not keep outlives the purchase it was typed for", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-once-card-"));
  try {
    await makeVault(dir);
    const before = Date.now();
    await addCard(dir, "visa", { ...CARD, saveToVault: "false" }, ADDRESS);

    const { privateKeyPem } = JSON.parse(await readFile(statePaths(dir).mainKey, "utf8"));
    const vault = await openVault({ stateDir: dir, privateKeyPem });
    const card = vault.get("visa");
    const hours = (card.transient.until - before) / (60 * 60 * 1000);
    assert.ok(hours >= 24 && hours < 25, `an unkept card lives ${hours} hours`);
    // And the box itself is never written down as if it were a card field.
    assert.ok(!("saveToVault" in card));
    vault.lock();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a card the owner keeps is kept", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-kept-card-"));
  try {
    await makeVault(dir);
    await addCard(dir, "visa", { ...CARD, saveToVault: "true" }, ADDRESS);

    const { privateKeyPem } = JSON.parse(await readFile(statePaths(dir).mainKey, "utf8"));
    const vault = await openVault({ stateDir: dir, privateKeyPem });
    assert.equal(vault.get("visa").transient, undefined);
    vault.lock();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// What the caller has to know before it spends the owner's approval: which
// boxes on the checkout this card can answer. Asking `read-card` would answer
// it with the card itself, which is why the question has a reader of its own.
test("card-fields names what a card can answer and hands over nothing", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-fields-"));
  try {
    await makeVault(dir);
    await addCard(dir, "visa", CARD, ADDRESS);

    const out = (await runCli(["card-fields", "--name", "visa"], dir)).stdout;
    const read = JSON.parse(out);
    assert.equal(read.ok, true);
    assert.deepEqual(read.fields, [...Object.keys(CARD), ...Object.keys(ADDRESS)]);
    for (const value of [PAN, CARD.cardSecurityCode, ADDRESS.billingPostalCode]) {
      assert.ok(!out.includes(value), `card-fields returned ${value}`);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// The apartment line is the one field the owner may leave empty, and a ref
// aimed at a box this card cannot answer is refused — so the caller has to be
// able to tell an empty one from a stored one.
test("card-fields leaves out the box the owner did not fill", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-fields-gap-"));
  try {
    await makeVault(dir);
    await addCard(dir, "visa", CARD, { ...ADDRESS, billingAddressLine2: "" });

    const read = JSON.parse((await runCli(["card-fields", "--name", "visa"], dir)).stdout);
    assert.ok(!read.fields.includes("billingAddressLine2"));
    assert.ok(read.fields.includes("billingAddressLine1"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// A delivery step asks for an address and has nothing to do with paying, so
// whatever fills one has no business holding the card.
test("read-address hands over the address and never the card", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-readaddr-"));
  try {
    await makeVault(dir);
    await addCard(dir, "visa", CARD, { ...ADDRESS, saveBillingAddress: "true" });

    const out = (await runCli(["read-address", "--card", "visa"], dir)).stdout;
    const read = JSON.parse(out);
    assert.equal(read.ok, true);
    assert.deepEqual(read.billing, ADDRESS);
    for (const value of [PAN, CARD.cardSecurityCode, CARD.cardExpiry]) {
      assert.ok(!out.includes(value), `read-address returned ${value}`);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a card with no address reads back no address to fill", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-readaddr-none-"));
  try {
    await makeVault(dir);
    await addCard(dir, "visa", CARD, {});

    const read = JSON.parse((await runCli(["read-address", "--card", "visa"], dir)).stdout);
    assert.equal(read.ok, true);
    assert.equal(read.billing, null);

    const fields = JSON.parse((await runCli(["card-fields", "--name", "visa"], dir)).stdout);
    assert.deepEqual(fields.fields, Object.keys(CARD));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("neither new reader reads anything but a card", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-notacard-"));
  try {
    await makeVault(dir);
    await addCard(dir, "visa", CARD, { ...ADDRESS, saveBillingAddress: "true" });

    const listed = JSON.parse((await runCli(["list"], dir)).stdout);
    const address = listed.credentials.find((c) => c.type === "address").name;
    for (const args of [
      ["card-fields", "--name", address],
      ["read-address", "--card", address],
    ]) {
      const refused = JSON.parse((await runCli(args, dir)).stdout);
      assert.equal(refused.ok, false);
      assert.match(refused.error, /is a address/);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
