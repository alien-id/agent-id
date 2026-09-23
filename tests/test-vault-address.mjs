#!/usr/bin/env node

// End-to-end test for the billing address a card is billed to, through the REAL CLI.
//
// The address is what the issuer checks: a card-not-present payment without one
// is declined by AVS long before anything we wrote gets a say. It is asked for
// when a checkout needs it — `set-address`, raised by the agent once a form has
// asked for boxes the vault cannot answer — and never when the card is stored.
// Three things can silently stop working and none fails loudly, which is why
// they are tested from outside the module: that `add` asks for the card alone,
// the eight field names (a wire contract with the phone, exactly as the card's
// four are), and where the values end up — the owner's choice between an
// address kept for re-use and one that belongs to this card alone.
//
// Run: node --test tests/test-vault-address.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
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

// An address from a country that issues no postal code and has no states.
const DUBAI = {
  billingFirstName: "Andrei",
  billingLastName: "Rybin",
  billingCountry: "AE",
  billingAddressLine1: "Marina Gate 1, Dubai Marina",
  billingAddressLine2: "",
  billingCity: "Dubai",
  billingState: "",
  billingPostalCode: "",
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

async function openStored(dir) {
  const { privateKeyPem } = JSON.parse(await readFile(statePaths(dir).mainKey, "utf8"));
  return openVault({ stateDir: dir, privateKeyPem });
}

// Drives one `--form` command through the localhost browser form. `values` is
// what the owner types; `null` means the command is expected to finish without
// raising a form at all, and a form that appears anyway fails the test.
async function driveForm(dir, args, values) {
  const child = spawn("node", [CLI, ...args, "--form", "--state-dir", dir], {
    env: {
      ...process.env,
      AGENT_ID_NO_BROWSER: "1",
      AGENT_ID_SECURE_PROMPT: "browser",
      AGENT_ID_SAVE_TO_VAULT_BOX: "1",
    },
  });
  let stdout = "";
  let stderr = "";
  let exited = false;
  child.stdout.on("data", (d) => (stdout += d));
  child.stderr.on("data", (d) => (stderr += d));
  child.on("exit", () => (exited = true));

  const nextUrl = async () => {
    const deadline = Date.now() + 30_000;
    for (;;) {
      const url = (stderr.match(/http:\/\/127\.0\.0\.1:\d+\/\?t=[a-f0-9]+/g) || [])[0];
      if (url) return url;
      if (exited) throw new Error(`CLI exited before printing a URL:\n${stderr}`);
      if (Date.now() > deadline) throw new Error(`no secure form in 30s:\n${stderr}`);
      await new Promise((tick) => setTimeout(tick, 20));
    }
  };

  try {
    let form = null;
    if (values !== null) {
      const url = await nextUrl();
      const u = new URL(url);
      form = await (await fetch(url)).text();
      const res = await fetch(`http://127.0.0.1:${u.port}/submit`, {
        method: "POST",
        body: new URLSearchParams({ _token: u.searchParams.get("t"), ...values }),
      });
      assert.equal(res.status, 200);
    }
    // A command that keeps waiting once its form is answered is waiting on a
    // second form nobody is going to answer — the shape this test exists to
    // keep out.
    const code = await Promise.race([
      new Promise((r) => child.on("exit", r)),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error(`CLI still running 15s after the form:\n${stderr}`)), 15_000),
      ),
    ]);
    assert.equal(code, 0, `CLI failed: ${stderr}`);
    assert.ok(
      values !== null || !/http:\/\/127\.0\.0\.1/.test(stderr),
      `a form was raised where none was expected:\n${stderr}`,
    );
    return { form, out: JSON.parse(stdout), stdout, stderr };
  } catch (error) {
    child.kill();
    throw error;
  }
}

// `add --type card --form`: one screen, the card in hand.
async function addCard(dir, name, values) {
  const { form, stdout, stderr } = await driveForm(
    dir,
    ["add", "--name", name, "--type", "card"],
    values,
  );
  return { cardForm: form, stdout, stderr };
}

// `set-address --card N --form`: the billing screen, when the vault has no
// address to answer with.
async function setAddress(dir, name, values, extra = []) {
  const { form, out } = await driveForm(dir, ["set-address", "--card", name, ...extra], values);
  return { billingForm: form, out };
}

// A hosted card host that ends every card the way the owner asked, so a decline
// on the address screen can be driven without a browser.
function hostedSocket(reason) {
  const sock = path.join(os.tmpdir(), `vault-address-${process.pid}-${Date.now()}.sock`);
  const server = http.createServer((req, res) => {
    req.on("data", () => {});
    req.on("end", () => {
      res.writeHead(409, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "cancelled", reason }));
    });
  });
  return new Promise((resolve) => server.listen(sock, () => resolve({ sock, server })));
}

async function setAddressAgainstCard(dir, name, reason) {
  const { sock, server } = await hostedSocket(reason);
  try {
    const child = spawn(
      "node",
      [CLI, "set-address", "--card", name, "--form", "--state-dir", dir],
      { env: { ...process.env, AGENT_ID_SECURE_PROMPT: "hosted", AGENT_ID_SECURE_PROMPT_SOCK: sock } },
    );
    let stdout = "";
    child.stdout.on("data", (d) => (stdout += d));
    const code = await new Promise((r) => child.on("exit", r));
    return { code, out: JSON.parse(stdout) };
  } finally {
    server.close();
  }
}

// Storing a card used to raise the address screen right behind the card's,
// with seven boxes the owner could not get past — and no way to tell, from a
// checkout in Dubai, that none of it would ever be asked for.
test("storing a card asks for the card and nothing else", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-add-"));
  try {
    await makeVault(dir);
    const { cardForm } = await addCard(dir, "visa", CARD);

    for (const field of Object.keys(ADDRESS)) {
      assert.ok(!cardForm.includes(`name="${field}"`), `${field} was asked for on the card screen`);
    }
    assert.ok(!cardForm.includes('name="saveBillingAddress"'));
    const read = JSON.parse((await runCli(["read-card", "--name", "visa"], dir)).stdout);
    assert.equal(read.ok, true);
    assert.equal(read.card.cardNumber, PAN);
    assert.equal(read.card.billing, null);
    const fields = JSON.parse((await runCli(["card-fields", "--name", "visa"], dir)).stdout);
    assert.deepEqual(fields.fields, Object.keys(CARD));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("set-address raises the address screen under the names the phone draws it by", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-form-"));
  try {
    await makeVault(dir);
    await addCard(dir, "visa", CARD);
    const { billingForm, out } = await setAddress(dir, "visa", ADDRESS);

    for (const field of Object.keys(ADDRESS)) {
      assert.ok(
        billingForm.includes(`id="${field}" name="${field}" type="text"`),
        `${field} must be asked for, and in the clear — an address masked cannot be checked`,
      );
    }
    assert.ok(billingForm.includes('name="saveBillingAddress"'), "the owner is offered the choice");
    // Two names, not one: the clients find a box by its name, and a screen that
    // reused the card's would tick the wrong record.
    assert.ok(!billingForm.includes('name="saveToVault"'));
    assert.equal(out.ok, true);
    assert.equal(out.source, "typed");
    assert.deepEqual(out.fields, [...Object.keys(CARD), ...Object.keys(ADDRESS)]);
    for (const value of [PAN, ADDRESS.billingAddressLine1, ADDRESS.billingPostalCode]) {
      assert.ok(!JSON.stringify(out).includes(value), `set-address returned ${value}`);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// Most countries have no states and some sixty issue no postal code, so the
// screen cannot insist on either — a checkout that does refuses the fill for
// the one box it lacks, before anything is spent.
test("the state and the postal code are the owner's to leave empty", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-optional-"));
  try {
    await makeVault(dir);
    await addCard(dir, "visa", CARD);
    const { billingForm, out } = await setAddress(dir, "visa", DUBAI);

    for (const field of ["billingState", "billingPostalCode", "billingAddressLine2"]) {
      const box = billingForm.match(new RegExp(`<input[^>]*name="${field}"[^>]*>`))[0];
      assert.ok(!/\brequired\b/.test(box), `${field} is still required on the screen`);
    }
    for (const field of ["billingCountry", "billingAddressLine1", "billingCity"]) {
      const box = billingForm.match(new RegExp(`<input[^>]*name="${field}"[^>]*>`))[0];
      assert.ok(/\brequired\b/.test(box), `${field} stopped being required`);
    }
    assert.equal(out.ok, true);
    assert.deepEqual(out.fields, [
      ...Object.keys(CARD),
      "billingFirstName",
      "billingLastName",
      "billingCountry",
      "billingAddressLine1",
      "billingCity",
    ]);
    const read = JSON.parse((await runCli(["read-address", "--card", "visa"], dir)).stdout);
    assert.deepEqual(read.billing, DUBAI);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("an address the owner keeps becomes a credential the next card can name", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-kept-"));
  try {
    await makeVault(dir);
    await addCard(dir, "visa", CARD);
    const { out } = await setAddress(dir, "visa", { ...ADDRESS, saveBillingAddress: "true" });

    const vault = await openStored(dir);
    const card = vault.get("visa");
    const address = vault.get(card.billingAddress);
    assert.equal(out.address, card.billingAddress);
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
    await addCard(dir, "visa", CARD);
    const { out } = await setAddress(dir, "visa", { ...ADDRESS, saveBillingAddress: "false" });

    assert.equal(out.address, null);
    const vault = await openStored(dir);
    assert.equal(vault.get("visa").billingAddress, undefined);
    assert.equal(
      vault.list().filter((c) => c.type === "address").length,
      0,
      "an address nobody asked to keep was kept anyway",
    );
    vault.lock();

    const read = JSON.parse((await runCli(["read-card", "--name", "visa"], dir)).stdout);
    assert.deepEqual(read.card.billing, ADDRESS);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// The second card is billed where the first one is, and the owner is not asked
// to type their home address a second time to say so.
test("a card added after the address is linked to it without a screen", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-shared-"));
  try {
    await makeVault(dir);
    await addCard(dir, "visa", CARD);
    await setAddress(dir, "visa", { ...ADDRESS, saveBillingAddress: "true" });
    await addCard(dir, "mastercard", { ...CARD, cardNumber: "5555555555554444" });
    const { out } = await setAddress(dir, "mastercard", null);

    assert.equal(out.ok, true);
    assert.equal(out.source, "existing");
    assert.deepEqual(out.fields, [...Object.keys(CARD), ...Object.keys(ADDRESS)]);
    const vault = await openStored(dir);
    const addresses = vault.list().filter((c) => c.type === "address");
    assert.equal(addresses.length, 1, "the same address was stored twice");
    assert.equal(vault.get("visa").billingAddress, addresses[0].name);
    assert.equal(vault.get("mastercard").billingAddress, addresses[0].name);
    vault.lock();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a card that already has an address is left alone", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-already-"));
  try {
    await makeVault(dir);
    await addCard(dir, "visa", CARD);
    await setAddress(dir, "visa", ADDRESS);
    const { out } = await setAddress(dir, "visa", null);

    assert.equal(out.ok, true);
    assert.equal(out.source, "already");
    assert.deepEqual(out.fields, [...Object.keys(CARD), ...Object.keys(ADDRESS)]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// An address without a postal code meets a shop that insists on one: the owner
// types the address again, whole, and the card moves to the new record. The
// old values are never put in front of them — they are sealed, and the form's
// spec travels in the clear.
test("--replace asks again and moves the card to the address typed", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-replace-"));
  try {
    await makeVault(dir);
    await addCard(dir, "visa", CARD);
    await setAddress(dir, "visa", { ...DUBAI, saveBillingAddress: "true" });
    const { billingForm, out } = await setAddress(
      dir,
      "visa",
      { ...ADDRESS, saveBillingAddress: "true" },
      ["--replace"],
    );

    assert.ok(!billingForm.includes(DUBAI.billingAddressLine1), "the stored address was shown");
    assert.equal(out.source, "typed");
    const vault = await openStored(dir);
    const addresses = vault.list().filter((c) => c.type === "address");
    assert.equal(addresses.length, 2);
    assert.equal(vault.get(vault.get("visa").billingAddress).billingPostalCode, "94025");
    vault.lock();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("typing the same address twice updates one record", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-dedup-"));
  try {
    await makeVault(dir);
    await addCard(dir, "visa", CARD);
    await setAddress(dir, "visa", { ...ADDRESS, saveBillingAddress: "true" });
    await setAddress(dir, "visa", { ...ADDRESS, saveBillingAddress: "true" }, ["--replace"]);

    const vault = await openStored(dir);
    assert.equal(vault.list().filter((c) => c.type === "address").length, 1);
    vault.lock();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// Closing the address screen is a decision, not a fault: the card stays as it
// was and the caller is told not to raise it again.
test("a card whose address screen is closed keeps its card and gets no address", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-closed-"));
  try {
    await makeVault(dir);
    await addCard(dir, "visa", CARD);
    const { code, out } = await setAddressAgainstCard(dir, "visa", undefined);

    assert.equal(code, 1);
    assert.equal(out.ok, false);
    assert.equal(out.stored, false);
    assert.equal(out.error, "FORM_CANCELLED");
    assert.equal(out.reason, "owner_dismissed_the_card");
    assert.equal(out.card, "visa");
    const read = JSON.parse((await runCli(["read-card", "--name", "visa"], dir)).stdout);
    assert.equal(read.card.cardNumber, PAN);
    assert.equal(read.card.billing, null);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("an owner who would rather type the address into the page is handed the browser", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-browser-"));
  try {
    await makeVault(dir);
    await addCard(dir, "visa", CARD);
    const { code, out } = await setAddressAgainstCard(dir, "visa", "use_browser");

    assert.equal(code, 1);
    assert.equal(out.error, "FORM_USE_BROWSER");
    assert.equal(out.action, "owner_must_drive");
    assert.match(out.message, /type the address into the page/);
    assert.ok(!/sign in/.test(out.message), "the stock sign-in wording leaked through");
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
    await addCard(dir, "visa", CARD);
    await setAddress(dir, "visa", { ...ADDRESS, saveBillingAddress: "true" });

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

// The box the card screen never had. Every other credential asks whether it
// should outlive the thing it was typed for; the card — the one worth asking
// about twice — was stored for good without a word, and the owner reported it
// as a missing box rather than as a surprise, which is the good outcome only
// because they happened to look.
test("the card screen asks whether to keep the card", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-keepbox-"));
  try {
    await makeVault(dir);
    const { cardForm } = await addCard(dir, "visa", CARD);

    assert.ok(cardForm.includes('name="saveToVault"'), "the card screen offers no choice");
    // The clients find a box by its name, so the name is the login form's; the
    // wording is not, because "Save to vault" on a card screen says nothing
    // about where the number is going.
    assert.ok(cardForm.includes("Save card to Secure Vault"), "the card box is worded for a login");
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
    await addCard(dir, "visa", { ...CARD, saveToVault: "false" });

    const vault = await openStored(dir);
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
    await addCard(dir, "visa", { ...CARD, saveToVault: "true" });

    const vault = await openStored(dir);
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
    await addCard(dir, "visa", CARD);
    await setAddress(dir, "visa", ADDRESS);

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

// A box the owner left empty is one a ref must not be aimed at, so the caller
// has to be able to tell an empty one from a stored one.
test("card-fields leaves out the box the owner did not fill", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-fields-gap-"));
  try {
    await makeVault(dir);
    await addCard(dir, "visa", CARD);
    await setAddress(dir, "visa", { ...ADDRESS, billingAddressLine2: "" });

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
    await addCard(dir, "visa", CARD);
    await setAddress(dir, "visa", { ...ADDRESS, saveBillingAddress: "true" });

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
    await addCard(dir, "visa", CARD);

    const read = JSON.parse((await runCli(["read-address", "--card", "visa"], dir)).stdout);
    assert.equal(read.ok, true);
    assert.equal(read.billing, null);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("none of the address commands works on anything but a card", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "billing-notacard-"));
  try {
    await makeVault(dir);
    await addCard(dir, "visa", CARD);
    await setAddress(dir, "visa", { ...ADDRESS, saveBillingAddress: "true" });

    const listed = JSON.parse((await runCli(["list"], dir)).stdout);
    const address = listed.credentials.find((c) => c.type === "address").name;
    for (const args of [
      ["card-fields", "--name", address],
      ["read-address", "--card", address],
      ["set-address", "--card", address, "--form"],
    ]) {
      const refused = JSON.parse((await runCli(args, dir)).stdout);
      assert.equal(refused.ok, false, args.join(" "));
      assert.match(refused.error, /is a address/);
    }
    const noForm = JSON.parse((await runCli(["set-address", "--card", "visa"], dir)).stdout);
    assert.equal(noForm.ok, false);
    assert.match(noForm.error, /--form/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
