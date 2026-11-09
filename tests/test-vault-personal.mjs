#!/usr/bin/env node

// End-to-end test for the owner's own details in the vault, through the REAL CLI.
//
// A `personal` record exists so the agent can type a phone number or a passport
// into a website without ever holding it. What can go wrong without anything
// failing loudly: a value showing up in `list` or `show`, the record being
// creatable with no owner at the form, and the `confirm` answer not being the
// owner's to give.
//
// Run: node --test tests/test-vault-personal.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { spawn } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";

import { initVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { writeJsonFile, statePaths } from "../plugins/agent-id-core/lib/state.mjs";
import { fingerprintPublicKeyPem } from "../plugins/agent-id-core/lib/crypto.mjs";

const CLI = new URL("../plugins/agent-id-vault/bin/cli.mjs", import.meta.url).pathname;
const PHONE = "+49 151 2345 6789";

async function withVault(run) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "vault-personal-"));
  try {
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
    await run(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

function cli(dir, args, { stdin = null, env = {} } = {}) {
  return new Promise((resolve) => {
    const child = spawn("node", [CLI, ...args, "--state-dir", dir], {
      env: { ...process.env, ...env },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("exit", (code) => {
      let json = null;
      try {
        json = JSON.parse(stdout);
      } catch {
        /* a refusal may print nothing parseable */
      }
      resolve({ code, stdout, stderr, json });
    });
    if (stdin != null) child.stdin.write(stdin);
    child.stdin.end();
  });
}

const addPersonal = (dir, name, kind, values) =>
  cli(dir, ["add", "--name", name, "--type", "personal", "--kind", kind, "--form", "--values-stdin"], {
    stdin: JSON.stringify(values),
  });

test("a stored phone is listed by name and kind, never by value", () =>
  withVault(async (dir) => {
    const added = await addPersonal(dir, "phone", "phone", { number: PHONE });
    assert.equal(added.json?.ok, true, added.stdout + added.stderr);
    assert.equal(added.json.kind, "phone");
    assert.deepEqual(added.json.fields, ["number"]);
    assert.equal(added.json.confirm, true);
    assert.equal(added.json.access, "ro");
    assert.ok(!added.stdout.includes(PHONE));

    const listed = await cli(dir, ["list"]);
    const entry = listed.json.credentials.find((c) => c.name === "phone");
    assert.equal(entry.type, "personal");
    assert.equal(entry.kind, "phone");
    assert.deepEqual(entry.fields, ["number"]);
    assert.equal(entry.confirm, true);
    assert.ok(!listed.stdout.includes(PHONE));
  }));

test("read-personal gives the values, and show keeps them sealed", () =>
  withVault(async (dir) => {
    await addPersonal(dir, "phone", "phone", { number: PHONE });
    const read = await cli(dir, ["read-personal", "--name", "phone"]);
    assert.deepEqual(read.json, { ok: true, kind: "phone", confirm: true, fields: { number: PHONE } });

    const shown = await cli(dir, ["show", "--name", "phone"]);
    assert.equal(shown.json.sealed, true);
    assert.ok(!shown.stdout.includes(PHONE));
  }));

test("confirm is the owner's answer on the form, and there is no flag for it", () =>
  withVault(async (dir) => {
    const off = await addPersonal(dir, "phone", "phone", { number: PHONE, confirmBeforeUse: "false" });
    assert.equal(off.json.confirm, false);
    const read = await cli(dir, ["read-personal", "--name", "phone"]);
    assert.equal(read.json.confirm, false);
    assert.deepEqual(Object.keys(read.json.fields), ["number"], "the box is not stored as a field");

    const flagged = await cli(
      dir,
      ["add", "--name", "other", "--type", "personal", "--kind", "phone", "--no-confirm", "--confirm", "false", "--form", "--values-stdin"],
      { stdin: JSON.stringify({ number: PHONE }) },
    );
    assert.equal(flagged.json.confirm, true, "a flag does not turn it off");
  }));

test("a record is only ever typed by the owner, and goes nowhere by default", () =>
  withVault(async (dir) => {
    const refused = async (args, needle) => {
      const out = await cli(dir, args);
      assert.notEqual(out.json?.ok, true, out.stdout);
      assert.match(out.stdout + out.stderr, needle);
    };
    await refused(["add", "--name", "p", "--type", "personal", "--kind", "phone"], /secure form/);
    await refused(["add", "--name", "a", "--type", "address"], /secure form/);
    await refused(["add", "--name", "p", "--type", "personal", "--form"], /--kind/);
    await refused(["add", "--name", "p", "--type", "personal", "--kind", "constructor", "--form"], /--kind/);
    await refused(
      ["add", "--name", "p", "--type", "personal", "--kind", "phone", "--form", "--domains", "x.com"],
      /no --domains/,
    );
    await refused(
      ["add", "--name", "p", "--type", "personal", "--kind", "phone", "--form", "--access", "rw"],
      /read-only/,
    );
  }));

test("what a kind requires is enforced, and a refusal repeats no value", () =>
  withVault(async (dir) => {
    const noExpiry = await addPersonal(dir, "passport", "passport", {
      number: "X1234567",
      issuingCountry: "DE",
    });
    assert.notEqual(noExpiry.json?.ok, true);
    assert.match(noExpiry.stdout + noExpiry.stderr, /expiry/);
    assert.ok(!(noExpiry.stdout + noExpiry.stderr).includes("X1234567"));

    const id = await addPersonal(dir, "id.anna", "national_id", { number: "A1" });
    assert.equal(id.json?.ok, true, id.stdout + id.stderr);

    const noAccount = await addPersonal(dir, "bank", "bank_account", { routingCode: "DEUTDEFF" });
    assert.notEqual(noAccount.json?.ok, true);
    assert.match(noAccount.stdout + noAccount.stderr, /iban, accountNumber/);

    const bank = await addPersonal(dir, "bank", "bank_account", { iban: "DE89370400440532013000" });
    assert.equal(bank.json?.ok, true, bank.stdout + bank.stderr);
    assert.deepEqual(bank.json.fields, ["iban"]);
  }));

test("an address can be its own record, and is read by name", () =>
  withVault(async (dir) => {
    const added = await cli(dir, ["add", "--name", "home", "--type", "address", "--form", "--values-stdin"], {
      stdin: JSON.stringify({
        billingFirstName: "Anna",
        billingLastName: "Weber",
        billingCountry: "de",
        billingAddressLine1: "Hauptstr. 1",
        billingCity: "Berlin",
      }),
    });
    assert.equal(added.json?.ok, true, added.stdout + added.stderr);
    assert.equal(added.json.confirm, true);
    const read = await cli(dir, ["read-address", "--name", "home"]);
    assert.equal(read.json.billing.billingCity, "Berlin");
    assert.equal(read.json.billing.billingCountry, "DE");
    const asCard = await cli(dir, ["read-address", "--card", "home"]);
    assert.notEqual(asCard.json?.ok, true, "--card still reads nothing but a card");
    const listed = await cli(dir, ["list"]);
    assert.ok(!listed.stdout.includes("Hauptstr"));
  }));

test("the card's words are the vault's, and the box waits for clients that draw it", () =>
  withVault(async (dir) => {
    const args = ["form-spec", "--name", "passport.anna", "--type", "personal", "--kind", "passport"];
    const plain = await cli(dir, args);
    assert.equal(plain.json.spec.title, "Passport");
    assert.match(plain.json.spec.description, /For anna\./);
    assert.deepEqual(plain.json.spec.fields.map((f) => f.name), ["number", "expiry", "issuingCountry"]);

    const boxed = await cli(dir, args, { env: { AGENT_ID_SAVE_TO_VAULT_BOX: "1" } });
    const box = boxed.json.spec.fields.at(-1);
    assert.equal(box.name, "confirmBeforeUse");
    assert.equal(box.kind, "checkbox");
    assert.equal(box.default, "true");
  }));
