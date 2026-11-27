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

function cli(dir, args, { stdin = null, env = {}, timeoutMs = null } = {}) {
  return new Promise((resolve) => {
    const child = spawn("node", [CLI, ...args, "--state-dir", dir], {
      env: { ...process.env, ...env },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    // A command still waiting on a form at the deadline is killed; it exits with no code.
    const timer = timeoutMs == null ? null : setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    child.on("exit", (code) => {
      if (timer) clearTimeout(timer);
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

const PASSPORT = { number: "X1234567", expiry: "2031-04-01", issuingCountry: "DE" };

// An add is an upsert by name. A caller that stores what the owner just typed
// would otherwise swap an unrelated record for it without anything failing: a
// second traveller's passport over the first one's, or a document over a login.
test("a name that is taken is not overwritten by a record that was meant to be new", () =>
  withVault(async (dir) => {
    const first = await addPersonal(dir, "passport.anna", "passport", PASSPORT);
    assert.equal(first.json?.ok, true, first.stdout + first.stderr);

    const again = await cli(
      dir,
      ["add", "--name", "passport.anna", "--type", "personal", "--kind", "passport", "--form", "--values-stdin", "--if-absent"],
      { stdin: JSON.stringify({ ...PASSPORT, number: "Y7654321" }) },
    );
    assert.notEqual(again.code, 0);
    assert.equal(again.json?.ok, false);
    assert.ok(!again.stdout.includes("Y7654321"), "a refusal repeats no value");
    assert.ok(!again.stderr.includes("Y7654321"), "a refusal repeats no value");

    const kept = await cli(dir, ["read-personal", "--name", "passport.anna"]);
    assert.equal(kept.json?.fields?.number, "X1234567");
  }));

test("a replacement goes only over a record of the same kind", () =>
  withVault(async (dir) => {
    await addPersonal(dir, "passport", "passport", PASSPORT);
    await addPersonal(dir, "id", "national_id", { number: "ID-1" });

    const replaced = await cli(
      dir,
      ["add", "--name", "passport", "--type", "personal", "--kind", "passport", "--form", "--values-stdin", "--expect-kind", "passport"],
      { stdin: JSON.stringify({ ...PASSPORT, number: "Y7654321" }) },
    );
    assert.equal(replaced.json?.ok, true, replaced.stdout + replaced.stderr);
    const now = await cli(dir, ["read-personal", "--name", "passport"]);
    assert.equal(now.json?.fields?.number, "Y7654321");

    const wrong = await cli(
      dir,
      ["add", "--name", "id", "--type", "personal", "--kind", "passport", "--form", "--values-stdin", "--expect-kind", "passport"],
      { stdin: JSON.stringify(PASSPORT) },
    );
    assert.notEqual(wrong.code, 0);
    assert.equal(wrong.json?.ok, false);
    assert.ok(!wrong.stdout.includes("X1234567"), "a refusal repeats no value");
    assert.ok(!wrong.stderr.includes("X1234567"), "a refusal repeats no value");
    const untouched = await cli(dir, ["read-personal", "--name", "id"]);
    assert.equal(untouched.json?.kind, "national_id");
    assert.equal(untouched.json?.fields?.number, "ID-1");
  }));

// The owner would otherwise type a whole passport into a form whose answer is then
// refused. The form is raised in a browser that nobody answers: a command that gets
// that far waits on it until it is killed.
test("a taken name is refused before the form is raised", () =>
  withVault(async (dir) => {
    await addPersonal(dir, "passport", "passport", PASSPORT);
    await addPersonal(dir, "id", "national_id", { number: "ID-1" });
    const formEnv = { AGENT_ID_NO_BROWSER: "1", AGENT_ID_SECURE_PROMPT: "browser" };

    for (const guard of [["--if-absent"], ["--expect-kind", "passport"]]) {
      const name = guard[0] === "--if-absent" ? "passport" : "id";
      const refused = await cli(
        dir,
        ["add", "--name", name, "--type", "personal", "--kind", "passport", "--form", ...guard],
        { env: formEnv, timeoutMs: 15_000 },
      );
      assert.equal(refused.code, 1, `${guard[0]}: ${refused.stdout}${refused.stderr}`);
      assert.equal(refused.json?.ok, false);
      assert.ok(!/127\.0\.0\.1:\d+/.test(refused.stderr), `${guard[0]} raised a form`);
    }
  }));

test("--expect-kind takes one of the personal kinds", () =>
  withVault(async (dir) => {
    await addPersonal(dir, "passport", "passport", PASSPORT);
    for (const expectKind of [["--expect-kind"], ["--expect-kind", "boarding_pass"]]) {
      const refused = await cli(
        dir,
        ["add", "--name", "passport", "--type", "personal", "--kind", "passport", "--form", "--values-stdin", ...expectKind],
        { stdin: JSON.stringify({ ...PASSPORT, number: "Y7654321" }) },
      );
      assert.notEqual(refused.code, 0);
      assert.equal(refused.json?.ok, false);
      assert.match(refused.json?.error ?? "", /--expect-kind must be one of/);
    }
    const kept = await cli(dir, ["read-personal", "--name", "passport"]);
    assert.equal(kept.json?.fields?.number, "X1234567");
  }));

// The flag guards the record that is there; the record being added has to be the
// same kind of record, or a passport is replaced by a login that merely asked for it.
test("--expect-kind refuses an added record of another type or kind", () =>
  withVault(async (dir) => {
    await addPersonal(dir, "passport", "passport", PASSPORT);
    const attempts = [
      {
        args: ["--type", "personal", "--kind", "national_id", "--form", "--values-stdin"],
        values: { number: "ID-2" },
      },
      {
        args: ["--type", "login", "--login-url", "https://example.com/login", "--form", "--values-stdin"],
        values: { username: "anna", password: "hunter2" },
      },
    ];
    for (const { args, values } of attempts) {
      const refused = await cli(
        dir,
        ["add", "--name", "passport", ...args, "--expect-kind", "passport"],
        { stdin: JSON.stringify(values) },
      );
      assert.notEqual(refused.code, 0, refused.stdout);
      assert.equal(refused.json?.ok, false);
      assert.match(refused.json?.error ?? "", /needs --type personal --kind passport/);
    }
    const kept = await cli(dir, ["read-personal", "--name", "passport"]);
    assert.equal(kept.json?.kind, "passport");
    assert.equal(kept.json?.fields?.number, "X1234567");
  }));

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

test("a card is billed to a stored billing address, never to a home address saved on its own", () =>
  withVault(async (dir) => {
    const card = await cli(dir, ["add", "--name", "visa", "--type", "card", "--form", "--values-stdin"], {
      stdin: JSON.stringify({
        cardNumber: "4242424242424242",
        cardExpiry: "1234",
        cardSecurityCode: "123",
        cardholderName: "Anna Weber",
      }),
    });
    assert.equal(card.json?.ok, true, card.stdout + card.stderr);
    const address = (name) =>
      cli(dir, ["add", "--name", name, "--type", "address", "--form", "--values-stdin"], {
        stdin: JSON.stringify({
          billingFirstName: "Anna",
          billingLastName: "Weber",
          billingCountry: "DE",
          billingAddressLine1: name === "home" ? "Hauptstr. 1" : "Ringstr. 9",
          billingCity: "Berlin",
        }),
      });
    assert.equal((await address("home")).json?.ok, true);
    // No form can be raised here: with only a home address, the command must try to.
    const alone = await cli(dir, ["set-address", "--card", "visa", "--form"], {
      env: { AGENT_ID_SECURE_PROMPT: "tty" },
    });
    assert.notEqual(alone.json?.source, "existing", alone.stdout);

    assert.equal((await address("billing-1")).json?.ok, true);
    const linked = await cli(dir, ["set-address", "--card", "visa", "--form"]);
    assert.equal(linked.json?.source, "existing", linked.stdout + linked.stderr);
    assert.equal(linked.json?.address, "billing-1");
  }));

test("a card billed to the same street does not take over a home address", () =>
  withVault(async (dir) => {
    const street = {
      billingFirstName: "Anna",
      billingLastName: "Weber",
      billingCountry: "DE",
      billingAddressLine1: "Hauptstr. 1",
      billingCity: "Berlin",
    };
    const home = await cli(dir, ["add", "--name", "home", "--type", "address", "--form", "--values-stdin"], {
      stdin: JSON.stringify(street),
    });
    assert.equal(home.json?.ok, true, home.stdout + home.stderr);
    const card = await cli(dir, ["add", "--name", "visa", "--type", "card", "--form", "--values-stdin"], {
      stdin: JSON.stringify({
        cardNumber: "4242424242424242",
        cardExpiry: "1234",
        cardSecurityCode: "123",
        cardholderName: "Anna Weber",
        ...street,
        saveBillingAddress: "true",
      }),
    });
    assert.equal(card.json?.ok, true, card.stdout + card.stderr);
    const listed = (await cli(dir, ["list"])).json.credentials;
    const kept = listed.find((c) => c.name === "home");
    assert.equal(kept.confirm, true, "the home address keeps the owner's answer");
    assert.equal(kept.description, null);
    assert.ok(listed.some((c) => c.name === "billing-1" && c.type === "address"));
  }));
