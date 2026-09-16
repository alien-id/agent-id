#!/usr/bin/env node

// Unit tests for the stored card's schema, and for the copy on the form the
// owner types it into. No browser and no vault are opened.
//
// Run: node --test tests/test-payment-card.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";

import { CREDENTIAL_TYPES, SECRET_FIELDS, validateRecord } from "../plugins/agent-id-vault/lib/store.mjs";

// A Luhn-valid test number (the Visa test PAN every processor publishes).
const GOOD_PAN = "4242424242424242";

function card(overrides = {}) {
  return {
    name: "visa",
    type: "card",
    domains: [],
    cardNumber: GOOD_PAN,
    cardExpiry: "1234",
    cardSecurityCode: "123",
    cardholderName: "Alien Owner",
    ...overrides,
  };
}

test("a card is a credential type the vault knows", () => {
  assert.ok(CREDENTIAL_TYPES.includes("card"));
});

test("every field of a card is secret-bearing, so a lock wipes all of it", () => {
  for (const field of ["cardNumber", "cardExpiry", "cardSecurityCode", "cardholderName"]) {
    assert.ok(SECRET_FIELDS.includes(field), `${field} would survive an idle lock`);
  }
});

test("a card starts with no merchant granted, and that is not an error", () => {
  assert.doesNotThrow(() => validateRecord(card()));
});

test("a mistyped number is refused at the point of storage", () => {
  assert.throws(() => validateRecord(card({ cardNumber: "4242424242424243" })), /Luhn/);
  assert.throws(() => validateRecord(card({ cardNumber: "4242 4242 4242 4242" })), /12-19 digits/);
  assert.throws(() => validateRecord(card({ cardNumber: "424242424242424242424" })), /12-19 digits/);
});

test("an expiry must be a real month, and still ahead", () => {
  assert.throws(() => validateRecord(card({ cardExpiry: "1324" })), /01-12/);
  assert.throws(() => validateRecord(card({ cardExpiry: "12/34" })), /MMYY/);
  assert.throws(() => validateRecord(card({ cardExpiry: "0120" })), /in the past/);
});

test("a security code is three or four digits", () => {
  assert.doesNotThrow(() => validateRecord(card({ cardSecurityCode: "1234" })));
  assert.throws(() => validateRecord(card({ cardSecurityCode: "12" })), /3 or 4 digits/);
  assert.throws(() => validateRecord(card({ cardSecurityCode: "12a" })), /3 or 4 digits/);
});

test("a card missing any field is not a card", () => {
  for (const field of ["cardNumber", "cardExpiry", "cardSecurityCode", "cardholderName"]) {
    const incomplete = card();
    delete incomplete[field];
    assert.throws(() => validateRecord(incomplete), new RegExp(field));
  }
});

// The screen where somebody types a card number is the one place trust is the
// whole point, so what it says is worth pinning. The `ro` grant sentence used to
// land here — "the agent can read this, never change it" — directly above a
// security note promising the agent never sees the value.
test("the card form does not tell the owner the agent can read their card", async () => {
  const cli = await readFile(
    new URL("../plugins/agent-id-vault/bin/cli.mjs", import.meta.url),
    "utf8",
  );
  const source = cli.slice(
    cli.indexOf("function formDescription"),
    cli.indexOf("function formFieldsForType"),
  );
  const scratch = path.join(await mkdtemp(path.join(os.tmpdir(), "card-copy-")), "fd.mjs");
  await writeFile(
    scratch,
    "const siteName=()=>null, credentialHost=()=>null, saveToVaultBoxEnabled=()=>true;\n" +
      source +
      "\nexport default formDescription;\n",
  );
  const formDescription = (await import(`file://${scratch}`)).default;

  const card = formDescription({ name: "visa", type: "card", domains: [], access: "ro" });
  assert.ok(!/can read this/i.test(card), card);
  assert.ok(!/\bvisa\b/.test(card), "the name the agent invented is not the owner's business");
  assert.match(card, /approve every payment/i);

  // And the sentence is still there for a login, where it means what it says.
  const login = formDescription({ name: "booking", type: "login", domains: ["booking.com"], access: "ro" });
  assert.match(login, /can read this, never change it/);

  await rm(path.dirname(scratch), { recursive: true, force: true });
});
