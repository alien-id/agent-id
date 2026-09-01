#!/usr/bin/env node

// Unit tests for the card-payment pieces that are pure: the schema a stored card
// is validated against, and the 3-D Secure challenge card the owner answers.
// No browser and no vault are opened.
//
// The five schema tests here are RED until two edits land in
// plugins/agent-id-vault/lib/store.mjs — `case "card"` calling validateCardFields
// inside validateRecord, and the four card fields inside SECRET_FIELDS. They are
// written first on purpose: they are the acceptance criteria for that wiring, and
// a card whose fields are missing from SECRET_FIELDS survives an idle lock.
//
// Run: node --test tests/test-payment-card.mjs

import { test } from "node:test";
import assert from "node:assert/strict";

import { CREDENTIAL_TYPES, SECRET_FIELDS, validateRecord } from "../plugins/agent-id-vault/lib/store.mjs";
import { codeFieldLength, threeDsCardSpec } from "../plugins/agent-id-browser/lib/session-server.mjs";

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

test("the challenge card quotes the payment, never the page", () => {
  const spec = threeDsCardSpec({ merchant: "checkout.example.com", amount: "42.00 EUR", length: 6 });

  assert.match(spec.description, /42\.00 EUR at checkout\.example\.com/);
  assert.equal(spec.fields.length, 1);
  assert.equal(spec.fields[0].name, "otp");
  // Not masked: a single-use code being copied off a phone is exactly the
  // transcription whose slips dots would hide.
  assert.equal(spec.fields[0].secret, false);
  assert.equal(spec.fields[0].placeholder, "••••••");
});

test("the challenge card still stands up when the payment is not quotable", () => {
  const spec = threeDsCardSpec({ merchant: "", amount: "", length: null });

  assert.match(spec.description, /your bank sent a code/i);
  assert.ok(!("placeholder" in spec.fields[0]), "no length means a plain field, not guessed cells");
});

test("only a length the screen can draw cells for is passed on", async () => {
  const target = (maxlength) => ({
    locator: () => ({ evaluate: async (fn) => fn({ getAttribute: () => maxlength }) }),
  });

  assert.equal(await codeFieldLength(target("6"), "e1"), 6);
  assert.equal(await codeFieldLength(target("4"), "e1"), 4);
  assert.equal(await codeFieldLength(target("8"), "e1"), 8);
  assert.equal(await codeFieldLength(target("3"), "e1"), null);
  assert.equal(await codeFieldLength(target("40"), "e1"), null);
  assert.equal(await codeFieldLength(target(null), "e1"), null);
  assert.equal(await codeFieldLength(target("six"), "e1"), null);
});
