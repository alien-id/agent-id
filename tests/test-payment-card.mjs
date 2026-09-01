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
import {
  assertCardFieldShape,
  cardFieldShape,
  codeFieldLength,
  threeDsCardSpec,
} from "../plugins/agent-id-browser/lib/session-server.mjs";

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

// The refs come from the agent and the host check passes for the whole merchant
// page, so this is the only thing standing between a prompt injection and a card
// number in a box the page reads.
const cardInput = (overrides = {}) => ({
  tag: "input",
  inputType: "text",
  autocomplete: "cc-number",
  label: "cardnumber",
  maxLength: 19,
  isContentEditable: false,
  hasValue: false,
  ...overrides,
});

test("a card field must be an input, not a box that merely accepts text", () => {
  assert.doesNotThrow(() => assertCardFieldShape("number", cardInput()));
  assert.throws(() => assertCardFieldShape("number", cardInput({ tag: "textarea" })), /not a card input/);
  assert.throws(
    () => assertCardFieldShape("number", cardInput({ tag: "div", isContentEditable: true })),
    /not a card input/,
  );
  assert.throws(() => assertCardFieldShape("number", cardInput({ inputType: "search" })), /no card field is/);
  assert.throws(() => assertCardFieldShape("number", cardInput({ inputType: "email" })), /no card field is/);
});

test("the notes-to-seller box is refused however it is dressed up", () => {
  // A plain text input on the real checkout, with nothing saying it is a card
  // field. This is the shape an injection aims at, and the host check passes.
  assert.throws(
    () =>
      assertCardFieldShape(
        "number",
        cardInput({ autocomplete: "", label: "order notes for the seller", maxLength: null }),
      ),
    /does not identify itself/,
  );
});

test("a field too short for the value is not the field for it", () => {
  assert.throws(() => assertCardFieldShape("number", cardInput({ maxLength: 3 })), /too few for it/);
  assert.doesNotThrow(() => assertCardFieldShape("security_code", cardInput({ autocomplete: "cc-csc", label: "cvc", maxLength: 3 })));
});

test("a field that already holds something is left alone", () => {
  assert.throws(() => assertCardFieldShape("number", cardInput({ hasValue: true })), /already has a value/);
});

test("an honest form is accepted by its own words when it sets no autocomplete", () => {
  for (const [field, label] of [
    ["number", "ccNumber"],
    ["expiry", "card-expiration"],
    ["security_code", "CVV"],
    ["holder", "nameOnCard"],
  ]) {
    assert.doesNotThrow(
      () => assertCardFieldShape(field, cardInput({ autocomplete: "", label, maxLength: null })),
      `${field} via label ${label}`,
    );
  }
});

test("the provider's own frame is accepted by its autocomplete", () => {
  for (const [field, autocomplete] of [
    ["number", "cc-number"],
    ["expiry", "cc-exp"],
    ["security_code", "cc-csc"],
    ["holder", "cc-name"],
  ]) {
    assert.doesNotThrow(
      () => assertCardFieldShape(field, cardInput({ autocomplete, label: "", maxLength: null })),
      `${field} via autocomplete ${autocomplete}`,
    );
  }
});

test("the element is read in one round trip, attributes and all", async () => {
  const el = {
    tagName: "INPUT",
    id: "card-number",
    isContentEditable: false,
    value: "",
    getAttribute: (name) =>
      ({ type: "tel", autocomplete: "cc-number", maxlength: "19", name: "cardnumber" })[name] ?? null,
  };
  const target = { locator: () => ({ evaluate: async (fn) => fn(el) }) };

  const shape = await cardFieldShape(target, "e1");
  assert.equal(shape.tag, "input");
  assert.equal(shape.inputType, "tel");
  assert.equal(shape.autocomplete, "cc-number");
  assert.equal(shape.maxLength, 19);
  assert.equal(shape.hasValue, false);
  assert.doesNotThrow(() => assertCardFieldShape("number", shape));
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
