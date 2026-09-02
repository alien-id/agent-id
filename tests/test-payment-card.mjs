#!/usr/bin/env node

// Unit tests for the card-payment pieces that are pure: the schema a stored card
// is validated against, and the 3-D Secure challenge card the owner answers.
// No browser and no vault are opened.
//
// Run: node --test tests/test-payment-card.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";

import { CREDENTIAL_TYPES, SECRET_FIELDS, validateRecord } from "../plugins/agent-id-vault/lib/store.mjs";
import {
  assertCardFieldShape,
  cardFieldShape,
  isCardField,
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
    "const siteName=()=>null, credentialHost=()=>null;\n" + source + "\nexport default formDescription;\n",
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

// The plaintext fill path takes its value from the caller, so a card must never
// arrive through it — and the DOM gives it nothing to notice, because a card number
// input is type="text". This is the check that closes it.
// The attributes Stripe Elements actually emits, read off a live mount rather than
// remembered — both the split fields and the combined element expose these same
// three inputs. Recorded here so the guard is pinned against the real thing
// without the suite needing Stripe, a network, or a key.
const STRIPE_FIELDS = {
  number: { autocomplete: "cc-number", label: "cardnumber Card number cardNumber" },
  expiry: { autocomplete: "cc-exp", label: "exp-date MM / YY cardExpiry" },
  security_code: { autocomplete: "cc-csc", label: "cvc CVC cardCvc" },
};
// Stripe plants these to spoil browser autofill. Nothing may ever type into one.
const STRIPE_DECOY = { autocomplete: "fake", label: "hidden" };

test("the guard accepts what Stripe Elements really emits", () => {
  for (const [field, attrs] of Object.entries(STRIPE_FIELDS)) {
    assert.doesNotThrow(
      () => assertCardFieldShape(field, cardInput({ ...attrs, maxLength: null })),
      `${field}: ${attrs.autocomplete}`,
    );
    assert.ok(isCardField(cardInput({ ...attrs, maxLength: null })));
  }
  // Stripe serves no cardholder-name field; that one is the merchant's own input.
  assert.doesNotThrow(() =>
    assertCardFieldShape("holder", cardInput({ autocomplete: "cc-name", label: "ccname", maxLength: null })),
  );
});

test("Stripe's autofill decoy is not a card field", () => {
  assert.ok(!isCardField(cardInput({ ...STRIPE_DECOY, maxLength: null })));
  assert.throws(
    () => assertCardFieldShape("number", cardInput({ ...STRIPE_DECOY, maxLength: null })),
    /does not identify itself/,
  );
});

// Separators are stripped from both the element's names and the word lists, so a
// form is matched however it spells one. Before that they were stripped from only
// one side, and a merchant writing `card-number` went unrecognised.
test("a name is matched however the form spells it", () => {
  for (const label of ["card-number", "card_number", "cardNumber", "CARDNUMBER"]) {
    assert.ok(isCardField(cardInput({ autocomplete: "", label, maxLength: null })), label);
  }
  // And the refusal stays narrow: this list also decides what form-fill turns away.
  for (const label of ["export", "experience", "expand"]) {
    assert.ok(!isCardField(cardInput({ autocomplete: "", label, maxLength: null })), label);
  }
});

test("a card box is recognised as one even when it cannot be filled", () => {
  assert.ok(isCardField(cardInput()));
  assert.ok(isCardField(cardInput({ hasValue: true })), "already filled is still a card box");
  assert.ok(isCardField(cardInput({ maxLength: 3 })), "a short one is still a card box");
  assert.ok(isCardField(cardInput({ autocomplete: "cc-csc", label: "" })));
  assert.ok(isCardField(cardInput({ autocomplete: "", label: "nameOnCard" })));

  assert.ok(!isCardField(cardInput({ autocomplete: "", label: "order notes for the seller" })));
  assert.ok(!isCardField(cardInput({ autocomplete: "email", label: "your email" })));
  assert.ok(!isCardField({ autocomplete: "", label: "" }));
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
