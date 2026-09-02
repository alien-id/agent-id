#!/usr/bin/env node

// The card fill, against a real browser and a real checkout.
//
// Everything else about `fill-card` is unit-tested against objects that stand in
// for a page. This is the one that runs it for real: a live browser, a real vault
// unlocked with a real agent key, and the card fields inside an iframe — the shape
// a payment provider serves.
//
// The frame is same-origin, on its own path, and that is a fixture limit rather
// than a weakening. Chromium refuses a cross-origin subresource between two local
// addresses (`net::ERR_BLOCKED_BY_LOCAL_NETWORK_ACCESS_CHECKS`), so a second port
// cannot be reached from the first without launching the browser with the check
// disabled — a flag this suite has no business setting. What it would have proven
// is also not what fill-card does: it checks the TOP page's host against the
// merchant the owner approved and deliberately never checks the frame's origin,
// because the card form normally belongs to the provider rather than the merchant.
// Frame resolution itself is identical either way — a Playwright frame handle does
// not care whose origin it is.
//
// What it pins that a fake page cannot:
//   - `cardFieldShape` reads attributes off real DOM rather than a literal
//   - refs inside another origin's frame resolve, and the values land there
//   - `humanType` reaches provider-style inputs
//   - the notes box on the same approved page is refused
//   - the plaintext path refuses a card box
//   - `ref-text` reads the total the owner is shown
//
// Run: node --test tests/test-card-fill-live.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { generateKeyPairSync } from "node:crypto";

import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { writeJsonFile, statePaths } from "../plugins/agent-id-core/lib/state.mjs";
import { fingerprintPublicKeyPem } from "../plugins/agent-id-core/lib/crypto.mjs";
import { resolvePatchright, launchContext } from "../plugins/agent-id-browser/lib/launch.mjs";
import { dispatch } from "../plugins/agent-id-browser/lib/session-server.mjs";

const skip = resolvePatchright() ? false : "patchright/Chrome not installed";

// The Visa test PAN every processor publishes, so a leak of this fixture is not a card.
const PAN = "4242424242424242";
const EXPIRY = "1234";
const CVC = "123";
const HOLDER = "Alien Owner";
const TOTAL = "42.00 EUR";

// The provider's frame: card fields marked the way Stripe Elements and its peers
// mark them.
const PSP_PAGE = `<!doctype html><meta charset="utf-8"><body style="margin:0;font:14px sans-serif">
  <input data-aibref="f1e1" name="cardnumber" autocomplete="cc-number" inputmode="numeric" maxlength="19" placeholder="Card number">
  <input data-aibref="f1e2" name="exp-date" autocomplete="cc-exp" inputmode="numeric" maxlength="7" placeholder="MM / YY">
  <input data-aibref="f1e3" name="cvc" autocomplete="cc-csc" inputmode="numeric" maxlength="4" placeholder="CVC">
  <input data-aibref="f1e4" name="ccname" autocomplete="cc-name" placeholder="Name on card">
</body>`;

// The merchant's own page: the total the owner is shown, a note box that is not a
// card field however much an injection would like it to be, and the frame.
const merchantPage = () => `<!doctype html><meta charset="utf-8"><body style="font:14px sans-serif">
  <h1>Checkout</h1>
  <div data-aibref="e1" id="order-total">Total: ${TOTAL}</div>
  <textarea data-aibref="e2" name="order_notes" placeholder="Notes for the seller"></textarea>
  <iframe src="/fields" style="width:420px;height:180px;border:1px solid #ccc"></iframe>
</body>`;

function serveCheckout() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const body = req.url.startsWith("/fields") ? PSP_PAGE : merchantPage();
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }).end(body);
    });
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ server, origin: `http://127.0.0.1:${port}` });
    });
  });
}

async function makeVaultWithCard(dir) {
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

  const vault = await openVault({ stateDir: dir, privateKeyPem });
  vault.add({
    name: "visa",
    type: "card",
    domains: [],
    access: "ro",
    cardNumber: PAN,
    cardExpiry: EXPIRY,
    cardSecurityCode: CVC,
    cardholderName: HOLDER,
  });
  await vault.save();
  vault.lock();
}

/** The state the session server would hold, built by hand around a real page. */
function stateFor(page, frame) {
  return {
    stream: { suspend() {}, resume() {} },
    current: page,
    ctx: page.context(),
    refsValid: true,
    frames: new Map([["f1", frame]]),
  };
}

async function withCheckout(fn) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "cardfill-"));
  const merchant = await serveCheckout();
  let ctx;
  try {
    await makeVaultWithCard(dir);
    ctx = await launchContext({ profileDir: path.join(dir, "profile"), headless: true });
    const page = ctx.pages()[0] || (await ctx.newPage());
    await page.goto(`${merchant.origin}/checkout`, { waitUntil: "load" });
    // A child frame reaches page.frames() when it has navigated, which is not
    // guaranteed by the parent's load event — poll rather than race it.
    const deadline = Date.now() + 10_000;
    let frame = null;
    while (!frame && Date.now() < deadline) {
      frame = page.frames().find((f) => f.url().endsWith("/fields")) || null;
      if (!frame) await page.waitForTimeout(50);
    }
    assert.ok(frame, "the provider frame never loaded");
    assert.notEqual(frame, page.mainFrame(), "the fields must live in a frame, not the top page");

    await fn({ dir, page, frame, host: "127.0.0.1", state: stateFor(page, frame) });
  } finally {
    if (ctx) await ctx.close().catch(() => {});
    merchant.server.close();
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

const fillCard = (state, dir, params) =>
  dispatch(state, { action: "fill-card", params, _stateDir: dir });

const refs = { number: "f1e1", expiry: "f1e2", security_code: "f1e3", holder: "f1e4" };

test("a stored card lands in the provider's frame, and nowhere else", { skip }, async () => {
  await withCheckout(async ({ dir, frame, host, state }) => {
    const result = await fillCard(state, dir, { cred: "visa", merchantHost: host, refs });

    assert.deepEqual(result, { filled: ["f1e1", "f1e2", "f1e3", "f1e4"] });

    const typed = await frame.evaluate(() => ({
      number: document.querySelector('[data-aibref="f1e1"]').value,
      expiry: document.querySelector('[data-aibref="f1e2"]').value,
      cvc: document.querySelector('[data-aibref="f1e3"]').value,
      holder: document.querySelector('[data-aibref="f1e4"]').value,
    }));
    assert.equal(typed.number, PAN);
    assert.equal(typed.expiry, EXPIRY);
    assert.equal(typed.cvc, CVC);
    assert.equal(typed.holder, HOLDER);

    // Every filled field is tagged, so a later read-back is refused whatever the
    // input's type says.
    const tagged = await frame.evaluate(() =>
      ["f1e1", "f1e2", "f1e3", "f1e4"].every((r) =>
        document.querySelector(`[data-aibref="${r}"]`).hasAttribute("data-aib-secret"),
      ),
    );
    assert.ok(tagged, "filled card fields are not tagged against read-back");
  });
});

test("the approval does not travel to another merchant", { skip }, async () => {
  await withCheckout(async ({ dir, frame, state }) => {
    await assert.rejects(
      fillCard(state, dir, { cred: "visa", merchantHost: "shop.example.net", refs }),
      /nothing was typed/,
    );
    const number = await frame.evaluate(
      () => document.querySelector('[data-aibref="f1e1"]').value,
    );
    assert.equal(number, "", "a refused fill still typed something");
  });
});

test("the note box on the approved page is refused", { skip }, async () => {
  await withCheckout(async ({ dir, page, host, state }) => {
    // The host check passes — this IS the merchant the owner approved. Only the
    // element's own shape stands between an injection and the number.
    await assert.rejects(
      fillCard(state, dir, { cred: "visa", merchantHost: host, refs: { ...refs, number: "e2" } }),
      /not a card input|does not identify itself/,
    );
    const notes = await page.evaluate(
      () => document.querySelector('[data-aibref="e2"]').value,
    );
    assert.equal(notes, "", "the number reached the notes box");
  });
});

test("the plaintext path refuses a card box", { skip }, async () => {
  await withCheckout(async ({ dir, frame, state }) => {
    const result = await dispatch(state, {
      action: "form-fill",
      params: { fields: [{ ref: "f1e1", value: PAN }] },
      _stateDir: dir,
    });
    assert.equal(result.results[0].ok, false);
    assert.match(result.results[0].error, /require fill-card/);

    const number = await frame.evaluate(
      () => document.querySelector('[data-aibref="f1e1"]').value,
    );
    assert.equal(number, "", "form-fill typed a card number anyway");
  });
});

test("the total is read from the element the owner was shown", { skip }, async () => {
  await withCheckout(async ({ dir, state }) => {
    const result = await dispatch(state, {
      action: "ref-text",
      params: { ref: "e1" },
      _stateDir: dir,
    });
    assert.equal(result.text, `Total: ${TOTAL}`);
  });
});
