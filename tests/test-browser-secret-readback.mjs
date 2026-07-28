#!/usr/bin/env node

// Proof that a secret typed into a NON-password field can't be read back by the
// controlling agent — the two leak paths fill-secret/fill-otp used to leave open:
//
//   1. `snapshot` used el.value as the element's name fallback for any input, so
//      a value the vault typed (OTP into a type=text field, or a password field
//      flipped to type=text by a show-password toggle) surfaced in a later
//      snapshot.
//   2. `get --what value` returned inputValue guarded only by a type==="password"
//      check, so the same non-password field read straight back.
//
// The fix tags a filled field with SECRET_TAINT_ATTR (markSecretField); snapshot
// suppresses the el.value name fallback for every text-entry field, and
// refusePasswordRead refuses any tainted field regardless of type.
//
// LIVE real-browser test (snapshotInPage / the read-back guard run against actual
// DOM), so it SKIPS automatically when patchright / Chrome are not installed.
//
// Run: node --test tests/test-browser-secret-readback.mjs

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { resolvePatchright, launchContext } from "../plugins/agent-id-browser/lib/launch.mjs";
import {
  snapshotInPage,
  formSnapshotInPage,
  fillForm,
  refusePasswordRead,
  markSecretField,
  SECRET_TAINT_ATTR,
} from "../plugins/agent-id-browser/lib/session-server.mjs";

const patchrightAvailable = !!resolvePatchright();

// A login form standing in for the real thing: a password field, an OTP-style
// text field, a benign text field, and a submit button (whose value IS its
// visible label). The OTP/benign fields carry a value but NO aria-label /
// placeholder / name, so el.value is the only fallback that could surface them.
const FORM = `<!doctype html><meta charset=utf-8><title>login</title><form>
  <label for="pw">Password</label><input id="pw" type="password" value="hunter2" required>
  <input id="otp" type="text" autocomplete="one-time-code" value="778899">
  <input id="who" name="full_name" type="text" value="alice@example.com">
  <label for="plain">Plain text</label><input id="plain" name="plain">
  <label><input id="agree" type="checkbox" style="display:none"> Agree to terms</label>
  <label for="resume">Resume</label><input id="resume" type="file" style="display:none" accept=".pdf">
  <select id="degree" name="degree"><option value="bs">Bachelor's</option><option value="ms">Master's</option></select>
  <input id="go" type="submit" value="Sign in">
</form>`;

let ctx;
let workDir;
let page;

before(async () => {
  if (!patchrightAvailable) return;
  workDir = await fs.mkdtemp(path.join(os.tmpdir(), "secret-readback-"));
  ctx = await launchContext({ profileDir: workDir, headless: true, contextOptions: {} });
  page = ctx.pages()[0] || (await ctx.newPage());
  await page.setContent(FORM, { waitUntil: "domcontentloaded" });
});

after(async () => {
  if (ctx) await ctx.close().catch(() => {});
  if (workDir) await fs.rm(workDir, { recursive: true, force: true }).catch(() => {});
});

const skip = patchrightAvailable ? false : "patchright/Chrome not installed";

test("snapshot never surfaces a text field's value, but keeps a submit's label", { skip }, async () => {
  const snap = await page.evaluate(snapshotInPage, { prefix: "", generation: 1 });
  const names = snap.elements.map((e) => e.name);

  // Leak path 1 is closed: neither the OTP value nor the benign text value
  // appears as any element's accessible name.
  assert.ok(!names.includes("778899"), "OTP value must not leak into snapshot names");
  assert.ok(!names.includes("alice@example.com"), "text-field value must not leak into snapshot names");
  assert.ok(
    !snap.elements.some((e) => /778899|alice@example\.com|hunter2/.test(e.name)),
    "no field value may appear anywhere in a snapshot name",
  );

  // A submit button's value is a visible caption, not user content — still shown.
  assert.ok(names.includes("Sign in"), "a submit button's value is its label and stays visible");
});

test("form snapshot is compact, labelled, and includes hidden native controls", { skip }, async () => {
  const snap = await page.evaluate(formSnapshotInPage, { prefix: "", generation: 1 });
  assert.ok(Array.isArray(snap.controls));
  assert.ok(!JSON.stringify(snap).includes("hunter2"), "password value must never appear");
  assert.ok(!JSON.stringify(snap).includes("alice@example.com"), "text value must never appear");

  const password = snap.controls.find((control) => control.type === "password");
  assert.equal(password.label, "Password");
  assert.equal(password.required, true);

  const plain = snap.controls.find((control) => control.name === "plain");
  assert.equal(plain.type, "text", "an input without an explicit type defaults to text");

  const checkbox = snap.controls.find((control) => control.type === "checkbox");
  assert.equal(checkbox.hidden, true);
  assert.match(checkbox.label, /Agree to terms/);

  const upload = snap.controls.find((control) => control.type === "file");
  assert.equal(upload.hidden, true);
  assert.equal(upload.accept, ".pdf");

  const degree = snap.controls.find((control) => control.type === "select");
  assert.deepEqual(degree.options.map((option) => option.value), ["bs", "ms"]);
});

test("atomic form fill handles text, hidden checks, selects, and verifies each", { skip }, async () => {
  const snap = await page.evaluate(formSnapshotInPage, { prefix: "", generation: 1 });
  const text = snap.controls.find((control) => control.name === "full_name");
  const checkbox = snap.controls.find((control) => control.type === "checkbox");
  const degree = snap.controls.find((control) => control.name === "degree");
  const state = {
    current: page,
    frames: new Map(),
    refsValid: true,
    refsInvalidReason: null,
  };
  const result = await fillForm(state, {
    fields: [{ ref: text.ref, value: "Grace Hopper" }],
    checks: [{ ref: checkbox.ref, checked: true }],
    selects: [{ ref: degree.ref, values: ["ms"] }],
  });
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.completed, 3);
  assert.equal(result.failed, 0);
  assert.ok(result.results.every((entry) => entry.ok));
  assert.deepEqual(
    await page.evaluate(() => ({
      who: document.querySelector("#who").value,
      agree: document.querySelector("#agree").checked,
      degree: document.querySelector("#degree").value,
    })),
    { who: "Grace Hopper", agree: true, degree: "ms" },
  );
});

test("ordinary form fill refuses password fields without echoing the value", { skip }, async () => {
  const snap = await page.evaluate(formSnapshotInPage, { prefix: "", generation: 1 });
  const password = snap.controls.find((control) => control.type === "password");
  const result = await fillForm(
    { current: page, frames: new Map(), refsValid: true, refsInvalidReason: null },
    { fields: [{ ref: password.ref, value: "never-echo-this" }] },
  );
  assert.equal(result.ok, false);
  assert.equal(result.failed, 1);
  assert.match(result.results[0].error, /fill-secret|fill-otp/);
  assert.ok(!JSON.stringify(result).includes("never-echo-this"));
});

test("read-back guard: password refused, benign text allowed, tainted field refused", { skip }, async () => {
  // A password field is refused (the original guard).
  await assert.rejects(() => refusePasswordRead(page, "#pw"), /password|secret/i);

  // A benign, un-tainted text field is readable — the guard must not over-block.
  await assert.doesNotReject(() => refusePasswordRead(page, "#who"));

  // Before tainting, the OTP text field reads back (this is exactly the old leak).
  await assert.doesNotReject(() => refusePasswordRead(page, "#otp"));

  // markSecretField tags it; now leak path 2 is closed regardless of type=text.
  await markSecretField(page, "#otp");
  const tagged = await page.$eval("#otp", (el, attr) => el.hasAttribute(attr), SECRET_TAINT_ATTR);
  assert.equal(tagged, true, "markSecretField must set the taint attribute");
  await assert.rejects(() => refusePasswordRead(page, "#otp"), /secret/i);
});

test("taint survives a re-snapshot and keeps suppressing the value", { skip }, async () => {
  // snapshot clears data-aibref but leaves the taint attribute, so a field the
  // vault filled stays protected across the re-snapshots the agent does between
  // steps of a login flow.
  await markSecretField(page, "#otp");
  const snap = await page.evaluate(snapshotInPage, { prefix: "", generation: 1 });
  const stillTainted = await page.$eval("#otp", (el, attr) => el.hasAttribute(attr), SECRET_TAINT_ATTR);
  assert.equal(stillTainted, true, "re-snapshot must not strip the taint attribute");
  assert.ok(
    !snap.elements.some((e) => e.name === "778899"),
    "a tainted field's value stays out of snapshot names after re-snapshot",
  );
  await assert.rejects(() => refusePasswordRead(page, "#otp"), /secret/i);
});
