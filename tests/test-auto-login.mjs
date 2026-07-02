#!/usr/bin/env node

// Unit tests for the auto-login engine's deterministic pieces (lib/auto-login.mjs):
// placeholder substitution, recipe-step → page-call mapping with lazy {otp}
// resolution, and stored-TOTP code resolution. No real browser is launched.
//
// Run: node --test tests/test-auto-login.mjs

import { test } from "node:test";
import assert from "node:assert/strict";

import { applyVars, stepNeedsOtp, runRecipe, resolveOtp } from "../plugins/agent-id-browser/lib/auto-login.mjs";
import { generateTotp } from "../plugins/agent-id-core/lib/totp.mjs";

test("applyVars substitutes username/password/otp; passes non-strings through", () => {
  assert.equal(applyVars("{username}:{password}:{otp}", { username: "u", password: "p", otp: "123" }), "u:p:123");
  assert.equal(applyVars("nothing here", {}), "nothing here");
  assert.equal(applyVars(42, {}), 42);
});

test("stepNeedsOtp detects {otp} in a placeholder field", () => {
  assert.equal(stepNeedsOtp({ action: "fill", selector: "#code", value: "{otp}" }), true);
  assert.equal(stepNeedsOtp({ action: "fill", selector: "#pw", value: "{password}" }), false);
});

// A recording driver stands in for the human-input driver so the recipe
// mapping / var-substitution / lazy-OTP logic is tested without a browser.
function recordingDriver(calls) {
  return {
    navigate: async (_p, url) => calls.push(["goto", url]),
    fill: async (_p, sel, val) => calls.push(["fill", sel, val]),
    type: async (_p, sel, val) => calls.push(["type", sel, val]),
    click: async (_p, sel) => calls.push(["click", sel]),
    press: async (_p, sel, key) => calls.push(["press", sel, key]),
    wait: async (_p, ms) => calls.push(["wait", ms]),
  };
}

test("runRecipe maps steps to driver calls, substitutes vars, resolves {otp} once and lazily", async () => {
  const calls = [];
  let otpCalls = 0;
  const getOtp = async () => {
    otpCalls++;
    return "654321";
  };
  const steps = [
    { action: "navigate", url: "https://x/login" },
    { action: "fill", selector: "#user", value: "{username}" },
    { action: "fill", selector: "#pass", value: "{password}" },
    { action: "click", selector: "#submit" },
    { action: "fill", selector: "#otp", value: "{otp}" },
    { action: "press", selector: "#otp", key: "Enter" },
  ];
  await runRecipe({}, steps, {
    username: "alice",
    password: "s3cret",
    getOtp,
    driver: recordingDriver(calls),
  });
  assert.deepEqual(calls, [
    ["goto", "https://x/login"],
    ["fill", "#user", "alice"],
    ["fill", "#pass", "s3cret"],
    ["click", "#submit"],
    ["fill", "#otp", "654321"],
    ["press", "#otp", "Enter"],
  ]);
  assert.equal(otpCalls, 1);
});

test("runRecipe does not resolve OTP when no step needs it", async () => {
  let otpCalls = 0;
  await runRecipe({}, [{ action: "fill", selector: "#u", value: "{username}" }], {
    username: "u",
    password: "p",
    getOtp: async () => {
      otpCalls++;
      return "x";
    },
    driver: recordingDriver([]),
  });
  assert.equal(otpCalls, 0);
});

test("runRecipe rejects an unknown action", async () => {
  await assert.rejects(
    runRecipe({}, [{ action: "frobnicate" }], {
      username: "u",
      password: "p",
      getOtp: async () => "",
      driver: recordingDriver([]),
    }),
    /unknown recipe action/,
  );
});

test("resolveOtp generates a code from a stored TOTP seed (RFC vector)", async () => {
  const cred = { name: "demo", otp: "totp", totpSecret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", period: 30, digits: 6 };
  const code = await resolveOtp(cred, { now: 59_000 });
  assert.equal(code, "287082");
  assert.equal(code, generateTotp({ secret: cred.totpSecret, period: 30, digits: 6, now: 59_000 }));
});

test("resolveOtp throws when otp=totp but no seed is stored", async () => {
  await assert.rejects(resolveOtp({ name: "x", otp: "totp" }, {}), /totpSecret/);
});
