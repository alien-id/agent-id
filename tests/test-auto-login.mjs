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

test("runRecipe maps steps to page calls, substitutes vars, resolves {otp} once and lazily", async () => {
  const calls = [];
  const page = {
    goto: async (url) => calls.push(["goto", url]),
    fill: async (sel, val) => calls.push(["fill", sel, val]),
    click: async (sel) => calls.push(["click", sel]),
    press: async (sel, key) => calls.push(["press", sel, key]),
    waitForTimeout: async (ms) => calls.push(["wait", ms]),
  };
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
  await runRecipe(page, steps, { username: "alice", password: "s3cret", getOtp });
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
  const noop = async () => {};
  const page = { goto: noop, fill: noop, click: noop, press: noop, waitForTimeout: noop };
  let otpCalls = 0;
  await runRecipe(page, [{ action: "fill", selector: "#u", value: "{username}" }], {
    username: "u",
    password: "p",
    getOtp: async () => {
      otpCalls++;
      return "x";
    },
  });
  assert.equal(otpCalls, 0);
});

test("runRecipe rejects an unknown action", async () => {
  await assert.rejects(
    runRecipe({ goto: async () => {} }, [{ action: "frobnicate" }], {
      username: "u",
      password: "p",
      getOtp: async () => "",
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
