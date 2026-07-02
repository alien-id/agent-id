#!/usr/bin/env node

// Unit tests for the auto-login engine's deterministic pieces (lib/auto-login.mjs):
// placeholder substitution, recipe-step → page-call mapping with lazy {otp}
// resolution, and stored-TOTP code resolution. No real browser is launched.
//
// Run: node --test tests/test-auto-login.mjs

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  applyVars,
  stepNeedsOtp,
  runRecipe,
  resolveOtp,
  isLoginishPath,
  stillOnLoginPage,
  originOf,
  isDeepLoginUrl,
} from "../plugins/agent-id-browser/lib/auto-login.mjs";
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

// ── Positive-confirmation helpers (the "logged-in" false-positive guard) ──────────

test("isLoginishPath matches whole login/auth segments, not substrings", () => {
  for (const p of ["/login", "/login/", "/account/signin", "/oauth2/authorize", "/auth/callback", "/challenge"]) {
    assert.equal(isLoginishPath(p), true, `login-ish: ${p}`);
  }
  // "authors" must NOT match "auth"; app paths are not login-ish.
  for (const p of ["/", "/feed", "/authors/jane", "/r/test", "/user/me", "/settings"]) {
    assert.equal(isLoginishPath(p), false, `app path: ${p}`);
  }
});

test("stillOnLoginPage: true only when stuck on the same-host login page", () => {
  const loginUrl = "https://www.reddit.com/login";
  // The exact Reddit failure: form gone but still on /login with a js_challenge.
  assert.equal(
    stillOnLoginPage("https://www.reddit.com/login/?solution=abc&js_challenge=1", loginUrl),
    true,
  );
  // Real success leaves the login page (redirect to the feed) → confirmed.
  assert.equal(stillOnLoginPage("https://www.reddit.com/", loginUrl), false);
  assert.equal(stillOnLoginPage("https://www.reddit.com/r/programming/", loginUrl), false);
  // Left the auth host entirely → progressed.
  assert.equal(stillOnLoginPage("https://app.example.com/dashboard", loginUrl), false);
  // Garbage URLs don't wedge the caller into a false "stuck".
  assert.equal(stillOnLoginPage("not a url", loginUrl), false);
});

test("stillOnLoginPage: a modal login on the homepage isn't falsely flagged as stuck", () => {
  // loginUrl is the app homepage (login via modal, URL unchanged). After login we
  // are on "/" — NOT a login-ish path — so "logged-in" is confirmed, not rejected.
  assert.equal(stillOnLoginPage("https://app.example.com/", "https://app.example.com/"), false);
});

// ── Warmup helpers (the cold-deep-link block fix) ─────────────────────────────────

test("originOf returns scheme+host, null on garbage", () => {
  assert.equal(originOf("https://www.reddit.com/login/?x=1"), "https://www.reddit.com");
  assert.equal(originOf("http://host:8080/a/b"), "http://host:8080");
  assert.equal(originOf("not a url"), null);
});

test("isDeepLoginUrl: true for a real path, false for the bare origin root", () => {
  assert.equal(isDeepLoginUrl("https://www.reddit.com/login/"), true);
  assert.equal(isDeepLoginUrl("https://accounts.example.com/auth/signin"), true);
  // Bare root → nothing to warm up first.
  assert.equal(isDeepLoginUrl("https://www.reddit.com/"), false);
  assert.equal(isDeepLoginUrl("https://www.reddit.com"), false);
  assert.equal(isDeepLoginUrl("garbage"), false);
});
