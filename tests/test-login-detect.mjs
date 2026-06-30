#!/usr/bin/env node

// Unit tests for the 3-way login-outcome classifier (lib/login-detect.mjs).
// Pure — no browser.
//
// Run: node --test tests/test-login-detect.mjs

import { test } from "node:test";
import assert from "node:assert/strict";

import { classifyLogin } from "../plugins/agent-id-browser/lib/login-detect.mjs";

test("logged-in: no password field, no otp, no error", () => {
  assert.equal(classifyLogin({ hasPasswordField: false, bodyText: "Welcome back, alice" }), "logged-in");
});

test("otp-required: a one-time-code input is present", () => {
  assert.equal(classifyLogin({ hasPasswordField: false, hasOtpField: true }), "otp-required");
});

test("otp-required: an OTP-ish field name", () => {
  assert.equal(classifyLogin({ hasPasswordField: false, otpFieldNames: ["totp_code"] }), "otp-required");
});

test("otp-required: body copy describes 2FA (even with a password field still present)", () => {
  assert.equal(
    classifyLogin({
      hasPasswordField: true,
      bodyText: "Enter the verification code from your authenticator app",
    }),
    "otp-required",
  );
});

test("otp-required takes precedence over an error message", () => {
  assert.equal(
    classifyLogin({ hasPasswordField: false, hasOtpField: true, bodyText: "invalid code, try again" }),
    "otp-required",
  );
});

test("failed: a credential error and no OTP affordance", () => {
  assert.equal(
    classifyLogin({ hasPasswordField: true, bodyText: "That password is incorrect. Try again." }),
    "failed",
  );
});

test("unknown: password field present, no error, no OTP", () => {
  assert.equal(classifyLogin({ hasPasswordField: true, bodyText: "Sign in to continue" }), "unknown");
});

test("a bare 'code' field name (postal_code / promo code) does NOT trigger OTP", () => {
  assert.equal(
    classifyLogin({
      hasPasswordField: false,
      otpFieldNames: ["postal_code", "promo code", "username"],
      bodyText: "Welcome",
    }),
    "logged-in",
  );
});
