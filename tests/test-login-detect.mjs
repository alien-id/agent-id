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

// Regression: the exact false positive that sealed an UNauthenticated Reddit
// session — verbatim text captured from Reddit's real wall. It has no password
// field, no OTP affordance, and no credential-error copy (note: NO "try again"),
// so the OLD classifier returned "logged-in". It MUST now be "blocked".
test("blocked: Reddit's real network-security wall is NOT mistaken for logged-in", () => {
  assert.equal(
    classifyLogin({
      hasPasswordField: false,
      bodyText:
        "You've been blocked by network security. If you think you've been blocked by mistake, file a ticket below and we'll look into it.",
    }),
    "blocked",
  );
});

test("blocked: takes precedence over a vanished password field (logged-in) and over errors", () => {
  // No password field (would be "logged-in") + block copy → "blocked".
  assert.equal(classifyLogin({ hasPasswordField: false, bodyText: "unusual traffic detected" }), "blocked");
  // Block copy alongside a stray error phrase → still "blocked" (a wall, not a bad password).
  assert.equal(
    classifyLogin({ hasPasswordField: true, bodyText: "Verify you are human. try again" }),
    "blocked",
  );
});

test("blocked: an explicit blocked flag forces the outcome", () => {
  assert.equal(classifyLogin({ hasPasswordField: false, blocked: true, bodyText: "" }), "blocked");
});

test("blocked: a captcha / verification challenge is caught", () => {
  assert.equal(
    classifyLogin({ hasPasswordField: false, bodyText: "Are you a robot? Complete the challenge to continue." }),
    "blocked",
  );
});

test("NOT blocked: ordinary app copy that merely contains benign words stays logged-in", () => {
  assert.equal(
    classifyLogin({ hasPasswordField: false, bodyText: "Traffic report: your commute is clear today" }),
    "logged-in",
  );
});

test("NOT blocked: a legit page's Cloudflare footer does NOT trip the wall detector", () => {
  // The precision reason bare "cloudflare" was excluded from BLOCK_RE.
  assert.equal(
    classifyLogin({
      hasPasswordField: false,
      bodyText: "Welcome back!  •  Performance & security by Cloudflare",
    }),
    "logged-in",
  );
});

test("blocked: Google's real 'unusual traffic from your network' wall is caught", () => {
  assert.equal(
    classifyLogin({
      hasPasswordField: false,
      bodyText: "Our systems have detected unusual traffic from your computer network.",
    }),
    "blocked",
  );
});

// ── Device approval ─────────────────────────────────────────────────────────
//
// A push prompt shares body copy with OTP ("check your phone", "approve … sign
// in") but has no input: the sign-in completes when the owner taps Yes on their
// own device. Classifying it as "otp-required" sent the caller hunting for a
// code that never appears, so the login stalled until it timed out. It is also
// the cheapest challenge to satisfy — no secret has to be stored anywhere.

test("confirm-on-device: Google's push prompt is not mistaken for an OTP step", () => {
  assert.equal(
    classifyLogin({
      hasPasswordField: false,
      bodyText:
        "2-Step Verification\nCheck your phone\nGoogle sent a notification to your iPhone. Tap Yes to sign in.",
    }),
    "confirm-on-device",
  );
});

test("confirm-on-device: a number-match challenge", () => {
  assert.equal(
    classifyLogin({
      hasPasswordField: false,
      bodyText: "Open the Gmail app on your phone and tap 42 to sign in.",
    }),
    "confirm-on-device",
  );
});

test("otp-required still wins when the page has a code field (SMS shows both)", () => {
  assert.equal(
    classifyLogin({
      hasPasswordField: false,
      hasOtpField: true,
      bodyText: "Check your phone. Enter the 6-digit code we texted you.",
    }),
    "otp-required",
  );
});

test("otp-required still wins for an authenticator code with no device prompt", () => {
  assert.equal(
    classifyLogin({
      hasPasswordField: false,
      bodyText: "Enter the verification code from your authenticator app",
    }),
    "otp-required",
  );
});

test("blocked outranks a device prompt", () => {
  assert.equal(
    classifyLogin({
      hasPasswordField: false,
      bodyText: "Check your phone. But first, verify you are human.",
    }),
    "blocked",
  );
});

// ─── the identifier step is not a finished login ──────────────────────────────────

test("an e-mail-first screen is NOT mistaken for logged-in", () => {
  // Booking-shaped passwordless step 1: an identifier prompt, no password beside
  // it, and no code copy yet. Without the identifier signal this reads as success
  // and seals an unauthenticated session.
  assert.equal(
    classifyLogin({
      hasPasswordField: false,
      hasIdentifierField: true,
      bodyText: "Sign in or create an account\nEmail address\nContinue with email",
    }),
    "unknown",
  );
});

test("the identifier step yields to a code step once the code screen appears", () => {
  assert.equal(
    classifyLogin({
      hasPasswordField: false,
      hasIdentifierField: true,
      hasOtpField: true,
      bodyText: "Enter the 6-digit code we sent to a***@example.com",
    }),
    "otp-required",
  );
});

test("the identifier signal does not suppress a real logged-in page", () => {
  assert.equal(
    classifyLogin({ hasPasswordField: false, hasIdentifierField: false, bodyText: "Welcome back" }),
    "logged-in",
  );
});

test("the identifier signal does not outrank a block wall or a credential error", () => {
  assert.equal(
    classifyLogin({ hasIdentifierField: true, bodyText: "Verify you are human" }),
    "blocked",
  );
  assert.equal(
    classifyLogin({ hasIdentifierField: true, errorText: "That email is not recognized" }),
    "failed",
  );
});
