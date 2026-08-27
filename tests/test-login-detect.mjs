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
      onLoginPage: true,
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
      onLoginPage: true,
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
    classifyLogin({ hasIdentifierField: true, onLoginPage: true, bodyText: "Verify you are human" }),
    "blocked",
  );
  assert.equal(
    classifyLogin({ hasIdentifierField: true, onLoginPage: true, errorText: "That email is not recognized" }),
    "failed",
  );
});

// ─── the shapes real services actually use ────────────────────────────────────────
//
// The first cut of the passwordless work was written against one site and silently
// assumed all of them looked like it. These are the snapshots detectPageState
// produces for a spread of real sign-ins; each one used to come back "logged-in",
// which seals an unauthenticated profile and reports success.

const IDENTIFIER_STEPS = [
  ["booking, e-mail first", "Sign in or create an account\nEmail address\nContinue with email"],
  ["slack, e-mail first", "Sign in to your workspace\nyou@example.com\nSign In With Email"],
  ["notion, e-mail first", "Think it. Make it.\nEmail\nContinue"],
  ["airbnb, phone first", "Log in or sign up\nCountry/Region\nPhone number\nContinue"],
  ["uber, phone first", "Enter your mobile number"],
  ["telegram, phone first", "Sign in to Telegram\nPlease confirm your country code and enter your phone number."],
];

for (const [name, bodyText] of IDENTIFIER_STEPS) {
  test(`identifier step (${name}) is not a finished login`, () => {
    assert.equal(classifyLogin({ hasIdentifierField: true, onLoginPage: true, bodyText }), "unknown");
  });
}

const CODE_STEPS = [
  ["booking", { hasOtpField: true, bodyText: "Enter your verification code\nWe've sent a 6-digit code to a***@example.com" }],
  // Spells the digit count out; no autocomplete hint on the split inputs.
  ["slack", { bodyText: "Check your email for a code\nWe've sent a six-digit code to you@example.com." }],
  // Says "login code", which no earlier vocabulary covered.
  ["notion", { otpFieldNames: ["Enter code"], bodyText: "Check your inbox\nEnter the login code we just emailed you." }],
  ["airbnb sms", { hasOtpField: true, bodyText: "Confirm your number\nEnter the code we sent to +1 ***" }],
  ["amazon", { otpFieldNames: ["otpCode"], bodyText: "Two-Step Verification\nEnter OTP" }],
  ["confirmation-code wording", { bodyText: "We emailed you a confirmation code. Please enter it below." }],
  ["access-code wording", { bodyText: "Enter the access code sent to your email" }],
];

for (const [name, snap] of CODE_STEPS) {
  test(`code step (${name}) asks for a code`, () => {
    assert.equal(classifyLogin(snap), "otp-required");
  });
}

test("a mailed sign-in LINK is neither a code step nor a finished login", () => {
  // Nothing to type, and the link authenticates whichever browser opens it — so
  // this must not read as success, and must not send anyone hunting for a code.
  assert.equal(
    classifyLogin({ bodyText: "Check your email\nWe sent a login link to you@example.com. Click it to sign in." }),
    "magic-link",
  );
  assert.equal(
    classifyLogin({ bodyText: "We emailed a magic link to you@example.com" }),
    "magic-link",
  );
  assert.equal(
    classifyLogin({ bodyText: "Click the link in the email we just sent to finish signing in." }),
    "magic-link",
  );
});

test("a page offering BOTH a link and a code is an ordinary code step", () => {
  assert.equal(
    classifyLogin({
      hasOtpField: true,
      bodyText: "We sent a magic link to you@example.com — or enter the 6-digit code below.",
    }),
    "otp-required",
  );
});

// ─── the widened vocabulary must not fire on ordinary pages ───────────────────────
//
// Every one of these sits on a page where the login already SUCCEEDED. A false
// "otp-required" stalls the flow until timeout; a false "magic-link" turns a
// completed sign-in into a handover.

const SIGNED_IN_PAGES = [
  ["a promo code", "Welcome back!\nEnter your promo code at checkout for 10% off"],
  ["a discount code", "My trips\nYour discount code has been applied"],
  ["a postal code", "Billing address\nPostal code\nCountry"],
  ["a zip code", "Shipping\nZip code 10001"],
  ["a country code", "Profile\nPhone: country code +1"],
  ["a QR code", "Dashboard\nScan the QR code to open on mobile"],
  ["source code", "Repositories\nBrowse the source code"],
  ["a coupon code", "Cart\nHave a coupon code?"],
  ["a referral code", "Invite friends\nShare your referral code"],
  ["someone sharing a link", "Messages\nAlice sent you a link to the doc"],
  ["a shared link", "Inbox\nBob shared a link with you"],
];

for (const [name, bodyText] of SIGNED_IN_PAGES) {
  test(`${name} on a signed-in page stays logged-in`, () => {
    assert.equal(classifyLogin({ hasPasswordField: false, bodyText }), "logged-in");
  });
}

// ─── QR sign-in: found by probing telegram.org's real markup ──────────────────────

test("a QR sign-in screen is neither a finished login nor something to type into", () => {
  // A screen whose only affordance is a code to scan has no form left, so it was
  // otherwise indistinguishable from being signed in.
  for (const bodyText of [
    "Log in to Telegram by QR Code\nOpen Telegram on your phone\nPoint your phone at this screen",
    "Scan to log in\nLink with phone number instead.\nScan the QR code with your phone's camera",
    "Log in with QR Code\nScan with the Discord mobile app to log in instantly.",
  ]) {
    assert.equal(classifyLogin({ bodyText }), "qr-sign-in");
  }
});

test("a QR code that is not a sign-in leaves a signed-in page alone", () => {
  for (const bodyText of [
    "Dashboard\nScan the QR code to open on mobile",
    "Settings\nShow QR code for this device",
    "Tickets\nYour boarding pass QR code",
  ]) {
    assert.equal(classifyLogin({ hasPasswordField: false, bodyText }), "logged-in");
  }
});

test("a QR screen that also offers a code field is an ordinary code step", () => {
  assert.equal(
    classifyLogin({
      hasOtpField: true,
      bodyText: "Log in with QR code, or enter the 6-digit code we sent you",
    }),
    "otp-required",
  );
});

// ─── what the widened vocabulary must NOT do ──────────────────────────────────────
//
// Each of these was a live regression: the vocabulary was widened until real
// sign-in screens matched, without a pass over what those alternatives do to
// ordinary pages. Every one turns a login that SUCCEEDED into a failure — the
// expensive direction, since the caller then never seals the session.

test("an identifier field off the sign-in page is a newsletter box, not a sign-in step", () => {
  const snap = {
    hasPasswordField: false,
    hasIdentifierField: true,
    bodyText: "Welcome back, Daniel\nMy trips\nSubscribe to our newsletter",
  };
  assert.equal(classifyLogin({ ...snap, onLoginPage: false }), "logged-in");
  // On the sign-in page the same shape still means the sign-in has not started.
  assert.equal(classifyLogin({ ...snap, onLoginPage: true }), "unknown");
});

test("'the link' copy that is not about signing in leaves a signed-in page alone", () => {
  for (const bodyText of [
    "Welcome back! Open the link in a new tab to view your itinerary",
    "Click the link in the description below to watch",
    "Messages\nAlice sent you a link to the doc",
  ]) {
    assert.equal(classifyLogin({ hasPasswordField: false, bodyText }), "logged-in");
  }
});

test("'signin' inside an ordinary word is not a QR sign-in", () => {
  // No word boundary meant "signin" was found inside "designing" and "assigning".
  for (const bodyText of [
    "Designing QR codes for your storefront",
    "Assigning a QR code to each table",
    "Resigning from the QR pilot",
  ]) {
    assert.equal(classifyLogin({ hasPasswordField: false, bodyText }), "logged-in");
  }
});

test("a QR that signs you in ELSEWHERE is the linked-devices panel, not a sign-in screen", () => {
  for (const bodyText of [
    "Scan the QR code to sign in on another device",
    "Linked devices\nUse the QR code to log in on your phone",
  ]) {
    assert.equal(classifyLogin({ hasPasswordField: false, bodyText }), "logged-in");
  }
  assert.equal(classifyLogin({ bodyText: "Scan the QR code to sign in" }), "qr-sign-in");
});

test("'access code' is ordinary copy and must not raise a card for a code that does not exist", () => {
  for (const bodyText of [
    "Meeting access code: 482 910",
    "Enter the access code at checkout for members",
  ]) {
    assert.equal(classifyLogin({ hasPasswordField: false, bodyText }), "logged-in");
  }
});

test("an unqualified 'enter the code' still reads as a code step", () => {
  // Dropped once on the premise that it fires on "enter your promo code". It does
  // not — and dropping it cost the screens that say only this.
  assert.equal(classifyLogin({ bodyText: "Enter the code below to continue" }), "otp-required");
  assert.equal(
    classifyLogin({ hasPasswordField: false, bodyText: "Enter your promo code at checkout" }),
    "logged-in",
  );
});

test("a code screen that also mentions a link is a code step, however weak its field", () => {
  // The six-box screens this feature targets often carry no autocomplete hint, so
  // guarding the link/QR outcomes on the code INPUT sent them to a handover.
  assert.equal(
    classifyLogin({
      hasOtpField: false,
      otpFieldNames: [""],
      bodyText: "Enter the 6-digit code we sent, or use the login link in the same email",
    }),
    "otp-required",
  );
  assert.equal(
    classifyLogin({
      bodyText: "Log in with a QR code, or enter the verification code we sent you",
    }),
    "otp-required",
  );
});

test("failed: a Russian rejection is read as a bad credential, not `unknown`", () => {
  // lk.eneva.ru — without this the password field stays, every round is
  // `unknown`, and the result is a `timeout` blamed on the owner.
  assert.equal(
    classifyLogin({
      hasPasswordField: true,
      bodyText: "Вход в Личный кабинет\nПользователь не найден или неверный пароль\nВойти",
    }),
    "failed",
  );
  assert.equal(
    classifyLogin({ hasPasswordField: true, errorText: "Неверный логин или пароль" }),
    "failed",
  );
  assert.equal(
    classifyLogin({ hasPasswordField: true, bodyText: "Ошибка авторизации. Попробуйте ещё раз." }),
    "failed",
  );
});

test("Russian body copy without a rejection does not trip the error match", () => {
  assert.equal(
    classifyLogin({ hasPasswordField: true, bodyText: "Вход в Личный кабинет\nНомер договора\nПароль\nВойти" }),
    "unknown",
  );
  assert.equal(classifyLogin({ hasPasswordField: false, bodyText: "Добро пожаловать, Иван" }), "logged-in");
});
