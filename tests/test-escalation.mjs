#!/usr/bin/env node

// Unit tests for login escalation (lib/escalation.mjs).
//
// The bug this guards: every failed auto-login used to advise "sign in yourself
// with headed `login`", but headed login refuses without a display and points
// back at auto-login. The two pointed at each other, so on a hosted host the
// agent bounced between them or asked for a password that an SSO-only account
// does not have. An `action` field replaces the prose.
//
// Run: node --test tests/test-escalation.mjs

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  escalationFor,
  OWNER_MUST_DRIVE,
  OWNER_MUST_CONFIRM,
  FIX_CREDENTIAL,
} from "../plugins/agent-id-browser/lib/escalation.mjs";

const ctx = { credName: "acme", profile: "main" };

test("a bot challenge needs a human at the page", () => {
  const e = escalationFor("blocked", ctx);
  assert.equal(e.action, OWNER_MUST_DRIVE);
  assert.equal(e.reason, "bot_challenge");
});

test("an unresolved login escalates rather than looping on headed login", () => {
  const e = escalationFor("timeout", ctx);
  assert.equal(e.action, OWNER_MUST_DRIVE);
  // The old advice sent the agent to a command that refuses without a display.
  assert.doesNotMatch(e.message, /headed/i);
});

test("a device-approval timeout must not blame the credentials", () => {
  const e = escalationFor("confirm-timeout", ctx);
  assert.equal(e.action, OWNER_MUST_CONFIRM);
  assert.equal(e.reason, "device_approval_timeout");
  // Re-checking a password that was never wrong is exactly the wasted work
  // the generic branch used to cause.
  assert.match(e.message, /credentials are FINE/i);
  assert.match(e.message, /do not ask for the password/i);
});

test("a rejected password is a credential problem, not a viewport one", () => {
  const e = escalationFor("failed", ctx);
  assert.equal(e.action, FIX_CREDENTIAL);
});

test("an unexpected OTP tells you which credential field is missing", () => {
  const e = escalationFor("otp-unexpected", ctx);
  assert.equal(e.action, FIX_CREDENTIAL);
  assert.match(e.message, /set-totp|interactive/);
});

test("an unexpected OTP also names the case where the site has no password at all", () => {
  // This outcome is where a passwordless site lands when it was stored as an
  // ordinary login — the agent is here precisely because its first guess about
  // the site was wrong, and this message is the only sentence it gets to correct
  // itself from. It has to name `overwrite` too: re-adding an existing name
  // without it returns the stored entry and the agent loops.
  const e = escalationFor("otp-unexpected", ctx);
  assert.match(e.message, /passwordless/);
  assert.match(e.message, /overwrite/);
  assert.match(e.message, /no password field/i);
  assert.match(e.message, /do not retry as-is/i);
});

test("every outcome yields one of the three actions", () => {
  const actions = new Set([OWNER_MUST_DRIVE, OWNER_MUST_CONFIRM, FIX_CREDENTIAL]);
  for (const outcome of ["blocked", "confirm-timeout", "failed", "otp-unexpected", "weird", ""]) {
    const e = escalationFor(outcome, ctx);
    assert.ok(actions.has(e.action), `${outcome} → ${e.action}`);
    assert.ok(e.reason && e.message, `${outcome} needs a reason and a message`);
  }
});

test("magic-link tells the agent there is nothing to type, and where the link must be opened", () => {
  const { action, reason, message } = escalationFor("magic-link", {
    credName: "substack",
    profile: "substack",
  });
  assert.equal(action, OWNER_MUST_DRIVE);
  assert.equal(reason, "magic_link_sign_in");
  // The generic fallback blames big-IdP automation, which is wrong here and sends
  // the agent looking for a password or a code that does not exist.
  assert.ok(!/Google, Microsoft/.test(message));
  assert.match(message, /nothing to type/i);
  assert.match(message, /do not raise a secure card/i);
  // Clicking it anywhere else authenticates that browser, not the sealed profile.
  assert.match(message, /browser view for profile 'substack'/);
});

test("qr-sign-in sends the owner to the browser view, because that is where the code is drawn", () => {
  const { action, reason, message } = escalationFor("qr-sign-in", {
    credName: "telegram",
    profile: "telegram",
  });
  assert.equal(action, OWNER_MUST_DRIVE);
  assert.equal(reason, "qr_code_sign_in");
  assert.match(message, /nothing to type/i);
  // The code is rendered inside a headless browser the owner cannot see, so the
  // viewport is not a last resort here — it is the only way this signs in at all.
  assert.match(message, /browser view for profile 'telegram'/);
  assert.ok(!/Google, Microsoft/.test(message));
});
