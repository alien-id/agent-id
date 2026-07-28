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

test("every outcome yields one of the three actions", () => {
  const actions = new Set([OWNER_MUST_DRIVE, OWNER_MUST_CONFIRM, FIX_CREDENTIAL]);
  for (const outcome of ["blocked", "confirm-timeout", "failed", "otp-unexpected", "weird", ""]) {
    const e = escalationFor(outcome, ctx);
    assert.ok(actions.has(e.action), `${outcome} → ${e.action}`);
    assert.ok(e.reason && e.message, `${outcome} needs a reason and a message`);
  }
});
