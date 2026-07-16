#!/usr/bin/env node

// Tests for the browser CLI hint strings (lib/hints.mjs). The NO_PROFILE hint
// must name the headless `auto-login` path — it's the only way to create a
// profile on a server / in a container (headed `login` needs a display), and
// pointing the agent at `login` there is exactly what made a "no profile yet"
// state read as "the browser is broken". Pure — no browser.
//
// Run: node --test tests/test-browser-hints.mjs

import { test } from "node:test";
import assert from "node:assert/strict";

import { DEFAULT_PROFILE, loginHint, noProfileHint, profileName } from "../plugins/agent-id-browser/lib/hints.mjs";

test("profileName accepts safe slugs and rejects traversal", () => {
  assert.equal(profileName(), DEFAULT_PROFILE);
  assert.equal(profileName("work-2_A"), "work-2_A");
  assert.throws(() => profileName("../../etc/passwd"), /1-64 letters/);
  assert.throws(() => profileName("a/b"), /1-64 letters/);
  assert.throws(() => profileName("x".repeat(65)), /1-64 letters/);
});

test("loginHint: bare for the default profile, named otherwise", () => {
  assert.equal(loginHint(DEFAULT_PROFILE), "`login`");
  assert.equal(loginHint("reddit"), "`login --name reddit`");
});

test("noProfileHint: names the headless auto-login path first", () => {
  const hint = noProfileHint("reddit");
  assert.match(hint, /auto-login --cred/);
  // auto-login must come before the headed login fallback.
  assert.ok(hint.indexOf("auto-login") < hint.indexOf("login --name reddit"));
  // It must be clear the headed path needs a display (why it's the fallback).
  assert.match(hint, /headless/);
  assert.match(hint, /needs a display/);
});

test("noProfileHint: carries the profile name into the headed fallback", () => {
  assert.match(noProfileHint("acct2"), /login --name acct2/);
  assert.doesNotMatch(noProfileHint(DEFAULT_PROFILE), /--name/);
});
