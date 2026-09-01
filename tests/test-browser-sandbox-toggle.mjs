#!/usr/bin/env node

// The container sandbox opt-out (AGENT_ID_BROWSER_NO_SANDBOX=1): by default the
// launcher strips patchright's injected --no-sandbox to keep the renderer
// sandbox ON (the stealth-validated config). Chrome refuses to start as root
// with the sandbox on, so containerized deployments that run as root (e.g.
// hosted per-user containers) set the env var to keep the injected flag.
// Pure — no browser.
//
// Run: node --test tests/test-browser-sandbox-toggle.mjs

import { test } from "node:test";
import assert from "node:assert/strict";

import { sandboxDisabled, windowSize, launchOptions } from "../plugins/agent-id-browser/lib/launch.mjs";

test("windowSize: defaults to 1440,900 and accepts x/comma overrides", () => {
  assert.equal(windowSize({}), "1440,900");
  assert.equal(windowSize({ AGENT_ID_BROWSER_WINDOW_SIZE: "1600x1000" }), "1600,1000");
  assert.equal(windowSize({ AGENT_ID_BROWSER_WINDOW_SIZE: "1600,1000" }), "1600,1000");
  assert.equal(windowSize({ AGENT_ID_BROWSER_WINDOW_SIZE: " 800 x 600 " }), "800,600");
  // Garbage / injection attempts fall back to the default (no arbitrary flag text).
  assert.equal(windowSize({ AGENT_ID_BROWSER_WINDOW_SIZE: "1440,900 --foo" }), "1440,900");
  assert.equal(windowSize({ AGENT_ID_BROWSER_WINDOW_SIZE: "huge" }), "1440,900");
});

test("sandboxDisabled: only the literal '1' opts out", () => {
  assert.equal(sandboxDisabled({}), false);
  assert.equal(sandboxDisabled({ AGENT_ID_BROWSER_NO_SANDBOX: "1" }), true);
  assert.equal(sandboxDisabled({ AGENT_ID_BROWSER_NO_SANDBOX: "0" }), false);
  assert.equal(sandboxDisabled({ AGENT_ID_BROWSER_NO_SANDBOX: "true" }), false);
  assert.equal(sandboxDisabled({ AGENT_ID_BROWSER_NO_SANDBOX: "" }), false);
});

test("default launch strips --no-sandbox (sandbox stays on)", () => {
  delete process.env.AGENT_ID_BROWSER_NO_SANDBOX;
  const opts = launchOptions(true);
  assert.deepEqual(opts.ignoreDefaultArgs, ["--no-sandbox"]);
  assert.equal(opts.channel, "chrome");
});

test("opt-in keeps patchright's --no-sandbox (root-in-container launch works)", () => {
  process.env.AGENT_ID_BROWSER_NO_SANDBOX = "1";
  try {
    const opts = launchOptions(true);
    assert.deepEqual(opts.ignoreDefaultArgs, []);
    // Everything else about the stealth config is unchanged.
    assert.equal(opts.channel, "chrome");
    assert.deepEqual(opts.args, ["--test-type", "--window-size=1440,900"]);
  } finally {
    delete process.env.AGENT_ID_BROWSER_NO_SANDBOX;
  }
});
