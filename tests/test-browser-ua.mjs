#!/usr/bin/env node

// LIVE regression test for headless User-Agent normalization (launch.mjs).
//
// Chrome tags the UA with "HeadlessChrome" in headless mode and patchright does
// not strip it (upstream wontfix), which trips bot detection (Reddit, Google).
// launchContext normalizes it via Playwright's native `userAgent` override so a
// headless session is indistinguishable from a headed one. This test asserts:
//   - headless navigator.userAgent contains NO "Headless" token
//   - the override is native (navigator.userAgent getter reports [native code]),
//     not a detectable JS patch
//   - headed and headless report the SAME User-Agent
//   - navigator.webdriver stays false
//
// Skips automatically when patchright / Chrome are not installed.
//
// Run: node --test tests/test-browser-ua.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";

import { resolvePatchright, launchContext } from "../plugins/agent-id-browser/lib/launch.mjs";

const patchrightAvailable = !!resolvePatchright();

async function fingerprint(headless) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "ua-reg-"));
  let ctx;
  try {
    ctx = await launchContext({ profileDir: dir, headless });
    const page = ctx.pages()[0] || (await ctx.newPage());
    return await page.evaluate(() => ({
      ua: navigator.userAgent,
      uaGetterNative: Object.getOwnPropertyDescriptor(Navigator.prototype, "userAgent")
        ?.get?.toString()
        .includes("[native code]"),
      webdriver: navigator.webdriver,
    }));
  } finally {
    if (ctx) await ctx.close().catch(() => {});
    await fs.rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

test(
  "headless UA is normalized: no 'Headless' token, native getter, matches headed",
  { skip: patchrightAvailable ? false : "patchright/Chrome not installed" },
  async () => {
    const headless = await fingerprint(true);
    const headed = await fingerprint(false);

    assert.ok(
      !/Headless/i.test(headless.ua),
      `headless UA must not contain "Headless": ${headless.ua}`,
    );
    assert.equal(
      headless.uaGetterNative,
      true,
      "the UA override must be native (CDP), not a detectable JS patch",
    );
    assert.equal(headless.ua, headed.ua, "headed and headless must report the same UA");
    assert.equal(headless.webdriver, false, "navigator.webdriver must stay false");
  },
);
