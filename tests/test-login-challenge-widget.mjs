#!/usr/bin/env node

// The login classifier's ONE language-independent block signal: a visible
// anti-automation challenge WIDGET (Arkose / reCAPTCHA / hCaptcha / PerimeterX),
// matched by vendor DOM markers rather than page copy. This is what flags
// LinkedIn's post-login checkpoint (an Arkose FunCaptcha) as "blocked" regardless
// of the page's language — we deliberately do NOT try to enumerate block phrases
// in every language. LIVE (matches selectors in a real browser); auto-skips when
// patchright / Chrome are unavailable.
//
// Run: node --test tests/test-login-challenge-widget.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";

import { resolvePatchright, launchContext } from "../plugins/agent-id-browser/lib/launch.mjs";
import { CHALLENGE_WIDGET_SEL } from "../plugins/agent-id-browser/lib/auto-login.mjs";

const patchrightAvailable = !!resolvePatchright();
const skip = patchrightAvailable ? false : "patchright/Chrome not installed";

// Count only VISIBLE matches (the same test detectPageState applies) so an
// invisible token widget doesn't count as a challenge.
async function visibleChallengeCount(page) {
  return page.evaluate((sel) => {
    const visible = (e) => !!(e.offsetParent !== null || e.getClientRects().length);
    return Array.from(document.querySelectorAll(sel)).filter(visible).length;
  }, CHALLENGE_WIDGET_SEL);
}

async function withPage(fn) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "challenge-"));
  let ctx;
  try {
    ctx = await launchContext({ profileDir: dir, headless: true });
    const page = ctx.pages()[0] || (await ctx.newPage());
    await fn(page);
  } finally {
    if (ctx) await ctx.close().catch(() => {});
    await fs.rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

test("challenge widgets (Arkose / reCAPTCHA / hCaptcha) are detected, in any language", { skip }, async () => {
  await withPage(async (page) => {
    // Vendor markers only — no English text anywhere on the page.
    await page.setContent(
      `<div class="g-recaptcha" data-sitekey="x" style="width:300px;height:78px"></div>` +
        `<iframe title="Vérification de sécurité" src="https://client-api.arkoselabs.com/x"` +
        ` style="width:300px;height:200px"></iframe>`,
    );
    assert.ok((await visibleChallengeCount(page)) >= 1, "a visible challenge widget is found regardless of page language");
  });
});

test("an ordinary login form is NOT flagged as a challenge", { skip }, async () => {
  await withPage(async (page) => {
    await page.setContent(
      `<form><input type="email"><input type="password"><button>Se connecter</button></form>`,
    );
    assert.equal(await visibleChallengeCount(page), 0, "a plain login form has no challenge widget");
  });
});
