#!/usr/bin/env node

// LIVE test that human-input produces real human-shaped events in a real browser:
//   - a click is preceded by mousemove events (the cursor travels), not a
//     teleport-and-click (the classic bot signature),
//   - text is entered key-by-key (per-character keydown events), not pasted.
// Skips automatically when patchright / Chrome are not installed.
//
// Run: node --test tests/test-human-input-live.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";

import { resolvePatchright, launchContext } from "../plugins/agent-id-browser/lib/launch.mjs";
import { humanClick, humanType } from "../plugins/agent-id-browser/lib/human-input.mjs";

const patchrightAvailable = !!resolvePatchright();

const PAGE = `<!doctype html><meta charset=utf-8><title>t</title>
<input id="inp" type="text"><button id="btn">Go</button>`;

// Install the event recorder in the live document (an inline <script> in
// setContent doesn't reliably execute under the stealth context).
async function installRecorder(page) {
  await page.evaluate(() => {
    window.__ev = { mousemoves: 0, clicks: 0, keys: [] };
    document.addEventListener("mousemove", () => window.__ev.mousemoves++);
    document.getElementById("btn").addEventListener("click", () => window.__ev.clicks++);
    document.getElementById("inp").addEventListener("keydown", (e) => window.__ev.keys.push(e.key));
  });
}

test(
  "human input emits mousemoves before a click and types key-by-key (real Chrome)",
  { skip: patchrightAvailable ? false : "patchright/Chrome not installed" },
  async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "human-live-"));
    let ctx;
    try {
      ctx = await launchContext({ profileDir: dir, headless: true });
      const page = ctx.pages()[0] || (await ctx.newPage());
      await page.setContent(PAGE);
      await installRecorder(page);

      // Pre-fill the field so we also verify humanType REPLACES (like fill did),
      // not appends.
      await page.evaluate(() => {
        document.getElementById("inp").value = "STALE";
      });

      // Type into the field: focuses via a human click (→ mousemoves) then types.
      await humanType(page, "#inp", "hello");
      const afterType = await page.evaluate(() => ({
        value: document.getElementById("inp").value,
        mousemoves: window.__ev.mousemoves,
        keys: window.__ev.keys.slice(),
      }));
      assert.equal(afterType.value, "hello", "the field received the typed text (replaced, not appended)");
      assert.ok(afterType.mousemoves > 0, "the cursor moved before focusing (no teleport)");
      // Each character produced its own keydown (the leading Delete is the
      // clear-before-type step; filter to the single-character keys).
      assert.deepEqual(
        afterType.keys.filter((k) => k.length === 1),
        ["h", "e", "l", "l", "o"],
        "each character produced a keydown",
      );

      // Empty value must CLEAR the field (parity with fill), not leave it.
      await humanType(page, "#inp", "");
      assert.equal(
        await page.evaluate(() => document.getElementById("inp").value),
        "",
        "typing an empty string clears the field",
      );

      // Click the button: cursor should travel further before the click lands.
      await humanClick(page, "#btn");
      const afterClick = await page.evaluate(() => window.__ev);
      assert.equal(afterClick.clicks, 1, "the button was clicked exactly once");
      assert.ok(
        afterClick.mousemoves > afterType.mousemoves,
        "more mousemove events fired on the way to the button",
      );
    } finally {
      if (ctx) await ctx.close().catch(() => {});
      await fs.rm(dir, { recursive: true, force: true }).catch(() => {});
    }
  },
);

test(
  "AGENT_ID_HUMAN_INPUT=0 falls back to a direct fill (still works, no motion required)",
  { skip: patchrightAvailable ? false : "patchright/Chrome not installed" },
  async () => {
    const prev = process.env.AGENT_ID_HUMAN_INPUT;
    process.env.AGENT_ID_HUMAN_INPUT = "0";
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "human-off-"));
    let ctx;
    try {
      ctx = await launchContext({ profileDir: dir, headless: true });
      const page = ctx.pages()[0] || (await ctx.newPage());
      await page.setContent(PAGE);
      await installRecorder(page);
      await humanType(page, "#inp", "abc");
      assert.equal(await page.evaluate(() => document.getElementById("inp").value), "abc");
    } finally {
      if (prev === undefined) delete process.env.AGENT_ID_HUMAN_INPUT;
      else process.env.AGENT_ID_HUMAN_INPUT = prev;
      if (ctx) await ctx.close().catch(() => {});
      await fs.rm(dir, { recursive: true, force: true }).catch(() => {});
    }
  },
);

test(
  "human input types into an element inside an iframe via root: frame",
  { skip: patchrightAvailable ? false : "patchright/Chrome not installed" },
  async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "human-frame-"));
    let ctx;
    try {
      ctx = await launchContext({ profileDir: dir, headless: true });
      const page = ctx.pages()[0] || (await ctx.newPage());
      await page.setContent(`<iframe id="f" srcdoc="<input id='inp'>"></iframe>`);
      const frame = page.frames().find((f) => f !== page.mainFrame());
      assert.ok(frame, "the child frame exists");
      // The session server resolves an iframe ref to its Frame and passes it as
      // `root`; humanType must locate/clear/type through the frame while the
      // mouse/keyboard stay page-global.
      await humanType(page, "#inp", "framed", { root: frame });
      assert.equal(await frame.locator("#inp").inputValue(), "framed");
    } finally {
      if (ctx) await ctx.close().catch(() => {});
      await fs.rm(dir, { recursive: true, force: true }).catch(() => {});
    }
  },
);

test(
  "types into the first VISIBLE match when a hidden duplicate comes first (LinkedIn-style)",
  { skip: patchrightAvailable ? false : "patchright/Chrome not installed" },
  async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "human-dup-"));
    let ctx;
    try {
      ctx = await launchContext({ profileDir: dir, headless: true });
      const page = ctx.pages()[0] || (await ctx.newPage());
      // A hidden copy of the field FIRST in DOM order, then the visible one — the
      // shape LinkedIn's login page renders. A plain `.first()` targets the hidden
      // copy and fills nothing; the fix is to target the first VISIBLE match.
      await page.setContent(
        `<input id="hidden" type="email" style="display:none">` +
          `<input id="shown" type="email">`,
      );
      // Fill via the same kind of broad, multi-match selector the auto-login
      // heuristic uses (matches BOTH inputs).
      await humanType(page, 'input[type="email"]', "visible@example.com");
      assert.equal(
        await page.locator("#shown").inputValue(),
        "visible@example.com",
        "the visible field is the one that gets filled",
      );
      assert.equal(
        await page.locator("#hidden").inputValue(),
        "",
        "the hidden duplicate is left untouched",
      );
    } finally {
      if (ctx) await ctx.close().catch(() => {});
      await fs.rm(dir, { recursive: true, force: true }).catch(() => {});
    }
  },
);
