#!/usr/bin/env node

// Proof that `snapshot` and `form-inspect` share ONE ref space.
//
// They used to number over different element sets — snapshot over links/
// buttons/inputs, form-inspect over form controls only — and both wiped every
// existing data-aibref before renumbering from e1. So the same string meant
// different elements depending on which tool ran last: after a form-inspect
// "e7" was the First Name input, after a snapshot it was a toolbar button.
// Nothing detected the difference, so a form-fill built from form-inspect refs
// silently drove the wrong elements. Observed in the wild on an Oracle/Taleo
// careers form, where it burned the agent's whole tool budget.
//
// The invariant now: a ref denotes the same element in both modes. These two
// page functions cannot share a module constant (they are serialised into the
// page), so this test is what keeps their selectors and numbering loops in
// agreement.
//
// LIVE real-browser test — SKIPS automatically when patchright / Chrome are
// not installed.
//
// Run: node --test tests/test-browser-ref-space.mjs

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { resolvePatchright, launchContext } from "../plugins/agent-id-browser/lib/launch.mjs";
import {
  snapshotInPage,
  formSnapshotInPage,
  refGenerationOf,
  frameRefId,
} from "../plugins/agent-id-browser/lib/session-server.mjs";

// A page shaped like the form that broke: chrome/nav elements interleaved with
// the form controls, so the two modes would disagree if either filtered before
// numbering. Includes an ARIA combobox (the Taleo-style country picker) and a
// visually hidden checkbox, which each mode treats differently when REPORTING.
const PAGE = `<!doctype html><html><body>
  <a href="/help">Help</a>
  <button id="nav">Menu</button>
  <form name="careerform">
    <input id="first" name="firstName" aria-label="First Name">
    <input id="last" name="lastName" aria-label="Last Name">
    <input id="country" role="combobox" aria-label="Country" aria-autocomplete="list">
    <select id="permit" aria-label="Permit"><option value="B">B</option><option value="C">C</option></select>
    <input id="agree" type="checkbox" style="display:none">
    <button id="submit" type="submit">Apply</button>
  </form>
  <a href="/privacy">Privacy</a>
</body></html>`;

const patchrightAvailable = !!resolvePatchright();

let ctx;
let workDir;
let page;

before(async () => {
  if (!patchrightAvailable) return;
  workDir = await fs.mkdtemp(path.join(os.tmpdir(), "aib-refspace-"));
  ctx = await launchContext({ profileDir: workDir, headless: true, contextOptions: {} });
  page = ctx.pages()[0] || (await ctx.newPage());
  await page.setContent(PAGE, { waitUntil: "domcontentloaded" });
});

after(async () => {
  if (ctx) await ctx.close().catch(() => {});
  if (workDir) await fs.rm(workDir, { recursive: true, force: true }).catch(() => {});
});

const skip = patchrightAvailable ? false : "patchright/Chrome not installed";

test("a ref denotes the same element in both observation modes", { skip }, async () => {

  // Take each observation independently, exactly as the two tools do — each
  // clears the previous tagging and renumbers.
  const snap = await page.evaluate(snapshotInPage, { prefix: "", generation: 1 });
  const snapById = await page.evaluate(() =>
    Object.fromEntries(
      Array.from(document.querySelectorAll("[data-aibref]")).map((el) => [el.id, el.getAttribute("data-aibref")]),
    ),
  );

  const form = await page.evaluate(formSnapshotInPage, { prefix: "", generation: 2 });
  const formById = await page.evaluate(() =>
    Object.fromEntries(
      Array.from(document.querySelectorAll("[data-aibref]")).map((el) => [el.id, el.getAttribute("data-aibref")]),
    ),
  );

  // The version prefix is expected to differ (these are two observations);
  // the invariant under test is the ELEMENT NUMBERING behind it.
  const bare = (ref) => String(ref).replace(/^\d+:/, "");

  // Every element both modes tag must carry the same number.
  for (const [id, ref] of Object.entries(snapById)) {
    if (!(id in formById)) continue;
    assert.equal(
      bare(formById[id]),
      bare(ref),
      `element #${id} changed ref between modes (${ref} → ${formById[id]})`,
    );
  }

  // And specifically the case that broke: the first form field must not
  // collide with a nav control that precedes it in document order.
  assert.ok(snapById.first, "first-name input should be tagged by snapshot");
  assert.equal(bare(formById.first), bare(snapById.first));
  assert.notEqual(bare(formById.first), bare(snapById.nav));

  // Reported sets still differ — form-inspect describes controls, snapshot
  // describes everything interactive — even though the numbering agrees.
  const formRefs = form.controls.map((c) => bare(c.ref));
  assert.ok(formRefs.includes(bare(formById.country)), "combobox should be reported by form-inspect");
  assert.ok(
    snap.elements.some((e) => bare(e.ref) === bare(snapById.nav)),
    "nav button should be reported by snapshot",
  );
});

test("refs carry the observation that minted them", { skip }, async () => {
  const first = await page.evaluate(snapshotInPage, { prefix: "", generation: 1 });
  const second = await page.evaluate(snapshotInPage, { prefix: "", generation: 2 });

  // The version prefix is what makes staleness checkable without touching the
  // DOM — a ref held across an observation is refused by name.
  assert.ok(first.elements[0].ref.startsWith("1:"), `expected a 1: prefix, got ${first.elements[0].ref}`);
  assert.ok(second.elements[0].ref.startsWith("2:"), `expected a 2: prefix, got ${second.elements[0].ref}`);
  assert.equal(refGenerationOf(first.elements[0].ref), 1);
  assert.equal(refGenerationOf(second.elements[0].ref), 2);
  assert.equal(refGenerationOf("e7"), null, "unversioned refs stay recognisable");

  // The frame id must survive the version prefix, or child-frame refs break.
  assert.equal(frameRefId("3:f1e2"), "f1");
  assert.equal(frameRefId("3:e2"), null);
  assert.equal(frameRefId("f1e2"), "f1");
});

test("form-inspect reports the combobox as a combobox", { skip }, async () => {
  const form = await page.evaluate(formSnapshotInPage, { prefix: "", generation: 1 });
  const country = form.controls.find((c) => c.label === "Country");
  assert.ok(country, "country control should be reported");
  // form-fill dispatches on this: role=combobox must not be driven with
  // selectOption, which only works on a native <select>.
  assert.equal(country.role, "combobox");
  const permit = form.controls.find((c) => c.label === "Permit");
  assert.equal(permit.role, "select");
  assert.ok(Array.isArray(permit.options) && permit.options.length === 2);
});
