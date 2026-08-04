#!/usr/bin/env node

// Tests for the pure session-server helpers behind the iframe/tab/download
// additions: frameRefId (ref → frame prefix parsing, the contract every
// ref-based action resolves through) and safeFilename (download names must be
// joinable under the sessions dir without traversal). Pure — no browser.
//
// Run: node --test tests/test-browser-session-helpers.mjs

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  frameRefId,
  refuseRef,
  safeFilename,
} from "../plugins/agent-id-browser/lib/session-server.mjs";

test("refuseRef: a ref on a focus-typing action is refused, not dropped", () => {
  // The failure this guards: `type-text --ref e27 --text Switzerland` typed
  // into whatever held focus and reported success, so the country combobox
  // never saw the text and answered "There were no results".
  assert.throws(
    () => refuseRef("type-text", { ref: "e27", text: "Switzerland" }, "type --ref eN --text T"),
    (err) => {
      assert.match(err.message, /takes no --ref/);
      assert.match(err.message, /e27/); // names the ref it was handed
      assert.match(err.message, /type --ref eN/); // and the tool that accepts one
      return true;
    },
  );
});

test("refuseRef: absent/empty refs pass through untouched", () => {
  assert.doesNotThrow(() => refuseRef("type-text", { text: "hi" }, "type"));
  assert.doesNotThrow(() => refuseRef("type-text", { ref: undefined }, "type"));
  assert.doesNotThrow(() => refuseRef("type-text", { ref: null }, "type"));
  assert.doesNotThrow(() => refuseRef("type-text", { ref: "" }, "type"));
});

test("frameRefId: main-frame refs have no frame id", () => {
  assert.equal(frameRefId("e1"), null);
  assert.equal(frameRefId("e42"), null);
});

test("frameRefId: frame-prefixed refs resolve to their prefix", () => {
  assert.equal(frameRefId("f1e3"), "f1");
  assert.equal(frameRefId("f12e7"), "f12");
});

test("frameRefId: junk / partial refs are treated as main-frame (null)", () => {
  // These won't match any [data-aibref] anyway; the important part is that a
  // malformed ref can't be parsed into a surprising frame lookup.
  assert.equal(frameRefId("f1"), null);
  assert.equal(frameRefId("fe3"), null);
  assert.equal(frameRefId("f1e"), null);
  assert.equal(frameRefId(""), null);
  assert.equal(frameRefId(null), null);
  assert.equal(frameRefId(undefined), null);
});

test("safeFilename: separators and traversal are neutralized", () => {
  assert.equal(safeFilename("report.pdf"), "report.pdf");
  assert.ok(!safeFilename("../../etc/passwd").includes("/"));
  assert.ok(!safeFilename("..\\..\\x").includes("\\"));
  assert.notEqual(safeFilename("..")[0], ".");
  assert.equal(safeFilename("a b:c*d.png"), "a_b_c_d.png");
});

test("safeFilename: empty / dot-only names fall back, long names are bounded", () => {
  assert.equal(safeFilename(""), "file");
  assert.equal(safeFilename(null), "file");
  assert.equal(safeFilename("..."), "file");
  assert.ok(safeFilename("x".repeat(500)).length <= 80);
});
