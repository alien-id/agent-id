#!/usr/bin/env node

// Tests for the pure session-server helpers behind the iframe/tab/download
// additions: frameRefId (ref → frame prefix parsing, the contract every
// ref-based action resolves through) and safeFilename (download names must be
// joinable under the sessions dir without traversal). Pure — no browser.
//
// Run: node --test tests/test-browser-session-helpers.mjs

import { test } from "node:test";
import assert from "node:assert/strict";

import { frameRefId, safeFilename } from "../plugins/agent-id-browser/lib/session-server.mjs";

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
