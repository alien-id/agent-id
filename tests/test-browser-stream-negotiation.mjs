#!/usr/bin/env node

// Handshake and input contracts that must not fail silently.
//
// 1. `codec=h264&strict=1` is a REQUIREMENT. Falling back to jpeg hides broken
//    provisioning and quietly costs ~10x the traffic, so an unprovisioned host
//    must refuse at the handshake with a typed close code, not serve a format
//    the client never agreed to.
// 2. `char` carries its payload in `text`; `key` is only a fallback. Requiring
//    `key` dropped well-formed text-only chars on the floor without a word.
//
// Pure: parseStreamParams and applyInput against a stub page. No browser.
//
// Run: node --test tests/test-browser-stream-negotiation.mjs

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  parseStreamParams,
  applyInput,
  CLOSE_CODEC_UNAVAILABLE,
} from "../plugins/agent-id-browser/lib/stream-server.mjs";

const params = (qs) => parseStreamParams(new URL(`ws://x/?${qs}`));

test("strict only binds an explicit codec request", () => {
  assert.equal(params("codec=h264&strict=1").strict, true);
  // `auto` asks for the best available — jpeg is a valid answer to it, so
  // strict would be a contradiction.
  assert.equal(params("codec=auto&strict=1").strict, false);
  assert.equal(params("codec=h264").strict, false);
  assert.equal(params("strict=1").strict, false);
});

test("h264 implies binary framing; jpeg stays v1 by default", () => {
  assert.equal(params("codec=h264").binary, true);
  assert.equal(params("").binary, false);
  assert.equal(params("").codec, "jpeg");
});

test("the codec-refusal close code is in the application range", () => {
  assert.ok(CLOSE_CODEC_UNAVAILABLE >= 4000 && CLOSE_CODEC_UNAVAILABLE <= 4999);
});

function stubPage() {
  const calls = [];
  return {
    calls,
    keyboard: {
      down: (k) => (calls.push(["down", k]), Promise.resolve()),
      up: (k) => (calls.push(["up", k]), Promise.resolve()),
      insertText: (t) => (calls.push(["insertText", t]), Promise.resolve()),
    },
    mouse: {},
  };
}

test("char with only `text` inserts it (no `key` required)", async () => {
  const page = stubPage();
  await applyInput(page, { type: "input_keyboard", eventType: "char", text: "é" });
  assert.deepEqual(page.calls, [["insertText", "é"]]);
});

test("char still falls back to `key` when that is all there is", async () => {
  const page = stubPage();
  await applyInput(page, { type: "input_keyboard", eventType: "char", key: "a" });
  assert.deepEqual(page.calls, [["insertText", "a"]]);
});

test("a char with neither text nor key is reported, not swallowed", async () => {
  const page = stubPage();
  await assert.rejects(
    () => applyInput(page, { type: "input_keyboard", eventType: "char" }),
    /needs `text`/,
  );
  assert.deepEqual(page.calls, [], "nothing was typed");
});

test("keyDown without a key is reported — there is no pressing 'nothing'", async () => {
  const page = stubPage();
  await assert.rejects(
    () => applyInput(page, { type: "input_keyboard", eventType: "keyDown" }),
    /needs `key`/,
  );
});

test("keyDown/keyUp still work normally", async () => {
  const page = stubPage();
  await applyInput(page, { type: "input_keyboard", eventType: "keyDown", key: "Enter" });
  await applyInput(page, { type: "input_keyboard", eventType: "keyUp", key: "Enter" });
  assert.deepEqual(page.calls, [["down", "Enter"], ["up", "Enter"]]);
});
