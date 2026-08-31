#!/usr/bin/env node

// Unit tests for routing read/fetch to a live session (lib/session-route.mjs).
// Pure — no browser.
//
// Run: node --test tests/test-session-route.mjs

import { test } from "node:test";
import assert from "node:assert/strict";

import { sessionReplyError } from "../plugins/agent-id-browser/lib/session-route.mjs";

test("a successful reply is not an error", () => {
  assert.equal(
    sessionReplyError(
      { finalUrl: "https://claude.ai/new", loggedOut: false },
      {
        name: "main",
        action: "read",
      }
    ),
    null
  );
});

test("an explicit ok:true reply is not an error", () => {
  assert.equal(
    sessionReplyError(
      { ok: true, text: "hi" },
      { name: "main", action: "read" }
    ),
    null
  );
});

// callSession RESOLVES with the session's reply, so a failure arrives as a
// value. Returning it unchanged spread `ok:false` into the success envelope and
// reported a failure as a clean read with `sessionExpired:false`.
test("an ok:false reply becomes an error rather than a value", () => {
  const error = sessionReplyError(
    { ok: false, error: "navigation timed out" },
    { name: "main", action: "read" }
  );
  assert.ok(error instanceof Error);
  assert.match(error.message, /navigation timed out/);
});

test("an ok:false reply with no message still errors", () => {
  const error = sessionReplyError(
    { ok: false },
    { name: "main", action: "read" }
  );
  assert.ok(error instanceof Error);
  assert.match(error.message, /session action failed/);
});

// A session opened by an older build has no such action. Falling back to the
// one-shot would answer from the stale sealed copy — the bug this routing
// exists to prevent — so the caller must be told to cycle the session instead.
test("an unknown action names the fix and is tagged SESSION_TOO_OLD", () => {
  const error = sessionReplyError(
    { ok: false, error: "unknown action: read" },
    { name: "work", action: "read" }
  );
  assert.equal(error.code, "SESSION_TOO_OLD");
  assert.match(error.message, /close --name work/);
  assert.match(error.message, /open --name work/);
});

test("a null reply is not treated as a failure", () => {
  assert.equal(
    sessionReplyError(null, { name: "main", action: "fetch" }),
    null
  );
});
