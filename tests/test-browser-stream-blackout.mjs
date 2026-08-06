#!/usr/bin/env node

// The viewport blackout that protects a credential fill must ALWAYS be lifted.
//
// `fill-secret` suspends the stream, then unlocks the vault. That unlock can
// fail — locked vault, no agent-key slot, timeout — and the suspend used to sit
// outside the try that resumes, so the throw left the feed suspended for the
// rest of the session: frames were acked and dropped, every later viewer saw
// "screencasting" and not one frame. In the wild that looked like a dead
// browser view — an owner asked to sign in stared at a blank canvas — and
// nothing pointed at a failed fill an hour earlier.
//
// Pure: no browser, no vault. The fill never gets past the vault unlock, which
// is the point.
//
// Run: node --test tests/test-browser-stream-blackout.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { dispatch } from "../plugins/agent-id-browser/lib/session-server.mjs";

/** Counts suspend/resume the way the real stream server does (depth-counted). */
function fakeStream() {
  let depth = 0;
  return {
    suspends: 0,
    resumes: 0,
    get depth() {
      return depth;
    },
    suspend() {
      this.suspends++;
      depth++;
    },
    resume() {
      this.resumes++;
      depth = Math.max(0, depth - 1);
    },
  };
}

function fakeState(stream) {
  const page = {
    url: () => "https://example.com/login",
    isClosed: () => false,
    frames: () => [],
  };
  return {
    stream,
    current: page,
    ctx: {},
    // frameForRef runs before the suspend and refuses stale refs; a valid ref
    // space is what lets the test reach the blackout at all.
    refsValid: true,
    refGeneration: 1,
    frames: new Map(),
    invalidateRefs() {},
  };
}

for (const action of ["fill-secret", "fill-otp"]) {
  test(`${action}: a failed vault unlock still lifts the blackout`, async () => {
    // A state dir with no vault at all — openVaultAgentKey cannot succeed.
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "aid-blackout-"));
    const stream = fakeStream();
    const state = fakeState(stream);

    await assert.rejects(
      () =>
        dispatch(state, {
          action,
          params: { ref: "1:e1", cred: "example.password" },
          _stateDir: dir,
        }),
      "the fill must fail — there is no vault to unlock",
    );

    assert.equal(stream.suspends, 1, "the feed is blacked out for the fill");
    assert.equal(
      stream.resumes,
      1,
      "and the blackout is lifted even though the fill threw",
    );
    assert.equal(stream.depth, 0, "no leaked suspend depth");
    await fs.rm(dir, { recursive: true, force: true });
  });
}
