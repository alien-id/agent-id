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

// `fill-card` types four values instead of one, so it holds the blackout across
// all of them. The same unlock failure has to lift it, and the two guards that
// run BEFORE the suspend must not raise one at all — an approval refused on the
// wrong host should leave the feed exactly as it found it.
const CARD_REFS = { number: "1:e1", expiry: "1:e2", security_code: "1:e3", holder: "1:e4" };

test("fill-card: a failed vault unlock still lifts the blackout", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "aid-blackout-card-"));
  const stream = fakeStream();
  const state = fakeState(stream);

  await assert.rejects(
    () =>
      dispatch(state, {
        action: "fill-card",
        // fakeState's page is on example.com, so this is the approved merchant.
        params: { cred: "visa", merchantHost: "example.com", refs: CARD_REFS },
        _stateDir: dir,
      }),
    "the fill must fail — there is no vault to unlock",
  );

  assert.equal(stream.suspends, 1, "the feed is blacked out for the fill");
  assert.equal(stream.resumes, 1, "and the blackout is lifted even though the fill threw");
  assert.equal(stream.depth, 0, "no leaked suspend depth");
  await fs.rm(dir, { recursive: true, force: true });
});

test("fill-card: a merchant the owner did not approve is refused before anything is typed", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "aid-card-host-"));
  const stream = fakeStream();
  const state = fakeState(stream);

  await assert.rejects(
    () =>
      dispatch(state, {
        action: "fill-card",
        params: { cred: "visa", merchantHost: "checkout.attacker.net", refs: CARD_REFS },
        _stateDir: dir,
      }),
    /approved paying at checkout\.attacker\.net/,
  );

  assert.equal(stream.suspends, 0, "nothing was typed, so nothing was blacked out");
  await fs.rm(dir, { recursive: true, force: true });
});

test("fill-card: a form missing any of the four is not a card form", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "aid-card-refs-"));
  for (const missing of Object.keys(CARD_REFS)) {
    const stream = fakeStream();
    const refs = { ...CARD_REFS };
    delete refs[missing];
    await assert.rejects(
      () =>
        dispatch(fakeState(stream), {
          action: "fill-card",
          params: { cred: "visa", merchantHost: "example.com", refs },
          _stateDir: dir,
        }),
      new RegExp(`refs\\.${missing} is required`),
      `a form missing ${missing} was accepted`,
    );
    assert.equal(stream.suspends, 0, "a refused shape must not black out the feed");
  }
  await fs.rm(dir, { recursive: true, force: true });
});
