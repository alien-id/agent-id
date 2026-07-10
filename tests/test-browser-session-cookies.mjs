import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  captureSessionCookies,
  restoreSessionCookies,
} from "../plugins/agent-id-browser/lib/profile-store.mjs";

test("session-only cookies survive an encrypted-profile close/reopen cycle", async () => {
  const profileDir = await fs.mkdtemp(path.join(os.tmpdir(), "agent-id-cookie-test-"));
  try {
    const session = {
      name: "session",
      value: "secret-session-value",
      domain: "example.com",
      path: "/",
      expires: -1,
      httpOnly: true,
      secure: true,
      sameSite: "Lax",
    };
    const persistent = { ...session, name: "persistent", expires: 2_000_000_000 };
    const source = { cookies: async () => [session, persistent] };
    assert.equal(await captureSessionCookies({ context: source, profileDir }), 1);

    let restored = null;
    const target = { addCookies: async (cookies) => { restored = cookies; } };
    assert.equal(await restoreSessionCookies({ context: target, profileDir }), 1);
    assert.deepEqual(restored, [session]);
  } finally {
    await fs.rm(profileDir, { recursive: true, force: true });
  }
});

test("capturing an empty cookie jar clears a stale session checkpoint", async () => {
  const profileDir = await fs.mkdtemp(path.join(os.tmpdir(), "agent-id-cookie-test-"));
  try {
    await captureSessionCookies({
      context: {
        cookies: async () => [
          { name: "old", value: "value", domain: "example.com", path: "/", expires: -1 },
        ],
      },
      profileDir,
    });
    await captureSessionCookies({ context: { cookies: async () => [] }, profileDir });

    let called = false;
    const count = await restoreSessionCookies({
      context: { addCookies: async () => { called = true; } },
      profileDir,
    });
    assert.equal(count, 0);
    assert.equal(called, false);
  } finally {
    await fs.rm(profileDir, { recursive: true, force: true });
  }
});
