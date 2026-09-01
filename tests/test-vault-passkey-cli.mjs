#!/usr/bin/env node

// CLI integration: `vault init --unlock passkey` enrolls a passkey-only vault, and
// later unlock runs the WebAuthn ceremony. We can't drive a real authenticator in
// CI, so we feed the ceremony's PRF output by POSTing to the loopback form — the
// same bytes the browser would post. The PRF secret never appears on the agent's
// streams.
//
// Run: node --test tests/test-vault-passkey-cli.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { spawn } from "node:child_process";

const CLI = new URL("../plugins/agent-id-vault/bin/cli.mjs", import.meta.url).pathname;
const PRF_HEX = "ab".repeat(32); // 32-byte stand-in for the authenticator PRF output
const REG = { credentialId: "Y3JlZA", rpId: "localhost", prfSecret: PRF_HEX };
const AUTH = { prfSecret: PRF_HEX };

// Run a vault command that opens a WebAuthn form; when its localhost URL appears,
// POST the simulated ceremony fields, then resolve with the result.
function runWithCeremony(args, ceremonyFields) {
  return new Promise((resolve, reject) => {
    const child = spawn("node", [CLI, ...args], { env: { ...process.env, AGENT_ID_NO_BROWSER: "1" } });
    let stdout = "";
    let stderr = "";
    let posted = false;
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => {
      stderr += d;
      const m = stderr.match(/http:\/\/localhost:\d+\/\?t=[a-f0-9]+/);
      if (m && !posted) {
        posted = true;
        const u = new URL(m[0]);
        const body = new URLSearchParams({ _token: u.searchParams.get("t"), ...ceremonyFields });
        fetch(`http://localhost:${u.port}/submit`, { method: "POST", body }).catch(() => {});
      }
    });
    child.on("exit", (code) => resolve({ code, stdout, stderr }));
    child.on("error", reject);
  });
}

test("init --unlock passkey enrolls a passkey-only vault and unlocks via the ceremony", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "pk-cli-"));
  try {
    // Enroll (register ceremony posts credentialId + rpId + prfSecret).
    const init = await runWithCeremony(["init", "--unlock", "passkey", "--state-dir", dir], REG);
    assert.equal(init.code, 0, `init failed: ${init.stderr}`);
    const initOut = JSON.parse(init.stdout);
    assert.equal(initOut.ok, true);
    assert.equal(initOut.slots, 1, "passkey-only: a single slot");
    assert.ok(!init.stdout.includes(PRF_HEX) && !init.stderr.includes(PRF_HEX), "PRF secret must not leak");

    // Unlock: no agent key, so `list` triggers the passkey authenticate ceremony.
    const list = await runWithCeremony(["list", "--state-dir", dir], AUTH);
    assert.equal(list.code, 0, `list failed: ${list.stderr}`);
    const listOut = JSON.parse(list.stdout);
    assert.equal(listOut.slots.length, 1);
    assert.equal(listOut.slots[0].type, "passkey");
    assert.ok(!list.stdout.includes(PRF_HEX) && !list.stderr.includes(PRF_HEX), "PRF secret must not leak");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
