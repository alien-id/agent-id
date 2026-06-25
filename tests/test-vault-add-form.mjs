#!/usr/bin/env node

// End-to-end test for `agent-id-vault add --form`: the agent supplies metadata,
// the human types the secret into the loopback form, and the value is stored in
// the vault WITHOUT ever appearing on the CLI's stdout/stderr (the agent's view).
//
// Run: node --test tests/test-vault-add-form.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";

import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { writeJsonFile, statePaths } from "../plugins/agent-id-core/lib/state.mjs";
import { fingerprintPublicKeyPem } from "../plugins/agent-id-core/lib/crypto.mjs";

const CLI = new URL("../plugins/agent-id-vault/bin/cli.mjs", import.meta.url).pathname;

async function makeVault(dir) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
  const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  await writeJsonFile(statePaths(dir).mainKey, {
    version: 1,
    agentId: "main",
    keyNonce: 0,
    createdAt: 1,
    publicKeyPem,
    privateKeyPem,
    fingerprint: fingerprintPublicKeyPem(publicKeyPem),
  });
  await initVault({ stateDir: dir, privateKeyPem, agentId: "main" });
}

// Pull the loopback form URL out of the CLI's stderr stream.
function waitForUrl(child) {
  return new Promise((resolve, reject) => {
    let buf = "";
    const onData = (d) => {
      buf += d.toString();
      const m = buf.match(/http:\/\/127\.0\.0\.1:\d+\/\?t=[a-f0-9]+/);
      if (m) {
        child.stderr.off("data", onData);
        resolve(m[0]);
      }
    };
    child.stderr.on("data", onData);
    child.on("exit", () => reject(new Error(`CLI exited before printing a URL:\n${buf}`)));
  });
}

test("add --form stores the value typed in the form; the value never hits stdout/stderr", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "addform-"));
  try {
    await makeVault(dir);
    const SECRET = "ghp_only_the_form_sees_this_42";

    const child = spawn(
      "node",
      [CLI, "add", "--name", "gh", "--type", "bearer", "--domains", "api.github.com", "--form", "--state-dir", dir],
      { env: { ...process.env, AGENT_ID_NO_BROWSER: "1" } },
    );
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));

    const url = await waitForUrl(child);
    const u = new URL(url);
    const token = u.searchParams.get("t");

    // Simulate the human submitting the form.
    const res = await fetch(`http://127.0.0.1:${u.port}/submit`, {
      method: "POST",
      body: new URLSearchParams({ _token: token, value: SECRET }),
    });
    assert.equal(res.status, 200);

    const code = await new Promise((r) => child.on("exit", r));
    assert.equal(code, 0, `CLI failed: ${stderr}`);

    // The agent-visible streams must NOT contain the secret.
    assert.ok(!stdout.includes(SECRET), "stdout leaked the secret");
    assert.ok(!stderr.includes(SECRET), "stderr leaked the secret");
    // stdout is the name-only success JSON.
    const out = JSON.parse(stdout);
    assert.equal(out.ok, true);
    assert.equal(out.name, "gh");

    // The value really landed in the vault.
    const { privateKeyPem } = JSON.parse(await readFile(statePaths(dir).mainKey, "utf8"));
    const vault = await openVault({ stateDir: dir, privateKeyPem });
    assert.equal(vault.get("gh").value, SECRET);
    vault.lock();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
