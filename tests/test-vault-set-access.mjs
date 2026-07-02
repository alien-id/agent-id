#!/usr/bin/env node

// CLI-level tests for the access-level lifecycle:
//   - `set-access` tightens (rw→ro) with no ceremony
//   - relaxing (ro→rw) requires the OWNER to confirm via the secure prompt;
//     a wrong confirmation leaves the level unchanged
//   - `add` refuses to widen an existing credential's level
//   - `show` redacts and `exec` refuses secret fields of a ro credential
//
// Run: node --test tests/test-vault-set-access.mjs

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
  return privateKeyPem;
}

function run(args, env = {}) {
  return new Promise((resolve) => {
    const child = spawn("node", [CLI, ...args], { env: { ...process.env, ...env } });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("exit", (code) => resolve({ code, stdout, stderr }));
  });
}

// Spawn the CLI and, when it prints the secure-form URL, submit `confirm` as
// the human would.
function runWithFormConfirm(args, confirm) {
  return new Promise((resolve, reject) => {
    const child = spawn("node", [CLI, ...args], {
      env: { ...process.env, AGENT_ID_NO_BROWSER: "1", AGENT_ID_SECURE_PROMPT: "browser" },
    });
    let stdout = "";
    let stderr = "";
    let submitted = false;
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", async (d) => {
      stderr += d;
      const m = stderr.match(/http:\/\/127\.0\.0\.1:\d+\/\?t=[a-f0-9]+/);
      if (m && !submitted) {
        submitted = true;
        try {
          const u = new URL(m[0]);
          await fetch(`http://127.0.0.1:${u.port}/submit`, {
            method: "POST",
            body: new URLSearchParams({ _token: u.searchParams.get("t"), confirm }),
          });
        } catch (err) {
          reject(err);
        }
      }
    });
    child.on("exit", (code) => resolve({ code, stdout, stderr }));
  });
}

async function getRecord(dir, name) {
  const { privateKeyPem } = JSON.parse(await readFile(statePaths(dir).mainKey, "utf8"));
  const vault = await openVault({ stateDir: dir, privateKeyPem });
  const rec = vault.get(name);
  const copy = rec ? { ...rec } : null;
  vault.lock();
  return copy;
}

test("access-level lifecycle via the CLI", async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "setaccess-"));
  try {
    await makeVault(dir);

    await t.test("add --access ro stores the level", async () => {
      const r = await run(
        ["add", "--name", "mail", "--type", "bearer", "--domains", "mail.example.com",
         "--access", "ro", "--value-env", "TOK", "--state-dir", dir],
        { TOK: "sekret_token_1" },
      );
      assert.equal(r.code, 0, r.stderr);
      assert.equal(JSON.parse(r.stdout).access, "ro");
    });

    await t.test("show redacts a ro credential's secret", async () => {
      const r = await run(["show", "--name", "mail", "--state-dir", dir]);
      assert.equal(r.code, 0, r.stderr);
      assert.ok(!r.stdout.includes("sekret_token_1"), "show leaked a ro secret");
      assert.equal(JSON.parse(r.stdout).sealed, true);
    });

    await t.test("exec refuses a ro credential's secret field", async () => {
      const r = await run([
        "exec", "--env", "T=mail.value", "--state-dir", dir, "--", "node", "-e", "0",
      ]);
      assert.notEqual(r.code, 0);
      assert.match(r.stderr + r.stdout, /access level 'ro'/);
    });

    await t.test("add cannot widen an existing ro credential", async () => {
      const r = await run(
        ["add", "--name", "mail", "--type", "bearer", "--domains", "mail.example.com",
         "--access", "rw", "--value-env", "TOK", "--state-dir", dir],
        { TOK: "attacker_supplied" },
      );
      assert.notEqual(r.code, 0);
      assert.match(r.stderr + r.stdout, /widen|set-access/);
      assert.equal((await getRecord(dir, "mail")).access, "ro");
    });

    await t.test("set-access relax with a WRONG confirmation is refused", async () => {
      const r = await runWithFormConfirm(
        ["set-access", "--name", "mail", "--access", "rw", "--state-dir", dir],
        "not-the-name",
      );
      assert.notEqual(r.code, 0);
      assert.match(r.stderr + r.stdout, /did not match/);
      assert.equal((await getRecord(dir, "mail")).access, "ro");
    });

    await t.test("set-access relax with the owner's confirmation applies", async () => {
      const r = await runWithFormConfirm(
        ["set-access", "--name", "mail", "--access", "rw", "--state-dir", dir],
        "mail",
      );
      assert.equal(r.code, 0, r.stderr);
      assert.equal(JSON.parse(r.stdout).access, "rw");
      assert.equal((await getRecord(dir, "mail")).access, "rw");
    });

    await t.test("set-access tighten needs no ceremony", async () => {
      const r = await run(["set-access", "--name", "mail", "--access", "ro", "--state-dir", dir]);
      assert.equal(r.code, 0, r.stderr);
      assert.equal((await getRecord(dir, "mail")).access, "ro");
    });

    await t.test("set-access adding a deny rule needs no ceremony; an allow rule does", async () => {
      const deny = await run([
        "set-access", "--name", "mail",
        "--rules", '[{"effect":"deny","methods":["GET"],"path":"/admin/*"}]',
        "--state-dir", dir,
      ]);
      assert.equal(deny.code, 0, deny.stderr);

      const allow = await runWithFormConfirm(
        ["set-access", "--name", "mail",
         "--rules", '[{"effect":"allow","methods":["POST"],"path":"/search"}]',
         "--state-dir", dir],
        "mail",
      );
      assert.equal(allow.code, 0, allow.stderr);
      const rec = await getRecord(dir, "mail");
      assert.equal(rec.accessRules.length, 1);
      assert.equal(rec.accessRules[0].effect, "allow");
    });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
