#!/usr/bin/env node

// Tests for the `login` credential type and the `set-totp` command:
//   - validateRecord happy/sad paths for `login`
//   - `add --type login --form` stores username/password/totpSecret without the
//     secrets ever appearing on the CLI's stdout/stderr
//   - `set-totp` attaches a 2FA seed (an otpauth:// URI) to an existing login
//
// Run: node --test tests/test-vault-login.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";

import { validateRecord } from "../plugins/agent-id-vault/lib/store.mjs";
import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { writeJsonFile, statePaths } from "../plugins/agent-id-core/lib/state.mjs";
import { fingerprintPublicKeyPem } from "../plugins/agent-id-core/lib/crypto.mjs";

const CLI = new URL("../plugins/agent-id-vault/bin/cli.mjs", import.meta.url).pathname;

function loginRec(over = {}) {
  return { name: "demo", type: "login", domains: ["example.com"], username: "u", password: "p", ...over };
}

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

// ─── schema ───────────────────────────────────────────────────────────────────────

test("validateRecord: a valid login passes (otp defaults to none)", () => {
  assert.doesNotThrow(() => validateRecord(loginRec()));
  assert.doesNotThrow(() => validateRecord(loginRec({ otp: "none" })));
  assert.doesNotThrow(() => validateRecord(loginRec({ otp: "interactive" })));
  assert.doesNotThrow(() => validateRecord(loginRec({ loginUrl: "https://example.com/login" })));
});

test("validateRecord: login requires username and password", () => {
  assert.throws(() => validateRecord(loginRec({ password: "" })), /password.*required/i);
  assert.throws(
    () => validateRecord({ name: "demo", type: "login", domains: ["x"], password: "p" }),
    /username.*required/i,
  );
});

test("validateRecord: rejects a bad otp mode", () => {
  assert.throws(() => validateRecord(loginRec({ otp: "sms" })), /otp must be one of/i);
});

test("validateRecord: otp=totp requires a totpSecret", () => {
  assert.throws(() => validateRecord(loginRec({ otp: "totp" })), /totpSecret.*required/i);
  assert.doesNotThrow(() =>
    validateRecord(loginRec({ otp: "totp", totpSecret: "GEZDGNBVGY3TQOJQ" })),
  );
});

test("validateRecord: rejects an invalid loginUrl", () => {
  assert.throws(() => validateRecord(loginRec({ loginUrl: "not a url" })), /loginUrl/i);
});

// ─── add --type login --form (secret never leaks) ──────────────────────────────────

test("add --type login --form stores username/password/totpSecret; nothing leaks to the agent", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "vault-login-"));
  try {
    const privateKeyPem = await makeVault(dir);
    const USER = "alice@example.com";
    const PW = "p@ss-only-the-form-sees";
    const SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    const child = spawn(
      "node",
      [
        CLI, "add", "--name", "demo", "--type", "login",
        "--otp", "totp", "--login-url", "https://example.com/login",
        "--form", "--state-dir", dir,
      ],
      { env: { ...process.env, AGENT_ID_NO_BROWSER: "1", AGENT_ID_SECURE_PROMPT: "browser" } },
    );
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));

    const u = new URL(await waitForUrl(child));
    const token = u.searchParams.get("t");
    const res = await fetch(`http://127.0.0.1:${u.port}/submit`, {
      method: "POST",
      body: new URLSearchParams({ _token: token, username: USER, password: PW, totpSecret: SEED }),
    });
    assert.equal(res.status, 200);

    const code = await new Promise((r) => child.on("exit", r));
    assert.equal(code, 0, `CLI failed: ${stderr}`);

    // The username is non-secret context, but the password and seed must not leak.
    assert.ok(!stdout.includes(PW) && !stderr.includes(PW), "password leaked");
    assert.ok(!stdout.includes(SEED) && !stderr.includes(SEED), "TOTP seed leaked");
    assert.equal(JSON.parse(stdout).type, "login");

    const vault = await openVault({ stateDir: dir, privateKeyPem });
    const rec = vault.get("demo");
    assert.equal(rec.username, USER);
    assert.equal(rec.password, PW);
    assert.equal(rec.otp, "totp");
    assert.equal(rec.totpSecret, SEED);
    assert.deepEqual(rec.domains, ["example.com"]); // derived from loginUrl host
    vault.lock();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ─── set-totp (attach a seed later, accepting an otpauth:// URI) ────────────────────

test("set-totp attaches a TOTP seed (otpauth URI) to an existing interactive login", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "vault-settotp-"));
  try {
    const privateKeyPem = await makeVault(dir);
    // Seed the vault with a login that has no 2FA seed yet.
    let vault = await openVault({ stateDir: dir, privateKeyPem });
    vault.add(loginRec({ otp: "interactive" }));
    await vault.save();
    vault.lock();

    const SEED_URI =
      "otpauth://totp/Demo:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30&digits=6";
    const child = spawn(
      "node",
      [CLI, "set-totp", "--name", "demo", "--seed-env", "SEED_URI", "--state-dir", dir],
      { env: { ...process.env, SEED_URI } },
    );
    let stderr = "";
    child.stderr.on("data", (d) => (stderr += d));
    const code = await new Promise((r) => child.on("exit", r));
    assert.equal(code, 0, `set-totp failed: ${stderr}`);

    vault = await openVault({ stateDir: dir, privateKeyPem });
    const rec = vault.get("demo");
    assert.equal(rec.otp, "totp");
    assert.equal(rec.totpSecret, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    assert.equal(rec.period, 30);
    assert.equal(rec.digits, 6);
    vault.lock();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
