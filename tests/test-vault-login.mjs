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

import { listMetadata, validateRecord } from "../plugins/agent-id-vault/lib/store.mjs";
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

// ─── passwordless ─────────────────────────────────────────────────────────────────

test("validateRecord: a passwordless login needs no password, but still needs a code step", () => {
  const pwless = { name: "demo", type: "login", domains: ["x"], username: "u", passwordless: true };
  assert.doesNotThrow(() => validateRecord({ ...pwless, otp: "interactive" }));
  assert.doesNotThrow(() =>
    validateRecord({ ...pwless, otp: "totp", totpSecret: "GEZDGNBVGY3TQOJQ" }),
  );
  // Nothing to sign in with: no password and no code.
  assert.throws(() => validateRecord({ ...pwless, otp: "none" }), /needs otp=interactive or totp/i);
  assert.throws(() => validateRecord(pwless), /needs otp=interactive or totp/i);
  // The username is still mandatory — it is what gets submitted.
  assert.throws(
    () => validateRecord({ name: "demo", type: "login", domains: ["x"], passwordless: true, otp: "interactive" }),
    /username.*required/i,
  );
});

test("validateRecord: password + an e-mailed code stays expressible (the axes are separate)", () => {
  assert.doesNotThrow(() => validateRecord(loginRec({ otp: "interactive" })));
});

test("validateRecord: a stored login predating `passwordless` is still valid", () => {
  const legacy = { name: "demo", type: "login", domains: ["x"], username: "u", password: "p" };
  assert.doesNotThrow(() => validateRecord(legacy));
});

// ─── recipe ───────────────────────────────────────────────────────────────────────

test("validateRecord: a recipe is checked against the action vocabulary on the way in", () => {
  const withRecipe = (recipe) => loginRec({ recipe });
  assert.doesNotThrow(() =>
    validateRecord(
      withRecipe([
        { action: "fill", selector: "#u", value: "{username}" },
        { action: "click", selector: "#go" },
        { action: "wait", ms: 500 },
      ]),
    ),
  );
  assert.throws(() => validateRecord(withRecipe([{ action: "frobnicate" }])), /must be one of/i);
  assert.throws(() => validateRecord(withRecipe(["fill #u"])), /step 0 must be an object/i);
  assert.throws(() => validateRecord(withRecipe({ action: "fill" })), /must be an array of steps/i);
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

// ─── the passwordless card: ONE field ──────────────────────────────────────────────

test("add --type login --passwordless --form shows a single identifier field, and stores no password", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "vault-pwless-"));
  try {
    const privateKeyPem = await makeVault(dir);
    const USER = "alice@example.com";

    const child = spawn(
      "node",
      [
        CLI, "add", "--name", "booking", "--type", "login",
        "--passwordless", "--otp", "interactive",
        "--login-url", "https://account.example.com/sign-in",
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

    // The card itself is the contract: one field, and it is the identifier.
    const html = await (await fetch(u)).text();
    const names = [...html.matchAll(/<input[^>]*\bname="([^"]+)"/g)]
      .map((m) => m[1])
      .filter((n) => n !== "_token");
    assert.deepEqual(names, ["username"], `expected one identifier field, got ${names.join(", ")}`);
    assert.ok(!/type="password"/.test(html), "a passwordless card must render no password input");

    const res = await fetch(`http://127.0.0.1:${u.port}/submit`, {
      method: "POST",
      body: new URLSearchParams({ _token: token, username: USER }),
    });
    assert.equal(res.status, 200);

    const code = await new Promise((r) => child.on("exit", r));
    assert.equal(code, 0, `CLI failed: ${stderr}`);

    const vault = await openVault({ stateDir: dir, privateKeyPem });
    const rec = vault.get("booking");
    assert.equal(rec.username, USER);
    assert.equal(rec.passwordless, true);
    assert.equal(rec.password, undefined, "nothing may be stored as a password");
    assert.equal(rec.otp, "interactive");
    assert.deepEqual(rec.domains, ["account.example.com"]);
    vault.lock();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("add --type login without --domains or --login-url is refused instead of minting an unusable cred", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "vault-nodomains-"));
  try {
    await makeVault(dir);
    const child = spawn(
      "node",
      [CLI, "add", "--name", "x", "--type", "login", "--username", "u", "--password", "p", "--state-dir", dir],
      { env: { ...process.env } },
    );
    let stdout = "";
    child.stdout.on("data", (d) => (stdout += d));
    const code = await new Promise((r) => child.on("exit", r));
    assert.notEqual(code, 0, "must not succeed");
    assert.match(stdout, /--domains .* or a --login-url/i);
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

// ─── set-recipe ───────────────────────────────────────────────────────────────────

test("set-recipe attaches a recipe to an existing login and re-validates its steps", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "vault-setrecipe-"));
  try {
    const privateKeyPem = await makeVault(dir);
    let vault = await openVault({ stateDir: dir, privateKeyPem });
    vault.add(loginRec({ otp: "interactive" }));
    await vault.save();
    vault.lock();

    const RECIPE = JSON.stringify([
      { action: "fill", selector: "input[type=email]", value: "{username}" },
      { action: "press", selector: "input[type=email]", key: "Enter" },
      { action: "fill", selector: "input[autocomplete=one-time-code]", value: "{otp}" },
    ]);
    const run = (args) =>
      new Promise((resolve) => {
        const child = spawn("node", [CLI, "set-recipe", "--name", "demo", ...args, "--state-dir", dir]);
        let stdout = "";
        child.stdout.on("data", (d) => (stdout += d));
        child.on("exit", (code) => resolve({ code, stdout }));
      });

    const ok = await run(["--recipe", RECIPE]);
    assert.equal(ok.code, 0, ok.stdout);
    assert.equal(JSON.parse(ok.stdout).steps, 3);

    vault = await openVault({ stateDir: dir, privateKeyPem });
    assert.equal(vault.get("demo").recipe.length, 3);
    vault.lock();

    // An unknown action is refused here, not mid-login with a browser open.
    const bad = await run(["--recipe", JSON.stringify([{ action: "frobnicate" }])]);
    assert.notEqual(bad.code, 0);
    assert.match(bad.stdout, /must be one of/i);

    const garbage = await run(["--recipe", "{not json"]);
    assert.notEqual(garbage.code, 0);
    assert.match(garbage.stdout, /not valid JSON/i);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ─── list metadata ────────────────────────────────────────────────────────────────

test("listMetadata surfaces a login's shape without surfacing its secrets", () => {
  const [meta] = listMetadata({
    credentials: [
      loginRec({
        otp: "interactive",
        passwordless: true,
        password: undefined,
        loginUrl: "https://example.com/login",
        recipe: [{ action: "click", selector: "#go" }],
        createdAt: 1,
        updatedAt: 2,
      }),
    ],
  });
  assert.equal(meta.otp, "interactive");
  assert.equal(meta.passwordless, true);
  assert.equal(meta.loginUrl, "https://example.com/login");
  assert.equal(meta.hasRecipe, true);
  assert.equal(meta.username, undefined, "the identifier is a secret field");
  assert.equal(meta.password, undefined);
  assert.equal(meta.recipe, undefined, "the steps themselves stay in the record");
});

test("the card names the site, not the credential the agent invented", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "vault-cardtitle-"));
  try {
    await makeVault(dir);

    const child = spawn(
      "node",
      [
        CLI, "add", "--name", "airbnb-passwordless-again", "--type", "login",
        "--passwordless", "--otp", "interactive",
        "--login-url", "https://www.airbnb.com/login",
        "--form", "--state-dir", dir,
      ],
      { env: { ...process.env, AGENT_ID_NO_BROWSER: "1", AGENT_ID_SECURE_PROMPT: "browser" } },
    );
    child.stdout.on("data", () => {});
    child.stderr.on("data", () => {});

    const u = new URL(await waitForUrl(child));
    const html = await (await fetch(u)).text();

    // The name is the vault's key and the agent's to choose; it named its own
    // second attempt, and the owner was asked to "Add credential:
    // airbnb-passwordless-again" while looking at Airbnb's sign-in page.
    assert.ok(!html.includes("airbnb-passwordless-again"), "the credential's name must not reach the card");
    // The title says what is being asked, the line below says what it is for.
    assert.match(html, /Enter it securely/);
    assert.match(html, /Airbnb\.com sign-in/, "the site, as the owner calls it");
    assert.ok(!html.includes("www.Airbnb"), "a sign-in subdomain is noise");
    // Metadata for addressing a credential, not for a person: `*.airbnb.com` reads
    // as a typo, and the type is the agent's vocabulary.
    assert.ok(!html.includes("login ·"), "the type does not belong on the card");
    assert.ok(!/\*\.airbnb\.com/.test(html), "the allowlist does not belong on the card");
    // The primitive told the owner nothing they could act on, and read as a warning
    // label on a screen meant to reassure.
    assert.ok(!/AES-256-GCM|HKDF/.test(html), "no cipher names on a card");
    // "isn't saved anywhere" was false on the one card whose whole purpose is to
    // save it. What is true is where it goes, and that is the reassuring part.
    assert.match(html, /I never see it\. It goes straight into your encrypted vault\./);
    assert.ok(!/isn't saved anywhere/.test(html), "the card must not deny what it is doing");
    // Airbnb's own first screen says "Phone number or email"; the old label
    // promised a mailbox and the code arrived as an SMS.
    assert.match(html, /Email or phone number/, "a passwordless identifier is not email-only");
    // Step one of two: submitting it looks like nothing happened unless it says so.
    assert.match(html, /The code comes at sign-in/);

    child.kill();
    await new Promise((r) => child.on("exit", r));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
