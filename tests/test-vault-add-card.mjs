#!/usr/bin/env node

// End-to-end test for `agent-id-vault add --type card --form`, through the REAL CLI.
//
// The four field names are a wire contract, not labels: the secure-input envelope
// carries no field type, so the name a value is sealed under is what tells the
// phone which screen to draw. A rename here downgrades it to four plain text
// boxes with the wrong keyboards and nothing fails loudly — which is exactly the
// break a test has to catch, and it can only be seen from outside the module.
//
// Run: node --test tests/test-vault-add-card.mjs

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

// The Visa test PAN every processor publishes, so a leak of this fixture is not a card.
const PAN = "4242424242424242";
const EXPIRY = "1234";
const CVC = "123";
const HOLDER = "Alien Owner";

const CONTRACT_FIELDS = ["cardNumber", "cardExpiry", "cardSecurityCode", "cardholderName"];

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

function runCli(args, dir) {
  return new Promise((resolve) => {
    const child = spawn("node", [CLI, ...args, "--state-dir", dir]);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("exit", (code) => resolve({ code, stdout, stderr }));
  });
}

test("a card is typed into the secure form under the names the clients key their screens off", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "addcard-"));
  let child = null;
  let submitted = false;
  try {
    await makeVault(dir);

    // No --domains: where a card may be used is the owner's to grant, one
    // approved payment at a time, so it must be storable without one.
    child = spawn(
      "node",
      [CLI, "add", "--name", "visa", "--type", "card", "--form", "--state-dir", dir],
      { env: { ...process.env, AGENT_ID_NO_BROWSER: "1", AGENT_ID_SECURE_PROMPT: "browser" } },
    );
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));

    const url = await waitForUrl(child);
    const u = new URL(url);
    const token = u.searchParams.get("t");

    const form = await (await fetch(url)).text();
    for (const field of CONTRACT_FIELDS) {
      assert.ok(
        form.includes(`name="${field}"`),
        `the form does not ask for ${field} — the phone would draw a plain box for it`,
      );
    }

    const res = await fetch(`http://127.0.0.1:${u.port}/submit`, {
      method: "POST",
      body: new URLSearchParams({
        _token: token,
        cardNumber: PAN,
        cardExpiry: EXPIRY,
        cardSecurityCode: CVC,
        cardholderName: HOLDER,
      }),
    });
    assert.equal(res.status, 200);
    submitted = true;

    const code = await new Promise((r) => child.on("exit", r));
    assert.equal(code, 0, `CLI failed: ${stderr}`);

    // The PAN and the holder, not the security code: three digits cannot be told
    // apart from the epoch milliseconds the success JSON already carries, so a
    // check on it would fail on whichever run happened to mint a matching stamp.
    for (const secret of [PAN, HOLDER]) {
      assert.ok(!stdout.includes(secret), "stdout leaked a card value");
      assert.ok(!stderr.includes(secret), "stderr leaked a card value");
    }

    const { privateKeyPem } = JSON.parse(await readFile(statePaths(dir).mainKey, "utf8"));
    const vault = await openVault({ stateDir: dir, privateKeyPem });
    const rec = vault.get("visa");
    assert.equal(rec.cardNumber, PAN);
    assert.equal(rec.cardExpiry, EXPIRY);
    assert.equal(rec.cardSecurityCode, CVC);
    assert.equal(rec.cardholderName, HOLDER);
    // Storing a card grants no merchant.
    assert.deepEqual(rec.domains, []);
    assert.equal(rec.access, "ro");
    vault.lock();

    // …and a read of it never comes back out through the agent's own channel.
    const shown = JSON.parse((await runCli(["show", "--name", "visa"], dir)).stdout);
    assert.equal(shown.sealed, true);
    assert.ok(!JSON.stringify(shown).includes(PAN), "show returned the card number");
    assert.ok(!JSON.stringify(shown).includes(HOLDER), "show returned the cardholder");

    // What the agent may learn about a stored card: that it exists, and which one.
    const listed = JSON.parse((await runCli(["list"], dir)).stdout);
    const entry = listed.credentials.find((c) => c.name === "visa");
    assert.equal(entry.type, "card");
    assert.equal(entry.cardLast4, "4242");
    for (const field of CONTRACT_FIELDS) {
      assert.ok(!(field in entry), `list exposed ${field}`);
    }
  } finally {
    // An assertion above the submit leaves the CLI waiting on a form nobody will
    // fill; without this the runner hangs instead of reporting the failure.
    if (!submitted) child?.kill();
    await rm(dir, { recursive: true, force: true });
  }
});

test("a card refuses to be typed on the command line", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "addcard-argv-"));
  try {
    await makeVault(dir);
    const { code, stdout } = await runCli(["add", "--name", "visa", "--type", "card"], dir);
    assert.notEqual(code, 0);
    assert.match(JSON.parse(stdout).error, /--form/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a card refuses an allowlist the caller declared for itself", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "addcard-domains-"));
  try {
    await makeVault(dir);
    const { code, stdout } = await runCli(
      ["add", "--name", "visa", "--type", "card", "--domains", "shop.example.com", "--form"],
      dir,
    );
    assert.notEqual(code, 0);
    assert.match(JSON.parse(stdout).error, /no --domains/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
