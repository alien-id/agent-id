#!/usr/bin/env node

// CLI lifecycle for owner-confirmed semantic capability policies: caller epoch
// values are ignored, every successful replacement increments the vault-owned
// epoch, invalid closed-schema input fails before prompting, and clear removes
// the policy only after the same owner ceremony.

import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { generateKeyPairSync } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";

import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { fingerprintPublicKeyPem } from "../plugins/agent-id-core/lib/crypto.mjs";
import { statePaths, writeJsonFile } from "../plugins/agent-id-core/lib/state.mjs";

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
  const vault = await openVault({ stateDir: dir, privateKeyPem });
  vault.add({
    name: "mail",
    type: "bearer",
    domains: ["mail.example.com"],
    value: "secret-token",
  });
  await vault.save();
  vault.lock();
}

function policy(decision = "ask", extra = {}) {
  return {
    version: 999,
    epoch: 999,
    onUnmatched: "deny",
    grants: [
      {
        id: "mail-send",
        principal: "*",
        capability: "mail.send",
        decision,
        match: { methods: ["POST"], path: "/messages/send" },
      },
    ],
    ...extra,
  };
}

function run(args) {
  return new Promise((resolve) => {
    const child = spawn("node", [CLI, ...args], { env: { ...process.env } });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("exit", (code) => resolve({ code, stdout, stderr }));
  });
}

function runWithFormConfirm(args, confirm, inspectHtml = null) {
  return new Promise((resolve, reject) => {
    const child = spawn("node", [CLI, ...args], {
      env: {
        ...process.env,
        AGENT_ID_NO_BROWSER: "1",
        AGENT_ID_SECURE_PROMPT: "browser",
      },
    });
    let stdout = "";
    let stderr = "";
    let submitted = false;
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", async (chunk) => {
      stderr += chunk;
      const match = stderr.match(/http:\/\/127\.0\.0\.1:\d+\/\?t=[a-f0-9]+/);
      if (!match || submitted) return;
      submitted = true;
      try {
        const url = new URL(match[0]);
        if (inspectHtml) {
          const html = await fetch(url).then((response) => response.text());
          inspectHtml(html);
        }
        await fetch(`http://127.0.0.1:${url.port}/submit`, {
          method: "POST",
          body: new URLSearchParams({
            _token: url.searchParams.get("t"),
            confirm,
          }),
        });
      } catch (err) {
        reject(err);
      }
    });
    child.on("exit", (code) => resolve({ code, stdout, stderr }));
  });
}

async function getRecord(dir) {
  const { privateKeyPem } = JSON.parse(await readFile(statePaths(dir).mainKey, "utf8"));
  const vault = await openVault({ stateDir: dir, privateKeyPem });
  const copy = structuredClone(vault.get("mail"));
  vault.lock();
  return copy;
}

async function getPolicy(dir) {
  return (await getRecord(dir)).capabilityPolicy || null;
}

test("set-capabilities owns epochs and requires owner confirmation", async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "setcapabilities-"));
  try {
    await makeVault(dir);

    await t.test("inline policy is normalized to version 1 and epoch 1", async () => {
      const result = await runWithFormConfirm(
        [
          "set-capabilities",
          "--name",
          "mail",
          "--policy",
          JSON.stringify(policy()),
          "--state-dir",
          dir,
        ],
        "mail",
      );
      assert.equal(result.code, 0, result.stderr);
      const stored = await getPolicy(dir);
      assert.deepEqual(
        { version: stored.version, epoch: stored.epoch },
        { version: 1, epoch: 1 },
      );
      assert.equal(JSON.parse(result.stdout).capabilityPolicy.epoch, 1);
    });

    await t.test("policy-file replacement increments epoch and ignores its epoch", async () => {
      const file = path.join(dir, "next-policy.json");
      await writeFile(file, JSON.stringify(policy("allow")), "utf8");
      const result = await runWithFormConfirm(
        [
          "set-capabilities",
          "--name",
          "mail",
          "--policy-file",
          file,
          "--state-dir",
          dir,
        ],
        "mail",
      );
      assert.equal(result.code, 0, result.stderr);
      const stored = await getPolicy(dir);
      assert.equal(stored.version, 1);
      assert.equal(stored.epoch, 2);
      assert.equal(stored.grants[0].decision, "allow");
    });

    await t.test("wrong confirmation leaves policy unchanged", async () => {
      const result = await runWithFormConfirm(
        [
          "set-capabilities",
          "--name",
          "mail",
          "--policy",
          JSON.stringify(policy("deny")),
          "--state-dir",
          dir,
        ],
        "not-mail",
      );
      assert.notEqual(result.code, 0);
      assert.match(result.stdout + result.stderr, /did not match/);
      assert.equal((await getPolicy(dir)).epoch, 2);
    });

    await t.test("owner form shows every grant and semantic constraint", async () => {
      const many = policy("ask", {
        grants: Array.from({ length: 13 }, (_, index) => ({
          id: `grant-${index + 1}`,
          principal: "*",
          capability: index === 12 ? "commerce.purchase" : "mail.send",
          decision: index === 12 ? "allow" : "ask",
          priority: index,
          match: {
            methods: ["POST"],
            path: index === 12 ? "/orders/commit" : `/messages/${index + 1}`,
          },
          ...(index === 12
            ? { constraints: [{ path: "/totalMinor", op: "lte", value: 999999 }] }
            : {}),
        })),
      });
      const result = await runWithFormConfirm(
        [
          "set-capabilities",
          "--name",
          "mail",
          "--policy",
          JSON.stringify(many),
          "--state-dir",
          dir,
        ],
        "not-mail",
        (html) => {
          assert.match(html, /grant-13/);
          assert.match(html, /commerce\.purchase/);
          assert.match(html, /totalMinor/);
          assert.match(html, /999999/);
          assert.doesNotMatch(html, /and 1 more grant/);
        },
      );
      assert.notEqual(result.code, 0);
      assert.equal((await getPolicy(dir)).epoch, 2);
    });

    await t.test("closed-schema validation fails before the owner ceremony", async () => {
      const result = await run([
        "set-capabilities",
        "--name",
        "mail",
        "--policy",
        JSON.stringify(policy("ask", { surprise: true })),
        "--state-dir",
        dir,
      ]);
      assert.notEqual(result.code, 0);
      assert.match(result.stdout + result.stderr, /unknown key 'surprise'/);
      assert.equal((await getPolicy(dir)).epoch, 2);
    });

    await t.test("inline JSON null is rejected rather than treated as clear", async () => {
      const result = await run([
        "set-capabilities",
        "--name",
        "mail",
        "--policy",
        "null",
        "--state-dir",
        dir,
      ]);
      assert.notEqual(result.code, 0);
      assert.match(result.stdout + result.stderr, /JSON object/);
      assert.equal((await getPolicy(dir)).epoch, 2);
    });

    await t.test("duplicate policy keys are rejected before the owner ceremony", async () => {
      const duplicate = JSON.stringify(policy()).replace(
        '"onUnmatched":"deny"',
        '"onUnmatched":"ask","onUnmatched":"deny"',
      );
      const result = await run([
        "set-capabilities",
        "--name",
        "mail",
        "--policy",
        duplicate,
        "--state-dir",
        dir,
      ]);
      assert.notEqual(result.code, 0);
      assert.match(result.stdout + result.stderr, /duplicate JSON key/);
      assert.equal((await getPolicy(dir)).epoch, 2);
    });

    await t.test("clear removes policy only after owner confirmation", async () => {
      const result = await runWithFormConfirm(
        ["set-capabilities", "--name", "mail", "--clear-policy", "--state-dir", dir],
        "mail",
      );
      assert.equal(result.code, 0, result.stderr);
      assert.equal(JSON.parse(result.stdout).capabilityPolicy, null);
      assert.equal(await getPolicy(dir), null);
      assert.equal((await getRecord(dir)).capabilityPolicyEpoch, 3);
    });

    await t.test("re-adding after clear continues the epoch instead of rolling back", async () => {
      const result = await runWithFormConfirm(
        [
          "set-capabilities",
          "--name",
          "mail",
          "--policy",
          JSON.stringify(policy()),
          "--state-dir",
          dir,
        ],
        "mail",
      );
      assert.equal(result.code, 0, result.stderr);
      const stored = await getRecord(dir);
      assert.equal(stored.capabilityPolicy.epoch, 4);
      assert.equal(stored.capabilityPolicyEpoch, 4);
    });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
