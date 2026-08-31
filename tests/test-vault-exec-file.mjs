#!/usr/bin/env node

// `agent-id-vault exec --file VAR=cred.field` materializes a secret to a temp
// 0600 file, sets VAR to the path, runs the command, and shreds the file after.
// The agent gets the path, never the contents.
//
// Run: node --test tests/test-vault-exec-file.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm, readFile, writeFile } from "node:fs/promises";
import { existsSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";

import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import {
  writeJsonFile,
  statePaths,
} from "../plugins/agent-id-core/lib/state.mjs";
import { fingerprintPublicKeyPem } from "../plugins/agent-id-core/lib/crypto.mjs";

const CLI = new URL("../plugins/agent-id-vault/bin/cli.mjs", import.meta.url)
  .pathname;
const KEY =
  "-----BEGIN PRIVATE KEY-----\nMOCKKEYLINE1\nMOCKKEYLINE2\n-----END PRIVATE KEY-----\n";

async function makeVaultWithSecret(dir) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey
    .export({ format: "pem", type: "spki" })
    .toString();
  const privateKeyPem = privateKey
    .export({ format: "pem", type: "pkcs8" })
    .toString();
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
  const v = await openVault({ stateDir: dir, privateKeyPem });
  v.add({ name: "deploy-key", type: "secret", domains: ["*"], value: KEY });
  await v.save();
  v.lock();
}

test("exec --file writes a 0600 temp file, passes its path, shreds it after", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "execfile-"));
  try {
    await makeVaultWithSecret(dir);
    const probe = path.join(dir, "probe.txt");

    // The child reads $K (the file) and records the path + perms + contents so we
    // can assert materialization; then exec shreds the file on exit.
    const r = spawnSync(
      "node",
      [
        CLI,
        "exec",
        "--file",
        "K=deploy-key.value",
        "--state-dir",
        dir,
        // GNU `stat -c` first (fails cleanly on BSD with no stdout), then BSD
        // `stat -f`. The reverse order pollutes the output on Linux: GNU treats
        // `-f` as --file-system and prints to stdout before the `||` fires.
        "--",
        "sh",
        "-c",
        `printf '%s\\n%s\\n' "$K" "$(stat -c '%a' "$K" 2>/dev/null || stat -f '%Lp' "$K")" > "${probe}"; cat "$K" >> "${probe}"`,
      ],
      { encoding: "utf8" }
    );
    assert.equal(r.status, 0, `exec failed: ${r.stderr}`);

    // The agent-visible streams never carry the key material.
    assert.ok(
      !(r.stdout || "").includes("MOCKKEYLINE1"),
      "stdout leaked the key"
    );
    assert.ok(
      !(r.stderr || "").includes("MOCKKEYLINE1"),
      "stderr leaked the key"
    );
    assert.match(r.stderr, /K=deploy-key\.value \(file\)/);

    // What the child saw via the file path.
    const lines = (await readFile(probe, "utf8")).split("\n");
    const filePath = lines[0];
    const mode = lines[1];
    assert.ok(
      filePath.startsWith(os.tmpdir()) || filePath.includes("agent-id-exec-"),
      `path: ${filePath}`
    );
    assert.equal(mode.trim(), "600", "file must be mode 0600");
    assert.ok(
      (await readFile(probe, "utf8")).includes("MOCKKEYLINE1"),
      "child read the key from the file"
    );

    // After exec exits, the temp file is gone.
    assert.equal(
      existsSync(filePath),
      false,
      "temp key file must be shredded + removed"
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
