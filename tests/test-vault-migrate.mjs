#!/usr/bin/env node

// Migration test: legacy v4.0.0 per-credential vault → portable v5 single-file.

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { execFile as execFileCb } from "node:child_process";

import {
  ensureDir,
  statePaths,
  writeJsonFile,
} from "../plugins/agent-id-core/lib/state.mjs";
import { deriveLegacyVaultKey } from "../plugins/agent-id-vault/lib/legacy.mjs";
import { openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { generateEd25519PemPair } from "../plugins/agent-id-core/lib/crypto.mjs";

import { createCipheriv, randomBytes } from "node:crypto";

const execFile = promisify(execFileCb);
const VAULT_CLI = path.resolve("plugins/agent-id-vault/bin/cli.mjs");

function legacyEncryptForTest(key, plaintext) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString("hex"),
    data: ct.toString("hex"),
    tag: tag.toString("hex"),
  };
}

describe("vault migration v4 → v5", () => {
  let stateDir;
  let passphraseFile;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "vault-migrate-"));
    const paths = statePaths(stateDir);

    // Plant a v4 agent key + two legacy credential files.
    const { privateKeyPem, publicKeyPem } = generateEd25519PemPair();
    await writeJsonFile(paths.mainKey, {
      version: 1,
      agentId: "did:test:agent-1",
      publicKeyPem,
      privateKeyPem,
      createdAt: 0,
    });

    await ensureDir(paths.vaultDir);
    const legacyKey = deriveLegacyVaultKey(privateKeyPem);
    for (const [service, value] of [
      ["github", "ghp_legacy_1"],
      ["openai", "sk-legacy-2"],
    ]) {
      const enc = legacyEncryptForTest(legacyKey, value);
      await writeJsonFile(path.join(paths.vaultDir, `${service}.json`), {
        version: 1,
        service,
        type: "api-key",
        url: null,
        username: null,
        encrypted: enc,
        createdAt: 1,
        updatedAt: 1,
      });
    }

    passphraseFile = path.join(stateDir, "pass.txt");
    await fs.writeFile(passphraseFile, "migration-pass-9999\n");
  });

  after(async () => {
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("migrate moves both credentials into vault.enc", async () => {
    const { stdout } = await execFile(
      "node",
      [
        VAULT_CLI,
        "migrate",
        "--passphrase-file",
        passphraseFile,
        "--state-dir",
        stateDir,
      ],
      { encoding: "utf8" }
    );
    const result = JSON.parse(stdout);
    assert.equal(result.ok, true);
    assert.equal(result.migrated, 2);

    // Open the new vault and confirm both credentials present.
    const vault = await openVault({
      stateDir,
      passphrase: "migration-pass-9999",
    });
    try {
      const names = vault
        .list()
        .map((c) => c.name)
        .sort();
      assert.deepEqual(names, ["github", "openai"]);
      assert.equal(vault.get("github").value, "ghp_legacy_1");
      assert.equal(vault.get("openai").value, "sk-legacy-2");
      // Domains default to UNCONFIGURED so the proxy refuses to inject
      // until the user updates them.
      assert.deepEqual(vault.get("github").domains, ["UNCONFIGURED.invalid"]);
    } finally {
      vault.lock();
    }

    // Legacy dir renamed.
    const renamedExists = await fs
      .access(path.join(stateDir, "vault.bak"))
      .then(() => true)
      .catch(() => false);
    assert.equal(renamedExists, true);
  });
});
