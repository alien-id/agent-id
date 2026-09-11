#!/usr/bin/env node

// `vault.enc` holds the only copy of every credential in it, and `save()`
// rewrites the whole file. A write that lands in place can therefore be
// observed — or interrupted — half done, which no unlock method can recover
// from. The file is written temp-then-rename instead, so a reader sees the
// whole previous vault or the whole new one, and a failed write changes
// nothing.
//
// Run: node --test --test-force-exit tests/test-vault-atomic-write.mjs

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { statePaths } from "../plugins/agent-id-core/lib/state.mjs";

async function tempStateDir(tag) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), `vault-atomic-${tag}-`));
  await initVault({ stateDir: dir, passphrase: "p" });
  return dir;
}

describe("vault save is atomic", () => {
  it("never exposes a partially written vault and leaves no temp file", async () => {
    const stateDir = await tempStateDir("concurrent");
    const vaultFile = statePaths(stateDir).vaultFile;
    try {
      const vault = await openVault({ stateDir, passphrase: "p" });
      vault.add({ name: "seed", type: "bearer", domains: ["example.test"], value: "SEED" });
      await vault.save();

      // Large enough that an in-place write takes several chunks, so a reader
      // polling across it would catch a truncated file.
      vault.add({
        name: "big",
        type: "secret",
        domains: ["*"],
        value: "x".repeat(6 * 1024 * 1024),
      });

      const inoBefore = (await fs.stat(vaultFile)).ino;
      let stop = false;
      let reads = 0;
      let torn = 0;
      const reader = (async () => {
        while (!stop) {
          let raw;
          try {
            raw = await fs.readFile(vaultFile, "utf8");
          } catch {
            torn += 1;
            continue;
          }
          reads += 1;
          try {
            JSON.parse(raw);
          } catch {
            torn += 1;
          }
        }
      })();

      await vault.save();
      stop = true;
      await reader;
      vault.lock();

      assert.ok(reads > 0, "the reader never got to look at the file");
      assert.equal(torn, 0, "a reader observed a vault.enc that was not a whole file");
      assert.notEqual(
        (await fs.stat(vaultFile)).ino,
        inoBefore,
        "the vault must be replaced by a rename, not rewritten in place — only the " +
          "replacement gives a concurrent reader an all-or-nothing view",
      );

      const leftovers = (await fs.readdir(stateDir)).filter((f) => f.includes(".tmp-"));
      assert.deepEqual(leftovers, [], "the temp file must not outlive the save");

      const reopened = await openVault({ stateDir, passphrase: "p" });
      assert.equal(reopened.get("seed").value, "SEED");
      assert.equal(reopened.get("big").value.length, 6 * 1024 * 1024);
      reopened.lock();
    } finally {
      await fs.rm(stateDir, { recursive: true, force: true });
    }
  });

  it(
    "leaves the previous vault intact when the write cannot land",
    {
      skip:
        process.getuid && process.getuid() === 0
          ? "runs as root, which is not stopped by directory permissions"
          : false,
    },
    async () => {
      const stateDir = await tempStateDir("failed");
      const vaultFile = statePaths(stateDir).vaultFile;
      try {
        const vault = await openVault({ stateDir, passphrase: "p" });
        vault.add({ name: "first", type: "bearer", domains: ["example.test"], value: "FIRST" });
        await vault.save();
        const before = await fs.readFile(vaultFile, "utf8");

        vault.add({ name: "second", type: "bearer", domains: ["example.test"], value: "SECOND" });
        await fs.chmod(stateDir, 0o500);
        try {
          await assert.rejects(
            () => vault.save(),
            "a save that cannot write must fail loudly, not half-write the vault",
          );
          assert.equal(
            await fs.readFile(vaultFile, "utf8"),
            before,
            "the previous vault.enc must be untouched",
          );
        } finally {
          await fs.chmod(stateDir, 0o700);
        }
        vault.lock();

        const reopened = await openVault({ stateDir, passphrase: "p" });
        assert.equal(reopened.get("first").value, "FIRST");
        assert.equal(reopened.get("second"), null);
        reopened.lock();

        const leftovers = (await fs.readdir(stateDir)).filter((f) => f.includes(".tmp-"));
        assert.deepEqual(leftovers, [], "a failed save must clean its temp file up");
      } finally {
        await fs.chmod(stateDir, 0o700).catch(() => {});
        await fs.rm(stateDir, { recursive: true, force: true });
      }
    },
  );
});
