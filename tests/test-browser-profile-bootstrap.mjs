#!/usr/bin/env node

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import {
  ensureAnonymousDefaultProfile,
  sealedProfileExists,
  unsealProfile,
} from "../plugins/agent-id-browser/lib/profile-store.mjs";

function mockVault() {
  const records = new Map();
  let saves = 0;
  return {
    get: (name) => records.get(name) || null,
    add: (record) => {
      records.set(record.name, record);
      return record;
    },
    save: async () => {
      saves++;
    },
    records,
    saveCount: () => saves,
  };
}

test("first use creates one sealed anonymous L0 default profile", async () => {
  const stateDir = await fs.mkdtemp(
    path.join(os.tmpdir(), "agentid-anon-profile-")
  );
  const vault = mockVault();
  try {
    const record = await ensureAnonymousDefaultProfile({
      vault,
      stateDir,
      name: "main",
    });
    assert.equal(record.type, "browser-profile");
    assert.equal(record.bootstrap, "anonymous-l0");
    assert.equal(record.exportable, false);
    assert.equal(record.headless, true);
    assert.match(record.dek, /^[0-9a-f]{64}$/);
    assert.equal(await sealedProfileExists(stateDir, record.profileFile), true);
    assert.equal(vault.saveCount(), 1);

    const restored = path.join(stateDir, "restored");
    await unsealProfile({
      stateDir,
      file: record.profileFile,
      dekHex: record.dek,
      destDir: restored,
    });
    assert.deepEqual(await fs.readdir(restored), []);

    const same = await ensureAnonymousDefaultProfile({
      vault,
      stateDir,
      name: "main",
    });
    assert.equal(same, record);
    assert.equal(vault.saveCount(), 1, "bootstrap must be idempotent");
  } finally {
    await fs.rm(stateDir, { recursive: true, force: true });
  }
});

test("named profiles never auto-create", async () => {
  const stateDir = await fs.mkdtemp(
    path.join(os.tmpdir(), "agentid-named-profile-")
  );
  const vault = mockVault();
  try {
    await assert.rejects(
      () => ensureAnonymousDefaultProfile({ vault, stateDir, name: "work" }),
      (error) => error?.code === "NO_PROFILE"
    );
    assert.equal(vault.records.size, 0);
    assert.equal(vault.saveCount(), 0);
  } finally {
    await fs.rm(stateDir, { recursive: true, force: true });
  }
});
