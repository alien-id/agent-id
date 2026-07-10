#!/usr/bin/env node

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";

const policy = (epoch) => ({
  version: 1,
  epoch,
  onUnmatched: "deny",
  grants: [
    {
      id: "mail-send",
      principal: "*",
      capability: "mail.send",
      decision: "ask",
    },
  ],
});

test("a stale vault handle cannot roll back a capability epoch", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "vault-cas-"));
  try {
    await initVault({ stateDir: dir, passphrase: "pass" });
    const seed = await openVault({ stateDir: dir, passphrase: "pass" });
    seed.add({
      name: "mail",
      type: "bearer",
      domains: ["mail.example.com"],
      value: "secret",
      capabilityPolicyEpoch: 1,
      capabilityPolicy: policy(1),
    });
    await seed.save();
    seed.lock();

    const owner = await openVault({ stateDir: dir, passphrase: "pass" });
    const stale = await openVault({ stateDir: dir, passphrase: "pass" });
    owner.add({
      ...owner.get("mail"),
      capabilityPolicyEpoch: 2,
      capabilityPolicy: policy(2),
    });
    await owner.save();

    stale.add({ ...stale.get("mail"), description: "unrelated stale edit" });
    await assert.rejects(stale.save(), (err) => err?.code === "VAULT_CONFLICT");
    owner.lock();
    stale.lock();

    const final = await openVault({ stateDir: dir, passphrase: "pass" });
    assert.equal(final.get("mail").capabilityPolicy.epoch, 2);
    assert.equal(final.get("mail").capabilityPolicyEpoch, 2);
    final.lock();
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("capability tombstones survive prototype-sensitive credential names", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "vault-proto-name-"));
  try {
    await initVault({ stateDir: dir, passphrase: "pass" });
    const vault = await openVault({ stateDir: dir, passphrase: "pass" });
    vault.add({
      name: "__proto__",
      type: "bearer",
      domains: ["api.example.com"],
      value: "secret",
      capabilityPolicyEpoch: 1,
      capabilityPolicy: policy(1),
    });
    await vault.save();
    vault.remove("__proto__");
    await vault.save();
    assert.throws(
      () =>
        vault.add({
          name: "__proto__",
          type: "bearer",
          domains: ["api.example.com"],
          value: "replacement",
        }),
      /epoch rollback/,
    );
    assert.equal(vault.capabilityEpochs().__proto__, 2);
    assert.equal(vault.credentialRevisions().__proto__, 2);
    vault.lock();
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("vault records and nested policy data never escape by mutable alias", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "vault-owned-records-"));
  try {
    await initVault({ stateDir: dir, passphrase: "pass" });
    const vault = await openVault({ stateDir: dir, passphrase: "pass" });
    const input = {
      name: "mail",
      type: "bearer",
      domains: ["mail.example.com"],
      value: "token-a",
      capabilityPolicyEpoch: 1,
      capabilityPolicy: policy(1),
    };
    const added = vault.add(input);

    input.domains[0] = "evil.example";
    input.capabilityPolicy.grants[0].decision = "allow";
    added.domains[0] = "added-alias.example";
    added.capabilityPolicy.grants[0].decision = "deny";
    const fetched = vault.get("mail");
    fetched.value = "token-b";
    fetched.domains.push("fetched-alias.example");
    fetched.capabilityPolicy.grants[0].decision = "allow";
    const listed = vault.list()[0];
    listed.domains.push("listed-alias.example");
    listed.capabilityPolicy.grants[0].decision = "allow";
    vault.raw().slots.length = 0;

    await vault.save();
    vault.lock();

    const reopened = await openVault({ stateDir: dir, passphrase: "pass" });
    const stored = reopened.get("mail");
    assert.equal(stored.value, "token-a");
    assert.deepEqual(stored.domains, ["mail.example.com"]);
    assert.equal(stored.capabilityPolicy.grants[0].decision, "ask");
    assert.equal(stored.credentialRevision, 1);
    assert.equal(reopened.slots.length, 1);
    reopened.lock();
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
