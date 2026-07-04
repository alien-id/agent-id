#!/usr/bin/env node

// Unit tests for the two pure helpers extracted from the vault sync CLI:
//   redactSecretFields — strips every SECRET_FIELDS entry before a conflict's
//                        losing record is printed by `sync resolve` (no --restore).
//   parseListenPort    — validates the --port flag (parseFlags yields boolean
//                        `true` for a bare flag; Number(true) === 1 would silently
//                        bind port 1, so a non-digit / boolean value must error).
// Run: node --test tests/test-sync-cli.mjs

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { redactSecretFields, parseListenPort } from "../plugins/agent-id-vault/bin/cli.mjs";
import { SECRET_FIELDS } from "../plugins/agent-id-vault/lib/store.mjs";

const REDACTION = "(redacted — use --restore)";

describe("redactSecretFields", () => {
  it("redacts the bearer/header/query/cookie `value` field", () => {
    const rec = { name: "api", type: "bearer", value: "sk-live-supersecret", note: "keep" };
    const out = redactSecretFields(rec);
    assert.equal(out.value, REDACTION);
    assert.equal(out.note, "keep");
    // pure: original untouched
    assert.equal(rec.value, "sk-live-supersecret");
  });

  it("redacts every oauth2 secret (refreshToken/clientSecret/accessToken)", () => {
    const rec = {
      name: "svc",
      type: "oauth2",
      clientId: "public-id",
      refreshToken: "rt-secret",
      clientSecret: "cs-secret",
      accessToken: "at-secret",
    };
    const out = redactSecretFields(rec);
    assert.equal(out.refreshToken, REDACTION);
    assert.equal(out.clientSecret, REDACTION);
    assert.equal(out.accessToken, REDACTION);
    assert.equal(out.clientId, "public-id"); // non-secret preserved
    assert.ok(!JSON.stringify(out).includes("secret"));
  });

  it("redacts login secrets (password/totpSecret) but keeps username listed as a secret too", () => {
    const rec = {
      name: "site",
      type: "login",
      username: "alice",
      password: "hunter2",
      totpSecret: "JBSWY3DPEHPK3PXP",
      loginUrl: "https://example.test/login",
    };
    const out = redactSecretFields(rec);
    assert.equal(out.password, REDACTION);
    assert.equal(out.totpSecret, REDACTION);
    // username is in SECRET_FIELDS, so it is redacted too
    assert.equal(out.username, REDACTION);
    assert.equal(out.loginUrl, "https://example.test/login");
    assert.ok(!JSON.stringify(out).includes("hunter2"));
    assert.ok(!JSON.stringify(out).includes("JBSWY3DPEHPK3PXP"));
  });

  it("redacts evm privateKey", () => {
    const rec = { name: "w", type: "evm-keypair", address: "0xabc", privateKey: "0xdeadbeef" };
    const out = redactSecretFields(rec);
    assert.equal(out.privateKey, REDACTION);
    assert.equal(out.address, "0xabc");
    assert.ok(!JSON.stringify(out).includes("deadbeef"));
  });

  it("redacts solana secretSeed", () => {
    const rec = { name: "w", type: "solana-keypair", address: "So11", secretSeed: "seedmaterial" };
    const out = redactSecretFields(rec);
    assert.equal(out.secretSeed, REDACTION);
    assert.equal(out.address, "So11");
    assert.ok(!JSON.stringify(out).includes("seedmaterial"));
  });

  it("leaves absent secret fields absent (does not introduce keys)", () => {
    const rec = { name: "x", type: "bearer" };
    const out = redactSecretFields(rec);
    for (const f of SECRET_FIELDS) {
      assert.ok(!(f in out), `did not add absent field '${f}'`);
    }
  });

  it("redacts EVERY SECRET_FIELDS entry when present (no plaintext survives)", () => {
    const rec = { name: "kitchen-sink", type: "secret" };
    for (const f of SECRET_FIELDS) rec[f] = `PLAINTEXT_${f}`;
    const out = redactSecretFields(rec);
    for (const f of SECRET_FIELDS) {
      assert.equal(out[f], REDACTION, `field '${f}' not redacted`);
    }
    assert.ok(!JSON.stringify(out).includes("PLAINTEXT_"), "some plaintext leaked");
  });
});

describe("parseListenPort", () => {
  it("returns 0 when --port is absent (ephemeral bind)", () => {
    assert.equal(parseListenPort({}), 0);
  });

  it("parses a valid digit string", () => {
    assert.equal(parseListenPort({ port: "8080" }), 8080);
  });

  it("throws for boolean true (bare --port flag)", () => {
    assert.throws(() => parseListenPort({ port: true }), /--port/);
  });

  it("throws for a non-digit string", () => {
    assert.throws(() => parseListenPort({ port: "abc" }), /--port/);
  });

  it("throws for a value with trailing junk", () => {
    assert.throws(() => parseListenPort({ port: "80x" }), /--port/);
  });

  it("throws for an out-of-range port", () => {
    assert.throws(() => parseListenPort({ port: "70000" }), /--port/);
  });
});
