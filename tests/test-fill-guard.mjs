#!/usr/bin/env node

// Regression tests for the fill-secret / fill-otp authorization guard
// (assertFillAllowed in lib/session-server.mjs): the seal check (exportable:false
// secret fields must not leave the vault) and the audience check (a credential may
// only be typed into a page whose host is on its domain allowlist). Pure — no
// browser, no vault.
//
// Run: node --test tests/test-fill-guard.mjs

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  assertFillAllowed,
  hostOfUrl,
} from "../plugins/agent-id-browser/lib/session-server.mjs";

const login = (over = {}) => ({
  type: "login",
  domains: ["portail.unige.ch"],
  ...over,
});
const sealedWallet = {
  type: "solana-keypair",
  exportable: false,
  domains: ["rpc.x"],
  secretSeed: "ab".repeat(32),
};

test("hostOfUrl extracts the hostname; about:blank / junk → empty", () => {
  assert.equal(hostOfUrl("https://adfs.unige.ch/adfs/oauth2"), "adfs.unige.ch");
  assert.equal(hostOfUrl("about:blank"), "");
  assert.equal(hostOfUrl("not a url"), "");
});

test("SEAL: a sealed (exportable:false) secret field is refused on any host", () => {
  assert.throws(
    () => assertFillAllowed(sealedWallet, "rpc.x", "secretSeed"),
    /sealed/i
  );
  // …even though the host is on the allowlist.
});

test("SEAL: a non-secret field on a sealed cred passes the seal check (but still origin-checked)", () => {
  // `publicKey` is not in SECRET_FIELDS, so the seal check doesn't block it.
  assert.doesNotThrow(() =>
    assertFillAllowed(
      { ...sealedWallet, publicKey: "abc" },
      "rpc.x",
      "publicKey"
    )
  );
});

test("AUDIENCE: typing is refused on a host not in the credential's domains", () => {
  assert.throws(
    () => assertFillAllowed(login(), "attacker.example", "password"),
    /allowlist/i
  );
  // about:blank (empty host) is denied too — kills the read-back-on-blank exfil path.
  assert.throws(() => assertFillAllowed(login(), "", "password"), /allowlist/i);
});

test("AUDIENCE: typing is allowed on a listed host and via a wildcard", () => {
  assert.doesNotThrow(() =>
    assertFillAllowed(login(), "portail.unige.ch", "password")
  );
  // A wildcard covers the IdP host an SSO login redirects to.
  assert.doesNotThrow(() =>
    assertFillAllowed(
      login({ domains: ["*.unige.ch"] }),
      "adfs.unige.ch",
      "password"
    )
  );
  assert.throws(
    () =>
      assertFillAllowed(
        login({ domains: ["*.unige.ch"] }),
        "evil.com",
        "password"
      ),
    /allowlist/i
  );
});

test("OTP path (no field): origin-checked only, no seal check", () => {
  assert.doesNotThrow(() => assertFillAllowed(login(), "portail.unige.ch"));
  assert.throws(
    () => assertFillAllowed(login(), "attacker.example"),
    /allowlist/i
  );
});

test("a bare '*' domain matches nothing (deny) — consistent with hostMatchesAllowlist", () => {
  assert.throws(
    () =>
      assertFillAllowed(
        login({ domains: ["*"] }),
        "portail.unige.ch",
        "password"
      ),
    /allowlist/i
  );
});
