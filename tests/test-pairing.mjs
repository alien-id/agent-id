#!/usr/bin/env node

// Phone-pairing payload: reachable-host resolution, the build→parse round-trip,
// and rejection of malformed payloads. This is the mechanism that hands the
// control-plane token to an external phone so the mobile-slot unlock can reach
// the (token-gated) control plane.
//
// Run: node --test tests/test-pairing.mjs

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  PAIRING_SCHEME,
  buildPairingPayload,
  parsePairingPayload,
  pickReachableHost,
} from "../plugins/agent-id-proxy/lib/pairing.mjs";

const LAN = {
  lo: [{ family: "IPv4", address: "127.0.0.1", internal: true }],
  eth0: [{ family: "IPv4", address: "192.168.1.50", internal: false }],
};

describe("pickReachableHost", () => {
  it("uses a specific routable bind host as-is", () => {
    assert.equal(pickReachableHost("192.168.1.7", LAN), "192.168.1.7");
  });

  it("resolves a wildcard bind to a non-internal IPv4", () => {
    assert.equal(pickReachableHost("0.0.0.0", LAN), "192.168.1.50");
    assert.equal(pickReachableHost("::", LAN), "192.168.1.50");
  });

  it("returns null for a loopback bind (a phone can't reach it)", () => {
    assert.equal(pickReachableHost("127.0.0.1", LAN), null);
    assert.equal(pickReachableHost("localhost", LAN), null);
    assert.equal(pickReachableHost("::1", LAN), null);
  });

  it("returns null for a wildcard bind with no external interface", () => {
    assert.equal(pickReachableHost("0.0.0.0", { lo: LAN.lo }), null);
  });
});

describe("pairing payload round-trip", () => {
  const PK = "04" + "ab".repeat(64); // X9.63 uncompressed P-256 point (130 hex)

  it("builds a scheme://pair URI and parses it back (incl. the seal key)", () => {
    const payload = buildPairingPayload({
      controlUrl: "http://192.168.1.50:48772",
      token: "tok.en-123_ABC",
      publicKey: PK,
    });
    assert.ok(payload.startsWith(`${PAIRING_SCHEME}://pair?`));
    const parsed = parsePairingPayload(payload);
    assert.equal(parsed.control, "http://192.168.1.50:48772");
    assert.equal(parsed.token, "tok.en-123_ABC");
    assert.equal(parsed.publicKey, PK);
    assert.equal(parsed.version, 1);
  });

  it("requires controlUrl, token, and publicKey to build", () => {
    assert.throws(() => buildPairingPayload({ controlUrl: "http://x:1", publicKey: PK }), /required/);
    assert.throws(() => buildPairingPayload({ token: "t", publicKey: PK }), /required/);
    assert.throws(() => buildPairingPayload({ controlUrl: "http://x:1", token: "t" }), /publicKey/);
  });

  it("rejects a non-pairing URI", () => {
    assert.throws(() => parsePairingPayload("https://example.com/pair"), /not an/);
    assert.throws(() => parsePairingPayload("not a uri"), /invalid pairing payload/);
  });

  it("rejects a payload missing control or token", () => {
    assert.throws(
      () => parsePairingPayload(`${PAIRING_SCHEME}://pair?v=1&token=t&pk=${PK}`),
      /missing control or token/,
    );
    assert.throws(
      () => parsePairingPayload(`${PAIRING_SCHEME}://pair?v=1&control=http%3A%2F%2Fx%3A1&pk=${PK}`),
      /missing control or token/,
    );
  });

  it("rejects a payload missing the control-plane public key", () => {
    assert.throws(
      () => parsePairingPayload(`${PAIRING_SCHEME}://pair?v=1&control=http%3A%2F%2Fx%3A1&token=t`),
      /missing control-plane public key/,
    );
  });

  it("rejects a payload whose control URL is not http(s)", () => {
    const bad = `${PAIRING_SCHEME}://pair?v=1&control=${encodeURIComponent("ftp://x/y")}&token=t&pk=${PK}`;
    assert.throws(() => parsePairingPayload(bad), /invalid control URL/);
  });
});
