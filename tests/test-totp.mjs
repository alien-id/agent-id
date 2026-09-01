#!/usr/bin/env node

// Tests that the RFC 6238 TOTP generator now lives in core and that the proxy's
// back-compat re-export shim produces identical codes.
//
// Run: node --test tests/test-totp.mjs

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  generateTotp as coreTotp,
  normalizeTotpInput,
  parseOtpauthUri,
  validateBase32Secret,
} from "../plugins/agent-id-core/lib/totp.mjs";
import { generateTotp as proxyTotp } from "../plugins/agent-id-proxy/lib/totp.mjs";

// RFC 6238 reference seed "12345678901234567890" → base32; at T=59s the SHA-1,
// 8-digit code is 94287082, so the 6-digit truncation is 287082.
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

test("core TOTP matches the RFC 6238 vector (T=59, SHA1, 6 digits)", () => {
  const code = coreTotp({ secret: RFC_SECRET, now: 59_000, period: 30, digits: 6 });
  assert.equal(code, "287082");
});

test("proxy re-export produces the same code as core", () => {
  const now = 1_700_000_000_000;
  assert.equal(proxyTotp({ secret: RFC_SECRET, now }), coreTotp({ secret: RFC_SECRET, now }));
});

test("validateBase32Secret normalizes whitespace/case and rejects junk", () => {
  assert.equal(validateBase32Secret(" gezd gnbv "), "GEZDGNBV");
  assert.throws(() => validateBase32Secret(""), /empty/i);
  assert.throws(() => validateBase32Secret("not-base32!"), /base32|Invalid/i);
});

test("parseOtpauthUri extracts the secret and parameters", () => {
  const out = parseOtpauthUri(
    "otpauth://totp/ACME:alice?secret=GEZDGNBVGY3TQOJQ&period=60&digits=8&algorithm=sha256&issuer=ACME",
  );
  assert.deepEqual(out, { secret: "GEZDGNBVGY3TQOJQ", period: 60, digits: 8, algorithm: "SHA256" });
});

test("parseOtpauthUri rejects a non-otpauth URI or a missing secret", () => {
  assert.throws(() => parseOtpauthUri("https://example.com"), /otpauth/i);
  assert.throws(() => parseOtpauthUri("otpauth://totp/x?issuer=ACME"), /secret/i);
});

test("normalizeTotpInput accepts a raw base32 secret or an otpauth URI", () => {
  assert.deepEqual(normalizeTotpInput("GEZDGNBVGY3TQOJQ"), { secret: "GEZDGNBVGY3TQOJQ" });
  assert.equal(normalizeTotpInput("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ").secret, "GEZDGNBVGY3TQOJQ");
});
