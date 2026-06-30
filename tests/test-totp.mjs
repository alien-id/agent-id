#!/usr/bin/env node

// Tests that the RFC 6238 TOTP generator now lives in core and that the proxy's
// back-compat re-export shim produces identical codes.
//
// Run: node --test tests/test-totp.mjs

import { test } from "node:test";
import assert from "node:assert/strict";

import { generateTotp as coreTotp } from "../plugins/agent-id-core/lib/totp.mjs";
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
