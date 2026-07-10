#!/usr/bin/env node

import test from "node:test";
import assert from "node:assert/strict";

import {
  canonicalJSONString,
  sha256HexCanonical,
} from "../plugins/agent-id-core/lib/crypto.mjs";

test("canonical JSON preserves an own __proto__ member", () => {
  const withProtoKey = JSON.parse('{"x":{"__proto__":{"admin":true}}}');
  const withoutProtoKey = { x: {} };
  assert.equal(
    canonicalJSONString(withProtoKey),
    '{"x":{"__proto__":{"admin":true}}}',
  );
  assert.notEqual(canonicalJSONString(withProtoKey), canonicalJSONString(withoutProtoKey));
  assert.notEqual(sha256HexCanonical(withProtoKey), sha256HexCanonical(withoutProtoKey));
});
