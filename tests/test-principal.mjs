#!/usr/bin/env node

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import { agentPrincipalFromPublicKeyPem } from "../plugins/agent-id-core/lib/principal.mjs";

test("agent authorization principal is a stable RFC 7638 JKT", () => {
  const { publicKey } = generateKeyPairSync("ed25519");
  const pem = publicKey.export({ format: "pem", type: "spki" }).toString();
  const first = agentPrincipalFromPublicKeyPem(pem);
  const second = agentPrincipalFromPublicKeyPem(pem);
  assert.equal(first, second);
  assert.match(first, /^agent:jkt:[A-Za-z0-9_-]{43}$/);
});

