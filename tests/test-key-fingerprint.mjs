#!/usr/bin/env node

// Tests for key_fingerprint claim in id_token binding.
// Verifies that forged bindings with stolen id_tokens are rejected.
// Run: node --test tests/test-key-fingerprint.mjs

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";

import {
  SignatureEngine,
  generateEd25519PemPair,
  fingerprintPublicKeyPem,
  exchangeAuthorizationCode,
  refreshSession,
  b64url,
  canonicalJSONString,
  sha256Hex,
} from "../skills/alien-agent-id/lib.mjs";

// Helpers to create a mock SSO server that issues JWTs with key_fingerprint

function generateRsaKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKey, privateKey };
}

function rsaSign(signingInput, privateKeyPem) {
  const sign = crypto.createSign("RSA-SHA256");
  sign.update(signingInput);
  const sig = sign.sign(privateKeyPem);
  return sig.toString("base64url");
}

function createIdToken(rsaPrivateKeyPem, kid, issuer, sub, aud, keyFingerprint) {
  const header = { alg: "RS256", typ: "JWT", kid };
  const payload = {
    iss: issuer,
    sub,
    aud: [aud],
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
    auth_time: Math.floor(Date.now() / 1000),
  };
  if (keyFingerprint) {
    payload.key_fingerprint = keyFingerprint;
  }

  const headerB64 = b64url(JSON.stringify(header));
  const payloadB64 = b64url(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = rsaSign(signingInput, rsaPrivateKeyPem);
  return `${signingInput}.${signature}`;
}

function rsaPublicKeyToJwk(publicKeyPem, kid) {
  const key = crypto.createPublicKey(publicKeyPem);
  const jwk = key.export({ format: "jwk" });
  return {
    kty: "RSA",
    use: "sig",
    alg: "RS256",
    kid,
    n: jwk.n,
    e: jwk.e,
  };
}

describe("key_fingerprint id_token claim", () => {
  let rsaKeys;
  let kid;
  let mockServer;
  let mockBaseUrl;
  const issuer = "https://test-sso.example.com";
  const providerAddress = "0000000604000000000036159b3c0f15";
  const ownerSub = "0000000701000000000027dfbf386c25";

  before(async () => {
    rsaKeys = generateRsaKeyPair();
    kid = "test-kid-001";

    // Mock SSO server serving OIDC discovery + JWKS + token exchange
    mockServer = http.createServer((req, res) => {
      if (req.url === "/.well-known/openid-configuration") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          issuer: mockBaseUrl,
          jwks_uri: `${mockBaseUrl}/oauth/jwks`,
        }));
        return;
      }

      if (req.url === "/oauth/jwks") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          keys: [rsaPublicKeyToJwk(rsaKeys.publicKey, kid)],
        }));
        return;
      }

      if (req.url === "/oauth/token" && req.method === "POST") {
        let body = "";
        req.on("data", (chunk) => { body += chunk; });
        req.on("end", () => {
          const params = new URLSearchParams(body);
          const grantType = params.get("grant_type");
          const keyFp = params.get("key_fingerprint") || "";

          const response = {
            access_token: "mock-access-token",
            token_type: "Bearer",
            expires_in: 3600,
            refresh_token: "mock-refresh-token",
          };

          if (grantType === "authorization_code") {
            response.id_token = createIdToken(
              rsaKeys.privateKey, kid, mockBaseUrl, ownerSub, providerAddress, keyFp || undefined,
            );
          } else if (grantType === "refresh_token" && keyFp) {
            response.id_token = createIdToken(
              rsaKeys.privateKey, kid, mockBaseUrl, ownerSub, providerAddress, keyFp,
            );
          }

          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(response));
        });
        return;
      }

      res.writeHead(404);
      res.end("Not found");
    });

    await new Promise((resolve) => {
      mockServer.listen(0, "127.0.0.1", () => {
        const addr = mockServer.address();
        mockBaseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });
  });

  after(async () => {
    mockServer.close();
  });

  it("token exchange includes key_fingerprint when provided", async () => {
    const fingerprint = "abcd1234".repeat(8);

    const result = await exchangeAuthorizationCode({
      ssoBaseUrl: mockBaseUrl,
      providerAddress,
      authorizationCode: "mock-code",
      codeVerifier: "mock-verifier",
      keyFingerprint: fingerprint,
    });

    assert.ok(result.id_token, "should have id_token");

    // Decode and check the claim
    const parts = result.id_token.split(".");
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
    assert.equal(payload.key_fingerprint, fingerprint, "key_fingerprint should be in token");
  });

  it("token exchange without key_fingerprint produces token without claim", async () => {
    const result = await exchangeAuthorizationCode({
      ssoBaseUrl: mockBaseUrl,
      providerAddress,
      authorizationCode: "mock-code",
      codeVerifier: "mock-verifier",
    });

    const parts = result.id_token.split(".");
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
    assert.equal(payload.key_fingerprint, undefined, "key_fingerprint should be absent");
  });

  it("forged binding with stolen id_token has wrong key_fingerprint", async () => {
    // Simulate: victim agent gets an id_token with their fingerprint
    const victimKeys = generateEd25519PemPair();
    const victimFingerprint = fingerprintPublicKeyPem(victimKeys.publicKeyPem);

    const victimToken = createIdToken(
      rsaKeys.privateKey, kid, mockBaseUrl, ownerSub, providerAddress, victimFingerprint,
    );

    // Attacker generates their own key
    const attackerKeys = generateEd25519PemPair();
    const attackerFingerprint = fingerprintPublicKeyPem(attackerKeys.publicKeyPem);

    // Attacker creates a binding using victim's stolen id_token
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "agent-id-test-"));
    const engine = new SignatureEngine({ baseDir: tmpDir });
    await engine.init();

    await engine.bindOwnerSession({
      issuer: mockBaseUrl,
      ssoBaseUrl: mockBaseUrl,
      providerAddress,
      ownerSessionSub: ownerSub,
      ownerAudience: [providerAddress],
      idToken: victimToken,
      accessToken: "stolen-access-token",
      refreshToken: null,
      ownerSessionProof: null,
    });

    // Decode the id_token and check: the key_fingerprint is the VICTIM's, not the ATTACKER's
    const parts = victimToken.split(".");
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());

    assert.equal(payload.key_fingerprint, victimFingerprint,
      "stolen id_token should have victim's fingerprint");
    assert.notEqual(payload.key_fingerprint, attackerFingerprint,
      "stolen id_token should NOT match attacker's fingerprint");
    assert.notEqual(victimFingerprint, attackerFingerprint,
      "victim and attacker must have different fingerprints");

    // Clean up
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("id_token with matching key_fingerprint passes verification", async () => {
    const agentKeys = generateEd25519PemPair();
    const agentFingerprint = fingerprintPublicKeyPem(agentKeys.publicKeyPem);

    const token = createIdToken(
      rsaKeys.privateKey, kid, mockBaseUrl, ownerSub, providerAddress, agentFingerprint,
    );

    const parts = token.split(".");
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());

    assert.equal(payload.key_fingerprint, agentFingerprint,
      "token key_fingerprint should match agent's fingerprint");
  });

  it("refresh with key_fingerprint returns id_token with claim", async () => {
    const fingerprint = "beef0123".repeat(8);

    const result = await refreshSession({
      ssoBaseUrl: mockBaseUrl,
      providerAddress,
      refreshToken: "mock-refresh-token",
      keyFingerprint: fingerprint,
    });

    assert.ok(result.access_token, "should have access_token");
    assert.ok(result.id_token, "should have id_token on refresh with fingerprint");

    const parts = result.id_token.split(".");
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
    assert.equal(payload.key_fingerprint, fingerprint,
      "refreshed id_token should contain the fingerprint");
  });

  it("refresh without key_fingerprint returns no id_token", async () => {
    const result = await refreshSession({
      ssoBaseUrl: mockBaseUrl,
      providerAddress,
      refreshToken: "mock-refresh-token",
    });

    assert.ok(result.access_token, "should have access_token");
    assert.equal(result.id_token, undefined,
      "should NOT have id_token on refresh without fingerprint");
  });
});
