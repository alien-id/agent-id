#!/usr/bin/env node

// Tests for JWK helpers and DPoP proof signer (RFC 7638 + RFC 9449).
// Run: node --test tests/test-dpop.mjs

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import crypto, {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  verify as cryptoVerify,
} from "node:crypto";

import {
  ed25519PublicKeyToJwk,
  jwkThumbprint,
  createDPoPProof,
  beginOidcAuthorization,
  exchangeAuthorizationCode,
  refreshSession,
  generateEd25519PemPair,
  fromB64url,
  b64url,
  getUserInfo,
} from "../skills/alien-agent-id/lib.mjs";

// ─── Fixtures ────────────────────────────────────────────────────────────────────
//
// RFC 8037 Appendix A.2 — Ed25519 JWK thumbprint reference vector.
//
//   JWK: {"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
//   Canonical: {"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
//   Thumbprint (SHA-256, base64url, no pad): kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k
//
const RFC8037_JWK = {
  kty: "OKP",
  crv: "Ed25519",
  x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
};
const RFC8037_THUMBPRINT = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";

// ASN.1 DER prefix for an Ed25519 SubjectPublicKeyInfo (12 bytes), then 32-byte raw public key.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function rawEd25519PublicKeyToPem(rawBytes) {
  const der = Buffer.concat([ED25519_SPKI_PREFIX, rawBytes]);
  const key = createPublicKey({ key: der, format: "der", type: "spki" });
  return key.export({ format: "pem", type: "spki" }).toString();
}

function rfc8037PemFixture() {
  return rawEd25519PublicKeyToPem(fromB64url(RFC8037_JWK.x));
}

// ─── ed25519PublicKeyToJwk ───────────────────────────────────────────────────────

describe("ed25519PublicKeyToJwk()", () => {
  it("produces an OKP/Ed25519 JWK with the correct x parameter for RFC 8037 fixture", () => {
    const pem = rfc8037PemFixture();
    const jwk = ed25519PublicKeyToJwk(pem);
    assert.equal(jwk.kty, "OKP");
    assert.equal(jwk.crv, "Ed25519");
    assert.equal(jwk.x, RFC8037_JWK.x);
  });

  it("round-trips a freshly generated Ed25519 key (x is base64url of raw public bytes)", () => {
    const { publicKeyPem } = generateEd25519PemPair();
    const jwk = ed25519PublicKeyToJwk(publicKeyPem);
    assert.equal(jwk.kty, "OKP");
    assert.equal(jwk.crv, "Ed25519");
    // x must decode back to 32 bytes that match the raw public key extracted from the PEM.
    const rawFromJwk = fromB64url(jwk.x);
    assert.equal(rawFromJwk.length, 32);
    const der = createPublicKey(publicKeyPem).export({ format: "der", type: "spki" });
    const rawFromPem = der.subarray(der.length - 32);
    assert.deepEqual(rawFromJwk, rawFromPem);
  });

  it("rejects an X25519 SPKI even though it is also 44 bytes (RFC 8410 OID 1.3.101.110)", () => {
    const { publicKey } = generateKeyPairSync("x25519");
    const pem = publicKey.export({ format: "pem", type: "spki" }).toString();
    assert.throws(
      () => ed25519PublicKeyToJwk(pem),
      /Ed25519/,
      "expected Ed25519-only key acceptance, got silent X25519 acceptance",
    );
  });

  it("rejects an Ed448 SPKI (different OID, different key length)", () => {
    const { publicKey } = generateKeyPairSync("ed448");
    const pem = publicKey.export({ format: "pem", type: "spki" }).toString();
    assert.throws(() => ed25519PublicKeyToJwk(pem), /Ed25519/);
  });

  it("rejects a synthetic 44-byte DER with wrong OID prefix (defense in depth)", () => {
    // Build a 44-byte buffer whose length matches Ed25519 SPKI but whose OID bytes are bogus.
    const bogus = Buffer.concat([
      Buffer.from("302a300506030000000003210000", "hex").subarray(0, 12),
      Buffer.alloc(32, 0xab),
    ]);
    // Hand-craft PEM around the bogus DER so we bypass createPublicKey's parsing.
    // This test pokes at the prefix check directly: import the bogus DER, let createPublicKey
    // throw, and verify a clear error reaches the caller (any throw with descriptive message).
    assert.throws(() => {
      const pem = `-----BEGIN PUBLIC KEY-----\n${bogus.toString("base64")}\n-----END PUBLIC KEY-----\n`;
      ed25519PublicKeyToJwk(pem);
    });
  });
});

// ─── jwkThumbprint ───────────────────────────────────────────────────────────────

describe("jwkThumbprint()", () => {
  it("matches RFC 8037 Appendix A.2 reference thumbprint", () => {
    const tp = jwkThumbprint(RFC8037_JWK);
    assert.equal(tp, RFC8037_THUMBPRINT);
  });

  it("ignores extra fields in the JWK (canonicalises only crv/kty/x)", () => {
    const tp = jwkThumbprint({ ...RFC8037_JWK, alg: "EdDSA", use: "sig", kid: "ignored" });
    assert.equal(tp, RFC8037_THUMBPRINT);
  });

  it("produces different thumbprints for different keys", () => {
    const a = ed25519PublicKeyToJwk(generateEd25519PemPair().publicKeyPem);
    const b = ed25519PublicKeyToJwk(generateEd25519PemPair().publicKeyPem);
    assert.notEqual(jwkThumbprint(a), jwkThumbprint(b));
  });
});

// ─── createDPoPProof ─────────────────────────────────────────────────────────────

function decodePart(b64) {
  return JSON.parse(fromB64url(b64).toString("utf8"));
}

describe("createDPoPProof()", () => {
  it("emits a compact JWS with header typ=dpop+jwt, alg=EdDSA, embedded jwk", () => {
    const { privateKeyPem } = generateEd25519PemPair();
    const proof = createDPoPProof({
      privateKeyPem,
      htm: "POST",
      htu: "https://sso.example.com/oauth/token",
      jti: "fixed-jti",
      iat: 1700000000,
    });
    const [h, p, s] = proof.split(".");
    assert.ok(h && p && s, "compact JWS has three parts");
    const header = decodePart(h);
    assert.equal(header.typ, "dpop+jwt");
    assert.equal(header.alg, "EdDSA");
    assert.ok(header.jwk, "header has embedded jwk");
    assert.equal(header.jwk.kty, "OKP");
    assert.equal(header.jwk.crv, "Ed25519");
    assert.ok(typeof header.jwk.x === "string" && header.jwk.x.length > 0);
  });

  it("payload contains htm, htu, iat, and unique jti", () => {
    const { privateKeyPem } = generateEd25519PemPair();
    const proof = createDPoPProof({
      privateKeyPem,
      htm: "POST",
      htu: "https://sso.example.com/oauth/token",
      jti: "the-jti",
      iat: 1700000000,
    });
    const payload = decodePart(proof.split(".")[1]);
    assert.equal(payload.htm, "POST");
    assert.equal(payload.htu, "https://sso.example.com/oauth/token");
    assert.equal(payload.iat, 1700000000);
    assert.equal(payload.jti, "the-jti");
  });

  it("strips query and fragment from htu (RFC 9449 §4.2)", () => {
    const { privateKeyPem } = generateEd25519PemPair();
    const proof = createDPoPProof({
      privateKeyPem,
      htm: "POST",
      htu: "https://sso.example.com/oauth/token?foo=bar#frag",
      jti: "j",
      iat: 1,
    });
    const payload = decodePart(proof.split(".")[1]);
    assert.equal(payload.htu, "https://sso.example.com/oauth/token");
  });

  it("canonicalizes htu (lowercase scheme+host, default port stripped) per RFC 3986 §6.2", () => {
    const { privateKeyPem } = generateEd25519PemPair();
    const cases = [
      ["HTTPS://sso.example.com/oauth/token", "https://sso.example.com/oauth/token"],
      ["https://SSO.EXAMPLE.COM/oauth/token", "https://sso.example.com/oauth/token"],
      ["https://sso.example.com:443/oauth/token", "https://sso.example.com/oauth/token"],
      ["http://sso.example.com:80/oauth/token", "http://sso.example.com/oauth/token"],
      ["HTTPS://SSO.example.com:443/oauth/token?x=1#f", "https://sso.example.com/oauth/token"],
      ["https://sso.example.com:8443/oauth/token", "https://sso.example.com:8443/oauth/token"], // non-default port preserved
    ];
    for (const [input, expected] of cases) {
      const proof = createDPoPProof({
        privateKeyPem,
        htm: "POST",
        htu: input,
        jti: "j",
        iat: 1,
      });
      const payload = decodePart(proof.split(".")[1]);
      assert.equal(payload.htu, expected, `input=${input}`);
    }
  });

  it("auto-generates a jti and iat when not provided", () => {
    const { privateKeyPem } = generateEd25519PemPair();
    const a = createDPoPProof({
      privateKeyPem,
      htm: "POST",
      htu: "https://x.example/y",
    });
    const b = createDPoPProof({
      privateKeyPem,
      htm: "POST",
      htu: "https://x.example/y",
    });
    const pa = decodePart(a.split(".")[1]);
    const pb = decodePart(b.split(".")[1]);
    assert.ok(typeof pa.jti === "string" && pa.jti.length >= 8);
    assert.ok(typeof pb.jti === "string" && pb.jti.length >= 8);
    assert.notEqual(pa.jti, pb.jti, "jti must be unique per call");
    assert.ok(typeof pa.iat === "number" && pa.iat > 1_000_000_000);
  });

  it("is deterministic when jti and iat are fixed", () => {
    const { privateKeyPem } = generateEd25519PemPair();
    const args = {
      privateKeyPem,
      htm: "POST",
      htu: "https://x.example/y",
      jti: "stable",
      iat: 1700000000,
    };
    assert.equal(createDPoPProof(args), createDPoPProof(args));
  });

  it("signature verifies with crypto.verify against the embedded JWK", () => {
    const { privateKeyPem, publicKeyPem } = generateEd25519PemPair();
    const proof = createDPoPProof({
      privateKeyPem,
      htm: "POST",
      htu: "https://x.example/y",
      jti: "z",
      iat: 1700000000,
    });
    const [h, p, s] = proof.split(".");
    const signingInput = Buffer.from(`${h}.${p}`);
    const signature = fromB64url(s);
    const ok = cryptoVerify(null, signingInput, createPublicKey(publicKeyPem), signature);
    assert.equal(ok, true);
  });

  it("emits ath = base64url(SHA-256(accessToken)) when accessToken is provided (RFC 9449 §4.2)", () => {
    const { privateKeyPem } = generateEd25519PemPair();
    const accessToken = "fake.access.token";
    const proof = createDPoPProof({
      privateKeyPem,
      htm: "GET",
      htu: "https://sso.example.com/oauth/userinfo",
      accessToken,
      jti: "j",
      iat: 1,
    });
    const payload = decodePart(proof.split(".")[1]);
    const expected = b64url(crypto.createHash("sha256").update(accessToken).digest());
    assert.equal(payload.ath, expected);
  });

  it("omits ath when accessToken is not provided (token-endpoint usage)", () => {
    const { privateKeyPem } = generateEd25519PemPair();
    const proof = createDPoPProof({
      privateKeyPem,
      htm: "POST",
      htu: "https://sso.example.com/oauth/token",
      jti: "j",
      iat: 1,
    });
    const payload = decodePart(proof.split(".")[1]);
    assert.equal(payload.ath, undefined);
  });

  it("emits nonce claim when provided (RFC 9449 §8 server-issued nonce challenge)", () => {
    const { privateKeyPem } = generateEd25519PemPair();
    const proof = createDPoPProof({
      privateKeyPem,
      htm: "POST",
      htu: "https://sso.example.com/oauth/token",
      nonce: "server-nonce-abc",
      jti: "j",
      iat: 1,
    });
    const payload = decodePart(proof.split(".")[1]);
    assert.equal(payload.nonce, "server-nonce-abc");
  });
});

// ─── getUserInfo client ──────────────────────────────────────────────────────────

describe("getUserInfo client", () => {
  it("sends Authorization: DPoP <token> + DPoP proof with ath, parses JSON claims", async () => {
    const pair = generateEd25519PemPair();
    let receivedAuthHeader = null;
    let receivedDPoPHeader = null;
    let receivedURL = null;
    const mock = await createMockServer((req, res) => {
      receivedAuthHeader = req.headers["authorization"];
      receivedDPoPHeader = req.headers["dpop"];
      receivedURL = req.url;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ sub: "user-123", aud: "client-xyz" }));
    });

    try {
      const claims = await getUserInfo({
        ssoBaseUrl: mock.baseUrl,
        accessToken: "the-access-token",
        agentPrivateKeyPem: pair.privateKeyPem,
      });
      assert.deepEqual(claims, { sub: "user-123", aud: "client-xyz" });
      assert.equal(receivedURL, "/oauth/userinfo");
      assert.equal(receivedAuthHeader, "DPoP the-access-token");
      assert.ok(receivedDPoPHeader, "DPoP proof header sent");

      // Verify proof's ath claim hashes the access token.
      const [, payloadB64] = receivedDPoPHeader.split(".");
      const payload = JSON.parse(fromB64url(payloadB64).toString("utf8"));
      assert.equal(payload.htm, "GET");
      assert.equal(payload.htu, `${mock.baseUrl}/oauth/userinfo`);
      const expectedATH = b64url(
        crypto.createHash("sha256").update("the-access-token").digest(),
      );
      assert.equal(payload.ath, expectedATH);
    } finally {
      mock.server.close();
    }
  });

  it("throws on 401 with descriptive error", async () => {
    const pair = generateEd25519PemPair();
    const mock = await createMockServer((_req, res) => {
      res.writeHead(401, {
        "Content-Type": "application/json",
        "WWW-Authenticate": `DPoP error="invalid_token"`,
      });
      res.end(JSON.stringify({ error: "Invalid or expired token" }));
    });

    try {
      await assert.rejects(
        () =>
          getUserInfo({
            ssoBaseUrl: mock.baseUrl,
            accessToken: "expired",
            agentPrivateKeyPem: pair.privateKeyPem,
          }),
        /401|userinfo|invalid_token/i,
      );
    } finally {
      mock.server.close();
    }
  });
});

// ─── beginOidcAuthorization wires dpop_jkt ────────────────────────────────────────

function createMockServer(handler) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => handler(req, res, body));
    });
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ server, baseUrl: `http://127.0.0.1:${port}` });
    });
  });
}

describe("beginOidcAuthorization with DPoP", () => {
  it("appends dpop_jkt=<thumbprint> to the authorize URL", async () => {
    let receivedUrl = null;
    const mock = await createMockServer((req, res) => {
      receivedUrl = req.url;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          deep_link: "alien://x",
          polling_code: "p",
          expired_at: Date.now() + 60000,
        }),
      );
    });

    try {
      const pair = generateEd25519PemPair();
      const expectedThumbprint = jwkThumbprint(ed25519PublicKeyToJwk(pair.publicKeyPem));

      await beginOidcAuthorization({
        ssoBaseUrl: mock.baseUrl,
        providerAddress: "test-provider",
        agentPublicKeyPem: pair.publicKeyPem,
      });

      assert.ok(receivedUrl, "mock received a request");
      const u = new URL(receivedUrl, mock.baseUrl);
      assert.equal(u.searchParams.get("dpop_jkt"), expectedThumbprint);
    } finally {
      mock.server.close();
    }
  });
});

// ─── exchangeAuthorizationCode sends DPoP header ─────────────────────────────────

describe("exchangeAuthorizationCode with DPoP", () => {
  it("sends a DPoP header whose proof matches htm=POST, htu=<token-url>, and JWK thumbprint", async () => {
    let receivedDpop = null;
    const mock = await createMockServer((req, res) => {
      receivedDpop = req.headers["dpop"];
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          access_token: "at",
          id_token: "it",
          refresh_token: "rt",
        }),
      );
    });

    try {
      const pair = generateEd25519PemPair();
      const expectedThumbprint = jwkThumbprint(ed25519PublicKeyToJwk(pair.publicKeyPem));

      await exchangeAuthorizationCode({
        ssoBaseUrl: mock.baseUrl,
        providerAddress: "p",
        authorizationCode: "code",
        codeVerifier: "v",
        agentPrivateKeyPem: pair.privateKeyPem,
        agentPublicKeyPem: pair.publicKeyPem,
      });

      assert.ok(receivedDpop, "DPoP header was sent");
      const [h, p] = receivedDpop.split(".");
      const header = decodePart(h);
      const payload = decodePart(p);
      assert.equal(header.typ, "dpop+jwt");
      assert.equal(header.alg, "EdDSA");
      assert.equal(payload.htm, "POST");
      assert.equal(payload.htu, `${mock.baseUrl}/oauth/token`);
      assert.equal(jwkThumbprint(header.jwk), expectedThumbprint);
    } finally {
      mock.server.close();
    }
  });

  it("retries with nonce echoed in proof on use_dpop_nonce challenge (RFC 9449 §8)", async () => {
    let calls = 0;
    let secondProofPayload = null;
    const SERVER_NONCE = "srv-issued-nonce-xyz";
    const mock = await createMockServer((req, res) => {
      calls++;
      const dpop = req.headers["dpop"];
      if (calls === 1) {
        res.writeHead(400, {
          "Content-Type": "application/json",
          "DPoP-Nonce": SERVER_NONCE,
        });
        res.end(JSON.stringify({ error: "use_dpop_nonce" }));
        return;
      }
      secondProofPayload = decodePart(dpop.split(".")[1]);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ access_token: "at", id_token: "it", refresh_token: "rt" }));
    });

    try {
      const pair = generateEd25519PemPair();
      await exchangeAuthorizationCode({
        ssoBaseUrl: mock.baseUrl,
        providerAddress: "p",
        authorizationCode: "code",
        codeVerifier: "v",
        agentPrivateKeyPem: pair.privateKeyPem,
        agentPublicKeyPem: pair.publicKeyPem,
      });
      assert.equal(calls, 2, "must retry once after nonce challenge");
      assert.equal(secondProofPayload.nonce, SERVER_NONCE);
    } finally {
      mock.server.close();
    }
  });
});

// ─── refreshSession sends DPoP header ────────────────────────────────────────────

describe("refreshSession with DPoP", () => {
  it("sends a DPoP header on the refresh request with matching htm/htu and thumbprint", async () => {
    let receivedDpop = null;
    const mock = await createMockServer((req, res) => {
      receivedDpop = req.headers["dpop"];
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ access_token: "new-at" }));
    });

    try {
      const pair = generateEd25519PemPair();
      const expectedThumbprint = jwkThumbprint(ed25519PublicKeyToJwk(pair.publicKeyPem));

      await refreshSession({
        ssoBaseUrl: mock.baseUrl,
        providerAddress: "p",
        refreshToken: "rt",
        agentPrivateKeyPem: pair.privateKeyPem,
        agentPublicKeyPem: pair.publicKeyPem,
      });

      assert.ok(receivedDpop, "DPoP header was sent");
      const [h, p] = receivedDpop.split(".");
      const header = decodePart(h);
      const payload = decodePart(p);
      assert.equal(header.typ, "dpop+jwt");
      assert.equal(payload.htm, "POST");
      assert.equal(payload.htu, `${mock.baseUrl}/oauth/token`);
      assert.equal(jwkThumbprint(header.jwk), expectedThumbprint);
    } finally {
      mock.server.close();
    }
  });

  it("works without DPoP keys (backwards compatible — header omitted)", async () => {
    let receivedDpop = "MISSING";
    const mock = await createMockServer((req, res) => {
      receivedDpop = req.headers["dpop"];
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ access_token: "at" }));
    });

    try {
      const result = await refreshSession({
        ssoBaseUrl: mock.baseUrl,
        providerAddress: "p",
        refreshToken: "rt",
      });
      assert.equal(result.access_token, "at");
      assert.equal(receivedDpop, undefined, "no DPoP header when keys not supplied");
    } finally {
      mock.server.close();
    }
  });

  it("retries with nonce echoed in proof on use_dpop_nonce challenge (RFC 9449 §8)", async () => {
    let calls = 0;
    let secondProofPayload = null;
    const SERVER_NONCE = "rs-nonce-abc-123";
    const mock = await createMockServer((req, res) => {
      calls++;
      const dpop = req.headers["dpop"];
      if (calls === 1) {
        res.writeHead(400, {
          "Content-Type": "application/json",
          "DPoP-Nonce": SERVER_NONCE,
        });
        res.end(JSON.stringify({ error: "use_dpop_nonce" }));
        return;
      }
      secondProofPayload = decodePart(dpop.split(".")[1]);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ access_token: "new-at" }));
    });

    try {
      const pair = generateEd25519PemPair();
      await refreshSession({
        ssoBaseUrl: mock.baseUrl,
        providerAddress: "p",
        refreshToken: "rt",
        agentPrivateKeyPem: pair.privateKeyPem,
        agentPublicKeyPem: pair.publicKeyPem,
      });
      assert.equal(calls, 2);
      assert.equal(secondProofPayload.nonce, SERVER_NONCE);
    } finally {
      mock.server.close();
    }
  });
});

// ─── SignatureEngine forwards DPoP key on refresh ───────────────────────────────

describe("SignatureEngine.ensureValidSession() forwards DPoP key", () => {
  it("emits a DPoP proof bound to the agent's main key on the refresh request", async () => {
    // We need the engine to discover the same key on disk and use it for DPoP.
    // Reuse helpers from the existing refresh test bench.
    const { default: fs } = await import("node:fs/promises");
    const { default: os } = await import("node:os");
    const { default: pathMod } = await import("node:path");
    const {
      SignatureEngine,
      statePaths,
      ensureDir,
      writeJsonFile,
      readJsonFile,
      generateEd25519PemPair,
      fingerprintPublicKeyPem,
      nowMs,
      canonicalJSONString,
      sha256Hex,
      signEd25519Base64Url,
    } = await import("../skills/alien-agent-id/lib.mjs");

    const stateDir = pathMod.join(os.tmpdir(), `agent-id-dpop-${crypto.randomUUID()}`);
    await fs.mkdir(stateDir, { recursive: true });

    let receivedDpop = null;
    const mock = await createMockServer((req, res) => {
      receivedDpop = req.headers["dpop"];
      // Echo back a fresh access token (no expiry check after — we only need
      // the engine to issue the request so we can inspect the header).
      const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
      const payload = b64url(
        JSON.stringify({
          sub: "test-owner-sub",
          exp: Math.floor(Date.now() / 1000) + 3600,
        }),
      );
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          access_token: `${header}.${payload}.sig`,
          refresh_token: "new-rt",
        }),
      );
    });

    try {
      const paths = statePaths(stateDir);
      const pair = generateEd25519PemPair();
      const fingerprint = fingerprintPublicKeyPem(pair.publicKeyPem);
      const expectedThumbprint = jwkThumbprint(ed25519PublicKeyToJwk(pair.publicKeyPem));

      await ensureDir(pathMod.dirname(paths.mainKey));
      await writeJsonFile(paths.mainKey, {
        version: 1,
        agentId: "main",
        keyNonce: 0,
        createdAt: nowMs(),
        publicKeyPem: pair.publicKeyPem,
        privateKeyPem: pair.privateKeyPem,
        fingerprint,
      });

      // Minimal binding so the engine can init.
      const bindingPayload = {
        version: 1,
        issuedAt: nowMs(),
        issuer: mock.baseUrl,
        providerAddress: "p",
        ownerSessionSub: "test-owner-sub",
        ownerAudience: "p",
        idTokenHash: sha256Hex("fake-id-token"),
        ownerSessionProof: null,
        ownerSessionProofHash: null,
        agentInstance: { hostname: os.hostname(), publicKeyFingerprint: fingerprint, publicKeyPem: pair.publicKeyPem },
      };
      const canonical = canonicalJSONString(bindingPayload);
      await writeJsonFile(paths.ownerBinding, {
        version: 1,
        binding: {
          id: crypto.randomUUID(),
          payload: bindingPayload,
          payloadHash: sha256Hex(canonical),
          signature: signEd25519Base64Url(canonical, pair.privateKeyPem),
          createdAt: nowMs(),
        },
      });

      // Expired access token so refresh fires.
      const expiredHeader = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
      const expiredPayload = b64url(
        JSON.stringify({ sub: "test-owner-sub", exp: Math.floor(Date.now() / 1000) - 600 }),
      );
      await writeJsonFile(paths.ownerSession, {
        version: 1,
        issuer: mock.baseUrl,
        ssoBaseUrl: mock.baseUrl,
        providerAddress: "p",
        ownerSessionSub: "test-owner-sub",
        idToken: "fake-id-token",
        accessToken: `${expiredHeader}.${expiredPayload}.sig`,
        refreshToken: "old-rt",
        ownerSessionProof: null,
        savedAt: nowMs(),
      });
      await ensureDir(pathMod.dirname(paths.auditJsonl));

      const engine = new SignatureEngine({ baseDir: stateDir });
      await engine.init();
      const session = await engine.ensureValidSession();
      assert.ok(session, "session refreshed");

      assert.ok(receivedDpop, "DPoP header was sent on engine-driven refresh");
      const [h, p] = receivedDpop.split(".");
      const proofHeader = decodePart(h);
      const proofPayload = decodePart(p);
      assert.equal(proofHeader.typ, "dpop+jwt");
      assert.equal(proofHeader.alg, "EdDSA");
      assert.equal(proofPayload.htm, "POST");
      assert.equal(proofPayload.htu, `${mock.baseUrl}/oauth/token`);
      assert.equal(jwkThumbprint(proofHeader.jwk), expectedThumbprint);
    } finally {
      mock.server.close();
      await fs.rm(stateDir, { recursive: true, force: true });
    }
  });
});
