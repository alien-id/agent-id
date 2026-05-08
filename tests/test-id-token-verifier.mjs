#!/usr/bin/env node

// Tests for verifyIdToken's claim-validation contract beyond signature.
// Run: node --test tests/test-id-token-verifier.mjs

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import {
  generateKeyPairSync,
  sign as cryptoSign,
} from "node:crypto";

import {
  verifyIdToken,
  ed25519PublicKeyToJwk,
  jwkThumbprint,
  generateEd25519PemPair,
  signEd25519Base64Url,
  b64url,
  fromB64url,
} from "../skills/alien-agent-id/lib.mjs";

function generateRsaKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  return {
    publicKeyJwk: {
      ...publicKey.export({ format: "jwk" }),
      use: "sig",
      alg: "RS256",
      kid: "test-sso-kid",
    },
    privateKey,
  };
}

function makeRs256IdToken({ privateKey, kid, payload, headerExtra }) {
  const header = { alg: "RS256", typ: "JWT", kid, ...(headerExtra || {}) };
  const headerB64 = b64url(JSON.stringify(header));
  const payloadB64 = b64url(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = cryptoSign("RSA-SHA256", Buffer.from(signingInput), privateKey);
  return `${signingInput}.${b64url(sig)}`;
}

function startSsoMock({ jwk, issuerOverride }) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      if (req.url === "/.well-known/openid-configuration") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            issuer: issuerOverride || `http://127.0.0.1:${server.address().port}`,
            jwks_uri: `http://127.0.0.1:${server.address().port}/jwks`,
          }),
        );
        return;
      }
      if (req.url === "/jwks") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ keys: [jwk] }));
        return;
      }
      res.writeHead(404).end();
    });
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ server, baseUrl: `http://127.0.0.1:${port}` });
    });
  });
}

describe("verifyIdToken — RFC 7519 §4.1.5 nbf", () => {
  let rsa, mock, providerAddress;
  before(async () => {
    rsa = generateRsaKeyPair();
    providerAddress = "0xprovider";
    mock = await startSsoMock({ jwk: rsa.publicKeyJwk });
  });
  after(() => {
    mock.server.close();
  });

  // RFC 7519 §4.1.5: when `nbf` is present, verifier MUST reject if current
  // time < nbf. Spec text: "The processing of the 'nbf' claim requires that
  // the current date/time MUST be after or equal to the not-before
  // date/time listed in the 'nbf' claim."
  it("rejects id_token whose nbf is in the future", async () => {
    const now = Math.floor(Date.now() / 1000);
    const idToken = makeRs256IdToken({
      privateKey: rsa.privateKey,
      kid: rsa.publicKeyJwk.kid,
      payload: {
        iss: mock.baseUrl,
        sub: "owner-sub",
        aud: providerAddress,
        iat: now,
        nbf: now + 600, // not valid for 10 minutes
        exp: now + 3600,
      },
    });

    await assert.rejects(
      () =>
        verifyIdToken({
          ssoBaseUrl: mock.baseUrl,
          providerAddress,
          idToken,
        }),
      /not yet valid|nbf/i,
    );
  });

  it("accepts id_token whose nbf is in the past", async () => {
    const now = Math.floor(Date.now() / 1000);
    const idToken = makeRs256IdToken({
      privateKey: rsa.privateKey,
      kid: rsa.publicKeyJwk.kid,
      payload: {
        iss: mock.baseUrl,
        sub: "owner-sub",
        aud: providerAddress,
        iat: now,
        nbf: now - 600,
        exp: now + 3600,
      },
    });

    const result = await verifyIdToken({
      ssoBaseUrl: mock.baseUrl,
      providerAddress,
      idToken,
    });
    assert.equal(result.payload.sub, "owner-sub");
  });

  it("accepts id_token without an nbf claim (claim is OPTIONAL)", async () => {
    const now = Math.floor(Date.now() / 1000);
    const idToken = makeRs256IdToken({
      privateKey: rsa.privateKey,
      kid: rsa.publicKeyJwk.kid,
      payload: {
        iss: mock.baseUrl,
        sub: "owner-sub",
        aud: providerAddress,
        iat: now,
        exp: now + 3600,
      },
    });

    const result = await verifyIdToken({
      ssoBaseUrl: mock.baseUrl,
      providerAddress,
      idToken,
    });
    assert.equal(result.payload.sub, "owner-sub");
  });
});

describe("verifyIdToken — RFC 9449 §6.1 cnf.jkt at bind time", () => {
  let rsa, mock, providerAddress;
  before(async () => {
    rsa = generateRsaKeyPair();
    providerAddress = "0xprovider";
    mock = await startSsoMock({ jwk: rsa.publicKeyJwk });
  });
  after(() => {
    mock.server.close();
  });

  // RFC 9449 §6.1 + RFC 7800 §3.1: the cnf claim communicates the public key
  // to which the AT/ID-token is bound. When the caller passes the agent's
  // public key, verifyIdToken MUST surface the mismatch immediately rather
  // than deferring to later proof-chain verification.
  it("rejects id_token whose cnf.jkt does not match the agent public key", async () => {
    const agent = generateEd25519PemPair();
    const otherAgent = generateEd25519PemPair();
    const wrongJkt = jwkThumbprint(ed25519PublicKeyToJwk(otherAgent.publicKeyPem));

    const now = Math.floor(Date.now() / 1000);
    const idToken = makeRs256IdToken({
      privateKey: rsa.privateKey,
      kid: rsa.publicKeyJwk.kid,
      payload: {
        iss: mock.baseUrl,
        sub: "owner-sub",
        aud: providerAddress,
        iat: now,
        exp: now + 3600,
        cnf: { jkt: wrongJkt },
      },
    });

    await assert.rejects(
      () =>
        verifyIdToken({
          ssoBaseUrl: mock.baseUrl,
          providerAddress,
          idToken,
          agentPublicKeyPem: agent.publicKeyPem,
        }),
      /cnf\.jkt|cnf jkt|jkt mismatch/i,
    );
  });

  it("rejects id_token missing cnf.jkt when agent key is provided", async () => {
    const agent = generateEd25519PemPair();
    const now = Math.floor(Date.now() / 1000);
    const idToken = makeRs256IdToken({
      privateKey: rsa.privateKey,
      kid: rsa.publicKeyJwk.kid,
      payload: {
        iss: mock.baseUrl,
        sub: "owner-sub",
        aud: providerAddress,
        iat: now,
        exp: now + 3600,
      },
    });

    await assert.rejects(
      () =>
        verifyIdToken({
          ssoBaseUrl: mock.baseUrl,
          providerAddress,
          idToken,
          agentPublicKeyPem: agent.publicKeyPem,
        }),
      /cnf\.jkt|missing cnf/i,
    );
  });

  it("accepts id_token whose cnf.jkt matches the agent public key", async () => {
    const agent = generateEd25519PemPair();
    const matchJkt = jwkThumbprint(ed25519PublicKeyToJwk(agent.publicKeyPem));

    const now = Math.floor(Date.now() / 1000);
    const idToken = makeRs256IdToken({
      privateKey: rsa.privateKey,
      kid: rsa.publicKeyJwk.kid,
      payload: {
        iss: mock.baseUrl,
        sub: "owner-sub",
        aud: providerAddress,
        iat: now,
        exp: now + 3600,
        cnf: { jkt: matchJkt },
      },
    });

    const result = await verifyIdToken({
      ssoBaseUrl: mock.baseUrl,
      providerAddress,
      idToken,
      agentPublicKeyPem: agent.publicKeyPem,
    });
    assert.equal(result.payload.cnf.jkt, matchJkt);
  });

  it("does not require cnf.jkt when no agent key is supplied (back-compat)", async () => {
    const now = Math.floor(Date.now() / 1000);
    const idToken = makeRs256IdToken({
      privateKey: rsa.privateKey,
      kid: rsa.publicKeyJwk.kid,
      payload: {
        iss: mock.baseUrl,
        sub: "owner-sub",
        aud: providerAddress,
        iat: now,
        exp: now + 3600,
        // no cnf
      },
    });

    const result = await verifyIdToken({
      ssoBaseUrl: mock.baseUrl,
      providerAddress,
      idToken,
    });
    assert.equal(result.payload.sub, "owner-sub");
  });
});

// RFC 8037 §2 + RFC 7515 §10.7: an asymmetric algorithm beyond RS256 is a
// legitimate AS rotation outcome. Lock in EdDSA acceptance so the verifier
// does not fail closed if the SSO publishes an Ed25519 OIDC signing key.
describe("verifyIdToken — RFC 7515 §10.7 alg allowlist", () => {
  function startSsoMockWithKey({ jwk, issuerOverride }) {
    return new Promise((resolve) => {
      const server = http.createServer((req, res) => {
        if (req.url === "/.well-known/openid-configuration") {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              issuer: issuerOverride || `http://127.0.0.1:${server.address().port}`,
              jwks_uri: `http://127.0.0.1:${server.address().port}/jwks`,
            }),
          );
          return;
        }
        if (req.url === "/jwks") {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ keys: [jwk] }));
          return;
        }
        res.writeHead(404).end();
      });
      server.listen(0, "127.0.0.1", () => {
        const { port } = server.address();
        resolve({ server, baseUrl: `http://127.0.0.1:${port}` });
      });
    });
  }

  function makeEdDsaIdToken({ privateKeyPem, kid, payload }) {
    const header = { alg: "EdDSA", typ: "JWT", kid };
    const headerB64 = b64url(JSON.stringify(header));
    const payloadB64 = b64url(JSON.stringify(payload));
    const signingInput = `${headerB64}.${payloadB64}`;
    const sig = signEd25519Base64Url(signingInput, privateKeyPem);
    return `${signingInput}.${sig}`;
  }

  it("accepts EdDSA-signed id_token published in JWKS (RFC 8037 §2)", async () => {
    const ssoKey = generateEd25519PemPair();
    const okpJwk = {
      ...ed25519PublicKeyToJwk(ssoKey.publicKeyPem),
      use: "sig",
      alg: "EdDSA",
      kid: "test-eddsa-kid",
    };
    const mock = await startSsoMockWithKey({ jwk: okpJwk });
    try {
      const now = Math.floor(Date.now() / 1000);
      const idToken = makeEdDsaIdToken({
        privateKeyPem: ssoKey.privateKeyPem,
        kid: okpJwk.kid,
        payload: {
          iss: mock.baseUrl,
          sub: "owner-sub",
          aud: "0xprovider",
          iat: now,
          exp: now + 3600,
        },
      });

      const result = await verifyIdToken({
        ssoBaseUrl: mock.baseUrl,
        providerAddress: "0xprovider",
        idToken,
      });
      assert.equal(result.payload.sub, "owner-sub");
      assert.equal(result.header.alg, "EdDSA");
    } finally {
      mock.server.close();
    }
  });
});

// RFC 7515 §4.1.11 + RFC 7519 §7.2: any unrecognised `crit` extension MUST
// cause the JWS to be considered invalid. This implementation supports no
// extensions, so any non-empty `crit` array is grounds for rejection.
describe("verifyIdToken — RFC 7515 §4.1.11 crit", () => {
  let rsa, mock, providerAddress;
  before(async () => {
    rsa = generateRsaKeyPair();
    providerAddress = "0xprovider";
    mock = await startSsoMock({ jwk: rsa.publicKeyJwk });
  });
  after(() => {
    mock.server.close();
  });

  it("rejects id_token whose JOSE header carries a non-empty crit array", async () => {
    const now = Math.floor(Date.now() / 1000);
    const idToken = makeRs256IdToken({
      privateKey: rsa.privateKey,
      kid: rsa.publicKeyJwk.kid,
      headerExtra: { crit: ["http://example.com/UNKNOWN"] },
      payload: {
        iss: mock.baseUrl,
        sub: "owner-sub",
        aud: providerAddress,
        iat: now,
        exp: now + 3600,
      },
    });

    await assert.rejects(
      () => verifyIdToken({ ssoBaseUrl: mock.baseUrl, providerAddress, idToken }),
      /crit/i,
    );
  });
});

// RFC 6749 §10: access tokens, refresh tokens, and bearer credentials MUST
// only be transmitted over TLS. Reject plain http:// SSO base URLs unless
// they target loopback (development convenience).
describe("verifyIdToken — RFC 6749 §10 ssoBaseUrl scheme guard", () => {
  it("rejects ssoBaseUrl with http:// scheme on a non-loopback host", async () => {
    await assert.rejects(
      () =>
        verifyIdToken({
          ssoBaseUrl: "http://example.com",
          providerAddress: "0xprovider",
          idToken: "x.y.z",
        }),
      /https/i,
    );
  });

  it("rejects ssoBaseUrl with empty string", async () => {
    await assert.rejects(
      () =>
        verifyIdToken({
          ssoBaseUrl: "",
          providerAddress: "0xprovider",
          idToken: "x.y.z",
        }),
      /ssoBaseUrl/i,
    );
  });

  it("permits http://localhost for development", async () => {
    // Construction must not throw on the scheme guard; the call still fails
    // (no real server), but with a network/parse error rather than a scheme
    // violation. The assertion is the absence of an /https/i message.
    await assert.rejects(
      () =>
        verifyIdToken({
          ssoBaseUrl: "http://localhost:1",
          providerAddress: "0xprovider",
          idToken: "x.y.z",
        }),
      (err) => !/https/i.test(err.message),
    );
  });

  it("permits http://127.0.0.1 for development", async () => {
    await assert.rejects(
      () =>
        verifyIdToken({
          ssoBaseUrl: "http://127.0.0.1:1",
          providerAddress: "0xprovider",
          idToken: "x.y.z",
        }),
      (err) => !/https/i.test(err.message),
    );
  });
});

// OIDC Core 1.0 §3.1.3.7.6/.7: when an id_token's aud is multi-valued, the
// `azp` claim MUST be present and MUST equal the client's id; when `azp` is
// present at all, it MUST equal the client's id.
describe("verifyIdToken — OIDC §3.1.3.7 azp / multi-aud handling", () => {
  let rsa, mock, providerAddress;
  before(async () => {
    rsa = generateRsaKeyPair();
    providerAddress = "0xprovider";
    mock = await startSsoMock({ jwk: rsa.publicKeyJwk });
  });
  after(() => {
    mock.server.close();
  });

  function basePayload(extra) {
    const now = Math.floor(Date.now() / 1000);
    return {
      iss: mock.baseUrl,
      sub: "owner-sub",
      iat: now,
      exp: now + 3600,
      ...extra,
    };
  }
  function mint(payload) {
    return makeRs256IdToken({ privateKey: rsa.privateKey, kid: rsa.publicKeyJwk.kid, payload });
  }

  it("rejects multi-aud id_token without an azp claim", async () => {
    const idToken = mint(basePayload({ aud: [providerAddress, "0xother"] }));
    await assert.rejects(
      () => verifyIdToken({ ssoBaseUrl: mock.baseUrl, providerAddress, idToken }),
      /azp/i,
    );
  });

  it("rejects multi-aud id_token whose azp does not equal client id", async () => {
    const idToken = mint(basePayload({ aud: [providerAddress, "0xother"], azp: "0xother" }));
    await assert.rejects(
      () => verifyIdToken({ ssoBaseUrl: mock.baseUrl, providerAddress, idToken }),
      /azp/i,
    );
  });

  it("accepts multi-aud id_token whose azp equals client id", async () => {
    const idToken = mint(basePayload({ aud: [providerAddress, "0xother"], azp: providerAddress }));
    const result = await verifyIdToken({ ssoBaseUrl: mock.baseUrl, providerAddress, idToken });
    assert.equal(result.payload.sub, "owner-sub");
  });

  it("rejects single-aud id_token whose azp is set but does not match client id", async () => {
    const idToken = mint(basePayload({ aud: providerAddress, azp: "0xother" }));
    await assert.rejects(
      () => verifyIdToken({ ssoBaseUrl: mock.baseUrl, providerAddress, idToken }),
      /azp/i,
    );
  });

  it("accepts single-aud id_token without azp", async () => {
    const idToken = mint(basePayload({ aud: providerAddress }));
    const result = await verifyIdToken({ ssoBaseUrl: mock.baseUrl, providerAddress, idToken });
    assert.equal(result.payload.sub, "owner-sub");
  });

  it("accepts single-aud id_token with azp matching client id", async () => {
    const idToken = mint(basePayload({ aud: providerAddress, azp: providerAddress }));
    const result = await verifyIdToken({ ssoBaseUrl: mock.baseUrl, providerAddress, idToken });
    assert.equal(result.payload.sub, "owner-sub");
  });
});

// RFC 7515 §2 / RFC 7519 §7.2: the JOSE Base64url Encoding has the alphabet
// [A-Za-z0-9_-]; padding ('=') is omitted; whitespace and other characters
// are not part of the encoding and MUST cause the JWS to be rejected.
describe("fromB64url — RFC 7515 §2 strict alphabet", () => {
  it("decodes canonical base64url (no padding) round-trip", () => {
    const data = Buffer.from("hello world");
    assert.deepEqual(fromB64url(b64url(data)), data);
  });

  it("rejects whitespace anywhere in the input", () => {
    assert.throws(() => fromB64url(" abcd"), /alphabet/i);
    assert.throws(() => fromB64url("abcd "), /alphabet/i);
    assert.throws(() => fromB64url("ab cd"), /alphabet/i);
    assert.throws(() => fromB64url("ab\ncd"), /alphabet/i);
    assert.throws(() => fromB64url("ab\rcd"), /alphabet/i);
    assert.throws(() => fromB64url("ab\tcd"), /alphabet/i);
  });

  it("rejects standard-base64 alphabet leakage (+, /)", () => {
    assert.throws(() => fromB64url("ab+d"), /alphabet/i);
    assert.throws(() => fromB64url("ab/d"), /alphabet/i);
  });

  it("rejects '=' padding (canonical base64url omits padding)", () => {
    assert.throws(() => fromB64url("abcd="), /alphabet/i);
    assert.throws(() => fromB64url("abc="), /alphabet/i);
  });

  it("rejects invalid 4-char-residue length", () => {
    // A residue of 1 character cannot be produced by canonical encoding.
    assert.throws(() => fromB64url("a"), /length/i);
  });

  it("rejects non-string input", () => {
    assert.throws(() => fromB64url(undefined), /string/i);
    assert.throws(() => fromB64url(null), /string/i);
    assert.throws(() => fromB64url(123), /string/i);
    assert.throws(() => fromB64url(Buffer.from("abcd")), /string/i);
  });
});

// RFC 7519 §7.2: validating a JWT requires verifying the JOSE Header is a
// completely valid JSON object encoded with strict base64url. parseJwt is
// the entry point used by verifyIdToken and refresh checks; it must surface
// alphabet violations as a parse failure rather than silently decoding.
describe("verifyIdToken — RFC 7519 §7.2 strict JWS structural validation", () => {
  it("rejects an id_token whose segments contain whitespace", async () => {
    // Build a real-looking JWT then inject a space into the header segment.
    const ssoBaseUrl = "http://127.0.0.1:1";
    const tampered = `eyJ\n.payload.sig`;
    await assert.rejects(
      () =>
        verifyIdToken({
          ssoBaseUrl,
          providerAddress: "0xprovider",
          idToken: tampered,
        }),
      /alphabet|format|JWT/i,
    );
  });

  it("rejects an id_token with the wrong segment count", async () => {
    const ssoBaseUrl = "http://127.0.0.1:1";
    await assert.rejects(
      () =>
        verifyIdToken({
          ssoBaseUrl,
          providerAddress: "0xprovider",
          idToken: "only.two",
        }),
      /JWT format/i,
    );
  });

  it("rejects an id_token with an empty segment", async () => {
    const ssoBaseUrl = "http://127.0.0.1:1";
    await assert.rejects(
      () =>
        verifyIdToken({
          ssoBaseUrl,
          providerAddress: "0xprovider",
          idToken: "eyJ..",
        }),
      /JWT format/i,
    );
  });
});

// RFC 7519 §4.1.6: "iat" Claim, when present, MUST be a NumericDate
// (numeric value). A non-numeric `iat` is a malformed claim and the token
// MUST be rejected. §4.1.5 says the same about `nbf`.
describe("verifyIdToken — RFC 7519 §4.1.6 iat / §4.1.5 nbf NumericDate", () => {
  let rsa, mock, providerAddress;
  before(async () => {
    rsa = generateRsaKeyPair();
    providerAddress = "0xprovider";
    mock = await startSsoMock({ jwk: rsa.publicKeyJwk });
  });
  after(() => {
    mock.server.close();
  });

  it("rejects id_token whose iat is a string (not a NumericDate)", async () => {
    const now = Math.floor(Date.now() / 1000);
    const idToken = makeRs256IdToken({
      privateKey: rsa.privateKey,
      kid: rsa.publicKeyJwk.kid,
      payload: {
        iss: mock.baseUrl,
        sub: "owner-sub",
        aud: providerAddress,
        iat: String(now),
        exp: now + 3600,
      },
    });
    await assert.rejects(
      () => verifyIdToken({ ssoBaseUrl: mock.baseUrl, providerAddress, idToken }),
      /iat/i,
    );
  });

  it("rejects id_token whose iat is null", async () => {
    const now = Math.floor(Date.now() / 1000);
    const idToken = makeRs256IdToken({
      privateKey: rsa.privateKey,
      kid: rsa.publicKeyJwk.kid,
      payload: {
        iss: mock.baseUrl,
        sub: "owner-sub",
        aud: providerAddress,
        iat: null,
        exp: now + 3600,
      },
    });
    await assert.rejects(
      () => verifyIdToken({ ssoBaseUrl: mock.baseUrl, providerAddress, idToken }),
      /iat/i,
    );
  });

  it("rejects id_token whose nbf is a string (not a NumericDate)", async () => {
    const now = Math.floor(Date.now() / 1000);
    const idToken = makeRs256IdToken({
      privateKey: rsa.privateKey,
      kid: rsa.publicKeyJwk.kid,
      payload: {
        iss: mock.baseUrl,
        sub: "owner-sub",
        aud: providerAddress,
        iat: now,
        nbf: "not-a-number",
        exp: now + 3600,
      },
    });
    await assert.rejects(
      () => verifyIdToken({ ssoBaseUrl: mock.baseUrl, providerAddress, idToken }),
      /nbf/i,
    );
  });

  it("accepts id_token without iat (claim is OPTIONAL)", async () => {
    const now = Math.floor(Date.now() / 1000);
    const idToken = makeRs256IdToken({
      privateKey: rsa.privateKey,
      kid: rsa.publicKeyJwk.kid,
      payload: {
        iss: mock.baseUrl,
        sub: "owner-sub",
        aud: providerAddress,
        // no iat
        exp: now + 3600,
      },
    });
    const result = await verifyIdToken({ ssoBaseUrl: mock.baseUrl, providerAddress, idToken });
    assert.equal(result.payload.sub, "owner-sub");
  });
});

// OIDC Core 1.0 §3.1.3.7 step 11: when the client included a `nonce` in the
// authorization request, the id_token MUST carry the same value and the
// client MUST verify it. Replay protection for the auth-code/id-token flow.
describe("verifyIdToken — OIDC §3.1.3.7 nonce", () => {
  let rsa, mock, providerAddress;
  before(async () => {
    rsa = generateRsaKeyPair();
    providerAddress = "0xprovider";
    mock = await startSsoMock({ jwk: rsa.publicKeyJwk });
  });
  after(() => {
    mock.server.close();
  });

  function mint(extra) {
    const now = Math.floor(Date.now() / 1000);
    return makeRs256IdToken({
      privateKey: rsa.privateKey,
      kid: rsa.publicKeyJwk.kid,
      payload: {
        iss: mock.baseUrl,
        sub: "owner-sub",
        aud: providerAddress,
        iat: now,
        exp: now + 3600,
        ...extra,
      },
    });
  }

  it("rejects id_token whose nonce does not equal expectedNonce", async () => {
    const idToken = mint({ nonce: "wrong-nonce" });
    await assert.rejects(
      () =>
        verifyIdToken({
          ssoBaseUrl: mock.baseUrl,
          providerAddress,
          idToken,
          expectedNonce: "right-nonce",
        }),
      /nonce/i,
    );
  });

  it("rejects id_token missing nonce when expectedNonce is set", async () => {
    const idToken = mint({});
    await assert.rejects(
      () =>
        verifyIdToken({
          ssoBaseUrl: mock.baseUrl,
          providerAddress,
          idToken,
          expectedNonce: "right-nonce",
        }),
      /nonce/i,
    );
  });

  it("accepts id_token whose nonce equals expectedNonce", async () => {
    const idToken = mint({ nonce: "right-nonce" });
    const result = await verifyIdToken({
      ssoBaseUrl: mock.baseUrl,
      providerAddress,
      idToken,
      expectedNonce: "right-nonce",
    });
    assert.equal(result.payload.nonce, "right-nonce");
  });

  it("accepts id_token without nonce when expectedNonce is omitted (refresh flow)", async () => {
    const idToken = mint({});
    const result = await verifyIdToken({ ssoBaseUrl: mock.baseUrl, providerAddress, idToken });
    assert.equal(result.payload.sub, "owner-sub");
  });
});

// RFC 8725 §3.11 / OIDC Core §2: id_tokens are typed JWTs. Reject any
// `typ` value that names a different JWT class (`at+jwt`, `dpop+jwt`, …)
// to defend against cross-JWT confusion. Bare `JWT` and `application/jwt`
// are accepted; missing `typ` is tolerated for legacy tokens. RFC 6838 §4.2
// — media-type comparison is case-insensitive.
describe("verifyIdToken — RFC 8725 §3.11 typ confusion", () => {
  let rsa, mock, providerAddress;
  before(async () => {
    rsa = generateRsaKeyPair();
    providerAddress = "0xprovider";
    mock = await startSsoMock({ jwk: rsa.publicKeyJwk });
  });
  after(() => {
    mock.server.close();
  });

  function mint(typ) {
    const now = Math.floor(Date.now() / 1000);
    return makeRs256IdToken({
      privateKey: rsa.privateKey,
      kid: rsa.publicKeyJwk.kid,
      payload: {
        iss: mock.baseUrl,
        sub: "owner-sub",
        aud: providerAddress,
        iat: now,
        exp: now + 3600,
      },
      headerExtra: typ === undefined ? {} : { typ },
    });
  }

  it("rejects typ=at+jwt (RFC 9068 access token)", async () => {
    await assert.rejects(
      () => verifyIdToken({ ssoBaseUrl: mock.baseUrl, providerAddress, idToken: mint("at+jwt") }),
      /Unsupported id_token typ/,
    );
  });

  it("rejects typ=dpop+jwt (RFC 9449 proof)", async () => {
    await assert.rejects(
      () => verifyIdToken({ ssoBaseUrl: mock.baseUrl, providerAddress, idToken: mint("dpop+jwt") }),
      /Unsupported id_token typ/,
    );
  });

  it("rejects typ=application/at+jwt", async () => {
    await assert.rejects(
      () => verifyIdToken({ ssoBaseUrl: mock.baseUrl, providerAddress, idToken: mint("application/at+jwt") }),
      /Unsupported id_token typ/,
    );
  });

  it("accepts typ=JWT", async () => {
    const result = await verifyIdToken({ ssoBaseUrl: mock.baseUrl, providerAddress, idToken: mint("JWT") });
    assert.equal(result.payload.sub, "owner-sub");
  });

  it("accepts typ=application/jwt (case-insensitive per RFC 6838 §4.2)", async () => {
    const result = await verifyIdToken({ ssoBaseUrl: mock.baseUrl, providerAddress, idToken: mint("application/JWT") });
    assert.equal(result.payload.sub, "owner-sub");
  });

  it("tolerates missing typ (legacy backwards compatibility)", async () => {
    const result = await verifyIdToken({
      ssoBaseUrl: mock.baseUrl,
      providerAddress,
      idToken: makeRs256IdToken({
        privateKey: rsa.privateKey,
        kid: rsa.publicKeyJwk.kid,
        payload: {
          iss: mock.baseUrl,
          sub: "owner-sub",
          aud: providerAddress,
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 3600,
        },
        headerExtra: { typ: undefined },
      }),
    });
    assert.equal(result.payload.sub, "owner-sub");
  });
});
