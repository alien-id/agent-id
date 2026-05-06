#!/usr/bin/env node

// Unit tests for verifyProofChain — the universal Agent-ID provenance
// chain verifier. Every consumer (git-verify, @alien-id/sso-agent-id,
// future capability-proof flows) calls this function. The tests below
// exercise each step of the chain in isolation, with a focus on the
// substitution-forgery class: a binding/id_token from one agent must
// not verify when stitched onto a proof bundle whose agent.publicKeyPem
// is a different key.
//
// Run: node --test tests/test-chain-verifier.mjs

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import {
  generateKeyPairSync,
  sign as cryptoSign,
} from "node:crypto";

import {
  ChainError,
  verifyProofChain,
  generateEd25519PemPair,
  fingerprintPublicKeyPem,
  ed25519PublicKeyToJwk,
  jwkThumbprint,
  canonicalJSONString,
  sha256Hex,
  sha256HexCanonical,
  signEd25519Base64Url,
  b64url,
  nowMs,
} from "../skills/alien-agent-id/lib.mjs";

// ─── SSO mock + RSA fixture helpers ──────────────────────────────────────────────

function generateRsaKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
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

function makeRs256IdToken({ privateKey, kid, payload }) {
  const header = { alg: "RS256", typ: "JWT", kid };
  const headerB64 = b64url(JSON.stringify(header));
  const payloadB64 = b64url(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = cryptoSign("RSA-SHA256", Buffer.from(signingInput), privateKey);
  return `${signingInput}.${b64url(sig)}`;
}

function startSsoMock({ jwk }) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      if (req.url === "/.well-known/openid-configuration") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          issuer: `http://127.0.0.1:${server.address().port}`,
          jwks_uri: `http://127.0.0.1:${server.address().port}/jwks`,
        }));
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

// ─── Build a fully-valid chain, then mutate one piece per test ───────────────────

function buildValidChain({ rsa, ssoBaseUrl, agentOverride, bindingSignerOverride }) {
  // The "real" agent — the key that holds private control of the chain.
  const agent = agentOverride || generateEd25519PemPair();
  const agentFingerprint = fingerprintPublicKeyPem(agent.publicKeyPem);

  // Binding signer — defaults to the agent itself (legitimate case).
  // Tests pass a different keypair to construct the substitution forgery.
  const bindingSigner = bindingSignerOverride || agent;
  const bindingSignerFingerprint = fingerprintPublicKeyPem(bindingSigner.publicKeyPem);

  // 1. Mint an id_token whose cnf.jkt = thumbprint(agent.publicKeyPem).
  //    This is what the SSO would emit for a DPoP flow that proved the agent
  //    key at /token. (For forgery tests, callers may override what cnf.jkt
  //    is set to, by passing their own idToken in.)
  const cnfJkt = jwkThumbprint(ed25519PublicKeyToJwk(agent.publicKeyPem));
  const idToken = makeRs256IdToken({
    privateKey: rsa.privateKey,
    kid: rsa.publicKeyJwk.kid,
    payload: {
      iss: ssoBaseUrl,
      sub: "0xowner-sub",
      aud: "0xprovider",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      cnf: { jkt: cnfJkt },
    },
  });
  const idTokenHash = sha256Hex(idToken);

  // 2. Build the binding payload, signed by `bindingSigner`. In the
  //    legitimate case, bindingSigner === agent; in forgery tests they
  //    differ, so the chain's step 3 must reject.
  const bindingPayload = {
    version: 1,
    issuedAt: nowMs(),
    issuer: ssoBaseUrl,
    providerAddress: "0xprovider",
    ownerSessionSub: "0xowner-sub",
    ownerAudience: "0xprovider",
    idTokenHash,
    ownerSessionProof: null,
    ownerSessionProofHash: null,
    agentInstance: {
      hostname: "test-host",
      publicKeyFingerprint: bindingSignerFingerprint,
      publicKeyPem: bindingSigner.publicKeyPem,
    },
  };
  const canonical = canonicalJSONString(bindingPayload);
  const binding = {
    id: "binding-uuid",
    payload: bindingPayload,
    payloadHash: sha256HexCanonical(canonical),
    signature: signEd25519Base64Url(canonical, bindingSigner.privateKeyPem),
    createdAt: nowMs(),
  };

  // 3. The proof bundle — claims `agent.publicKeyPem` is the agent's key.
  //    In legit: this is the same key that signed the binding. In forgery:
  //    the bundle CLAIMS this key but the binding was signed by a different
  //    one.
  const proof = {
    version: 2,
    agent: {
      fingerprint: agentFingerprint,
      publicKeyPem: agent.publicKeyPem,
    },
    ownerBinding: binding,
    idToken: Buffer.from(idToken).toString("base64url"),
    ssoBaseUrl,
  };

  return { proof, agent, bindingSigner, idToken, cnfJkt };
}

// ─── Tests ───────────────────────────────────────────────────────────────────────

describe("verifyProofChain", () => {
  let mock = null;
  let rsa = null;

  beforeEach(async () => {
    rsa = generateRsaKeyPair();
    mock = await startSsoMock({ jwk: rsa.publicKeyJwk });
  });

  afterEach(() => {
    if (mock) {
      mock.server.close();
      mock = null;
    }
  });

  it("accepts a valid chain and returns the canonical output", async () => {
    const { proof, agent, cnfJkt } = buildValidChain({ rsa, ssoBaseUrl: mock.baseUrl });
    const result = await verifyProofChain(proof);
    assert.equal(result.agentFingerprint, fingerprintPublicKeyPem(agent.publicKeyPem));
    assert.equal(result.agentPublicKeyPem, agent.publicKeyPem);
    assert.equal(result.ownerSessionSub, "0xowner-sub");
    assert.equal(result.jkt, cnfJkt);
    assert.equal(result.idTokenPayload.sub, "0xowner-sub");
    assert.equal(result.idTokenPayload.aud, "0xprovider");
  });

  // Step 0 — structural

  it("rejects a missing proof", async () => {
    await assert.rejects(() => verifyProofChain(null), ChainError);
  });

  it("rejects an unknown proof version", async () => {
    const { proof } = buildValidChain({ rsa, ssoBaseUrl: mock.baseUrl });
    proof.version = 99;
    await assert.rejects(() => verifyProofChain(proof), /unsupported proof version/);
  });

  it("rejects a proof missing agent.publicKeyPem", async () => {
    const { proof } = buildValidChain({ rsa, ssoBaseUrl: mock.baseUrl });
    delete proof.agent.publicKeyPem;
    await assert.rejects(() => verifyProofChain(proof), /publicKeyPem missing/);
  });

  // Step 1 — agent fingerprint

  it("rejects a proof.agent.fingerprint that doesn't match its publicKeyPem", async () => {
    const { proof } = buildValidChain({ rsa, ssoBaseUrl: mock.baseUrl });
    proof.agent.fingerprint = "deadbeef".repeat(8);
    await assert.rejects(() => verifyProofChain(proof), /does not match publicKeyPem/);
  });

  // Step 2 — binding canonical hash

  it("rejects a binding whose payloadHash does not match its canonical payload", async () => {
    const { proof } = buildValidChain({ rsa, ssoBaseUrl: mock.baseUrl });
    proof.ownerBinding.payloadHash = sha256Hex("tampered");
    await assert.rejects(() => verifyProofChain(proof), /payloadHash does not match/);
  });

  // Step 3 — THE substitution-forgery test

  it("rejects a binding signed by a different key than proof.agent.publicKeyPem", async () => {
    // The substitution forgery: an attacker takes a victim's binding (signed
    // by K_victim, embedding K_victim) and stitches it onto a proof bundle
    // whose `agent.publicKeyPem` is the attacker's K_attacker. The chain
    // must reject because the binding signature was produced by K_victim,
    // not by the K_attacker the bundle claims.
    const victim = generateEd25519PemPair();
    const attacker = generateEd25519PemPair();

    // Build a chain where bindingSigner = victim, then swap the proof's
    // agent.publicKeyPem to the attacker's key. The trailer fingerprint and
    // proof.agent.fingerprint must remain consistent with each other (so
    // step 1 doesn't fire), but the binding signature is the forgery target.
    const { proof } = buildValidChain({
      rsa,
      ssoBaseUrl: mock.baseUrl,
      agentOverride: attacker,
      bindingSignerOverride: victim,
    });

    await assert.rejects(
      () => verifyProofChain(proof),
      /ownerBinding signature does not verify with proof\.agent\.publicKeyPem/,
    );
  });

  // Step 4 — embedded fingerprint must match the agent fingerprint

  it("rejects a binding whose embedded fingerprint differs from the agent fingerprint", async () => {
    const { proof } = buildValidChain({ rsa, ssoBaseUrl: mock.baseUrl });
    proof.ownerBinding.payload.agentInstance.publicKeyFingerprint = "ff".repeat(32);
    // Recompute the canonical hash so step 2 passes; the binding signature
    // would now be invalid (different canonical bytes), so step 3 also
    // fires. Re-sign with the agent key so we isolate step 4.
    const canonical = canonicalJSONString(proof.ownerBinding.payload);
    proof.ownerBinding.payloadHash = sha256HexCanonical(canonical);
    // Re-sign with the same key as proof.agent.publicKeyPem so step 3
    // passes. We need the private key — pull it from buildValidChain by
    // rebuilding with a known agent.
    // (Simpler: rebuild the whole chain with a known agent, then mutate.)
    const knownAgent = generateEd25519PemPair();
    const { proof: p2 } = buildValidChain({ rsa, ssoBaseUrl: mock.baseUrl, agentOverride: knownAgent });
    p2.ownerBinding.payload.agentInstance.publicKeyFingerprint = "ff".repeat(32);
    const c2 = canonicalJSONString(p2.ownerBinding.payload);
    p2.ownerBinding.payloadHash = sha256HexCanonical(c2);
    p2.ownerBinding.signature = signEd25519Base64Url(c2, knownAgent.privateKeyPem);
    await assert.rejects(
      () => verifyProofChain(p2),
      /agentInstance\.publicKeyFingerprint.*does not match agent fingerprint/,
    );
  });

  // Step 5 — id_token must be present

  it("rejects a proof with no id_token", async () => {
    const { proof } = buildValidChain({ rsa, ssoBaseUrl: mock.baseUrl });
    proof.idToken = null;
    await assert.rejects(() => verifyProofChain(proof), /idToken missing|id_token missing/);
  });

  // Step 6 — id_token hash must match binding

  it("rejects when id_token hash does not match ownerBinding.idTokenHash", async () => {
    const { proof } = buildValidChain({ rsa, ssoBaseUrl: mock.baseUrl });
    // Tamper with the binding's recorded hash; rebuild canonical + sig so
    // earlier steps pass.
    const knownAgent = generateEd25519PemPair();
    const { proof: p2 } = buildValidChain({ rsa, ssoBaseUrl: mock.baseUrl, agentOverride: knownAgent });
    p2.ownerBinding.payload.idTokenHash = sha256Hex("not-the-real-id-token");
    const c2 = canonicalJSONString(p2.ownerBinding.payload);
    p2.ownerBinding.payloadHash = sha256HexCanonical(c2);
    p2.ownerBinding.signature = signEd25519Base64Url(c2, knownAgent.privateKeyPem);
    await assert.rejects(
      () => verifyProofChain(p2),
      /id_token hash does not match ownerBinding\.payload\.idTokenHash/,
    );
  });

  // Step 7-8 — SSO signature

  it("rejects when the id_token RS256 signature does not verify against JWKS", async () => {
    const knownAgent = generateEd25519PemPair();
    // Mint a token with a different RSA key than the SSO mock advertises.
    const otherRsa = generateRsaKeyPair();
    const idToken = makeRs256IdToken({
      privateKey: otherRsa.privateKey,
      kid: rsa.publicKeyJwk.kid, // matching kid → JWKS lookup succeeds, but signature is wrong key
      payload: {
        iss: mock.baseUrl,
        sub: "0xowner-sub",
        aud: "0xprovider",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        cnf: { jkt: jwkThumbprint(ed25519PublicKeyToJwk(knownAgent.publicKeyPem)) },
      },
    });
    const { proof } = buildValidChain({ rsa, ssoBaseUrl: mock.baseUrl, agentOverride: knownAgent });
    proof.idToken = Buffer.from(idToken).toString("base64url");
    proof.ownerBinding.payload.idTokenHash = sha256Hex(idToken);
    const c = canonicalJSONString(proof.ownerBinding.payload);
    proof.ownerBinding.payloadHash = sha256HexCanonical(c);
    proof.ownerBinding.signature = signEd25519Base64Url(c, knownAgent.privateKeyPem);
    await assert.rejects(
      () => verifyProofChain(proof),
      /id_token SSO signature verification failed/,
    );
  });

  // Step 9 — cnf.jkt anchored to proof.agent.publicKeyPem

  it("rejects when cnf.jkt is missing from id_token", async () => {
    const knownAgent = generateEd25519PemPair();
    const idToken = makeRs256IdToken({
      privateKey: rsa.privateKey,
      kid: rsa.publicKeyJwk.kid,
      payload: {
        iss: mock.baseUrl,
        sub: "0xowner-sub",
        aud: "0xprovider",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        // no cnf claim
      },
    });
    const { proof } = buildValidChain({ rsa, ssoBaseUrl: mock.baseUrl, agentOverride: knownAgent });
    proof.idToken = Buffer.from(idToken).toString("base64url");
    proof.ownerBinding.payload.idTokenHash = sha256Hex(idToken);
    const c = canonicalJSONString(proof.ownerBinding.payload);
    proof.ownerBinding.payloadHash = sha256HexCanonical(c);
    proof.ownerBinding.signature = signEd25519Base64Url(c, knownAgent.privateKeyPem);
    await assert.rejects(() => verifyProofChain(proof), /id_token missing cnf\.jkt/);
  });

  it("rejects when cnf.jkt does not equal thumbprint(proof.agent.publicKeyPem)", async () => {
    const knownAgent = generateEd25519PemPair();
    // Mint an id_token whose cnf.jkt is for a different key.
    const otherKey = generateEd25519PemPair();
    const wrongJkt = jwkThumbprint(ed25519PublicKeyToJwk(otherKey.publicKeyPem));
    const idToken = makeRs256IdToken({
      privateKey: rsa.privateKey,
      kid: rsa.publicKeyJwk.kid,
      payload: {
        iss: mock.baseUrl,
        sub: "0xowner-sub",
        aud: "0xprovider",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        cnf: { jkt: wrongJkt },
      },
    });
    const { proof } = buildValidChain({ rsa, ssoBaseUrl: mock.baseUrl, agentOverride: knownAgent });
    proof.idToken = Buffer.from(idToken).toString("base64url");
    proof.ownerBinding.payload.idTokenHash = sha256Hex(idToken);
    const c = canonicalJSONString(proof.ownerBinding.payload);
    proof.ownerBinding.payloadHash = sha256HexCanonical(c);
    proof.ownerBinding.signature = signEd25519Base64Url(c, knownAgent.privateKeyPem);
    await assert.rejects(
      () => verifyProofChain(proof),
      /id_token cnf\.jkt mismatch/,
    );
  });
});
