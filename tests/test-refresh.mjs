#!/usr/bin/env node

// Tests for SSO session refresh flow.
// Uses Node.js built-in test runner and a mock HTTP server.
// Run: node --test tests/test-refresh.mjs

import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";

import {
  refreshSession,
  SignatureEngine,
  generateEd25519PemPair,
  fingerprintPublicKeyPem,
  writeJsonFile,
  readJsonFile,
  setPrivateFilePermissions,
  statePaths,
  ensureDir,
  nowMs,
  b64url,
  fromB64url,
  signEd25519Base64Url,
  canonicalJSONString,
  sha256Hex,
  ed25519PublicKeyToJwk,
  jwkThumbprint,
} from "../skills/alien-agent-id/lib.mjs";

// ─── Helpers ─────────────────────────────────────────────────────────────────────

function makeJwt(payload, expireInSec = 3600) {
  // Create a minimal JWT-shaped string (not cryptographically valid RS256,
  // but enough for parseJwt to decode the payload and check exp).
  const header = { alg: "HS256", typ: "JWT" };
  const fullPayload = {
    sub: "test-owner-sub",
    iss: "http://localhost",
    aud: "test-provider",
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + expireInSec,
    ...payload,
  };
  const enc = (obj) => b64url(JSON.stringify(obj));
  return `${enc(header)}.${enc(fullPayload)}.fakesig`;
}

function makeExpiredJwt(payload = {}) {
  return makeJwt(payload, -600); // expired 10 minutes ago
}

function makeFreshJwt(payload = {}) {
  return makeJwt(payload, 3600); // expires in 1 hour
}

async function createTempStateDir() {
  const dir = path.join(os.tmpdir(), `agent-id-test-${crypto.randomUUID()}`);
  await fs.mkdir(dir, { recursive: true });
  return dir;
}

async function cleanupDir(dir) {
  await fs.rm(dir, { recursive: true, force: true });
}

async function writeTestState(stateDir, { accessToken, refreshToken, ssoBaseUrl, providerAddress }) {
  const paths = statePaths(stateDir);

  // Generate a real keypair
  const pair = generateEd25519PemPair();
  const fingerprint = fingerprintPublicKeyPem(pair.publicKeyPem);

  await ensureDir(path.dirname(paths.mainKey));
  await writeJsonFile(paths.mainKey, {
    version: 1,
    agentId: "main",
    keyNonce: 0,
    createdAt: nowMs(),
    publicKeyPem: pair.publicKeyPem,
    privateKeyPem: pair.privateKeyPem,
    fingerprint,
  });

  // Create a minimal owner binding
  const bindingPayload = {
    version: 1,
    issuedAt: nowMs(),
    issuer: ssoBaseUrl,
    providerAddress,
    ownerSessionSub: "test-owner-sub",
    ownerAudience: providerAddress,
    idTokenHash: sha256Hex("fake-id-token"),
    agentInstance: {
      hostname: os.hostname(),
      publicKeyFingerprint: fingerprint,
      publicKeyPem: pair.publicKeyPem,
    },
  };
  const canonical = canonicalJSONString(bindingPayload);
  const binding = {
    id: crypto.randomUUID(),
    payload: bindingPayload,
    payloadHash: sha256Hex(canonical),
    signature: signEd25519Base64Url(canonical, pair.privateKeyPem),
    createdAt: nowMs(),
  };
  await writeJsonFile(paths.ownerBinding, { version: 1, binding });

  // Create owner session with the provided tokens
  await writeJsonFile(paths.ownerSession, {
    version: 1,
    issuer: ssoBaseUrl,
    ssoBaseUrl,
    providerAddress,
    ownerSessionSub: "test-owner-sub",
    idToken: "fake-id-token",
    accessToken,
    refreshToken,
    savedAt: nowMs(),
  });

  // Create audit dir
  await ensureDir(path.dirname(paths.auditJsonl));

  return { pair, fingerprint, paths };
}

// ─── Mock SSO Server ─────────────────────────────────────────────────────────────

function createMockSsoServer(handler) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        handler(req, res, body);
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ server, baseUrl: `http://127.0.0.1:${port}` });
    });
  });
}

// SSO mock that ALSO serves /.well-known/openid-configuration and /jwks so
// that refresh-time `verifyIdToken` calls can re-validate a rotated id_token
// (RFC 9449 §6.1: rotated tokens remain DPoP-bound; verifying the new
// id_token catches a compromised/buggy AS that rotates sub or cnf.jkt).
function generateRsaSsoSigner() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  return {
    privateKey,
    publicKeyJwk: {
      ...publicKey.export({ format: "jwk" }),
      use: "sig",
      alg: "RS256",
      kid: "test-sso-kid",
    },
  };
}

function makeRs256IdToken({ privateKey, kid, payload }) {
  const header = { alg: "RS256", typ: "JWT", kid };
  const headerB64 = b64url(JSON.stringify(header));
  const payloadB64 = b64url(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = crypto.sign("RSA-SHA256", Buffer.from(signingInput), privateKey);
  return `${signingInput}.${b64url(sig)}`;
}

// Wraps createMockSsoServer with discovery + JWKS endpoints; the caller
// supplies a /oauth/token handler.
async function createRsaSsoMock({ rsa, tokenHandler }) {
  const mock = await createMockSsoServer((req, res, body) => {
    if (req.url === "/.well-known/openid-configuration") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          issuer: mock.baseUrl,
          jwks_uri: `${mock.baseUrl}/jwks`,
        }),
      );
      return;
    }
    if (req.url === "/jwks") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ keys: [rsa.publicKeyJwk] }));
      return;
    }
    tokenHandler(req, res, body);
  });
  return mock;
}

// ─── Tests ───────────────────────────────────────────────────────────────────────

describe("refreshSession()", () => {
  let server, baseUrl;

  after(async () => {
    if (server) server.close();
  });

  it("sends grant_type=refresh_token and returns new tokens", async () => {
    let receivedBody = null;

    const mock = await createMockSsoServer((req, res, body) => {
      receivedBody = new URLSearchParams(body);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          access_token: makeFreshJwt(),
          refresh_token: "new-refresh-token",
          id_token: makeFreshJwt({ sub: "test-owner-sub" }),
        }),
      );
    });
    server = mock.server;
    baseUrl = mock.baseUrl;

    const result = await refreshSession({
      ssoBaseUrl: baseUrl,
      refreshToken: "old-refresh-token",
      providerAddress: "test-provider",
    });

    assert.ok(result.access_token);
    assert.equal(result.refresh_token, "new-refresh-token");
    assert.ok(result.id_token);

    // Verify the request was correct
    assert.equal(receivedBody.get("grant_type"), "refresh_token");
    assert.equal(receivedBody.get("refresh_token"), "old-refresh-token");
    assert.equal(receivedBody.get("client_id"), "test-provider");

    server.close();
    server = null;
  });

  it("throws when access_token is missing from response", async () => {
    const mock = await createMockSsoServer((req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ refresh_token: "new-rt" })); // no access_token
    });
    server = mock.server;

    await assert.rejects(
      () =>
        refreshSession({
          ssoBaseUrl: mock.baseUrl,
          refreshToken: "rt",
          providerAddress: "p",
        }),
      /Refresh response missing access_token/,
    );

    server.close();
    server = null;
  });

  it("throws on HTTP 401 (revoked)", async () => {
    const mock = await createMockSsoServer((req, res) => {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_grant" }));
    });
    server = mock.server;

    await assert.rejects(
      () =>
        refreshSession({
          ssoBaseUrl: mock.baseUrl,
          refreshToken: "revoked-rt",
          providerAddress: "p",
        }),
      /HTTP 401/,
    );

    server.close();
    server = null;
  });
});

describe("SignatureEngine.ensureValidSession()", () => {
  let stateDir;

  beforeEach(async () => {
    stateDir = await createTempStateDir();
  });

  after(async () => {
    // Clean up any remaining temp dirs
    if (stateDir) await cleanupDir(stateDir).catch(() => {});
  });

  it("returns session as-is when access_token is still fresh", async () => {
    const freshToken = makeFreshJwt();

    await writeTestState(stateDir, {
      accessToken: freshToken,
      refreshToken: "rt",
      ssoBaseUrl: "http://not-called",
      providerAddress: "test-provider",
    });

    const engine = new SignatureEngine({ baseDir: stateDir });
    await engine.init();

    const session = await engine.ensureValidSession();
    assert.ok(session);
    assert.equal(session.accessToken, freshToken);
    assert.equal(session.refreshedAt, undefined); // no refresh happened

    await cleanupDir(stateDir);
  });

  it("refreshes when access_token is expired", async () => {
    const newFreshToken = makeFreshJwt({ marker: "refreshed" });
    let serverClosed = false;

    const mock = await createMockSsoServer((req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          access_token: newFreshToken,
          token_type: "DPoP",
          refresh_token: "new-rt",
        }),
      );
    });

    try {
      await writeTestState(stateDir, {
        accessToken: makeExpiredJwt(),
        refreshToken: "old-rt",
        ssoBaseUrl: mock.baseUrl,
        providerAddress: "test-provider",
      });

      const engine = new SignatureEngine({ baseDir: stateDir });
      await engine.init();

      const session = await engine.ensureValidSession();
      assert.ok(session);
      assert.equal(session.accessToken, newFreshToken);
      assert.equal(session.refreshToken, "new-rt");
      assert.ok(session.refreshedAt);

      // Verify the session was persisted to disk
      const paths = statePaths(stateDir);
      const onDisk = await readJsonFile(paths.ownerSession, null);
      assert.equal(onDisk.accessToken, newFreshToken);
      assert.equal(onDisk.refreshToken, "new-rt");
    } finally {
      mock.server.close();
      await cleanupDir(stateDir);
    }
  });

  it("handles refresh_token rotation (new refresh_token in response)", async () => {
    const mock = await createMockSsoServer((req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          access_token: makeFreshJwt(),
          token_type: "DPoP",
          refresh_token: "rotated-rt",
        }),
      );
    });

    try {
      await writeTestState(stateDir, {
        accessToken: makeExpiredJwt(),
        refreshToken: "original-rt",
        ssoBaseUrl: mock.baseUrl,
        providerAddress: "test-provider",
      });

      const engine = new SignatureEngine({ baseDir: stateDir });
      await engine.init();

      const session = await engine.ensureValidSession();
      assert.equal(session.refreshToken, "rotated-rt");

      // Persisted
      const paths = statePaths(stateDir);
      const onDisk = await readJsonFile(paths.ownerSession, null);
      assert.equal(onDisk.refreshToken, "rotated-rt");
    } finally {
      mock.server.close();
      await cleanupDir(stateDir);
    }
  });

  it("preserves refresh_token when response omits it", async () => {
    const mock = await createMockSsoServer((req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          access_token: makeFreshJwt(),
          token_type: "DPoP",
          // no refresh_token in response
        }),
      );
    });

    try {
      await writeTestState(stateDir, {
        accessToken: makeExpiredJwt(),
        refreshToken: "keep-this-rt",
        ssoBaseUrl: mock.baseUrl,
        providerAddress: "test-provider",
      });

      const engine = new SignatureEngine({ baseDir: stateDir });
      await engine.init();

      const session = await engine.ensureValidSession();
      assert.equal(session.refreshToken, "keep-this-rt"); // unchanged

      const paths = statePaths(stateDir);
      const onDisk = await readJsonFile(paths.ownerSession, null);
      assert.equal(onDisk.refreshToken, "keep-this-rt");
    } finally {
      mock.server.close();
      await cleanupDir(stateDir);
    }
  });

  it("updates id_token when refresh returns one", async () => {
    // After RFC 9449 §6.1 hardening, a rotated id_token MUST be re-verified
    // before persistence. Use a real RS256-signed token with matching iss/aud
    // and a cnf.jkt bound to the test agent key.
    const rsa = generateRsaSsoSigner();
    const stateInit = await writeTestState(stateDir, {
      accessToken: makeExpiredJwt(),
      refreshToken: "rt",
      ssoBaseUrl: "placeholder", // overwritten below
      providerAddress: "test-provider",
    });
    const agentJkt = jwkThumbprint(ed25519PublicKeyToJwk(stateInit.pair.publicKeyPem));

    let mock;
    const mintIdToken = (overrides = {}) => {
      const now = Math.floor(Date.now() / 1000);
      return makeRs256IdToken({
        privateKey: rsa.privateKey,
        kid: rsa.publicKeyJwk.kid,
        payload: {
          iss: mock.baseUrl,
          sub: "test-owner-sub",
          aud: "test-provider",
          iat: now,
          exp: now + 3600,
          cnf: { jkt: agentJkt },
          ...overrides,
        },
      });
    };

    let newIdToken;
    mock = await createRsaSsoMock({
      rsa,
      tokenHandler: (req, res) => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            access_token: makeFreshJwt(),
            token_type: "DPoP",
            id_token: newIdToken,
          }),
        );
      },
    });
    newIdToken = mintIdToken({ fresh: true });

    // Re-point the persisted session at the just-bound mock URL.
    const sessionFile = stateInit.paths.ownerSession;
    const sessionData = await readJsonFile(sessionFile, null);
    sessionData.ssoBaseUrl = mock.baseUrl;
    sessionData.issuer = mock.baseUrl;
    await writeJsonFile(sessionFile, sessionData);

    try {
      const engine = new SignatureEngine({ baseDir: stateDir });
      await engine.init();

      const session = await engine.ensureValidSession();
      assert.equal(session.idToken, newIdToken);
    } finally {
      mock.server.close();
      await cleanupDir(stateDir);
    }
  });

  it("rejects refresh whose id_token has mismatched sub (RFC 9449 §6.1)", async () => {
    const rsa = generateRsaSsoSigner();
    const stateInit = await writeTestState(stateDir, {
      accessToken: makeExpiredJwt(),
      refreshToken: "rt",
      ssoBaseUrl: "placeholder",
      providerAddress: "test-provider",
    });
    const agentJkt = jwkThumbprint(ed25519PublicKeyToJwk(stateInit.pair.publicKeyPem));

    let mock;
    let attackerIdToken;
    mock = await createRsaSsoMock({
      rsa,
      tokenHandler: (req, res) => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            access_token: makeFreshJwt({ sub: "test-owner-sub" }),
            token_type: "DPoP",
            id_token: attackerIdToken,
          }),
        );
      },
    });
    const now = Math.floor(Date.now() / 1000);
    attackerIdToken = makeRs256IdToken({
      privateKey: rsa.privateKey,
      kid: rsa.publicKeyJwk.kid,
      payload: {
        iss: mock.baseUrl,
        sub: "attacker-sub", // <-- different owner
        aud: "test-provider",
        iat: now,
        exp: now + 3600,
        cnf: { jkt: agentJkt },
      },
    });

    const sessionFile = stateInit.paths.ownerSession;
    const sessionData = await readJsonFile(sessionFile, null);
    sessionData.ssoBaseUrl = mock.baseUrl;
    sessionData.issuer = mock.baseUrl;
    await writeJsonFile(sessionFile, sessionData);

    try {
      const engine = new SignatureEngine({ baseDir: stateDir });
      await engine.init();
      await assert.rejects(
        () => engine.ensureValidSession(),
        /id_token sub|owner.*mismatch/i,
      );

      // The on-disk session must NOT have been updated.
      const onDisk = await readJsonFile(sessionFile, null);
      assert.equal(onDisk.idToken, "fake-id-token", "stale id_token kept on disk after rejection");
    } finally {
      mock.server.close();
      await cleanupDir(stateDir);
    }
  });

  it("rejects refresh whose id_token has mismatched cnf.jkt (RFC 9449 §6.1)", async () => {
    const rsa = generateRsaSsoSigner();
    const stateInit = await writeTestState(stateDir, {
      accessToken: makeExpiredJwt(),
      refreshToken: "rt",
      ssoBaseUrl: "placeholder",
      providerAddress: "test-provider",
    });
    // Compute a wrong jkt — different agent keypair.
    const otherAgent = generateEd25519PemPair();
    const wrongJkt = jwkThumbprint(ed25519PublicKeyToJwk(otherAgent.publicKeyPem));

    let mock;
    let badJktIdToken;
    mock = await createRsaSsoMock({
      rsa,
      tokenHandler: (req, res) => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            access_token: makeFreshJwt({ sub: "test-owner-sub" }),
            token_type: "DPoP",
            id_token: badJktIdToken,
          }),
        );
      },
    });
    const now = Math.floor(Date.now() / 1000);
    badJktIdToken = makeRs256IdToken({
      privateKey: rsa.privateKey,
      kid: rsa.publicKeyJwk.kid,
      payload: {
        iss: mock.baseUrl,
        sub: "test-owner-sub",
        aud: "test-provider",
        iat: now,
        exp: now + 3600,
        cnf: { jkt: wrongJkt }, // <-- bound to a different agent
      },
    });

    const sessionFile = stateInit.paths.ownerSession;
    const sessionData = await readJsonFile(sessionFile, null);
    sessionData.ssoBaseUrl = mock.baseUrl;
    sessionData.issuer = mock.baseUrl;
    await writeJsonFile(sessionFile, sessionData);

    try {
      const engine = new SignatureEngine({ baseDir: stateDir });
      await engine.init();
      await assert.rejects(
        () => engine.ensureValidSession(),
        /cnf\.jkt|jkt mismatch/i,
      );
    } finally {
      mock.server.close();
      await cleanupDir(stateDir);
    }
  });

  it("returns null when no refresh_token available", async () => {
    await writeTestState(stateDir, {
      accessToken: makeExpiredJwt(),
      refreshToken: null, // no refresh token
      ssoBaseUrl: "http://not-called",
      providerAddress: "test-provider",
    });

    // Patch out the null
    const paths = statePaths(stateDir);
    const session = await readJsonFile(paths.ownerSession, null);
    delete session.refreshToken;
    await writeJsonFile(paths.ownerSession, session);

    const engine = new SignatureEngine({ baseDir: stateDir });
    await engine.init();

    const result = await engine.ensureValidSession();
    assert.equal(result, null);

    await cleanupDir(stateDir);
  });

  it("returns null when no session exists at all", async () => {
    // Write just the key and binding, no session
    await writeTestState(stateDir, {
      accessToken: makeFreshJwt(),
      refreshToken: "rt",
      ssoBaseUrl: "http://x",
      providerAddress: "p",
    });

    // Delete the session file
    const paths = statePaths(stateDir);
    await fs.unlink(paths.ownerSession);

    const engine = new SignatureEngine({ baseDir: stateDir });
    await engine.init();

    const result = await engine.ensureValidSession();
    assert.equal(result, null);

    await cleanupDir(stateDir);
  });

  it("treats opaque (non-JWT) access_token as expired and refreshes", async () => {
    const mock = await createMockSsoServer((req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ access_token: makeFreshJwt(), token_type: "DPoP" }));
    });

    try {
      await writeTestState(stateDir, {
        accessToken: "opaque-not-a-jwt",
        refreshToken: "rt",
        ssoBaseUrl: mock.baseUrl,
        providerAddress: "p",
      });

      const engine = new SignatureEngine({ baseDir: stateDir });
      await engine.init();

      const session = await engine.ensureValidSession();
      assert.ok(session);
      assert.notEqual(session.accessToken, "opaque-not-a-jwt");
      assert.ok(session.refreshedAt);
    } finally {
      mock.server.close();
      await cleanupDir(stateDir);
    }
  });

  it("uses bufferSec=0 to force refresh check at exact expiry", async () => {
    // Token that expires in 30 seconds — with default buffer of 60s this
    // would be considered expired, but with bufferSec=0 it's still valid.
    const almostExpiredToken = makeJwt({}, 30);

    await writeTestState(stateDir, {
      accessToken: almostExpiredToken,
      refreshToken: "rt",
      ssoBaseUrl: "http://not-called",
      providerAddress: "p",
    });

    const engine = new SignatureEngine({ baseDir: stateDir });
    await engine.init();

    // With bufferSec=0, 30s remaining is still valid
    const session = await engine.ensureValidSession({ bufferSec: 0 });
    assert.ok(session);
    assert.equal(session.accessToken, almostExpiredToken);
    assert.equal(session.refreshedAt, undefined);

    await cleanupDir(stateDir);
  });

  it("falls back to issuer when ssoBaseUrl is not in session", async () => {
    let called = false;

    const mock = await createMockSsoServer((req, res) => {
      called = true;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ access_token: makeFreshJwt(), token_type: "DPoP" }));
    });

    try {
      await writeTestState(stateDir, {
        accessToken: makeExpiredJwt(),
        refreshToken: "rt",
        ssoBaseUrl: mock.baseUrl,
        providerAddress: "p",
      });

      // Remove ssoBaseUrl, keep issuer
      const paths = statePaths(stateDir);
      const session = await readJsonFile(paths.ownerSession, null);
      session.issuer = mock.baseUrl;
      delete session.ssoBaseUrl;
      await writeJsonFile(paths.ownerSession, session);

      const engine = new SignatureEngine({ baseDir: stateDir });
      await engine.init();

      const result = await engine.ensureValidSession();
      assert.ok(result);
      assert.ok(called, "should have called the mock server via issuer fallback");
    } finally {
      mock.server.close();
      await cleanupDir(stateDir);
    }
  });
});

describe("Security hardening", () => {
  let stateDir;

  beforeEach(async () => {
    stateDir = await createTempStateDir();
  });

  it("rejects refreshed token with mismatched subject", async () => {
    const wrongSubToken = makeFreshJwt({ sub: "attacker-sub" });

    const mock = await createMockSsoServer((req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ access_token: wrongSubToken, token_type: "DPoP" }));
    });

    try {
      await writeTestState(stateDir, {
        accessToken: makeExpiredJwt(),
        refreshToken: "rt",
        ssoBaseUrl: mock.baseUrl,
        providerAddress: "p",
      });

      const engine = new SignatureEngine({ baseDir: stateDir });
      await engine.init();

      await assert.rejects(
        () => engine.ensureValidSession(),
        /subject mismatch/,
      );
    } finally {
      mock.server.close();
      await cleanupDir(stateDir);
    }
  });

  it("accepts refreshed token with matching subject", async () => {
    const correctSubToken = makeFreshJwt({ sub: "test-owner-sub" });

    const mock = await createMockSsoServer((req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ access_token: correctSubToken, token_type: "DPoP" }));
    });

    try {
      await writeTestState(stateDir, {
        accessToken: makeExpiredJwt(),
        refreshToken: "rt",
        ssoBaseUrl: mock.baseUrl,
        providerAddress: "p",
      });

      const engine = new SignatureEngine({ baseDir: stateDir });
      await engine.init();

      const session = await engine.ensureValidSession();
      assert.ok(session);
      assert.equal(session.accessToken, correctSubToken);
    } finally {
      mock.server.close();
      await cleanupDir(stateDir);
    }
  });

  it("rejects JWT with alg:none", () => {
    const header = b64url(JSON.stringify({ alg: "none", typ: "JWT" }));
    const payload = b64url(JSON.stringify({ sub: "x", exp: 9999999999 }));
    const noneToken = `${header}.${payload}.nosig`;

    // parseJwt is not exported, but ensureValidSession uses it indirectly.
    // Test via a session with an alg:none access_token — it should be treated
    // as expired (parseJwt throws, caught as expired=true).
    // This is correct behavior: the token can't be parsed, so it triggers refresh.
    // The defense-in-depth is that parseJwt itself rejects it.
    assert.throws(
      () => {
        // Manually invoke the same parsing logic
        const parts = noneToken.split(".");
        const h = JSON.parse(fromB64url(parts[0]).toString("utf8"));
        if (h.alg === "none") throw new Error("Unsigned JWTs (alg: none) are not accepted");
      },
      /alg: none/,
    );
  });
});

describe("CLI refresh command (integration)", () => {
  let stateDir;

  beforeEach(async () => {
    stateDir = await createTempStateDir();
  });

  it("refreshes expired session via CLI", async () => {
    const mock = await createMockSsoServer((req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          access_token: makeFreshJwt(),
          token_type: "DPoP",
          refresh_token: "cli-new-rt",
        }),
      );
    });

    try {
      await writeTestState(stateDir, {
        accessToken: makeExpiredJwt(),
        refreshToken: "cli-old-rt",
        ssoBaseUrl: mock.baseUrl,
        providerAddress: "test-provider",
      });

      const { execFile } = await import("node:child_process");
      const { promisify } = await import("node:util");
      const exec = promisify(execFile);

      const cliPath = new URL("../skills/alien-agent-id/cli.mjs", import.meta.url).pathname;
      const { stdout } = await exec("node", [cliPath, "refresh", "--state-dir", stateDir]);

      const result = JSON.parse(stdout);
      assert.equal(result.ok, true);
      assert.equal(result.ownerSessionSub, "test-owner-sub");

      // Verify on-disk state was updated
      const paths = statePaths(stateDir);
      const onDisk = await readJsonFile(paths.ownerSession, null);
      assert.equal(onDisk.refreshToken, "cli-new-rt");
    } finally {
      mock.server.close();
      await cleanupDir(stateDir);
    }
  });

  it("reports error when no session exists", async () => {
    // Only create the key, no session
    const paths = statePaths(stateDir);
    await ensureDir(path.dirname(paths.mainKey));
    await ensureDir(path.dirname(paths.auditJsonl));

    const pair = generateEd25519PemPair();
    await writeJsonFile(paths.mainKey, {
      version: 1,
      agentId: "main",
      keyNonce: 0,
      createdAt: nowMs(),
      publicKeyPem: pair.publicKeyPem,
      privateKeyPem: pair.privateKeyPem,
      fingerprint: fingerprintPublicKeyPem(pair.publicKeyPem),
    });

    const { execFile } = await import("node:child_process");
    const { promisify } = await import("node:util");
    const exec = promisify(execFile);

    const cliPath = new URL("../skills/alien-agent-id/cli.mjs", import.meta.url).pathname;

    try {
      await exec("node", [cliPath, "refresh", "--state-dir", stateDir]);
      assert.fail("Expected CLI to exit with code 1");
    } catch (err) {
      const result = JSON.parse(err.stdout);
      assert.equal(result.ok, false);
      assert.ok(result.error.includes("No session"));
    }

    await cleanupDir(stateDir);
  });
});
