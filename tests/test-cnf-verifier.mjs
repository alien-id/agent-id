#!/usr/bin/env node

// Tests for the cnf.jkt binding check in `git-verify`.
//
// The SSO server stamps an RFC 7800 `cnf` claim on each id_token whose `jkt`
// member is the RFC 7638 thumbprint of the agent's Ed25519 public key. The
// verifier MUST refuse any proof bundle whose id_token is missing `cnf.jkt`
// or whose `cnf.jkt` does not match the binding's agent key — a hard cutover,
// no flag can disable the check.
//
// Run: node --test tests/test-cnf-verifier.mjs

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import crypto, {
  generateKeyPairSync,
  randomUUID,
  sign as cryptoSign,
} from "node:crypto";
import { execFile as execFileCb } from "node:child_process";
import { promisify } from "node:util";

import {
  generateEd25519PemPair,
  fingerprintPublicKeyPem,
  ed25519PublicKeyToJwk,
  jwkThumbprint,
  canonicalJSONString,
  sha256Hex,
  signEd25519Base64Url,
  b64url,
  nowMs,
} from "../skills/alien-agent-id/lib.mjs";

const exec = promisify(execFileCb);
const CLI_PATH = new URL("../skills/alien-agent-id/cli.mjs", import.meta.url).pathname;

// ─── Fixture helpers ─────────────────────────────────────────────────────────────

function generateRsaKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  return {
    publicKeyJwk: { ...publicKey.export({ format: "jwk" }), use: "sig", alg: "RS256", kid: "test-sso-kid" },
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

async function makeTempGitRepo() {
  const dir = path.join(os.tmpdir(), `agent-id-cnf-test-${randomUUID()}`);
  await fs.mkdir(dir, { recursive: true });
  await exec("git", ["init", "-q", "-b", "main", dir]);
  await exec("git", ["-C", dir, "config", "user.email", "test@example.com"]);
  await exec("git", ["-C", dir, "config", "user.name", "test"]);
  await exec("git", ["-C", dir, "config", "commit.gpgsign", "false"]);
  return dir;
}

async function cleanup(dir) {
  await fs.rm(dir, { recursive: true, force: true }).catch(() => {});
}

/**
 * Build a synthetic proof bundle and attach it as a git note on a fresh
 * commit, so cmdGitVerify reads the bundle from `refs/notes/agent-id`.
 *
 * Returns `{ repoDir, commitHash }`.
 */
async function buildFixture({ ssoBaseUrl, idTokenCnfJkt, mismatchAgent = false }) {
  const repoDir = await makeTempGitRepo();

  // Agent keypair.
  const agent = generateEd25519PemPair();
  const agentFingerprint = fingerprintPublicKeyPem(agent.publicKeyPem);

  // Optionally use a different keypair for the binding's embedded public key,
  // so the trailer fingerprint mismatches — but the `cnf.jkt` mismatch is
  // tested by varying `idTokenCnfJkt` directly.
  const bindingAgent = mismatchAgent ? generateEd25519PemPair() : agent;
  const bindingFingerprint = mismatchAgent
    ? fingerprintPublicKeyPem(bindingAgent.publicKeyPem)
    : agentFingerprint;

  const ownerSub = "0xowner-sub";
  const providerAddress = "0xprovider";

  const bindingPayload = {
    version: 1,
    issuedAt: nowMs(),
    issuer: ssoBaseUrl,
    providerAddress,
    ownerSessionSub: ownerSub,
    ownerAudience: providerAddress,
    idTokenHash: null, // filled in once we mint the id_token below
    ownerSessionProof: null,
    ownerSessionProofHash: null,
    agentInstance: {
      hostname: "test-host",
      publicKeyFingerprint: bindingFingerprint,
      publicKeyPem: bindingAgent.publicKeyPem,
    },
  };

  // For the AC, we just need cmdGitVerify to read the bundle and reach the
  // cnf check; the binding signature itself doesn't need to match the
  // id_token hash — any mismatch would only surface as a warning.
  bindingPayload.idTokenHash = sha256Hex("placeholder-replaced-below");
  const canonical = canonicalJSONString(bindingPayload);
  const binding = {
    id: randomUUID(),
    payload: bindingPayload,
    payloadHash: sha256Hex(canonical),
    signature: signEd25519Base64Url(canonical, bindingAgent.privateKeyPem),
    createdAt: nowMs(),
  };

  return { repoDir, agent, agentFingerprint, ownerSub, binding };
}

async function attachProof({ repoDir, agent, ownerSub, binding, idToken, ssoBaseUrl, fingerprint }) {
  // Empty commit with the Agent-ID trailers so cmdGitVerify can read them.
  const trailers = [
    `Agent-ID-Fingerprint: ${fingerprint}`,
    `Agent-ID-Owner: ${ownerSub}`,
    `Agent-ID-Binding: ${binding.id}`,
  ];
  const message = `test commit\n\n${trailers.join("\n")}`;
  await exec("git", ["-C", repoDir, "commit", "--allow-empty", "-m", message]);
  const { stdout } = await exec("git", ["-C", repoDir, "rev-parse", "HEAD"]);
  const commitHash = stdout.trim();

  const proofBundle = {
    version: 2,
    agent: {
      fingerprint,
      publicKeyPem: agent.publicKeyPem,
    },
    ownerBinding: binding,
    idToken: idToken ? Buffer.from(idToken).toString("base64url") : null,
    ssoBaseUrl,
  };
  await exec(
    "git",
    [
      "-C",
      repoDir,
      "notes",
      "--ref=agent-id",
      "add",
      "-f",
      "-m",
      JSON.stringify(proofBundle),
      commitHash,
    ],
  );
  return commitHash;
}

async function runGitVerify({ repoDir, commitHash, stateDir }) {
  // cmdGitVerify uses outputError → exitCode=1 instead of throwing. Spawn the
  // CLI as a child so we observe the real exit code AND stdout JSON.
  try {
    const { stdout, stderr } = await exec(
      "node",
      [
        CLI_PATH,
        "git-verify",
        "--commit",
        commitHash,
        "--state-dir",
        stateDir,
      ],
      { cwd: repoDir },
    );
    return { exitCode: 0, stdout, stderr };
  } catch (err) {
    return {
      exitCode: err.code ?? 1,
      stdout: err.stdout ?? "",
      stderr: err.stderr ?? "",
    };
  }
}

// ─── Tests ───────────────────────────────────────────────────────────────────────

describe("git-verify cnf.jkt binding check", () => {
  let mock = null;
  let stateDir = null;
  let repoDir = null;

  beforeEach(async () => {
    stateDir = path.join(os.tmpdir(), `agent-id-cnf-state-${randomUUID()}`);
    await fs.mkdir(stateDir, { recursive: true });
  });

  afterEach(async () => {
    if (mock) {
      mock.server.close();
      mock = null;
    }
    if (repoDir) {
      await cleanup(repoDir);
      repoDir = null;
    }
    if (stateDir) {
      await cleanup(stateDir);
      stateDir = null;
    }
  });

  it("rejects an id_token without cnf.jkt", async () => {
    const rsa = generateRsaKeyPair();
    mock = await startSsoMock({ jwk: rsa.publicKeyJwk });

    const fixture = await buildFixture({ ssoBaseUrl: mock.baseUrl });
    repoDir = fixture.repoDir;

    // Synthetic id_token WITHOUT cnf.
    const idToken = makeRs256IdToken({
      privateKey: rsa.privateKey,
      kid: rsa.publicKeyJwk.kid,
      payload: {
        iss: mock.baseUrl,
        sub: fixture.ownerSub,
        aud: "0xprovider",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
      },
    });

    const commitHash = await attachProof({
      repoDir,
      agent: fixture.agent,
      ownerSub: fixture.ownerSub,
      binding: fixture.binding,
      idToken,
      ssoBaseUrl: mock.baseUrl,
      fingerprint: fixture.agentFingerprint,
    });

    const out = await runGitVerify({ repoDir, commitHash, stateDir });
    assert.notEqual(out.exitCode, 0, "verify should exit non-zero");
    const parsed = JSON.parse(out.stdout);
    assert.equal(parsed.ok, false);
    assert.match(parsed.error || "", /id_token missing cnf\.jkt/);
  });

  it("rejects an id_token with mismatched cnf.jkt", async () => {
    const rsa = generateRsaKeyPair();
    mock = await startSsoMock({ jwk: rsa.publicKeyJwk });

    const fixture = await buildFixture({ ssoBaseUrl: mock.baseUrl });
    repoDir = fixture.repoDir;

    // cnf.jkt that points to a DIFFERENT key than the agent's.
    const otherAgent = generateEd25519PemPair();
    const wrongJkt = jwkThumbprint(ed25519PublicKeyToJwk(otherAgent.publicKeyPem));

    const idToken = makeRs256IdToken({
      privateKey: rsa.privateKey,
      kid: rsa.publicKeyJwk.kid,
      payload: {
        iss: mock.baseUrl,
        sub: fixture.ownerSub,
        aud: "0xprovider",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        cnf: { jkt: wrongJkt },
      },
    });

    const commitHash = await attachProof({
      repoDir,
      agent: fixture.agent,
      ownerSub: fixture.ownerSub,
      binding: fixture.binding,
      idToken,
      ssoBaseUrl: mock.baseUrl,
      fingerprint: fixture.agentFingerprint,
    });

    const out = await runGitVerify({ repoDir, commitHash, stateDir });
    assert.notEqual(out.exitCode, 0);
    const parsed = JSON.parse(out.stdout);
    assert.equal(parsed.ok, false);
    assert.match(parsed.error || "", /id_token cnf\.jkt mismatch/);
  });

  it("accepts an id_token with matching cnf.jkt", async () => {
    const rsa = generateRsaKeyPair();
    mock = await startSsoMock({ jwk: rsa.publicKeyJwk });

    const fixture = await buildFixture({ ssoBaseUrl: mock.baseUrl });
    repoDir = fixture.repoDir;

    const expectedJkt = jwkThumbprint(ed25519PublicKeyToJwk(fixture.agent.publicKeyPem));

    const idToken = makeRs256IdToken({
      privateKey: rsa.privateKey,
      kid: rsa.publicKeyJwk.kid,
      payload: {
        iss: mock.baseUrl,
        sub: fixture.ownerSub,
        aud: "0xprovider",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        cnf: { jkt: expectedJkt },
      },
    });

    const commitHash = await attachProof({
      repoDir,
      agent: fixture.agent,
      ownerSub: fixture.ownerSub,
      binding: fixture.binding,
      idToken,
      ssoBaseUrl: mock.baseUrl,
      fingerprint: fixture.agentFingerprint,
    });

    const out = await runGitVerify({ repoDir, commitHash, stateDir });
    // The unsigned commit means sshSignatureValid=false → result.ok will be
    // false. The AC for the positive case is that the cnf check passes —
    // ssoSignatureValid=true, no `error` field set, and no warning or error
    // mentions cnf.jkt. (The provenance line that confirms a valid cnf.jkt
    // binding is allowed to mention it.)
    const parsed = JSON.parse(out.stdout);
    assert.equal(parsed.ssoSignatureValid, true);
    assert.equal(parsed.error, undefined, `unexpected error: ${parsed.error}`);
    for (const w of parsed.warnings || []) {
      assert.doesNotMatch(w, /cnf\.jkt/);
    }
    // The provenance MUST include a line confirming the cnf.jkt binding.
    assert.ok(
      (parsed.provenance || []).some((p) => /cnf\.jkt/.test(p)),
      "expected a provenance entry confirming cnf.jkt binding",
    );
  });
});
