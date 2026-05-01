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
  ed25519PemToSshPublicKey,
  ed25519PemToOpenSSHPrivateKey,
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
 * Build a coherent proof-bundle fixture: agent key, id_token with the
 * caller-specified payload, and a binding whose `idTokenHash` and signature
 * actually match the minted id_token (so the chain verifier sees a clean
 * structure and the test can isolate the cnf.jkt check).
 *
 * Returns `{ repoDir, agent, agentFingerprint, ownerSub, binding, idToken }`.
 */
async function buildFixture({ ssoBaseUrl, rsa, idTokenPayload, idTokenCnfJkt, mismatchAgent = false }) {
  const repoDir = await makeTempGitRepo();

  const agent = generateEd25519PemPair();
  const agentFingerprint = fingerprintPublicKeyPem(agent.publicKeyPem);

  // Optionally use a different keypair for the binding's embedded public
  // key — exercised by tests that probe pre-step-3 detection.
  const bindingAgent = mismatchAgent ? generateEd25519PemPair() : agent;
  const bindingFingerprint = mismatchAgent
    ? fingerprintPublicKeyPem(bindingAgent.publicKeyPem)
    : agentFingerprint;

  const ownerSub = "0xowner-sub";
  const providerAddress = "0xprovider";

  // Mint the id_token. Default payload binds cnf.jkt to the agent key;
  // tests can override `idTokenPayload` for missing/mismatched-cnf cases.
  const defaultPayload = {
    iss: ssoBaseUrl,
    sub: ownerSub,
    aud: providerAddress,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    cnf: { jkt: idTokenCnfJkt ?? jwkThumbprint(ed25519PublicKeyToJwk(agent.publicKeyPem)) },
  };
  const idToken = makeRs256IdToken({
    privateKey: rsa.privateKey,
    kid: rsa.publicKeyJwk.kid,
    payload: idTokenPayload || defaultPayload,
  });
  const idTokenHash = sha256Hex(idToken);

  const bindingPayload = {
    version: 1,
    issuedAt: nowMs(),
    issuer: ssoBaseUrl,
    providerAddress,
    ownerSessionSub: ownerSub,
    ownerAudience: providerAddress,
    idTokenHash,
    ownerSessionProof: null,
    ownerSessionProofHash: null,
    agentInstance: {
      hostname: "test-host",
      publicKeyFingerprint: bindingFingerprint,
      publicKeyPem: bindingAgent.publicKeyPem,
    },
  };
  const canonical = canonicalJSONString(bindingPayload);
  const binding = {
    id: randomUUID(),
    payload: bindingPayload,
    payloadHash: sha256Hex(canonical),
    signature: signEd25519Base64Url(canonical, bindingAgent.privateKeyPem),
    createdAt: nowMs(),
  };

  return { repoDir, agent, agentFingerprint, ownerSub, binding, idToken };
}

async function attachProof({ repoDir, agent, ownerSub, binding, idToken, ssoBaseUrl, fingerprint, signCommit = false }) {
  // Empty commit with the Agent-ID trailers so cmdGitVerify can read them.
  const trailers = [
    `Agent-ID-Fingerprint: ${fingerprint}`,
    `Agent-ID-Owner: ${ownerSub}`,
    `Agent-ID-Binding: ${binding.id}`,
  ];
  const message = `test commit\n\n${trailers.join("\n")}`;

  // For tests that exercise the full chain (positive cases), SSH-sign the
  // commit with the agent's key. The verifier rebuilds the allowed-signers
  // file from `proof.agent.publicKeyPem` and runs `git verify-commit`.
  if (signCommit) {
    // Place the signing key inside repoDir so afterEach's cleanup removes it.
    const signKeyPath = path.join(repoDir, ".agent-id-test-key");
    const opensshPriv = ed25519PemToOpenSSHPrivateKey(agent.privateKeyPem);
    await fs.writeFile(signKeyPath, opensshPriv, { mode: 0o600 });
    await exec("git", ["-C", repoDir, "config", "user.signingkey", signKeyPath]);
    await exec("git", ["-C", repoDir, "config", "gpg.format", "ssh"]);
    await exec("git", ["-C", repoDir, "commit", "--allow-empty", "-S", "-m", message]);
  } else {
    await exec("git", ["-C", repoDir, "commit", "--allow-empty", "-m", message]);
  }

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

    // id_token WITHOUT cnf — the binding inside buildFixture will record
    // sha256(this token), so the chain reaches the cnf check legitimately.
    const fixture = await buildFixture({
      ssoBaseUrl: mock.baseUrl,
      rsa,
      idTokenPayload: {
        iss: mock.baseUrl,
        sub: "0xowner-sub",
        aud: "0xprovider",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
      },
    });
    repoDir = fixture.repoDir;

    const commitHash = await attachProof({
      repoDir,
      agent: fixture.agent,
      ownerSub: fixture.ownerSub,
      binding: fixture.binding,
      idToken: fixture.idToken,
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

    // cnf.jkt that points to a DIFFERENT key than the agent's.
    const otherAgent = generateEd25519PemPair();
    const wrongJkt = jwkThumbprint(ed25519PublicKeyToJwk(otherAgent.publicKeyPem));

    const fixture = await buildFixture({
      ssoBaseUrl: mock.baseUrl,
      rsa,
      idTokenCnfJkt: wrongJkt,
    });
    repoDir = fixture.repoDir;

    const commitHash = await attachProof({
      repoDir,
      agent: fixture.agent,
      ownerSub: fixture.ownerSub,
      binding: fixture.binding,
      idToken: fixture.idToken,
      ssoBaseUrl: mock.baseUrl,
      fingerprint: fixture.agentFingerprint,
    });

    const out = await runGitVerify({ repoDir, commitHash, stateDir });
    assert.notEqual(out.exitCode, 0);
    const parsed = JSON.parse(out.stdout);
    assert.equal(parsed.ok, false);
    assert.match(parsed.error || "", /id_token cnf\.jkt mismatch/);
  });

  it("accepts a fully valid chain (cnf.jkt matches, commit SSH-signed by agent)", async () => {
    const rsa = generateRsaKeyPair();
    mock = await startSsoMock({ jwk: rsa.publicKeyJwk });

    const fixture = await buildFixture({ ssoBaseUrl: mock.baseUrl, rsa });
    repoDir = fixture.repoDir;

    const commitHash = await attachProof({
      repoDir,
      agent: fixture.agent,
      ownerSub: fixture.ownerSub,
      binding: fixture.binding,
      idToken: fixture.idToken,
      ssoBaseUrl: mock.baseUrl,
      fingerprint: fixture.agentFingerprint,
      signCommit: true,
    });

    const out = await runGitVerify({ repoDir, commitHash, stateDir });
    assert.equal(out.exitCode, 0, `expected ok exit, got ${out.exitCode}: ${out.stderr}`);
    const parsed = JSON.parse(out.stdout);
    assert.equal(parsed.ok, true);
    assert.equal(parsed.agentFingerprint, fixture.agentFingerprint);
    assert.equal(parsed.ownerSessionSub, fixture.ownerSub);
    assert.equal(
      parsed.jkt,
      jwkThumbprint(ed25519PublicKeyToJwk(fixture.agent.publicKeyPem)),
    );
    assert.equal(parsed.error, undefined);
  });

  it("rejects when binding signed by a different key than proof.agent.publicKeyPem", async () => {
    // Substitution forgery: binding's embedded key + signature are by
    // K_victim, but the proof bundle claims K_attacker as agent.publicKeyPem.
    // The chain verifier must refuse at step 3 (binding signature anchored
    // to proof.agent.publicKeyPem, NOT the binding's self-embedded key).
    const rsa = generateRsaKeyPair();
    mock = await startSsoMock({ jwk: rsa.publicKeyJwk });

    const fixture = await buildFixture({
      ssoBaseUrl: mock.baseUrl,
      rsa,
      mismatchAgent: true, // binding signed by a different keypair
    });
    repoDir = fixture.repoDir;

    const commitHash = await attachProof({
      repoDir,
      agent: fixture.agent,
      ownerSub: fixture.ownerSub,
      binding: fixture.binding,
      idToken: fixture.idToken,
      ssoBaseUrl: mock.baseUrl,
      fingerprint: fixture.agentFingerprint,
    });

    const out = await runGitVerify({ repoDir, commitHash, stateDir });
    assert.notEqual(out.exitCode, 0);
    const parsed = JSON.parse(out.stdout);
    assert.equal(parsed.ok, false);
    assert.match(
      parsed.error || "",
      /ownerBinding signature does not verify with proof\.agent\.publicKeyPem/,
    );
  });
});
