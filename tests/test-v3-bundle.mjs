#!/usr/bin/env node

// Tests for the v3 commit-attestation bundle (RFC 9449 cutover follow-up).
//
// The v3 bundle replaces the agent-self-signed `ownerBinding` envelope with
// the SSO-signed id_token directly. Bundle shape:
//
//   { version: 3, id_token: <base64url JWS>, agent_jwk: <OKP/Ed25519 JWK> }
//
// Verification walks: id_token JWS signature against SSO JWKS → claim checks
// (iss, sub matches Agent-ID-Owner trailer, cnf.jkt present) → agent_jwk
// thumbprint binding (cnf.jkt == jwkThumbprint(agent_jwk) == Agent-ID-JKT
// trailer) → SSH commit signature against agent_jwk.
//
// No pre-DPoP backward compat: v1/v2 bundles are unsupported by design.
//
// Run: node --test tests/test-v3-bundle.mjs

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  generateKeyPairSync,
  randomUUID,
  sign as cryptoSign,
} from "node:crypto";
import { execFile as execFileCb } from "node:child_process";
import { promisify } from "node:util";

import {
  b64url,
  ed25519PemToOpenSSHPrivateKey,
  ed25519PublicKeyToJwk,
  generateEd25519PemPair,
  jwkThumbprint,
} from "../plugins/agent-id-core/lib/crypto.mjs";
import {
  ensureDir,
  writeJsonFile,
} from "../plugins/agent-id-core/lib/state.mjs";

const HERMETIC_GIT_ENV = {
  ...process.env,
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_SYSTEM: "/dev/null",
};
const execRaw = promisify(execFileCb);
const exec = (file, args, opts = {}) =>
  execRaw(file, args, { ...opts, env: { ...HERMETIC_GIT_ENV, ...(opts.env || {}) } });
const CLI_PATH = new URL("../plugins/agent-id-git/bin/cli.mjs", import.meta.url).pathname;

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

function startSsoMock({ jwk }) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      if (req.url === "/.well-known/openid-configuration") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            issuer: `http://127.0.0.1:${server.address().port}`,
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
  const dir = path.join(os.tmpdir(), `agent-id-v3-test-${randomUUID()}`);
  await fs.mkdir(dir, { recursive: true });
  await exec("git", ["init", "-q", "-b", "main", dir]);
  await exec("git", ["-C", dir, "config", "user.email", "test@example.com"]);
  await exec("git", ["-C", dir, "config", "user.name", "test"]);
  await exec("git", ["-C", dir, "config", "commit.gpgsign", "false"]);
  return dir;
}

async function makeStateDir() {
  return path.join(os.tmpdir(), `agent-id-v3-state-${randomUUID()}`);
}

async function cleanup(dir) {
  if (!dir) return;
  await fs.rm(dir, { recursive: true, force: true }).catch(() => {});
}

/**
 * Set up agent state under `stateDir`: keypair (main.json) + ownerSession
 * with a valid id_token that pins cnf.jkt to the agent key. The emit side
 * reads these; the verify side fetches JWKS from `ssoBaseUrl`.
 */
async function buildAgentState({ stateDir, ssoBaseUrl, ownerSub, rsa, providerAddress }) {
  const agent = generateEd25519PemPair();
  const agentJwk = ed25519PublicKeyToJwk(agent.publicKeyPem);
  const agentJkt = jwkThumbprint(agentJwk);

  await ensureDir(stateDir);
  await ensureDir(path.join(stateDir, "keys"));

  await writeJsonFile(path.join(stateDir, "keys", "main.json"), {
    version: 1,
    agentId: "main",
    keyNonce: 0,
    createdAt: Date.now(),
    publicKeyPem: agent.publicKeyPem,
    privateKeyPem: agent.privateKeyPem,
    fingerprint: jwkThumbprint(agentJwk), // post-v3 we anchor on jkt; fingerprint field retained for compat
  });

  const idToken = makeRs256IdToken({
    privateKey: rsa.privateKey,
    kid: rsa.publicKeyJwk.kid,
    payload: {
      iss: ssoBaseUrl,
      sub: ownerSub,
      aud: providerAddress,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      jti: randomUUID(),
      cnf: { jkt: agentJkt },
    },
  });

  await writeJsonFile(path.join(stateDir, "owner-session.json"), {
    version: 1,
    issuer: ssoBaseUrl,
    ssoBaseUrl,
    providerAddress,
    ownerSessionSub: ownerSub,
    idToken,
    accessToken: idToken,
    refreshToken: null,
    savedAt: Date.now(),
  });

  return { agent, agentJwk, agentJkt, idToken };
}

async function runCli(args, opts = {}) {
  const { stdout = "", stderr: errOut = "", code } = await execRaw(
    "node",
    [CLI_PATH, ...args],
    { env: { ...HERMETIC_GIT_ENV, ...(opts.env || {}) }, cwd: opts.cwd },
  ).catch((err) => ({
    stdout: err.stdout || "",
    stderr: err.stderr || "",
    code: typeof err.code === "number" ? err.code : 1,
  }));
  let parsed = null;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    // ignore — caller inspects raw fields
  }
  return { stdout, stderr: errOut, code: typeof code === "number" ? code : 0, parsed };
}

// ─── Tracer bullet: emit → verify round trip ─────────────────────────────────────

describe("v3 bundle emit → verify round trip", () => {
  let sso;
  let rsa;
  let repoDir;
  let stateDir;

  beforeEach(async () => {
    rsa = generateRsaKeyPair();
    sso = await startSsoMock({ jwk: rsa.publicKeyJwk });
    repoDir = await makeTempGitRepo();
    stateDir = await makeStateDir();
  });

  afterEach(async () => {
    sso?.server?.close();
    await cleanup(repoDir);
    await cleanup(stateDir);
  });

  /**
   * Re-emit the just-attached v3 bundle with a tampered field. Returns the
   * commit hash so the caller can run git-verify against it.
   */
  async function tamperGitNote(commitHash, mutate) {
    const { stdout: noteRaw } = await exec(
      "git", ["-C", repoDir, "notes", "--ref=agent-id", "show", commitHash],
    );
    const bundle = JSON.parse(noteRaw.trim());
    const mutated = mutate(bundle);
    await exec(
      "git",
      [
        "-C", repoDir,
        "notes", "--ref=agent-id",
        "add", "-f", "-m", JSON.stringify(mutated), commitHash,
      ],
    );
  }

  it("git-commit emits a v3 bundle that git-verify accepts", async () => {
    const ownerSub = "0xowner-tracer";
    const providerAddress = "0xprovider-tracer";
    const { agentJkt } = await buildAgentState({
      stateDir,
      ssoBaseUrl: sso.baseUrl,
      ownerSub,
      rsa,
      providerAddress,
    });

    // Emit a v3 commit.
    const commit = await runCli(
      ["commit", "--state-dir", stateDir, "--message", "tracer bullet", "--allow-empty"],
      { cwd: repoDir },
    );
    assert.equal(
      commit.code,
      0,
      `git-commit failed: stdout=${commit.stdout} stderr=${commit.stderr}`,
    );
    assert.equal(commit.parsed?.ok, true);
    assert.equal(commit.parsed?.proofAttached, true);

    // Trailers and bundle should be v3 shape.
    const { stdout: commitMsg } = await exec(
      "git", ["-C", repoDir, "log", "-1", "--format=%B"],
    );
    assert.match(commitMsg, new RegExp(`^Agent-ID-JKT: ${agentJkt}$`, "m"));
    assert.match(commitMsg, new RegExp(`^Agent-ID-Owner: ${ownerSub}$`, "m"));
    assert.doesNotMatch(commitMsg, /^Agent-ID-Fingerprint:/m);
    assert.doesNotMatch(commitMsg, /^Agent-ID-Binding:/m);

    const { stdout: noteRaw } = await exec(
      "git", ["-C", repoDir, "notes", "--ref=agent-id", "show", "HEAD"],
    );
    const bundle = JSON.parse(noteRaw.trim());
    assert.equal(bundle.version, 3);
    assert.equal(typeof bundle.id_token, "string");
    assert.equal(bundle.agent_jwk?.kty, "OKP");
    assert.equal(bundle.agent_jwk?.crv, "Ed25519");
    assert.equal(jwkThumbprint(bundle.agent_jwk), agentJkt);
    assert.equal(bundle.ownerBinding, undefined);
    assert.equal(bundle.agent, undefined);

    // Verify accepts the bundle.
    const verify = await runCli(
      [
        "verify",
        "--state-dir", stateDir,
        "--commit", "HEAD",
        "--sso-url", sso.baseUrl,
      ],
      { cwd: repoDir },
    );
    assert.equal(verify.code, 0, `git-verify failed: ${verify.stderr || verify.stdout}`);
    assert.equal(verify.parsed?.ok, true);
    assert.equal(verify.parsed?.jkt, agentJkt);
    assert.equal(verify.parsed?.ownerSub, ownerSub);
    assert.equal(verify.parsed?.issuer, sso.baseUrl);
  });

  it("git-verify rejects when id_token has no cnf.jkt", async () => {
    const ownerSub = "0xowner-no-cnf";
    const providerAddress = "0xprovider";
    const { agentJwk, agentJkt } = await buildAgentState({
      stateDir, ssoBaseUrl: sso.baseUrl, ownerSub, rsa, providerAddress,
    });

    const commit = await runCli(
      ["commit", "--state-dir", stateDir, "--message", "no-cnf", "--allow-empty"],
      { cwd: repoDir },
    );
    assert.equal(commit.code, 0);

    // Re-mint an id_token WITHOUT cnf.jkt and swap it into the bundle.
    const idTokenNoCnf = makeRs256IdToken({
      privateKey: rsa.privateKey,
      kid: rsa.publicKeyJwk.kid,
      payload: {
        iss: sso.baseUrl, sub: ownerSub, aud: providerAddress,
        iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600,
        jti: randomUUID(),
        // no cnf
      },
    });
    await tamperGitNote(commit.parsed.commitHash, (b) => ({
      ...b,
      id_token: Buffer.from(idTokenNoCnf).toString("base64url"),
      agent_jwk: agentJwk,
    }));

    const verify = await runCli(
      ["verify", "--commit", commit.parsed.commitHash, "--sso-url", sso.baseUrl],
      { cwd: repoDir },
    );
    assert.equal(verify.code, 1);
    assert.equal(verify.parsed?.ok, false);
    assert.match(verify.parsed?.error || "", /cnf\.jkt/);
    // Sanity: the agent JKT was valid, the rejection isn't a side effect of thumbprint mismatch.
    assert.equal(jwkThumbprint(agentJwk), agentJkt);
  });

  it("git-verify rejects pre-v3 (v2) bundles — no backward compat", async () => {
    const ownerSub = "0xowner-v2-rejected";
    await buildAgentState({
      stateDir, ssoBaseUrl: sso.baseUrl, ownerSub, rsa, providerAddress: "0xprovider",
    });

    const commit = await runCli(
      ["commit", "--state-dir", stateDir, "--message", "v2-reject", "--allow-empty"],
      { cwd: repoDir },
    );
    assert.equal(commit.code, 0);

    // Replace v3 bundle with a v2-shaped bundle (legacy ownerBinding envelope).
    await tamperGitNote(commit.parsed.commitHash, () => ({
      version: 2,
      agent: { fingerprint: "deadbeef", publicKeyPem: "stub" },
      ownerBinding: { id: "legacy", payload: {}, payloadHash: "h", signature: "s" },
      idToken: "stub",
      ssoBaseUrl: sso.baseUrl,
    }));

    const verify = await runCli(
      ["verify", "--commit", commit.parsed.commitHash, "--sso-url", sso.baseUrl],
      { cwd: repoDir },
    );
    assert.equal(verify.code, 1);
    assert.equal(verify.parsed?.ok, false);
    assert.match(verify.parsed?.error || "", /version|only v3/i);
  });

  it("git-verify rejects when agent_jwk thumbprint != id_token cnf.jkt", async () => {
    const ownerSub = "0xowner-jkt-mismatch";
    const providerAddress = "0xprovider";
    await buildAgentState({
      stateDir, ssoBaseUrl: sso.baseUrl, ownerSub, rsa, providerAddress,
    });

    const commit = await runCli(
      ["commit", "--state-dir", stateDir, "--message", "jkt-mismatch", "--allow-empty"],
      { cwd: repoDir },
    );
    assert.equal(commit.code, 0);

    // Replace agent_jwk with a different key — its thumbprint will no longer
    // match cnf.jkt on the id_token, so the chain anchor breaks.
    const otherAgent = generateEd25519PemPair();
    const otherJwk = ed25519PublicKeyToJwk(otherAgent.publicKeyPem);
    await tamperGitNote(commit.parsed.commitHash, (b) => ({ ...b, agent_jwk: otherJwk }));

    const verify = await runCli(
      ["verify", "--commit", commit.parsed.commitHash, "--sso-url", sso.baseUrl],
      { cwd: repoDir },
    );
    assert.equal(verify.code, 1);
    assert.equal(verify.parsed?.ok, false);
    assert.match(verify.parsed?.error || "", /does not match id_token cnf\.jkt/);
  });

  it("git-verify rejects when Agent-ID-JKT trailer doesn't match the bundle's agent_jwk", async () => {
    const ownerSub = "0xowner-trailer-mismatch";
    await buildAgentState({
      stateDir, ssoBaseUrl: sso.baseUrl, ownerSub, rsa, providerAddress: "0xprovider",
    });

    const commit = await runCli(
      ["commit", "--state-dir", stateDir, "--message", "trailer-mismatch", "--allow-empty"],
      { cwd: repoDir },
    );
    assert.equal(commit.code, 0);

    // Amend the commit to lie about the JKT in its trailer. The bundle still
    // has the original agent_jwk and the id_token's cnf.jkt still matches it,
    // but the trailer now claims a different key — the verifier's last anchor
    // check (trailer == bundle thumbprint) must catch this.
    const { stdout: msg } = await exec("git", ["-C", repoDir, "log", "-1", "--format=%B"]);
    const fakeJkt = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbe";
    const newMsg = msg.replace(/^Agent-ID-JKT: .*$/m, `Agent-ID-JKT: ${fakeJkt}`);
    await exec("git", ["-C", repoDir, "commit", "--amend", "--allow-empty", "-m", newMsg, "--no-verify"]);
    const { stdout: newHash } = await exec("git", ["-C", repoDir, "rev-parse", "HEAD"]);

    // Re-attach the original (valid) bundle to the new SHA.
    const { stdout: noteRaw } = await exec(
      "git", ["-C", repoDir, "notes", "--ref=agent-id", "show", commit.parsed.commitHash],
    ).catch(() => ({ stdout: "" }));
    // amend may not preserve notes — read from old hash; if missing, skip the assertion path
    if (!noteRaw.trim()) {
      // graceful skip: amend wiped the note. Re-emit by running git-commit on the amended hash
      // would re-attach; but here we'd just rebuild manually. Instead assert reject-path on
      // the amended commit using a fresh bundle pointing at the original agent key.
      const stateMain = JSON.parse(
        await fs.readFile(path.join(stateDir, "keys", "main.json"), "utf8"),
      );
      const realJwk = ed25519PublicKeyToJwk(stateMain.publicKeyPem);
      const sessionJson = JSON.parse(
        await fs.readFile(path.join(stateDir, "owner-session.json"), "utf8"),
      );
      const freshBundle = {
        version: 3,
        id_token: Buffer.from(sessionJson.idToken).toString("base64url"),
        agent_jwk: realJwk,
      };
      await exec(
        "git",
        [
          "-C", repoDir,
          "notes", "--ref=agent-id",
          "add", "-f", "-m", JSON.stringify(freshBundle), newHash.trim(),
        ],
      );
    } else {
      await exec(
        "git",
        [
          "-C", repoDir,
          "notes", "--ref=agent-id",
          "add", "-f", "-m", noteRaw.trim(), newHash.trim(),
        ],
      );
    }

    const verify = await runCli(
      ["verify", "--commit", newHash.trim(), "--sso-url", sso.baseUrl],
      { cwd: repoDir },
    );
    assert.equal(verify.code, 1);
    assert.equal(verify.parsed?.ok, false);
    assert.match(verify.parsed?.error || "", /Agent-ID-JKT trailer/);
  });
});

// ─── Level 0 (self-asserted): commit + verify with NO owner binding ──────────────

describe("level-0 self-asserted commit → verify (no SSO)", () => {
  let repoDir;
  let stateDir;

  beforeEach(async () => {
    repoDir = await makeTempGitRepo();
    stateDir = await makeStateDir();
  });

  afterEach(async () => {
    await cleanup(repoDir);
    await cleanup(stateDir);
  });

  // Write ONLY the agent key — no owner-session.json. This is a fresh agent
  // straight out of `init`, before any binding.
  async function buildUnboundAgent() {
    const agent = generateEd25519PemPair();
    const agentJwk = ed25519PublicKeyToJwk(agent.publicKeyPem);
    const agentJkt = jwkThumbprint(agentJwk);
    await ensureDir(path.join(stateDir, "keys"));
    await writeJsonFile(path.join(stateDir, "keys", "main.json"), {
      version: 1,
      agentId: "main",
      keyNonce: 0,
      createdAt: Date.now(),
      publicKeyPem: agent.publicKeyPem,
      privateKeyPem: agent.privateKeyPem,
      fingerprint: agentJkt,
    });
    return { agentJkt };
  }

  it("commits at level 0 (JKT trailer, no Owner) and verify accepts it as L0", async () => {
    const { agentJkt } = await buildUnboundAgent();

    const commit = await runCli(
      ["commit", "--state-dir", stateDir, "--message", "fresh agent", "--allow-empty"],
      { cwd: repoDir },
    );
    assert.equal(commit.code, 0, `commit failed: ${commit.stderr || commit.stdout}`);
    assert.equal(commit.parsed?.ok, true);
    assert.equal(commit.parsed?.level, 0);
    assert.equal(commit.parsed?.assurance, "self-asserted");
    assert.equal(commit.parsed?.ownerSub, null);
    assert.equal(commit.parsed?.proofAttached, true);

    // JKT trailer present, Owner trailer ABSENT.
    const { stdout: commitMsg } = await exec("git", ["-C", repoDir, "log", "-1", "--format=%B"]);
    assert.match(commitMsg, new RegExp(`^Agent-ID-JKT: ${agentJkt}$`, "m"));
    assert.doesNotMatch(commitMsg, /^Agent-ID-Owner:/m);

    // The attached bundle is the L0 shape: agent_jwk, no id_token.
    const { stdout: noteRaw } = await exec(
      "git", ["-C", repoDir, "notes", "--ref=agent-id", "show", "HEAD"],
    );
    const bundle = JSON.parse(noteRaw.trim());
    assert.equal(bundle.version, 3);
    assert.equal(bundle.id_token, undefined);
    assert.equal(jwkThumbprint(bundle.agent_jwk), agentJkt);

    // Verify accepts it as level 0 — no --sso-url needed.
    const verify = await runCli(
      ["verify", "--state-dir", stateDir, "--commit", "HEAD"],
      { cwd: repoDir },
    );
    assert.equal(verify.code, 0, `verify failed: ${verify.stderr || verify.stdout}`);
    assert.equal(verify.parsed?.ok, true);
    assert.equal(verify.parsed?.level, 0);
    assert.equal(verify.parsed?.assurance, "self-asserted");
    assert.equal(verify.parsed?.ownerSub, null);
    assert.equal(verify.parsed?.jkt, agentJkt);
  });

  it("rejects a forged Agent-ID-Owner trailer on an L0 commit", async () => {
    const { agentJkt } = await buildUnboundAgent();
    // A clean L0 commit, to grab a genuine L0 bundle note (agent_jwk, no token).
    await runCli(
      ["commit", "--state-dir", stateDir, "--message", "fresh", "--allow-empty"],
      { cwd: repoDir },
    );
    const { stdout: noteRaw } = await exec(
      "git", ["-C", repoDir, "notes", "--ref=agent-id", "show", "HEAD"],
    );
    // A second commit whose message forges an owner trailer (same JKT), with the
    // genuine L0 bundle re-attached. The bundle says level 0 / ownerSub null, so
    // the owner trailer must be rejected as inconsistent.
    const forgedMsg = `forged\n\nAgent-ID-JKT: ${agentJkt}\nAgent-ID-Owner: 0xnot-the-owner`;
    await exec("git", ["-C", repoDir, "commit", "--allow-empty", "--no-gpg-sign", "-m", forgedMsg]);
    const { stdout: newHash } = await exec("git", ["-C", repoDir, "rev-parse", "HEAD"]);
    await exec(
      "git",
      ["-C", repoDir, "notes", "--ref=agent-id", "add", "-f", "-m", noteRaw.trim(), newHash.trim()],
    );

    const verify = await runCli(
      ["verify", "--state-dir", stateDir, "--commit", "HEAD"],
      { cwd: repoDir },
    );
    assert.equal(verify.parsed?.ok, false);
    assert.match(verify.parsed?.error || "", /Agent-ID-Owner trailer/);
  });
});
