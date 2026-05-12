#!/usr/bin/env node

// Alien Agent ID — CLI tool for agent identity management.
// Usage: node cli.mjs <command> [flags]
//
// Commands: bootstrap, setup-owner-session, init, auth, bind, status, sign, verify, export-proof,
//           git-setup, git-commit, git-verify, vault-store, vault-get, vault-list,
//           vault-remove, auth-header, call, discover-service, service-support, refresh

import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { execFile as execFileCb } from "node:child_process";
import { randomUUID, createPublicKey } from "node:crypto";

import {
  statePaths,
  readJsonFile,
  writeJsonFile,
  readJsonl,
  ensureDir,
  setPrivateFilePermissions,
  generateEd25519PemPair,
  fingerprintPublicKeyPem,
  nowMs,
  beginOidcAuthorization,
  pollForAuthorizationCode,
  exchangeAuthorizationCode,
  verifyIdToken,
  verifyIdTokenSignatureOnly,
  verifyState,
  AuthRevokedError,
  SignatureEngine,
  parseJwt,
  ed25519PublicKeyToJwk,
  jwkThumbprint,
  ed25519PemToSshPublicKey,
  ed25519PemToOpenSSHPrivateKey,
  deriveVaultKey,
  vaultEncrypt,
  vaultDecrypt,
  createDPoPProof,
  fetchServiceManifest,
  probeServiceSupportSignal,
  renderCapabilities,
} from "./lib.mjs";
import qrcode from "./qrcode.cjs";

// ─── Helpers ────────────────────────────────────────────────────────────────────

function stderr(msg) {
  process.stderr.write(`${msg}\n`);
}

function outputJson(obj) {
  process.stdout.write(JSON.stringify(obj, null, 2) + "\n");
}

function outputError(message) {
  outputJson({ ok: false, error: message });
  process.exitCode = 1;
}

function parseFlags(argv) {
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      if (key.startsWith("no-")) {
        flags[key.slice(3)] = false;
      } else if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
        flags[key] = argv[++i];
      } else {
        flags[key] = true;
      }
    }
  }
  return flags;
}

function resolveStateDir(flags) {
  if (flags["state-dir"]) {
    return path.resolve(String(flags["state-dir"]));
  }
  if (process.env.AGENT_ID_STATE_DIR) {
    return path.resolve(process.env.AGENT_ID_STATE_DIR);
  }
  return path.join(os.homedir(), ".agent-id");
}

function execFile(command, args, options = {}) {
  return new Promise((resolve) => {
    execFileCb(command, args, { timeout: 5000, ...options }, (err, stdout, stderr) => {
      resolve({
        code: err?.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER" ? 1 : err ? (err.code ?? 1) : 0,
        stdout: stdout || "",
        stderr: stderr || "",
      });
    });
  });
}

// ─── Commands ───────────────────────────────────────────────────────────────────

async function cmdInit(flags) {
  const stateDir = resolveStateDir(flags);
  const paths = statePaths(stateDir);

  await ensureDir(stateDir);
  await ensureDir(path.dirname(paths.mainKey));
  await ensureDir(path.dirname(paths.auditJsonl));

  let key = await readJsonFile(paths.mainKey, null);
  if (!key) {
    const pair = generateEd25519PemPair();
    key = {
      version: 1,
      agentId: "main",
      keyNonce: 0,
      createdAt: nowMs(),
      publicKeyPem: pair.publicKeyPem,
      privateKeyPem: pair.privateKeyPem,
      fingerprint: fingerprintPublicKeyPem(pair.publicKeyPem),
    };
    await writeJsonFile(paths.mainKey, key);
    await setPrivateFilePermissions(paths.mainKey);
    stderr(`Generated agent keypair: ${key.fingerprint.slice(0, 16)}...`);
  } else {
    stderr(`Agent keypair already exists: ${key.fingerprint.slice(0, 16)}...`);
  }

  if (!flags._quiet) {
    outputJson({
      ok: true,
      fingerprint: key.fingerprint,
      publicKeyPem: key.publicKeyPem,
      stateDir,
    });
  }

  return key;
}

async function cmdAuth(flags) {
  const stateDir = resolveStateDir(flags);
  const providerAddress = flags["provider-address"];
  const ssoBaseUrl = flags["sso-url"] || "https://sso.alien-api.com";
  const oidcOrigin = flags["oidc-origin"] || "http://localhost";
  if (!providerAddress) {
    outputError("--provider-address is required");
    return;
  }

  // Auto-init if needed — capture the agent key so we can advertise its
  // RFC 7638 thumbprint as `dpop_jkt` on the authorize URL.
  const agentKey = await cmdInit({ ...flags, _quiet: true });
  const agentPublicKeyPem = agentKey?.publicKeyPem || null;

  // Start OIDC authorization
  stderr(`Starting OIDC authorization against ${ssoBaseUrl}...`);
  let auth;
  try {
    auth = await beginOidcAuthorization({ ssoBaseUrl, providerAddress, oidcOrigin, agentPublicKeyPem });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (oidcOrigin !== "http://localhost" && msg.includes("Origin not allowed")) {
      stderr(`Origin ${oidcOrigin} rejected, retrying with http://localhost...`);
      auth = await beginOidcAuthorization({
        ssoBaseUrl,
        providerAddress,
        oidcOrigin: "http://localhost",
        agentPublicKeyPem,
      });
    } else {
      throw err;
    }
  }

  // Persist pending auth state. Includes the PKCE code_verifier (RFC 7636),
  // the OAuth `state` (RFC 6749 §10.12), and the OIDC `nonce` (OIDC Core
  // §3.1.3.7) so cmdBind can correlate the polled response and verify the
  // id_token against the value originally sent on the authorize URL.
  const paths = statePaths(stateDir);
  await writeJsonFile(paths.pendingAuth, {
    pollingCode: auth.pollingCode,
    codeVerifier: auth.codeVerifier,
    state: auth.state,
    nonce: auth.nonce,
    issuer: auth.issuer,
    deepLink: auth.deepLink,
    expiredAt: auth.expiredAt,
    providerAddress,
    ssoBaseUrl,
    oidcOrigin,
    createdAt: Date.now(),
  });
  await setPrivateFilePermissions(paths.pendingAuth);

  // Generate QR code text for agent to display
  let qrText = "";
  qrcode.generate(auth.deepLink, { small: true }, (code) => {
    qrText = code;
  });

  const result = {
    ok: true,
    deepLink: auth.deepLink,
    qrCode: qrText,
    pollingCode: auth.pollingCode,
    expiredAt: auth.expiredAt,
    message: "Ask the user to open the deep link or scan the QR code with Alien App",
  };
  if (!flags._noOutput) {
    outputJson(result);
  }
  return result;
}

async function cmdBind(flags) {
  const stateDir = resolveStateDir(flags);
  const timeoutSec = Number(flags["timeout-sec"] || 300);
  const pollIntervalMs = Number(flags["poll-interval-ms"] || 3000);

  const paths = statePaths(stateDir);
  const pending = await readJsonFile(paths.pendingAuth, null);
  if (!pending) {
    outputError("No pending auth found. Run `auth` first.");
    return;
  }

  // Poll for authorization. Pass the previously-recorded state so the AS's
  // echoed value (when present) is checked per RFC 6749 §10.12.
  stderr(`Polling for authorization (timeout ${timeoutSec}s)...`);
  const poll = await pollForAuthorizationCode({
    ssoBaseUrl: pending.ssoBaseUrl,
    pollingCode: pending.pollingCode,
    expectedState: pending.state || null,
    expectedIssuer: pending.issuer || null,
    pollIntervalMs,
    timeoutSec,
  });
  stderr("Authorization received. Exchanging tokens...");

  // Load the agent's main key so the token request carries a DPoP proof.
  const dpopKey = await readJsonFile(paths.mainKey, null);
  if (!dpopKey?.privateKeyPem || !dpopKey?.publicKeyPem) {
    outputError("No agent keypair. Run `init` or `bootstrap` first.");
    return;
  }

  // Exchange code for tokens
  const tokens = await exchangeAuthorizationCode({
    ssoBaseUrl: pending.ssoBaseUrl,
    providerAddress: pending.providerAddress,
    authorizationCode: poll.authorizationCode,
    codeVerifier: pending.codeVerifier,
    agentPrivateKeyPem: dpopKey.privateKeyPem,
  });

  // Verify id_token. Pass the agent public key so verifyIdToken enforces
  // RFC 9449 §6.1 cnf.jkt binding at bind time, not only at chain verify.
  // Pass the originally-sent nonce so OIDC §3.1.3.7 step 11 is enforced
  // (replay protection for the authorization-code flow).
  const id = await verifyIdToken({
    ssoBaseUrl: pending.ssoBaseUrl,
    providerAddress: pending.providerAddress,
    idToken: tokens.id_token,
    agentPublicKeyPem: dpopKey.publicKeyPem,
    expectedNonce: pending.nonce || undefined,
  });
  stderr(`Verified id_token: sub=${id.payload.sub}`);

  // Create engine and bind. The id_token IS the chain attestation
  // (signed by the SSO server, RFC-7519 §7.2 verified above), so no
  // separate owner-key proof is required at bind time.
  const engine = new SignatureEngine({ baseDir: stateDir });
  await engine.init();
  const owner = await engine.bindOwnerSession({
    issuer: id.issuer,
    ssoBaseUrl: pending.ssoBaseUrl,
    providerAddress: pending.providerAddress,
    ownerSessionSub: id.payload.sub,
    ownerAudience: id.payload.aud,
    idToken: tokens.id_token,
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
  });

  // Clean up pending auth
  await fs.unlink(paths.pendingAuth).catch(() => {});

  const mainKey = engine.keys.get("main");
  stderr("Owner binding created successfully.");

  const result = {
    ok: true,
    ownerSub: owner.ownerSessionSub,
    issuer: owner.issuer,
    providerAddress: owner.providerAddress,
    jkt: mainKey ? jwkThumbprint(ed25519PublicKeyToJwk(mainKey.publicKeyPem)) : null,
  };
  if (!flags._noOutput) {
    outputJson(result);
  }
  return result;
}

async function cmdStatus(flags) {
  const stateDir = resolveStateDir(flags);
  const paths = statePaths(stateDir);

  const key = await readJsonFile(paths.mainKey, null);
  if (!key) {
    outputJson({
      ok: true,
      initialized: false,
      bound: false,
      stateDir,
    });
    return;
  }

  const session = await readJsonFile(paths.ownerSession, null);
  const seq = await readJsonFile(paths.seq, null);
  const nonces = await readJsonFile(paths.nonces, null);

  const agentJkt = jwkThumbprint(ed25519PublicKeyToJwk(key.publicKeyPem));
  let idPayload = null;
  if (session?.idToken) {
    try {
      idPayload = parseJwt(session.idToken).payload;
    } catch {
      // ignore — bound:false will reflect the bad state
    }
  }

  outputJson({
    ok: true,
    initialized: true,
    bound: Boolean(idPayload?.sub),
    jkt: agentJkt,
    ownerSub: idPayload?.sub || null,
    providerAddress: session?.providerAddress || null,
    issuer: session?.issuer || null,
    nextSeq: seq?.nextSeq ?? null,
    nonceAgents: Object.keys(nonces?.byAgent || {}).length,
    stateDir,
  });
}

async function cmdSign(flags) {
  const stateDir = resolveStateDir(flags);
  const operationType = flags.type;
  const action = flags.action;
  const payloadRaw = flags.payload;

  if (!operationType || !action || !payloadRaw) {
    outputError("Required flags: --type <type> --action <action> --payload <json>");
    return;
  }

  let payload;
  try {
    payload = JSON.parse(payloadRaw);
  } catch {
    outputError("--payload must be valid JSON");
    return;
  }

  const engine = new SignatureEngine({ baseDir: stateDir });
  await engine.init();

  const rec = await engine.appendOperation({
    operationType,
    action,
    payload,
    ctx: { agentId: flags["agent-id"] || "main" },
    meta: flags.meta ? JSON.parse(flags.meta) : null,
  });

  outputJson({
    ok: true,
    operationId: rec.auditEntry.envelope.operationId,
    seq: rec.seq,
    nonce: rec.nonce,
    agentId: rec.agentId,
    signatureShort: rec.signatureShort,
    envelopeHashShort: rec.envelopeHashShort,
  });
}

async function cmdVerify(flags) {
  const stateDir = resolveStateDir(flags);
  const result = await verifyState(stateDir);
  outputJson(result);
  if (!result.ok) {
    process.exitCode = 1;
  }
}

async function cmdExportProof(flags) {
  const stateDir = resolveStateDir(flags);
  const paths = statePaths(stateDir);

  const session = await readJsonFile(paths.ownerSession, null);
  const audit = await readJsonl(paths.auditJsonl);

  outputJson({
    exportedAt: Date.now(),
    stateDir,
    ownerSession: session,
    operations: audit,
  });
}

// ─── Git Helpers ────────────────────────────────────────────────────────────────

/**
 * Sync and push Agent ID proof notes to the remote.
 * Git notes live under a single ref (refs/notes/agent-id) that contains notes
 * for ALL commits. Pushing this ref can conflict when the remote already has
 * notes from other commits. This helper fetches, merges, and pushes.
 */
async function syncAndPushNotes(remote = "origin") {
  const notesRef = "refs/notes/agent-id";

  // Try a plain push first — works when remote has no notes or we're ahead
  const directPush = await execFile("git", ["push", remote, notesRef], { timeout: 30000 });
  if (directPush.code === 0) {
    return { ok: true, method: "direct" };
  }

  // Fetch remote notes into a temporary ref
  const tmpRef = "refs/notes/agent-id-remote";
  const fetchResult = await execFile(
    "git",
    ["fetch", remote, `${notesRef}:${tmpRef}`],
    { timeout: 30000 },
  );
  if (fetchResult.code !== 0) {
    // Remote has no notes yet — our direct push should have worked.
    // Retry once in case of a transient error.
    const retry = await execFile("git", ["push", remote, notesRef], { timeout: 30000 });
    if (retry.code === 0) return { ok: true, method: "retry" };
    return { ok: false, error: `fetch failed: ${fetchResult.stderr.trim()}` };
  }

  // Merge remote notes into local
  const mergeResult = await execFile(
    "git",
    ["notes", "--ref=agent-id", "merge", tmpRef],
    { timeout: 10000 },
  );
  if (mergeResult.code !== 0) {
    return { ok: false, error: `notes merge failed: ${mergeResult.stderr.trim()}` };
  }

  // Clean up temporary ref
  await execFile("git", ["update-ref", "-d", tmpRef], { timeout: 5000 });

  // Push merged notes
  const pushResult = await execFile("git", ["push", remote, notesRef], { timeout: 30000 });
  if (pushResult.code !== 0) {
    return { ok: false, error: `push after merge failed: ${pushResult.stderr.trim()}` };
  }

  return { ok: true, method: "fetch-merge-push" };
}

// ─── Git Commands ───────────────────────────────────────────────────────────────

async function cmdGitSetup(flags) {
  const stateDir = resolveStateDir(flags);
  const paths = statePaths(stateDir);

  // Ensure we have a key
  const key = await readJsonFile(paths.mainKey, null);
  if (!key) {
    outputError("No agent keypair. Run `init` first.");
    return;
  }

  // Write SSH key files
  const sshDir = path.join(stateDir, "ssh");
  await ensureDir(sshDir);
  const privateKeyPath = path.join(sshDir, "agent-id");
  const publicKeyPath = path.join(sshDir, "agent-id.pub");
  const allowedSignersPath = path.join(sshDir, "allowed_signers");

  // Private key in OpenSSH format (required by ssh-keygen for Ed25519 signing)
  const opensshKey = ed25519PemToOpenSSHPrivateKey(key.privateKeyPem);
  await fs.writeFile(privateKeyPath, opensshKey, { encoding: "utf8", mode: 0o600 });
  await setPrivateFilePermissions(privateKeyPath);

  // Public key in SSH format
  const comment = `agent-id:${key.fingerprint.slice(0, 16)}`;
  const sshPubKey = ed25519PemToSshPublicKey(key.publicKeyPem, comment);
  await fs.writeFile(publicKeyPath, sshPubKey + "\n", "utf8");

  // Allowed signers for verification (always uses agent's stable identity)
  const agentJkt = jwkThumbprint(ed25519PublicKeyToJwk(key.publicKeyPem));
  const agentEmail = `agent-${agentJkt.slice(0, 12)}@agent-id.local`;
  const signerLine = `${agentEmail} ${sshPubKey}`;
  await fs.writeFile(allowedSignersPath, signerLine + "\n", "utf8");

  stderr(`SSH key files written.`);
  stderr(`Add this SSH public key to your GitHub account as a "Signing key":`);
  stderr(`  GitHub → Settings → SSH and GPG keys → New SSH key → Key type: Signing Key`);
  stderr(``);
  stderr(sshPubKey);

  const session = await readJsonFile(paths.ownerSession, null);
  let ownerSub = null;
  if (session?.idToken) {
    try {
      ownerSub = parseJwt(session.idToken).payload?.sub || null;
    } catch {
      // ignore — non-bound state, result omits ownerSub
    }
  }

  const result = {
    ok: true,
    privateKeyPath,
    publicKeyPath,
    allowedSignersPath,
    sshPublicKey: sshPubKey,
    jkt: agentJkt,
  };

  if (ownerSub) {
    result.ownerSub = ownerSub;
  }

  outputJson(result);
}

async function cmdGitCommit(flags) {
  const stateDir = resolveStateDir(flags);
  const message = flags.message || flags.m;

  if (!message) {
    outputError("--message <msg> is required");
    return;
  }

  // Read agent state. v3 commit attestation reads the SSO-signed id_token
  // directly from owner-session.json; the agent JWK thumbprint is the chain
  // anchor (RFC 7800 cnf.jkt on the id_token == jwkThumbprint(agent_jwk)).
  const paths = statePaths(stateDir);
  const key = await readJsonFile(paths.mainKey, null);
  const session = await readJsonFile(paths.ownerSession, null);

  if (!key) {
    outputError("No agent keypair. Run `init` first.");
    return;
  }
  if (!session?.idToken) {
    outputError("No owner session. Run `auth` and `bind` first.");
    return;
  }

  let idPayload;
  try {
    idPayload = parseJwt(session.idToken).payload;
  } catch (err) {
    outputError(`Could not parse id_token: ${err instanceof Error ? err.message : String(err)}`);
    return;
  }
  if (typeof idPayload?.sub !== "string" || !idPayload.sub) {
    outputError("id_token missing sub claim");
    return;
  }

  const agentJwk = ed25519PublicKeyToJwk(key.publicKeyPem);
  const agentJkt = jwkThumbprint(agentJwk);

  const trailers = [
    `Agent-ID-JKT: ${agentJkt}`,
    `Agent-ID-Owner: ${idPayload.sub}`,
    `Co-Authored-By: Alien Agent <alienagentid@eti.co>`,
  ];

  const fullMessage = `${message}\n\n${trailers.join("\n")}`;

  // Write SSH key files for signing
  const sshDir = path.join(stateDir, "ssh");
  await ensureDir(sshDir);
  const privateKeyPath = path.join(sshDir, "agent-id");

  // Ensure SSH key file exists (may already exist from git-setup or bootstrap)
  try {
    await fs.access(privateKeyPath);
  } catch {
    const opensshKey = ed25519PemToOpenSSHPrivateKey(key.privateKeyPem);
    await fs.writeFile(privateKeyPath, opensshKey, { encoding: "utf8", mode: 0o600 });
    await setPrivateFilePermissions(privateKeyPath);
  }

  // Pass signing config inline — no git config changes needed
  const commitArgs = [
    "-c", "gpg.format=ssh",
    "-c", `user.signingkey=${privateKeyPath}`,
    "commit", "-S", "-m", fullMessage,
  ];
  if (flags["allow-empty"]) {
    commitArgs.push("--allow-empty");
  }

  const commitResult = await execFile("git", commitArgs, { timeout: 30000 });
  if (commitResult.code !== 0) {
    outputError(`git commit failed: ${commitResult.stderr.trim()}`);
    return;
  }

  // Get the commit hash
  const hashResult = await execFile("git", ["rev-parse", "HEAD"]);
  const commitHash = hashResult.stdout.trim();

  // Log to audit trail (best-effort)
  let auditRecord = null;
  try {
    const engine = new SignatureEngine({ baseDir: stateDir });
    await engine.init();
    auditRecord = await engine.appendOperation({
      operationType: "GIT_COMMIT",
      action: "git.commit",
      payload: {
        commitHash,
        message,
        jkt: agentJkt,
      },
      ctx: { agentId: "main" },
    });
  } catch {
    // Non-fatal — commit succeeded, audit logging is best-effort
    stderr("Warning: could not log commit to audit trail");
  }

  // Attach v3 proof bundle as a git note for external verification.
  // Verifier reads {id_token, agent_jwk}; chain anchor is cnf.jkt on the
  // SSO-signed id_token == jwkThumbprint(agent_jwk).
  let proofAttached = false;
  try {
    const proofBundle = {
      version: 3,
      id_token: Buffer.from(session.idToken).toString("base64url"),
      agent_jwk: agentJwk,
    };
    const noteBody = JSON.stringify(proofBundle);
    const noteResult = await execFile(
      "git",
      ["notes", "--ref=agent-id", "add", "-f", "-m", noteBody, commitHash],
      { timeout: 10000 },
    );
    if (noteResult.code === 0) {
      proofAttached = true;
      stderr("Proof bundle attached as git note (refs/notes/agent-id).");
    } else {
      stderr(`Warning: could not attach proof note: ${noteResult.stderr.trim()}`);
    }
  } catch {
    stderr("Warning: could not attach proof note");
  }

  stderr(`Signed commit: ${commitHash.slice(0, 12)}`);

  // Push commit and notes if --push is set
  let pushed = false;
  let notesPushed = false;
  if (flags.push) {
    const remote = flags.remote || "origin";

    // Push the commit
    const pushResult = await execFile("git", ["push", remote], { timeout: 60000 });
    if (pushResult.code === 0) {
      pushed = true;
      stderr(`Pushed to ${remote}.`);
    } else {
      stderr(`Warning: git push failed: ${pushResult.stderr.trim()}`);
    }

    // Sync and push proof notes
    if (proofAttached) {
      const notesResult = await syncAndPushNotes(remote);
      if (notesResult.ok) {
        notesPushed = true;
        stderr(`Proof notes pushed to ${remote} (${notesResult.method}).`);
      } else {
        stderr(`Warning: could not push proof notes: ${notesResult.error}`);
      }
    }
  }

  const result = {
    ok: true,
    commitHash,
    signed: true,
    jkt: agentJkt,
    proofAttached,
    pushed,
    notesPushed,
  };
  if (auditRecord) {
    result.auditSeq = auditRecord.seq;
    result.signatureShort = auditRecord.signatureShort;
  }
  outputJson(result);
}

async function cmdGitVerify(flags) {
  const commitHash = flags.commit || "HEAD";

  // Resolve commit hash.
  const revResult = await execFile("git", ["rev-parse", commitHash]);
  if (revResult.code !== 0) {
    outputError(`Cannot resolve commit: ${commitHash}`);
    return;
  }
  const resolvedHash = revResult.stdout.trim();

  // Read v3 trailers (Agent-ID-JKT, Agent-ID-Owner). Pre-v3 commits are
  // intentionally not supported — their id_tokens predate the RFC 7800
  // cnf.jkt binding and cannot anchor the chain.
  const logResult = await execFile("git", ["log", "-1", "--format=%B", resolvedHash]);
  const commitMessage = logResult.stdout.trim();
  const trailerJkt = extractTrailer(commitMessage, "Agent-ID-JKT");
  const trailerOwner = extractTrailer(commitMessage, "Agent-ID-Owner");
  if (!trailerJkt) {
    outputError(
      `Commit ${resolvedHash.slice(0, 12)} has no Agent-ID-JKT trailer (pre-v3 commits are not supported)`,
    );
    return;
  }

  // Load v3 bundle from refs/notes/agent-id.
  const noteResult = await execFile(
    "git",
    ["notes", "--ref=agent-id", "show", resolvedHash],
    { timeout: 10000 },
  );
  if (noteResult.code !== 0 || !noteResult.stdout.trim()) {
    outputError(
      `Commit ${resolvedHash.slice(0, 12)} — no Agent-ID git note (refs/notes/agent-id) found`,
    );
    return;
  }

  let bundle;
  try {
    bundle = JSON.parse(noteResult.stdout.trim());
  } catch (err) {
    outputError(`Agent-ID note is not valid JSON: ${err instanceof Error ? err.message : String(err)}`);
    return;
  }

  if (bundle?.version !== 3) {
    outputError(
      `Unsupported bundle version ${String(bundle?.version)} (only v3 commits are verifiable)`,
    );
    return;
  }
  if (typeof bundle.id_token !== "string" || !bundle.id_token) {
    outputError("v3 bundle missing id_token");
    return;
  }
  if (!bundle.agent_jwk || typeof bundle.agent_jwk !== "object") {
    outputError("v3 bundle missing agent_jwk");
    return;
  }

  let idTokenStr;
  try {
    idTokenStr = Buffer.from(bundle.id_token, "base64url").toString("utf8");
  } catch (err) {
    outputError(`bundle.id_token is not valid base64url: ${err instanceof Error ? err.message : String(err)}`);
    return;
  }

  let ssoBaseUrl = flags["sso-url"] || null;
  if (!ssoBaseUrl) {
    try {
      ssoBaseUrl = parseJwt(idTokenStr).payload?.iss || null;
    } catch {
      // fall through — verifyIdTokenSignatureOnly will surface the parse error
    }
  }
  if (!ssoBaseUrl) {
    outputError("Could not determine SSO base URL (no --sso-url flag and id_token.iss missing)");
    return;
  }

  // Verify id_token SSO signature + issuer. exp/aud intentionally skipped —
  // commit attestation is historical, not runtime resource access.
  let tokenResult;
  try {
    tokenResult = await verifyIdTokenSignatureOnly({
      idToken: idTokenStr,
      ssoBaseUrl,
    });
  } catch (err) {
    outputError(`id_token SSO signature verification failed: ${err instanceof Error ? err.message : String(err)}`);
    return;
  }
  const idPayload = tokenResult.payload;

  if (typeof idPayload?.sub !== "string" || !idPayload.sub) {
    outputError("id_token missing sub claim");
    return;
  }
  if (trailerOwner && trailerOwner !== idPayload.sub) {
    outputError(
      `Agent-ID-Owner trailer ${trailerOwner} does not match id_token sub ${idPayload.sub}`,
    );
    return;
  }
  const cnfJkt = idPayload?.cnf?.jkt;
  if (typeof cnfJkt !== "string" || !cnfJkt) {
    outputError("id_token missing cnf.jkt (RFC 7800 §3.1 confirmation claim required)");
    return;
  }

  const computedJkt = jwkThumbprint(bundle.agent_jwk);
  if (computedJkt !== cnfJkt) {
    outputError(
      `agent_jwk thumbprint ${computedJkt} does not match id_token cnf.jkt ${cnfJkt}`,
    );
    return;
  }
  if (computedJkt !== trailerJkt) {
    outputError(
      `agent_jwk thumbprint ${computedJkt} does not match Agent-ID-JKT trailer ${trailerJkt}`,
    );
    return;
  }

  // SSH commit signature against agent_jwk. Reconstruct the public key as
  // PEM so the existing ed25519PemToSshPublicKey helper can format it for
  // git's gpg.ssh.allowedSignersFile.
  let agentPubKeyPem;
  try {
    const pubKey = createPublicKey({ key: bundle.agent_jwk, format: "jwk" });
    agentPubKeyPem = pubKey.export({ type: "spki", format: "pem" });
  } catch (err) {
    outputError(`agent_jwk is not a valid Ed25519 JWK: ${err instanceof Error ? err.message : String(err)}`);
    return;
  }
  const sshPub = ed25519PemToSshPublicKey(agentPubKeyPem);
  const tmpSignersPath = path.join(os.tmpdir(), `agent-id-signers-${randomUUID()}`);
  const signerEmail = `agent-${computedJkt.slice(0, 12)}@agent-id.local`;
  await fs.writeFile(tmpSignersPath, `${signerEmail} ${sshPub}\n`, "utf8");
  let sshOk = false;
  try {
    const verifyResult = await execFile(
      "git",
      [
        "-c", `gpg.ssh.allowedSignersFile=${tmpSignersPath}`,
        "verify-commit", resolvedHash,
      ],
      { timeout: 10000 },
    );
    sshOk = verifyResult.code === 0;
  } finally {
    await fs.unlink(tmpSignersPath).catch(() => {});
  }
  if (!sshOk) {
    outputError(
      `SSH commit signature verification failed for ${resolvedHash.slice(0, 12)} against agent_jwk ${computedJkt.slice(0, 16)}...`,
    );
    return;
  }

  outputJson({
    ok: true,
    commit: resolvedHash,
    jkt: computedJkt,
    ownerSub: idPayload.sub,
    issuer: tokenResult.issuer,
    aud: idPayload.aud ?? null,
    iat: idPayload.iat ?? null,
    summary: `Commit ${resolvedHash.slice(0, 12)} signed by agent ${computedJkt.slice(0, 16)}... owned by ${idPayload.sub}`,
  });
}

function extractTrailer(message, key) {
  const re = new RegExp(`^${key}:\\s*(.+)$`, "m");
  const match = message.match(re);
  return match ? match[1].trim() : null;
}

// ─── Bootstrap ──────────────────────────────────────────────────────────────────

async function resolveProviderAddress(flags) {
  if (flags["provider-address"]) return flags["provider-address"];
  if (process.env.ALIEN_PROVIDER_ADDRESS) return process.env.ALIEN_PROVIDER_ADDRESS;

  // Try default-provider.txt next to the CLI
  const scriptDir = path.dirname(new URL(import.meta.url).pathname);
  try {
    const txt = await fs.readFile(path.join(scriptDir, "default-provider.txt"), "utf8");
    const trimmed = txt.trim();
    if (trimmed) return trimmed;
  } catch (err) {
    // ENOENT is the expected case (no default-provider.txt). Other errors
    // (EACCES, EIO, …) indicate something the user should know about.
    if (err && err.code !== "ENOENT") throw err;
  }
  return null;
}

async function cmdBootstrap(flags) {
  const stateDir = resolveStateDir(flags);
  const paths = statePaths(stateDir);

  // 1. Already bootstrapped?
  const existingKey = await readJsonFile(paths.mainKey, null);
  const existingSession = await readJsonFile(paths.ownerSession, null);

  if (existingKey && existingSession?.idToken) {
    stderr("Agent ID already bootstrapped.");
    await cmdGitSetup({ ...flags, _quiet: true });
    let existingSub = null;
    try {
      existingSub = parseJwt(existingSession.idToken).payload?.sub || null;
    } catch {
      // ignore — state will be re-bound below if parseable; report what we have
    }
    outputJson({
      ok: true,
      alreadyBootstrapped: true,
      jkt: jwkThumbprint(ed25519PublicKeyToJwk(existingKey.publicKeyPem)),
      ownerSub: existingSub,
      providerAddress: existingSession.providerAddress || null,
      stateDir,
    });
    return;
  }

  // 2. Resolve provider address
  const providerAddress = await resolveProviderAddress(flags);
  if (!providerAddress) {
    outputError(
      "No provider address. Set --provider-address, ALIEN_PROVIDER_ADDRESS env, or create default-provider.txt next to the CLI.",
    );
    return;
  }
  stderr(`Provider address: ${providerAddress}`);

  // 3. Init (generate keypair)
  await cmdInit({ ...flags, _quiet: true });

  // 4. Auth (start OIDC, show QR)
  const authResult = await cmdAuth({
    ...flags,
    "provider-address": providerAddress,
    _noOutput: true,
  });

  // 5. Tell the user what to do
  stderr(`Open this link with your Alien App: ${authResult.deepLink}`);

  // 6. Bind (poll for approval)
  const bindResult = await cmdBind({
    ...flags,
    _noOutput: true,
  });

  // 7. Git setup
  stderr("Setting up git signing...");
  await cmdGitSetup({ ...flags, _quiet: true });

  stderr("Bootstrap complete.");
  outputJson({
    ok: true,
    fingerprint: bindResult.fingerprint,
    ownerSessionSub: bindResult.ownerSessionSub,
    bindingId: bindResult.bindingId,
    providerAddress,
    stateDir,
  });
}

// ─── Setup Owner Session — DPoP/cnf rebind ─────────────────────────────────────

// Force a fresh OAuth flow that produces a DPoP-bound, cnf-carrying id_token.
// Used to migrate pre-3.0 agents whose existing bindings carry cnf-less
// id_tokens that the 3.0 verifier rejects. Keys are preserved; only the
// owner-session and binding state files are cleared so cmdBind can rewrite.
async function cmdSetupOwnerSession(flags) {
  const stateDir = resolveStateDir(flags);
  const paths = statePaths(stateDir);

  const verbose = flags.verbose === true;

  // Clear only the session/pending-auth state. The keypair stays put — re-binding
  // under DPoP just adds cnf.jkt for the SAME key the agent already has; rotating
  // the key would gratuitously invalidate every signed commit. Also remove any
  // stale `owner-binding.json` from pre-v3 agents.
  let cleared = false;
  const legacyBindingPath = path.join(stateDir, "owner-binding.json");
  for (const p of [legacyBindingPath, paths.ownerSession, paths.pendingAuth]) {
    try {
      await fs.unlink(p);
      cleared = true;
    } catch (err) {
      if (err && err.code !== "ENOENT") throw err;
    }
  }
  if (cleared) {
    stderr("Cleared existing owner-session and binding for re-bind.");
  }

  const providerAddress = await resolveProviderAddress(flags);
  if (!providerAddress) {
    outputError(
      "No provider address. Set --provider-address, ALIEN_PROVIDER_ADDRESS env, or create default-provider.txt next to the CLI.",
    );
    return;
  }
  if (verbose) stderr(`Provider address: ${providerAddress}`);

  // Init (no-op if keypair exists; generates one otherwise).
  const agentKey = await cmdInit({ ...flags, _quiet: true });
  if (verbose && agentKey?.fingerprint) {
    stderr(`Agent fingerprint: ${agentKey.fingerprint}`);
  }

  const authResult = await cmdAuth({
    ...flags,
    "provider-address": providerAddress,
    _noOutput: true,
  });
  stderr(`Open this link with your Alien App: ${authResult.deepLink}`);
  if (verbose) stderr(`Polling code: ${authResult.pollingCode}`);

  const bindResult = await cmdBind({ ...flags, _noOutput: true });

  await cmdGitSetup({ ...flags, _quiet: true });

  outputJson({
    ok: true,
    rebound: true,
    fingerprint: bindResult?.fingerprint,
    ownerSessionSub: bindResult?.ownerSessionSub,
    bindingId: bindResult?.bindingId,
    providerAddress,
    stateDir,
  });
}

// ─── Vault ──────────────────────────────────────────────────────────────────────

function safeServiceName(name) {
  return name.replace(/[^a-zA-Z0-9._-]/g, "_");
}

async function loadVaultKey(stateDir) {
  const paths = statePaths(stateDir);
  const key = await readJsonFile(paths.mainKey, null);
  if (!key?.privateKeyPem) {
    throw new Error("No agent keypair. Run `bootstrap` or `init` first.");
  }
  return { vaultKey: deriveVaultKey(key.privateKeyPem), paths };
}

async function readStdin() {
  if (process.stdin.isTTY) return null;
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8").replace(/\n$/, "");
}

async function resolveCredential(flags) {
  // 1. --credential-file <path>  (most secure — never touches CLI args)
  if (flags["credential-file"]) {
    try {
      return (await fs.readFile(flags["credential-file"], "utf8")).replace(/\n$/, "");
    } catch (err) {
      throw new Error(`Cannot read credential file: ${err.message}`);
    }
  }

  // 2. --credential-env <VAR_NAME>  (reads from environment variable)
  if (flags["credential-env"]) {
    const val = process.env[flags["credential-env"]];
    if (!val) throw new Error(`Environment variable ${flags["credential-env"]} is not set`);
    return val;
  }

  // 3. stdin  (piped: echo "secret" | node cli.mjs vault-store ...)
  const fromStdin = await readStdin();
  if (fromStdin) return fromStdin;

  // 4. --credential <value>  (fallback — visible in process list)
  if (flags.credential) return flags.credential;

  return null;
}

async function cmdVaultStore(flags) {
  const stateDir = resolveStateDir(flags);
  const service = flags.service;
  const credType = flags.type || "api-key";

  if (!service) {
    outputError("--service <name> is required");
    return;
  }

  const credential = await resolveCredential(flags);
  if (!credential) {
    outputError(
      "Credential required. Provide via:\n" +
      "  --credential-file <path>   (read from file — most secure)\n" +
      "  --credential-env <VAR>     (read from environment variable)\n" +
      "  echo 'secret' | node cli.mjs vault-store ...   (pipe via stdin)\n" +
      "  --credential <value>       (CLI arg — visible in process list)",
    );
    return;
  }

  const { vaultKey, paths } = await loadVaultKey(stateDir);
  await ensureDir(paths.vaultDir);

  const filePath = path.join(paths.vaultDir, `${safeServiceName(service)}.json`);

  // Preserve creation time if updating an existing credential
  const existing = await readJsonFile(filePath, null);
  const encrypted = vaultEncrypt(vaultKey, credential);
  const record = {
    version: 1,
    service,
    type: credType,
    url: flags.url || existing?.url || null,
    username: flags.username || existing?.username || null,
    encrypted,
    createdAt: existing?.createdAt || nowMs(),
    updatedAt: nowMs(),
  };

  await writeJsonFile(filePath, record);
  await setPrivateFilePermissions(filePath);

  stderr(`Stored credential for "${service}" (${credType}).`);
  outputJson({ ok: true, service, type: credType, updated: !!existing });
}

async function cmdVaultGet(flags) {
  const stateDir = resolveStateDir(flags);
  const service = flags.service;

  if (!service) {
    outputError("--service <name> is required");
    return;
  }

  const { vaultKey, paths } = await loadVaultKey(stateDir);
  const filePath = path.join(paths.vaultDir, `${safeServiceName(service)}.json`);
  const record = await readJsonFile(filePath, null);

  if (!record) {
    outputError(`No credential stored for "${service}".`);
    return;
  }

  const credential = vaultDecrypt(vaultKey, record.encrypted);

  outputJson({
    ok: true,
    service: record.service,
    type: record.type,
    credential,
    url: record.url,
    username: record.username,
  });
}

async function cmdVaultList(flags) {
  const stateDir = resolveStateDir(flags);
  const paths = statePaths(stateDir);

  let files;
  try {
    files = await fs.readdir(paths.vaultDir);
  } catch {
    outputJson({ ok: true, credentials: [] });
    return;
  }

  const credentials = [];
  for (const file of files) {
    if (!file.endsWith(".json")) continue;
    const record = await readJsonFile(path.join(paths.vaultDir, file), null);
    if (record?.service) {
      credentials.push({
        service: record.service,
        type: record.type,
        url: record.url,
        username: record.username,
        createdAt: record.createdAt,
        updatedAt: record.updatedAt,
      });
    }
  }

  outputJson({ ok: true, credentials });
}

async function cmdVaultRemove(flags) {
  const stateDir = resolveStateDir(flags);
  const service = flags.service;

  if (!service) {
    outputError("--service <name> is required");
    return;
  }

  const paths = statePaths(stateDir);
  const filePath = path.join(paths.vaultDir, `${safeServiceName(service)}.json`);

  try {
    await fs.unlink(filePath);
    stderr(`Removed credential for "${service}".`);
    outputJson({ ok: true, service });
  } catch (err) {
    if (err?.code === "ENOENT") {
      outputError(`No credential stored for "${service}".`);
    } else {
      throw err;
    }
  }
}

// ─── Session Refresh ─────────────────────────────────────────────────────────────

async function cmdRefresh(flags) {
  const stateDir = resolveStateDir(flags);
  const engine = new SignatureEngine({ baseDir: stateDir });
  await engine.init();

  try {
    const session = await engine.ensureValidSession({ bufferSec: 0 });
    if (!session) {
      outputError("No session to refresh. Run `bootstrap` first.");
      return;
    }
    outputJson({
      ok: true,
      refreshedAt: session.refreshedAt || null,
      ownerSessionSub: session.ownerSessionSub,
      providerAddress: session.providerAddress,
    });
  } catch (err) {
    if (err instanceof AuthRevokedError) {
      outputError(
        `Session refresh failed (authorization revoked: ${err.errorCode || "HTTP " + err.status}): ${err.message}. Run \`bootstrap\` to re-authenticate.`,
      );
      return;
    }
    throw err;
  }
}

// ─── Auth Header ────────────────────────────────────────────────────────────────

// Build the DPoP-bound Authorization + DPoP headers for one request.
// RFC 9449 §4.2: the proof binds to a specific (method, URL) and is single-use.
// Returns null + writes an error if the agent isn't bootstrapped.
async function buildDPoPHeaders(stateDir, method, url) {
  const paths = statePaths(stateDir);
  const key = await readJsonFile(paths.mainKey, null);
  if (!key) {
    outputError("No agent keypair. Run `bootstrap` or `init` first.");
    return null;
  }

  // Refresh the SSO session — access_token is rotated on a tight cadence.
  const engine = new SignatureEngine({ baseDir: stateDir });
  await engine.init();
  try {
    await engine.ensureValidSession();
  } catch {
    stderr("Warning: SSO session refresh failed.");
  }

  const session = await readJsonFile(paths.ownerSession, null);
  if (!session?.accessToken) {
    outputError("No bound session with access_token. Run `bootstrap` or `bind` first.");
    return null;
  }

  const htm = String(method || "GET").toUpperCase();
  const htu = String(url);
  const proof = createDPoPProof({
    privateKeyPem: key.privateKeyPem,
    htm,
    htu,
    // RFC 9449 §4.2: `ath` binds the proof to this specific access token —
    // defends against proof reuse with a different captured token.
    accessToken: session.accessToken,
  });

  return { authorization: `DPoP ${session.accessToken}`, dpop: proof, method: htm, url: htu };
}

async function cmdAuthHeader(flags) {
  if (!flags.url) {
    outputError("--url is required. The DPoP proof's `htu` claim binds to a specific request target (RFC 9449 §4.2).");
    return;
  }
  const headers = await buildDPoPHeaders(resolveStateDir(flags), flags.method, flags.url);
  if (!headers) return;

  if (flags.raw) {
    process.stdout.write(`Authorization: ${headers.authorization}\n`);
    process.stdout.write(`DPoP: ${headers.dpop}\n`);
    return;
  }
  outputJson({ ok: true, ...headers });
}

// One-shot signed request: generate DPoP headers, send, return the response.
// Eliminates the two-header / single-use-jti footgun for agents that just
// want to "call this endpoint with my identity attached."
async function cmdCall(flags) {
  if (!flags.url) {
    outputError("--url is required.");
    return;
  }
  const method = String(flags.method || "GET").toUpperCase();
  if (!/^[A-Z]+$/.test(method)) {
    outputError("--method must be an HTTP verb (GET, POST, PUT, DELETE, …)");
    return;
  }

  // Body: --body-file <path> or --body <inline>. Inline is convenient for
  // tiny payloads but visible in process listings, so the file form is
  // preferred for anything non-trivial.
  let body;
  if (flags["body-file"]) {
    try {
      body = await fs.readFile(String(flags["body-file"]), "utf8");
    } catch (err) {
      outputError(`Failed to read --body-file: ${err.message}`);
      return;
    }
  } else if (typeof flags.body === "string") {
    body = flags.body;
  }

  const headers = await buildDPoPHeaders(resolveStateDir(flags), method, flags.url);
  if (!headers) return;

  const fetchHeaders = {
    Authorization: headers.authorization,
    DPoP: headers.dpop,
  };
  if (body !== undefined) {
    fetchHeaders["Content-Type"] = flags["content-type"]
      ? String(flags["content-type"])
      : "application/json";
  }

  let res;
  try {
    res = await fetch(String(flags.url), { method, headers: fetchHeaders, body });
  } catch (err) {
    outputError(`Request failed: ${err.message}`);
    return;
  }

  const contentType = res.headers.get("content-type") || "";
  const text = await res.text();
  let parsed;
  if (/^application\/json\b/i.test(contentType)) {
    try { parsed = JSON.parse(text); } catch { /* fall back to raw text */ }
  }

  outputJson({
    ok: res.ok,
    status: res.status,
    method,
    url: String(flags.url),
    contentType,
    body: parsed !== undefined ? parsed : text,
  });
}

async function cmdServiceSupport(flags) {
  const pageUrl = flags.url;
  if (!pageUrl) {
    outputError("Missing --url <page-url>");
    return;
  }
  const result = await probeServiceSupportSignal(String(pageUrl), {
    allowInsecure: flags["allow-insecure"] === true,
    timeoutMs: flags["timeout-ms"] ? Number(flags["timeout-ms"]) : undefined,
  });
  outputJson({ ok: true, ...result });
}

async function cmdDiscoverService(flags) {
  const serviceUrl = flags.url || flags.service;
  if (!serviceUrl) {
    outputError("Missing --url <service-url>");
    return;
  }
  const result = await fetchServiceManifest(String(serviceUrl), {
    allowInsecure: flags["allow-insecure"] === true,
    timeoutMs: flags["timeout-ms"] ? Number(flags["timeout-ms"]) : undefined,
  });
  outputJson({
    ok: true,
    manifestUrl: result.manifestUrl,
    allowedHost: result.allowedHost,
    manifest: result.manifest,
  });
}

async function cmdCapabilities(flags) {
  const serviceUrl = flags.url || flags.service;
  if (!serviceUrl) {
    outputError("Missing --url <service-url>");
    return;
  }
  const result = await fetchServiceManifest(String(serviceUrl), {
    allowInsecure: flags["allow-insecure"] === true,
    timeoutMs: flags["timeout-ms"] ? Number(flags["timeout-ms"]) : undefined,
  });
  const md = renderCapabilities(result.manifest);
  process.stdout.write(md.endsWith("\n") ? md : md + "\n");
}

// ─── Help ───────────────────────────────────────────────────────────────────────

function printHelp() {
  stderr(`
Alien Agent ID — Verifiable identity for AI agents

Usage: node cli.mjs <command> [flags]

Commands:
  bootstrap      One-command identity setup (init + auth + bind + git-setup)
  setup-owner-session  Re-bind an existing agent (DPoP/cnf migration; preserves keypair)
  init           Generate Ed25519 keypair and initialize state directory
  auth           Start OIDC authorization (returns deep link + QR page)
  bind           Poll for user approval and create owner binding
  status         Show current Agent ID status
  sign           Sign an operation and append to audit trail
  verify         Verify entire state chain integrity
  export-proof   Export proof bundle to stdout
  git-setup      Write SSH key files for commit signing
  git-commit     Create a signed commit with Agent ID trailers
  git-verify     Verify provenance chain of a signed commit
  call           One-shot signed HTTP request (generates DPoP headers + sends).
                 Flags: --url <URL> [--method GET|POST|…] [--body <inline>
                        | --body-file <path>] [--content-type <type>]
  auth-header    Emit RFC 9449 DPoP Authorization + DPoP headers for a request
                 (requires --url, optional --method, defaults to GET).
                 Prefer 'call' unless you specifically need to drive curl.
  discover-service  Fetch and validate /.well-known/alien-agent-id.json
  capabilities   Fetch a manifest and render api.operations[] as markdown.
                 Flags: --url <U>
  service-support   Probe a page for the <meta name="alien-agent-id"> support signal
  refresh        Refresh SSO session tokens (access_token / refresh_token)
  vault-store    Store an encrypted credential in the agent vault
  vault-get      Retrieve a decrypted credential from the vault
  vault-list     List all stored credentials
  vault-remove   Remove a credential from the vault

Bootstrap flags:
  --provider-address <addr>  Provider address (or ALIEN_PROVIDER_ADDRESS env / default-provider.txt)

Common flags:
  --state-dir <path>       State directory (default: ~/.agent-id)

Auth flags:
  --provider-address <addr>  Provider address (required)
  --sso-url <url>            SSO base URL (default: https://sso.alien-api.com)
  --oidc-origin <origin>     OIDC Origin header (default: http://localhost)

Bind flags:
  --timeout-sec <n>          Poll timeout (default: 300)
  --poll-interval-ms <n>     Poll interval (default: 3000)

Sign flags:
  --type <type>              Operation type (e.g., TOOL_CALL, MESSAGE_SEND)
  --action <action>          Action name (e.g., bash.exec, message.send)
  --payload <json>           Operation payload as JSON string
  --agent-id <id>            Agent ID (default: main)

Git flags:
  --message <msg>            Commit message (required for git-commit)
  --allow-empty              Allow empty commits
  --push                     Push commit and proof notes after committing
  --remote <name>            Remote to push to (default: origin)

Git-verify flags:
  --commit <hash>            Commit to verify (default: HEAD)
  --sso-url <url>            SSO base URL for id_token verification

Auth-header flags:
  --raw                      Output raw header (not JSON) for use with curl

Call flags:
  --url <url>                Target URL (required)
  --method <verb>            HTTP method (default: GET)
  --body <inline>            Request body as a literal string
  --body-file <path>         Request body read from a file (preferred for JSON)
  --content-type <type>      Content-Type header (default: application/json
                             when a body is supplied)

Vault flags:
  --service <name>           Service name (required for store/get/remove)
  --type <type>              Credential type: api-key, password, oauth, bearer (default: api-key)
  --credential <value>       Credential value (visible in process list — least secure)
  --credential-file <path>   Read credential from file (most secure)
  --credential-env <VAR>     Read credential from environment variable
                             Also accepts credential via stdin pipe
  --url <url>                Optional service URL
  --username <name>          Optional username

All commands output JSON to stdout. Progress and errors go to stderr.
`.trim());
}

// ─── Main ───────────────────────────────────────────────────────────────────────

const commands = {
  bootstrap: cmdBootstrap,
  "setup-owner-session": cmdSetupOwnerSession,
  init: cmdInit,
  auth: cmdAuth,
  bind: cmdBind,
  status: cmdStatus,
  sign: cmdSign,
  verify: cmdVerify,
  "export-proof": cmdExportProof,
  "git-setup": cmdGitSetup,
  "git-commit": cmdGitCommit,
  "git-verify": cmdGitVerify,
  "vault-store": cmdVaultStore,
  "vault-get": cmdVaultGet,
  "vault-list": cmdVaultList,
  "vault-remove": cmdVaultRemove,
  "auth-header": cmdAuthHeader,
  call: cmdCall,
  "discover-service": cmdDiscoverService,
  capabilities: cmdCapabilities,
  "service-support": cmdServiceSupport,
  refresh: cmdRefresh,
};

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === "help" || command === "--help" || command === "-h") {
    printHelp();
    return;
  }

  const handler = commands[command];
  if (!handler) {
    outputError(`Unknown command: ${command}. Run with --help for usage.`);
    return;
  }

  const flags = parseFlags(args.slice(1));

  try {
    await handler(flags);
  } catch (err) {
    outputError(err instanceof Error ? err.message : String(err));
  }
}

main();
