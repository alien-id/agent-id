#!/usr/bin/env node

// Alien Agent ID — CLI tool for agent identity management.
// Usage: node cli.mjs <command> [flags]
//
// Commands: bootstrap, init, auth, bind, status, sign, verify, export-proof,
//           git-setup, git-commit, git-verify, vault-store, vault-get, vault-list,
//           vault-remove, auth-header

import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { execFile as execFileCb } from "node:child_process";

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
  verifyOwnerSessionProof,
  verifyState,
  SignatureEngine,
  ed25519PemToSshPublicKey,
  ed25519PemToOpenSSHPrivateKey,
  canonicalJSONString,
  sha256Hex,
  sha256HexCanonical,
  verifyEd25519Base64Url,
  deriveVaultKey,
  vaultEncrypt,
  vaultDecrypt,
  createAgentToken,
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

  // Auto-init if needed
  await cmdInit({ ...flags, _quiet: true });

  // Start OIDC authorization
  stderr(`Starting OIDC authorization against ${ssoBaseUrl}...`);
  let auth;
  try {
    auth = await beginOidcAuthorization({ ssoBaseUrl, providerAddress, oidcOrigin });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (oidcOrigin !== "http://localhost" && msg.includes("Origin not allowed")) {
      stderr(`Origin ${oidcOrigin} rejected, retrying with http://localhost...`);
      auth = await beginOidcAuthorization({
        ssoBaseUrl,
        providerAddress,
        oidcOrigin: "http://localhost",
      });
    } else {
      throw err;
    }
  }

  // Persist pending auth state (includes PKCE code_verifier)
  const paths = statePaths(stateDir);
  await writeJsonFile(paths.pendingAuth, {
    pollingCode: auth.pollingCode,
    codeVerifier: auth.codeVerifier,
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
  const requireOwnerProof = flags["require-owner-proof"] !== false;

  const paths = statePaths(stateDir);
  const pending = await readJsonFile(paths.pendingAuth, null);
  if (!pending) {
    outputError("No pending auth found. Run `auth` first.");
    return;
  }

  // Poll for authorization
  stderr(`Polling for authorization (timeout ${timeoutSec}s)...`);
  const poll = await pollForAuthorizationCode({
    ssoBaseUrl: pending.ssoBaseUrl,
    pollingCode: pending.pollingCode,
    pollIntervalMs,
    timeoutSec,
  });
  stderr("Authorization received. Exchanging tokens...");

  // Exchange code for tokens
  const tokens = await exchangeAuthorizationCode({
    ssoBaseUrl: pending.ssoBaseUrl,
    providerAddress: pending.providerAddress,
    authorizationCode: poll.authorizationCode,
    codeVerifier: pending.codeVerifier,
  });

  // Verify id_token
  const id = await verifyIdToken({
    ssoBaseUrl: pending.ssoBaseUrl,
    providerAddress: pending.providerAddress,
    idToken: tokens.id_token,
  });
  stderr(`Verified id_token: sub=${id.payload.sub}`);

  // Verify owner session proof
  if (requireOwnerProof && !poll.ownerProof) {
    outputError(
      "OAuth poll did not return owner key proof (owner_proof). " +
        "Upgrade SSO server or pass --no-require-owner-proof.",
    );
    return;
  }

  let ownerSessionProof = null;
  if (poll.ownerProof) {
    const proofCheck = verifyOwnerSessionProof({
      proof: poll.ownerProof,
      expectedSessionAddress: id.payload.sub,
      expectedProviderAddress: pending.providerAddress,
    });
    if (!proofCheck.ok) {
      outputError(`Owner session proof verification failed: ${proofCheck.reason}`);
      return;
    }
    ownerSessionProof = proofCheck.proof;
    stderr(
      `Owner proof verified: session=${ownerSessionProof.sessionAddress} pub=${ownerSessionProof.sessionPublicKey.slice(0, 16)}...`,
    );
  }

  // Create engine and bind
  const engine = new SignatureEngine({ baseDir: stateDir });
  await engine.init();
  const owner = await engine.bindOwnerSession({
    issuer: id.issuer,
    providerAddress: pending.providerAddress,
    ownerSessionSub: id.payload.sub,
    ownerAudience: id.payload.aud,
    idToken: tokens.id_token,
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
    ownerSessionProof,
  });

  // Clean up pending auth
  await fs.unlink(paths.pendingAuth).catch(() => {});

  const mainKey = engine.keys.get("main");
  stderr("Owner binding created successfully.");

  const result = {
    ok: true,
    ownerSessionSub: owner.binding.payload.ownerSessionSub,
    bindingId: owner.binding.id,
    issuer: id.issuer,
    providerAddress: pending.providerAddress,
    fingerprint: mainKey?.fingerprint || null,
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

  const owner = await readJsonFile(paths.ownerBinding, null);
  const seq = await readJsonFile(paths.seq, null);
  const nonces = await readJsonFile(paths.nonces, null);

  outputJson({
    ok: true,
    initialized: true,
    bound: Boolean(owner?.binding),
    fingerprint: key.fingerprint,
    ownerSessionSub: owner?.binding?.payload?.ownerSessionSub || null,
    providerAddress: owner?.binding?.payload?.providerAddress || null,
    issuer: owner?.binding?.payload?.issuer || null,
    bindingId: owner?.binding?.id || null,
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

  const owner = await readJsonFile(paths.ownerBinding, null);
  const audit = await readJsonl(paths.auditJsonl);

  outputJson({
    exportedAt: Date.now(),
    stateDir,
    ownerBinding: owner,
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
  const scope = flags.global ? "--global" : "--local";

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

  // Allowed signers for verification
  const owner = await readJsonFile(paths.ownerBinding, null);
  const email = flags.email || `agent-${key.fingerprint.slice(0, 8)}@agent-id.local`;
  const signerLine = `${email} ${sshPubKey}`;
  await fs.writeFile(allowedSignersPath, signerLine + "\n", "utf8");

  // Configure git
  const gitConfigs = [
    ["gpg.format", "ssh"],
    ["user.signingkey", privateKeyPath],
    ["gpg.ssh.allowedSignersFile", allowedSignersPath],
    ["commit.gpgsign", "true"],
  ];

  for (const [k, v] of gitConfigs) {
    const out = await execFile("git", ["config", scope, k, v]);
    if (out.code !== 0) {
      outputError(`git config ${scope} ${k} failed: ${out.stderr.trim()}`);
      return;
    }
  }

  // Set committer identity for the agent
  const agentName = flags.name || "Agent";
  await execFile("git", ["config", scope, "user.name", agentName]);
  await execFile("git", ["config", scope, "user.email", email]);

  stderr(`Git SSH signing configured (${scope.replace("--", "")}).`);
  stderr(`Add this SSH public key to your GitHub account as a "Signing key":`);
  stderr(`  GitHub → Settings → SSH and GPG keys → New SSH key → Key type: Signing Key`);
  stderr(``);
  stderr(sshPubKey);

  const result = {
    ok: true,
    scope: scope.replace("--", ""),
    privateKeyPath,
    publicKeyPath,
    allowedSignersPath,
    sshPublicKey: sshPubKey,
    fingerprint: key.fingerprint,
    email,
    agentName,
  };

  if (owner?.binding) {
    result.ownerSessionSub = owner.binding.payload.ownerSessionSub;
    result.bindingId = owner.binding.id;
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

  // Read agent state for trailers
  const paths = statePaths(stateDir);
  const key = await readJsonFile(paths.mainKey, null);
  const owner = await readJsonFile(paths.ownerBinding, null);

  if (!key) {
    outputError("No agent keypair. Run `init` first.");
    return;
  }

  // Build commit message with Agent ID trailers
  const trailers = [
    `Agent-ID-Fingerprint: ${key.fingerprint}`,
  ];
  if (owner?.binding) {
    trailers.push(`Agent-ID-Owner: ${owner.binding.payload.ownerSessionSub}`);
    trailers.push(`Agent-ID-Binding: ${owner.binding.id}`);
  }

  const fullMessage = `${message}\n\n${trailers.join("\n")}`;

  const agentEmail = key.fingerprint ? `agent-${key.fingerprint.slice(0, 8)}@agent-id.local` : "agent@agent-id.local";

  // Commit with SSH signature (uses git config from git-setup)
  // Agent is the author (wrote the code), human committer is preserved from git config
  const commitArgs = ["commit", "-S", "-m", fullMessage, "--author", `Alien Agent <${agentEmail}>`];
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

  // Log to audit trail if bound
  let auditRecord = null;
  if (owner?.binding) {
    try {
      const engine = new SignatureEngine({ baseDir: stateDir });
      await engine.init();
      auditRecord = await engine.appendOperation({
        operationType: "GIT_COMMIT",
        action: "git.commit",
        payload: {
          commitHash,
          message,
          fingerprint: key.fingerprint,
        },
        ctx: { agentId: "main" },
      });
    } catch {
      // Non-fatal — commit succeeded, audit logging is best-effort
      stderr("Warning: could not log commit to audit trail");
    }
  }

  // Attach proof bundle as git note for external verification
  let proofAttached = false;
  if (owner?.binding) {
    try {
      const ownerSession = await readJsonFile(paths.ownerSession, null);
      const proofBundle = {
        version: 1,
        agent: {
          fingerprint: key.fingerprint,
          publicKeyPem: key.publicKeyPem,
        },
        ownerBinding: owner.binding,
        idToken: ownerSession?.idToken || null,
        ssoBaseUrl: ownerSession?.issuer
          ? ownerSession.issuer
          : "https://sso.alien-api.com",
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
    fingerprint: key.fingerprint,
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
  const stateDir = resolveStateDir(flags);
  const commitHash = flags.commit || "HEAD";

  // Step 1: Resolve commit hash
  const revResult = await execFile("git", ["rev-parse", commitHash]);
  if (revResult.code !== 0) {
    outputError(`Cannot resolve commit: ${commitHash}`);
    return;
  }
  const resolvedHash = revResult.stdout.trim();

  // Step 2: Read commit message to extract trailers
  const logResult = await execFile("git", ["log", "-1", "--format=%B", resolvedHash]);
  const commitMessage = logResult.stdout.trim();

  const trailerFingerprint = extractTrailer(commitMessage, "Agent-ID-Fingerprint");
  const trailerOwner = extractTrailer(commitMessage, "Agent-ID-Owner");
  const trailerBinding = extractTrailer(commitMessage, "Agent-ID-Binding");

  if (!trailerFingerprint) {
    outputError(`Commit ${resolvedHash.slice(0, 12)} has no Agent-ID-Fingerprint trailer`);
    return;
  }

  // Step 3: Try to read proof bundle from git note (self-contained, works anywhere)
  let proof = null;
  const noteResult = await execFile(
    "git",
    ["notes", "--ref=agent-id", "show", resolvedHash],
    { timeout: 10000 },
  );
  if (noteResult.code === 0 && noteResult.stdout.trim()) {
    try {
      proof = JSON.parse(noteResult.stdout.trim());
    } catch {
      // Malformed note — fall through to local state
    }
  }

  // Step 4: Fall back to local state if no git note
  let source = "none";
  let agentPublicKeyPem = null;
  let binding = null;
  let idToken = null;
  let ssoBaseUrl = flags["sso-url"] || "https://sso.alien-api.com";

  if (proof?.version === 1 && proof.ownerBinding) {
    source = "git-note";
    agentPublicKeyPem = proof.agent?.publicKeyPem || null;
    binding = proof.ownerBinding;
    idToken = proof.idToken || null;
    ssoBaseUrl = proof.ssoBaseUrl || ssoBaseUrl;
  } else {
    const paths = statePaths(stateDir);
    const key = await readJsonFile(paths.mainKey, null);
    const ownerRecord = await readJsonFile(paths.ownerBinding, null);
    const ownerSession = await readJsonFile(paths.ownerSession, null);
    if (key || ownerRecord || ownerSession) {
      source = "local-state";
      agentPublicKeyPem = key?.publicKeyPem || null;
      binding = ownerRecord?.binding || null;
      idToken = ownerSession?.idToken || null;
    }
  }

  const result = {
    ok: true,
    commit: resolvedHash,
    source,
    agentFingerprint: trailerFingerprint,
    ownerSessionSub: trailerOwner || null,
    bindingId: trailerBinding || null,
    provenance: [],
    warnings: [],
  };

  if (source === "none") {
    result.warnings.push("No proof found — no git note (refs/notes/agent-id) and no local state");
  }

  // Step 5: Verify SSH signature
  // To verify against the note's public key, write a temporary allowed_signers file
  let sshSignatureValid = false;
  if (agentPublicKeyPem) {
    const sshPub = ed25519PemToSshPublicKey(agentPublicKeyPem);
    const tmpSignersPath = path.join(os.tmpdir(), `agent-id-signers-${Date.now()}`);
    const signerEmail = `agent-${trailerFingerprint.slice(0, 8)}@agent-id.local`;
    await fs.writeFile(tmpSignersPath, `${signerEmail} ${sshPub}\n`, "utf8");

    // Configure temporary allowed signers for verification
    const verifyResult = await execFile(
      "git",
      [
        "-c", `gpg.ssh.allowedSignersFile=${tmpSignersPath}`,
        "verify-commit", resolvedHash,
      ],
      { timeout: 10000 },
    );
    sshSignatureValid = verifyResult.code === 0;
    await fs.unlink(tmpSignersPath).catch(() => {});
  } else {
    // Try without — uses whatever git config has
    const verifyResult = await execFile("git", ["verify-commit", "--raw", resolvedHash], { timeout: 10000 });
    sshSignatureValid = verifyResult.code === 0;
  }

  result.sshSignatureValid = sshSignatureValid;
  if (sshSignatureValid) {
    result.provenance.push("SSH commit signature valid");
  } else {
    result.warnings.push("SSH commit signature verification failed");
  }

  // Step 6: Verify agent fingerprint matches embedded public key
  if (agentPublicKeyPem) {
    const computedFingerprint = fingerprintPublicKeyPem(agentPublicKeyPem);
    if (computedFingerprint === trailerFingerprint) {
      result.provenance.push(`Agent public key matches trailer fingerprint (${trailerFingerprint.slice(0, 16)}...)`);
    } else {
      result.warnings.push(`Fingerprint mismatch: trailer=${trailerFingerprint.slice(0, 16)}... key=${computedFingerprint.slice(0, 16)}...`);
    }
  }

  // Step 7: Verify owner binding signature
  if (binding) {
    const bindingPayload = binding.payload;
    const payloadCanonical = canonicalJSONString(bindingPayload);
    const payloadHash = sha256HexCanonical(payloadCanonical);
    const signerPem = bindingPayload.agentInstance?.publicKeyPem;
    const bindingSigOk =
      payloadHash === binding.payloadHash &&
      signerPem &&
      verifyEd25519Base64Url(payloadCanonical, binding.signature, signerPem);

    if (bindingSigOk) {
      result.provenance.push(`Owner binding signature valid (binding: ${binding.id})`);
    } else {
      result.warnings.push("Owner binding signature verification failed");
    }

    if (bindingPayload.agentInstance?.publicKeyFingerprint === trailerFingerprint) {
      result.provenance.push(
        `Binding links agent ${trailerFingerprint.slice(0, 16)}... to owner ${bindingPayload.ownerSessionSub}`,
      );
    } else {
      result.warnings.push("Binding agent fingerprint does not match commit trailer");
    }

    result.ownerSessionSub = bindingPayload.ownerSessionSub;
    result.issuer = bindingPayload.issuer;
    result.providerAddress = bindingPayload.providerAddress;
  }

  // Step 8: Verify id_token server signature against SSO JWKS
  if (idToken) {
    // Verify the id_token hash matches what's in the binding
    if (binding?.payload?.idTokenHash) {
      const actualHash = sha256Hex(idToken);
      if (actualHash === binding.payload.idTokenHash) {
        result.provenance.push("id_token hash matches binding");
      } else {
        result.warnings.push("id_token hash does not match binding");
      }
    }

    try {
      const tokenResult = await verifyIdTokenSignatureOnly({
        idToken,
        ssoBaseUrl,
      });
      result.provenance.push(
        `SSO server signature valid (issuer: ${tokenResult.issuer}, sub: ${tokenResult.payload.sub})`,
      );
      result.ssoSignatureValid = true;
    } catch (err) {
      result.warnings.push(`id_token signature verification: ${err instanceof Error ? err.message : String(err)}`);
      result.ssoSignatureValid = false;
    }
  } else {
    result.warnings.push("No id_token available — cannot verify SSO attestation");
    result.ssoSignatureValid = false;
  }

  // Build summary
  if (result.provenance.length >= 3 && result.sshSignatureValid) {
    const ownerLabel = result.ownerSessionSub || "unknown";
    result.summary = `Commit ${resolvedHash.slice(0, 12)} was signed by agent ${trailerFingerprint.slice(0, 16)}... owned by ${ownerLabel}`;
  } else {
    result.summary = `Commit ${resolvedHash.slice(0, 12)} — provenance chain incomplete (see warnings)`;
    result.ok = result.sshSignatureValid && result.provenance.length > 0;
  }

  outputJson(result);
  if (!result.ok) {
    process.exitCode = 1;
  }
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

  // Try provider.txt next to the CLI
  const scriptDir = path.dirname(new URL(import.meta.url).pathname);
  try {
    const txt = await fs.readFile(path.join(scriptDir, "provider.txt"), "utf8");
    const trimmed = txt.trim();
    if (trimmed) return trimmed;
  } catch {}
  return null;
}

async function cmdBootstrap(flags) {
  const stateDir = resolveStateDir(flags);
  const paths = statePaths(stateDir);

  // 1. Already bootstrapped?
  const existingKey = await readJsonFile(paths.mainKey, null);
  const existingOwner = await readJsonFile(paths.ownerBinding, null);

  if (existingKey && existingOwner?.binding) {
    stderr("Agent ID already bootstrapped.");
    await cmdGitSetup({ ...flags, _quiet: true });
    outputJson({
      ok: true,
      alreadyBootstrapped: true,
      fingerprint: existingKey.fingerprint,
      ownerSessionSub: existingOwner.binding.payload.ownerSessionSub,
      providerAddress: existingOwner.binding.payload.providerAddress,
      stateDir,
    });
    return;
  }

  // 2. Resolve provider address
  const providerAddress = await resolveProviderAddress(flags);
  if (!providerAddress) {
    outputError(
      "No provider address. Set --provider-address, ALIEN_PROVIDER_ADDRESS env, or create provider.txt next to the CLI.",
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
  if (authResult.browserOpened) {
    stderr("QR code opened in browser. Scan with Alien App to authorize this agent.");
  } else {
    stderr(`Open this link with your Alien App: ${authResult.deepLink}`);
  }

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

// ─── Auth Header ────────────────────────────────────────────────────────────────

async function cmdAuthHeader(flags) {
  const stateDir = resolveStateDir(flags);
  const paths = statePaths(stateDir);

  const key = await readJsonFile(paths.mainKey, null);
  if (!key) {
    outputError("No agent keypair. Run `bootstrap` or `init` first.");
    return;
  }

  const owner = await readJsonFile(paths.ownerBinding, null);

  const token = createAgentToken({
    fingerprint: key.fingerprint,
    publicKeyPem: key.publicKeyPem,
    privateKeyPem: key.privateKeyPem,
    ownerSessionSub: owner?.binding?.payload?.ownerSessionSub || null,
  });

  const header = `AgentID ${token}`;

  if (flags.raw) {
    process.stdout.write(`Authorization: ${header}\n`);
  } else {
    outputJson({
      ok: true,
      header: `Authorization: ${header}`,
      token,
      fingerprint: key.fingerprint,
      owner: owner?.binding?.payload?.ownerSessionSub || null,
    });
  }
}

// ─── Help ───────────────────────────────────────────────────────────────────────

function printHelp() {
  stderr(`
Alien Agent ID — Verifiable identity for AI agents

Usage: node cli.mjs <command> [flags]

Commands:
  bootstrap      One-command identity setup (init + auth + bind + git-setup)
  init           Generate Ed25519 keypair and initialize state directory
  auth           Start OIDC authorization (returns deep link + QR page)
  bind           Poll for user approval and create owner binding
  status         Show current Agent ID status
  sign           Sign an operation and append to audit trail
  verify         Verify entire state chain integrity
  export-proof   Export proof bundle to stdout
  git-setup      Configure git to sign commits with Agent ID key
  git-commit     Create a signed commit with Agent ID trailers
  git-verify     Verify provenance chain of a signed commit
  auth-header    Generate a signed authentication token for service calls
  vault-store    Store an encrypted credential in the agent vault
  vault-get      Retrieve a decrypted credential from the vault
  vault-list     List all stored credentials
  vault-remove   Remove a credential from the vault

Bootstrap flags:
  --provider-address <addr>  Provider address (or ALIEN_PROVIDER_ADDRESS env / provider.txt)

Common flags:
  --state-dir <path>       State directory (default: ~/.agent-id)

Auth flags:
  --provider-address <addr>  Provider address (required)
  --sso-url <url>            SSO base URL (default: https://sso.alien-api.com)
  --oidc-origin <origin>     OIDC Origin header (default: http://localhost)

Bind flags:
  --timeout-sec <n>          Poll timeout (default: 300)
  --poll-interval-ms <n>     Poll interval (default: 3000)
  --no-require-owner-proof   Don't require owner session proof

Sign flags:
  --type <type>              Operation type (e.g., TOOL_CALL, MESSAGE_SEND)
  --action <action>          Action name (e.g., bash.exec, message.send)
  --payload <json>           Operation payload as JSON string
  --agent-id <id>            Agent ID (default: main)

Git flags:
  --global                   Apply git config globally (default: local)
  --email <email>            Committer email (default: agent-<fp>@agent-id.local)
  --name <name>              Committer name (default: Agent)
  --message <msg>            Commit message (required for git-commit)
  --allow-empty              Allow empty commits
  --push                     Push commit and proof notes after committing
  --remote <name>            Remote to push to (default: origin)

Git-verify flags:
  --commit <hash>            Commit to verify (default: HEAD)
  --sso-url <url>            SSO base URL for id_token verification

Auth-header flags:
  --raw                      Output raw header (not JSON) for use with curl

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
