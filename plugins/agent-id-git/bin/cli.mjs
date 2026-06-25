#!/usr/bin/env node

// Alien Agent ID — Git plugin CLI.
//
// Git-transport adapter for Alien Agent ID v3 attestation:
//
//   commit  → sign a commit with SSH (gpg.format=ssh), append Agent-ID
//             trailers, log to the audit trail via SignatureEngine, and
//             attach a v3 bundle to refs/notes/agent-id for external
//             verification.
//
//   verify  → read the bundle from refs/notes/agent-id, call the universal
//             verifier (core/bundle.verifyBundle), then add git-specific
//             checks: Agent-ID trailers must agree with the bundle, and
//             the SSH commit signature must validate against agent_jwk.
//
//   setup   → write the agent keypair into SSH-format files under
//             $stateDir/ssh and emit the public key to paste into the
//             user's git host (e.g. GitHub → Settings → SSH/GPG keys).

import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createPublicKey, randomUUID } from "node:crypto";

import {
  ed25519PemToOpenSSHPrivateKey,
  ed25519PemToSshPublicKey,
  ed25519PublicKeyToJwk,
  jwkThumbprint,
} from "../../agent-id-core/lib/crypto.mjs";

import {
  ensureDir,
  readJsonFile,
  setPrivateFilePermissions,
  statePaths,
} from "../../agent-id-core/lib/state.mjs";

import {
  BundleFormatError,
  BundleVerifyError,
  errorMessage,
} from "../../agent-id-core/lib/errors.mjs";

import {
  buildV3Bundle,
  parseBundle,
  verifyBundle,
} from "../../agent-id-core/lib/bundle.mjs";

import {
  ASSURANCE,
  classifyAssurance,
  describeAssurance,
} from "../../agent-id-core/lib/assurance.mjs";

import {
  parseJwt,
  verifyIdTokenSignatureOnly,
} from "../../agent-id-core/lib/oidc.mjs";

import { SignatureEngine } from "../../agent-id-core/lib/signature-engine.mjs";

import {
  execFile,
  outputError,
  outputJson,
  requireAgentKey,
  resolveStateDir,
  runCli,
  stderr,
} from "../../agent-id-core/lib/cli-runtime.mjs";

// ─── Helpers ────────────────────────────────────────────────────────────────────

function extractTrailer(message, key) {
  const re = new RegExp(`^${key}:\\s*(.+)$`, "m");
  const match = message.match(re);
  return match ? match[1].trim() : null;
}

/**
 * Push refs/notes/agent-id to the remote, handling the case where the
 * remote already has notes for other commits.
 *
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

// ─── Commands ───────────────────────────────────────────────────────────────────

async function cmdSetup(flags) {
  const stateDir = resolveStateDir(flags);
  const loaded = await requireAgentKey(stateDir);
  if (!loaded) return;
  const { key, paths } = loaded;

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

async function cmdCommit(flags) {
  const stateDir = resolveStateDir(flags);
  const message = flags.message || flags.m;

  if (!message) {
    outputError("--message <msg> is required");
    return;
  }

  const loaded = await requireAgentKey(stateDir);
  if (!loaded) return;
  const { key, paths } = loaded;

  // Binding is OPTIONAL. A bound agent (L1/L2) attaches its SSO id_token and an
  // `Agent-ID-Owner` trailer; an unbound agent (L0) commits with its key alone
  // — still SSH-signed, still independently verifiable as "this key", just with
  // no human attestation. This is the level-0 "use it immediately" path.
  const session = await readJsonFile(paths.ownerSession, null);
  let idToken = null;
  let idPayload = null;
  if (session?.idToken) {
    try {
      idPayload = parseJwt(session.idToken).payload;
    } catch (err) {
      outputError(`Could not parse id_token: ${errorMessage(err)}`);
      return;
    }
    if (typeof idPayload?.sub !== "string" || !idPayload.sub) {
      outputError("id_token present but missing sub claim — re-bind or remove the stale session.");
      return;
    }
    idToken = session.idToken;
  }
  const level = classifyAssurance(idPayload);

  const agentJwk = ed25519PublicKeyToJwk(key.publicKeyPem);
  const agentJkt = jwkThumbprint(agentJwk);

  const trailers = [`Agent-ID-JKT: ${agentJkt}`];
  // Only a human-backed commit carries an owner trailer (the pairwise pseudonym
  // at L1, the canonical AlienID at L2).
  if (idPayload?.sub) trailers.push(`Agent-ID-Owner: ${idPayload.sub}`);
  trailers.push(`Co-Authored-By: Alien Agent <alienagentid@eti.co>`);

  if (level === ASSURANCE.SELF) {
    stderr(
      "Committing at level 0 (self-asserted: signed by the agent key, no human " +
        "attestation). Run `agent-id-core auth` + `bind` to make later commits human-backed.",
    );
  }

  const fullMessage = `${message}\n\n${trailers.join("\n")}`;

  const privateKeyPath = await ensureSshKey(stateDir, key);

  const commitArgs = [
    "-c", "gpg.format=ssh",
    "-c", "gpg.ssh.program=ssh-keygen",
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

  const hashResult = await execFile("git", ["rev-parse", "HEAD"]);
  const commitHash = hashResult.stdout.trim();

  const auditRecord = await logCommitToAuditTrail(stateDir, { commitHash, message, agentJkt });
  const proofAttached = await attachProofBundle(idToken, agentJwk, commitHash);

  stderr(`Signed commit: ${commitHash.slice(0, 12)} (level ${level} — ${describeAssurance(level)})`);

  const { pushed, notesPushed } = flags.push
    ? await pushCommitAndNotes(flags.remote || "origin", proofAttached)
    : { pushed: false, notesPushed: false };

  const result = {
    ok: true,
    commitHash,
    signed: true,
    level,
    assurance: describeAssurance(level),
    jkt: agentJkt,
    ownerSub: idPayload?.sub || null,
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

async function ensureSshKey(stateDir, key) {
  const sshDir = path.join(stateDir, "ssh");
  await ensureDir(sshDir);
  const privateKeyPath = path.join(sshDir, "agent-id");
  try {
    await fs.access(privateKeyPath);
  } catch {
    const opensshKey = ed25519PemToOpenSSHPrivateKey(key.privateKeyPem);
    await fs.writeFile(privateKeyPath, opensshKey, { encoding: "utf8", mode: 0o600 });
    await setPrivateFilePermissions(privateKeyPath);
  }
  return privateKeyPath;
}

async function logCommitToAuditTrail(stateDir, { commitHash, message, agentJkt }) {
  try {
    const engine = new SignatureEngine({ baseDir: stateDir });
    await engine.init();
    return await engine.appendOperation({
      operationType: "GIT_COMMIT",
      action: "git.commit",
      payload: { commitHash, message, jkt: agentJkt },
      ctx: { agentId: "main" },
    });
  } catch {
    stderr("Warning: could not log commit to audit trail");
    return null;
  }
}

// Attach the v3 proof bundle as a git note. `idToken` is null for an L0
// (self-asserted) commit — the bundle then carries only agent_jwk, so a
// verifier can still check the SSH signature against the key and confirm the
// JKT trailer, and report level 0.
async function attachProofBundle(idToken, agentJwk, commitHash) {
  try {
    const proofBundle = buildV3Bundle({ idToken, agentJwk });
    const noteBody = JSON.stringify(proofBundle);
    const noteResult = await execFile(
      "git",
      ["notes", "--ref=agent-id", "add", "-f", "-m", noteBody, commitHash],
      { timeout: 10000 },
    );
    if (noteResult.code === 0) {
      stderr(
        idToken
          ? "Proof bundle attached as git note (refs/notes/agent-id)."
          : "Self-asserted (L0) proof bundle attached as git note (refs/notes/agent-id).",
      );
      return true;
    }
    stderr(`Warning: could not attach proof note: ${noteResult.stderr.trim()}`);
  } catch {
    stderr("Warning: could not attach proof note");
  }
  return false;
}

async function pushCommitAndNotes(remote, proofAttached) {
  let pushed = false;
  let notesPushed = false;

  const pushResult = await execFile("git", ["push", remote], { timeout: 60000 });
  if (pushResult.code === 0) {
    pushed = true;
    stderr(`Pushed to ${remote}.`);
  } else {
    stderr(`Warning: git push failed: ${pushResult.stderr.trim()}`);
  }

  if (proofAttached) {
    const notesResult = await syncAndPushNotes(remote);
    if (notesResult.ok) {
      notesPushed = true;
      stderr(`Proof notes pushed to ${remote} (${notesResult.method}).`);
    } else {
      stderr(`Warning: could not push proof notes: ${notesResult.error}`);
    }
  }

  return { pushed, notesPushed };
}

async function cmdVerify(flags) {
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

  let parsed;
  try {
    parsed = parseBundle(noteResult.stdout.trim());
  } catch (err) {
    if (err instanceof BundleFormatError) {
      outputError(err.message);
      return;
    }
    throw err;
  }

  // Universal v3 bundle verification: id_token SSO signature, cnf.jkt
  // binding, agent_jwk validity. exp/aud intentionally skipped — commit
  // attestation is historical, not runtime resource access.
  let verified;
  try {
    verified = await verifyBundle(parsed, {
      ssoBaseUrl: flags["sso-url"] || null,
      verifyIdToken: verifyIdTokenSignatureOnly,
    });
  } catch (err) {
    if (err instanceof BundleVerifyError) {
      outputError(err.message);
      return;
    }
    throw err;
  }

  const { jkt: computedJkt, ownerSub, agentJwk, level } = verified;

  // Git-specific binding: trailers in the commit message must agree with
  // the bundle's verified facts. At L0 there is no owner trailer and ownerSub
  // is null; a forged Agent-ID-Owner trailer on an L0 commit still fails here.
  if (trailerOwner && trailerOwner !== ownerSub) {
    outputError(
      `Agent-ID-Owner trailer ${trailerOwner} does not match id_token sub ${ownerSub ?? "(none — level 0)"}`,
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
  // git's gpg.ssh.allowedSignersFile. (agent_jwk is already validated by
  // verifyBundle, so this createPublicKey is expected to succeed.)
  const agentPubKeyPem = createPublicKey({ key: agentJwk, format: "jwk" })
    .export({ type: "spki", format: "pem" });
  const sshPub = ed25519PemToSshPublicKey(agentPubKeyPem);
  const tmpSignersPath = path.join(os.tmpdir(), `agent-id-signers-${randomUUID()}`);
  const signerEmail = `agent-${computedJkt.slice(0, 12)}@agent-id.local`;
  await fs.writeFile(tmpSignersPath, `${signerEmail} ${sshPub}\n`, "utf8");
  let sshOk = false;
  try {
    const verifyResult = await execFile(
      "git",
      [
        "-c", "gpg.ssh.program=ssh-keygen",
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

  const shortJkt = `${computedJkt.slice(0, 16)}...`;
  const summary =
    level === ASSURANCE.SELF
      ? `Commit ${resolvedHash.slice(0, 12)} signed by agent ${shortJkt} — level 0 (self-asserted, no human attestation)`
      : level === ASSURANCE.ANONYMOUS
        ? `Commit ${resolvedHash.slice(0, 12)} signed by agent ${shortJkt} — level 1 (anonymous human-backed, pseudonym ${ownerSub})`
        : `Commit ${resolvedHash.slice(0, 12)} signed by agent ${shortJkt} — level 2, owned by ${ownerSub}`;

  outputJson({
    ok: true,
    commit: resolvedHash,
    level,
    assurance: describeAssurance(level),
    jkt: computedJkt,
    ownerSub,
    issuer: verified.issuer,
    aud: verified.aud,
    iat: verified.iat,
    summary,
  });
}

function printHelp() {
  stderr(
    [
      "agent-id-git — SSH-signed commits with Alien Agent ID provenance",
      "",
      "Subcommands:",
      "  setup                                      Write SSH key files for signing",
      "  commit --message <M> [--push] [--remote R] [--allow-empty]",
      "                                             Signed commit with trailers + v3 proof note",
      "  verify [--commit HASH] [--sso-url URL]     Verify a commit's v3 attestation chain",
      "",
      "Common flags: --state-dir <path> (defaults to AGENT_ID_STATE_DIR or ~/.agent-id)",
    ].join("\n"),
  );
}

const commands = {
  setup: cmdSetup,
  commit: cmdCommit,
  verify: cmdVerify,
};

runCli({ commands, printHelp });
