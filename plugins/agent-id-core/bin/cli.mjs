#!/usr/bin/env node

// Alien Agent ID — Core CLI.
//
// Bootstrap, lifecycle, and universal-operation subcommands:
//
//   bootstrap, init, auth, bind, setup-owner-session, refresh
//                              — establish and maintain the agent identity
//   status                     — show whether an identity exists / is bound
//   sign                       — sign an arbitrary operation into the audit trail
//   verify                     — chain-integrity check on the local audit trail
//   export-proof               — emit a portable proof bundle to stdout
//
// For git-bound commits and verification, use agent-id-git/bin/cli.mjs.
// For DPoP-signed service calls, use agent-id-auth/bin/cli.mjs.
// For credential storage, use agent-id-vault/bin/cli.mjs.

import fs from "node:fs/promises";
import path from "node:path";

import {
  ed25519PublicKeyToJwk,
  fingerprintPublicKeyPem,
  generateEd25519PemPair,
  jwkThumbprint,
  nowMs,
} from "../lib/crypto.mjs";

import {
  ensureDir,
  readJsonFile,
  readJsonl,
  setPrivateFilePermissions,
  statePaths,
  writeJsonFile,
} from "../lib/state.mjs";

import { AuthRevokedError } from "../lib/errors.mjs";

import {
  beginOidcAuthorization,
  exchangeAuthorizationCode,
  parseJwt,
  pollForAuthorizationCode,
  verifyIdToken,
} from "../lib/oidc.mjs";

import {
  SignatureEngine,
  verifyState,
} from "../lib/signature-engine.mjs";

import {
  outputError,
  outputJson,
  resolveStateDir,
  runCli,
  stderr,
} from "../lib/cli-runtime.mjs";

import qrcode from "./qrcode.cjs";

// ─── Helpers ────────────────────────────────────────────────────────────────────

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

async function cmdBootstrap(flags) {
  const stateDir = resolveStateDir(flags);
  const paths = statePaths(stateDir);

  // 1. Already bootstrapped?
  const existingKey = await readJsonFile(paths.mainKey, null);
  const existingSession = await readJsonFile(paths.ownerSession, null);

  if (existingKey && existingSession?.idToken) {
    stderr("Agent ID already bootstrapped.");
    stderr("If you also want git signing, run agent-id-git setup.");
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

  stderr("Bootstrap complete. For git signing, run agent-id-git setup.");
  outputJson({
    ok: true,
    fingerprint: bindResult.fingerprint,
    ownerSessionSub: bindResult.ownerSessionSub,
    bindingId: bindResult.bindingId,
    providerAddress,
    stateDir,
  });
}

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

  stderr("Owner session rebound. For git signing, run agent-id-git setup.");
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

function printHelp() {
  stderr(
    [
      "agent-id-core — bootstrap and lifecycle for Alien Agent ID",
      "",
      "Bootstrap (one-shot, blocks ≤5 min while waiting for Alien App):",
      "  bootstrap [--provider-address ADDR]   Init + auth + bind",
      "",
      "Bootstrap steps (run individually when the QR must be surfaced first):",
      "  init                                  Generate the agent keypair",
      "  auth --provider-address ADDR          Start OIDC authorization (emits deep-link + QR)",
      "  bind [--timeout-sec N]                Poll for approval; bind owner session",
      "  setup-owner-session                   Force a fresh OAuth flow (re-bind, preserves key)",
      "",
      "Operations:",
      "  status                                Show identity / binding state",
      "  refresh                               Refresh the SSO access_token + id_token",
      "  sign --type T --action A --payload J  Sign an arbitrary operation into the audit trail",
      "  verify                                Chain-integrity check on the local audit trail",
      "  export-proof                          Emit owner session + audit trail to stdout",
      "",
      "Common flag: --state-dir <path> (defaults to AGENT_ID_STATE_DIR or ~/.agent-id)",
      "",
      "For git-bound signed commits, use agent-id-git/bin/cli.mjs.",
      "For DPoP-signed service calls, use agent-id-auth/bin/cli.mjs.",
      "For encrypted credential storage, use agent-id-vault/bin/cli.mjs.",
    ].join("\n"),
  );
}

const commands = {
  bootstrap: cmdBootstrap,
  init: cmdInit,
  auth: cmdAuth,
  bind: cmdBind,
  "setup-owner-session": cmdSetupOwnerSession,
  refresh: cmdRefresh,
  status: cmdStatus,
  sign: cmdSign,
  verify: cmdVerify,
  "export-proof": cmdExportProof,
};

runCli({ commands, printHelp });
