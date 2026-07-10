// Alien Agent ID — Local HTTP proxy with two modes:
//
// 1. URL-rewrite (recommended, universal): the agent calls
//      http://localhost:PORT/<credname>/<upstream-host>/<path>
//    The proxy resolves credname, validates the host against that
//    credential's allowlist, materializes the credential into the
//    appropriate request location based on its type, and forwards to
//    the real upstream over HTTPS (or HTTP if the credential opts in).
//    System CA bundle verifies the upstream cert — no TLS interception
//    on our side.
//
// 2. HTTP_PROXY stub injection (legacy, HTTP only): the agent sets
//    HTTP_PROXY and writes `AgentVault <name>` markers in headers / query
//    parameters. Works only for plain HTTP upstream. Kept for backward
//    compatibility; new agents should prefer mode 1.
//
// CONNECT requests are tunneled transparently in both modes — TLS MITM
// is deliberately out of scope (see vault-proxy-mvp-proposal.md).

import http from "node:http";
import https from "node:https";
import net from "node:net";
import path from "node:path";
import { createECDH, createHash, randomBytes, randomUUID } from "node:crypto";
import { URL } from "node:url";

import { rewriteHeaders, rewriteUrl, StubError } from "./stub.mjs";
import {
  injectCredential,
  parseRewritePath,
  prepareUpstreamHeaders,
  resolveCredential,
  RewriteError,
} from "./rewrite.mjs";
import {
  approvalError,
  createControlServer,
  createPendingRegistry,
} from "./control.mjs";
import { OAuthError, refreshAccessToken } from "./oauth.mjs";
import { blockedAddressReason, makeUpstreamLookup } from "./ssrf.mjs";
import { signSolanaRpcBody } from "@alien-id/agent-id-core/lib/solana.mjs";
import { signEvmRpcBody } from "@alien-id/agent-id-core/lib/evm.mjs";
import {
  openVaultWithMasterKey,
  readMobileSlotChallenges,
  readOwnerApprovalChallenge,
} from "@alien-id/agent-id-vault/lib/vault.mjs";
import { effectiveAccess, evaluateAccess } from "@alien-id/agent-id-vault/lib/access.mjs";
import {
  capabilityCredentialBindingHash,
  evaluateCapabilityAccess,
} from "@alien-id/agent-id-vault/lib/capability.mjs";
import { unsealFromPublicKey } from "@alien-id/agent-id-vault/lib/format.mjs";
import { fingerprintOfCertPem, generateControlCert } from "./control-tls.mjs";
import { appendJsonl } from "@alien-id/agent-id-core/lib/state.mjs";
import { withFileLock } from "@alien-id/agent-id-core/lib/file-lock.mjs";

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

function stripHopByHop(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    if (HOP_BY_HOP_HEADERS.has(k.toLowerCase())) continue;
    out[k] = v;
  }
  return out;
}

// Wallet-credential JSON-RPC bodies are buffered so transaction-submitting
// calls (sendTransaction / eth_sendTransaction) can be signed before
// forwarding. A Solana transaction tops out at 1232 bytes and EVM call data
// is rarely larger; 1 MiB leaves generous headroom for batches while
// bounding memory.
const WALLET_MAX_BODY_BYTES = 1024 * 1024;

// Non-read requests on an access-restricted ("ro") credential buffer the body
// so POST-tunneled reads (GraphQL query / JMAP get / JSON-RPC calls) can be
// classified before the write-block applies. Same bound as wallet bodies.
const ACCESS_MAX_BODY_BYTES = 1024 * 1024;
const OAUTH_REFRESH_LOCK_WAIT_MS = 120_000;

// Private, process-local identity for OAuth cache/in-flight work. Unlike the
// capability credential binding, this intentionally ignores policy,
// description, domains, timestamps, and credentialRevision so an owner can
// edit metadata while a provider rotates a refresh token. It includes the
// exact refresh token and OAuth client material, so account/config replacement
// never joins or receives the old refresh result.
function hashOauthMaterial(material) {
  return createHash("sha256").update(JSON.stringify(material)).digest("hex");
}

function oauthClientBindingHash(cred) {
  return hashOauthMaterial([
    cred?.name ?? null,
    cred?.type ?? null,
    cred?.tokenEndpoint ?? null,
    cred?.clientId ?? null,
  ]);
}

function oauthRefreshBindingHash(cred, refreshToken = cred?.refreshToken) {
  const material = [
    oauthClientBindingHash(cred),
    refreshToken ?? null,
  ];
  return hashOauthMaterial(material);
}

function oauthCacheBindingHash(cred, refreshToken = cred?.refreshToken) {
  return hashOauthMaterial([
    oauthRefreshBindingHash(cred, refreshToken),
    cred?.clientSecret ?? null,
    cred?.scope ?? null,
    cred?.accessToken ?? null,
    cred?.accessTokenExpiresAt ?? null,
  ]);
}

// Refresh tokens are commonly single-use. Serialize the exchange across local
// broker processes, then reload under the lease so a waiter advances the token
// chain instead of replaying the predecessor. This lock is separate from the
// vault write lock, so owner policy/metadata edits are not blocked by network
// latency; the typed vault merge reconciles them afterwards.
async function withOauthRefreshLock(baseDir, credentialName, operation) {
  if (!baseDir) throw approvalError("oauth_refresh_lock_unavailable", 503);
  try {
    return await withFileLock(
      {
        directory: path.join(baseDir, "locks"),
        name: `oauth:${credentialName}`,
        timeoutMs: OAUTH_REFRESH_LOCK_WAIT_MS,
        pollMs: 20,
      },
      operation,
    );
  } catch (err) {
    if (err?.code === "FILE_LOCK_BUSY") {
      throw approvalError("oauth_refresh_busy", 503);
    }
    if (err?.code === "FILE_LOCK_LOST") {
      throw approvalError("oauth_refresh_lock_lost", 409);
    }
    throw err;
  }
}

function readRequestBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        const err = new Error(`request body exceeds ${maxBytes} bytes`);
        err.code = "body_too_large";
        err.status = 413;
        reject(err);
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function structuredError(res, status, body) {
  const payload = JSON.stringify({ ok: false, ...body });
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload),
    "X-AgentVault-Proxy-Error": body.error || "unknown",
    // These errors are returned BEFORE the request body is consumed (bad host,
    // access denied, locked, …). On a keep-alive connection Node would parse
    // the unread body as a pipelined request and reject it with a spurious 400,
    // masking our status. Closing the connection discards the leftover body so
    // the client sees this response cleanly.
    Connection: "close",
  });
  res.end(payload);
}

// Default idle window before the proxy zeros the master key. Mirrors
// 1Password's default — long enough that an interactive session isn't
// disrupted, short enough that a long-idle process isn't a fat memory
// target for an attacker. Override via createProxy({ idleTimeoutMs }) or
// the CLI `--idle-timeout` flag.
export const DEFAULT_IDLE_TIMEOUT_MS = 12 * 60 * 60 * 1000;
const IDLE_TICK_MS = 60 * 1000;

export function createProxy({
  vault = null,
  logPath,
  stateDir = null,
  listen = { port: 0, host: "127.0.0.1" },
  idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS,
  now = () => Date.now(),
  onLock = null,
  onUnlock = null,
  // When set, enables the control plane (phone-approved unlock + consent).
  // Shape: { listen?: {port, host}, approvalTimeoutMs?: number }.
  control = null,
  // Per-credential consent: prompt on first use of a (credential, host) pair.
  requireConsent = false,
  // SSRF guard: link-local (incl. cloud metadata), unspecified, and multicast
  // upstream addresses are always refused. Set true to additionally refuse all
  // loopback/RFC1918/ULA/CGNAT targets.
  blockPrivateHosts = false,
  // How long an approved (credential, host) grant stays valid. Infinity = for
  // the life of the process.
  grantTtlMs = 60 * 60 * 1000,
  // Canonical principal for this local broker. A future Frame transport can
  // replace this with `resolvePrincipal(req)` backed by mTLS/DPoP attestation;
  // a request header is deliberately never trusted as identity.
  principal = "agent:local",
  resolvePrincipal = null,
  // Optional fail-closed sink for capability decisions. The production CLI
  // supplies the hash-chained SignatureEngine; tests/embedders may omit it.
  capabilityAudit = null,
}) {
  const controlEnabled = !!control;
  if (controlEnabled && !stateDir) {
    throw new Error("createProxy: control plane requires `stateDir` to unlock the vault");
  }
  if (resolvePrincipal != null && typeof resolvePrincipal !== "function") {
    throw new Error("createProxy: resolvePrincipal must be a function");
  }
  if (capabilityAudit != null && typeof capabilityAudit !== "function") {
    throw new Error("createProxy: capabilityAudit must be a function");
  }
  // Bearer token gating the control plane's credential-bearing routes (pending /
  // approve / deny / register). Auto-generated unless the caller supplies one;
  // exposed as `proxy.controlToken` so the local approver and the pairing flow
  // can present it. Loopback is no longer the sole trust boundary.
  const controlToken = controlEnabled
    ? control.authToken || randomBytes(32).toString("base64url")
    : null;
  // Per-run control-plane ECDH keypair. Approvers seal the master key to this
  // public key (pinned out-of-band via the pairing QR) so it's never sent in
  // cleartext. The private scalar never leaves this process.
  let controlEcdh = null;
  let controlPublicKey = null;
  // TLS for the control plane: on when exposed beyond loopback (or forced via
  // control.tls) so the bearer token isn't sniffable. Loopback stays HTTP.
  let controlTls = null;
  let controlScheme = "http";
  let controlCertFingerprint = null;
  if (controlEnabled) {
    controlEcdh = createECDH("prime256v1");
    controlEcdh.generateKeys();
    controlPublicKey = controlEcdh.getPublicKey().toString("hex");

    const controlHost = (control.listen && control.listen.host) || "127.0.0.1";
    const hostIsLoopback =
      controlHost === "127.0.0.1" || controlHost === "::1" || controlHost === "localhost";
    const wantTls =
      control.tls === true ||
      (control.tls && typeof control.tls === "object") ||
      (control.tls !== false && !hostIsLoopback);
    if (wantTls) {
      if (control.tls && control.tls.certPem && control.tls.keyPem) {
        controlTls = { certPem: control.tls.certPem, keyPem: control.tls.keyPem };
        controlCertFingerprint = control.tls.fingerprint || fingerprintOfCertPem(control.tls.certPem);
      } else {
        const gen = generateControlCert();
        controlTls = { certPem: gen.certPem, keyPem: gen.keyPem };
        controlCertFingerprint = gen.fingerprint;
      }
      controlScheme = "https";
    }
  }

  // Mutable state — vault gets nulled on idle lock; the request handler
  // checks `locked` first and refuses with 401 (or, when the control plane is
  // enabled, parks the request and asks the phone to unlock).
  const state = {
    vault,
    locked: !vault,
    lockedAt: vault ? null : now(),
    lockedReason: vault ? null : "awaiting_unlock",
    lastRequestAt: now(),
    idleTimeoutMs,
    // Approved (credential\0host) → expiry epoch ms (Infinity = no expiry).
    grants: new Map(),
    // De-dupe concurrent prompts: a single in-flight unlock, one per (cred,host).
    unlockInFlight: null,
    grantInFlight: new Map(),
    // oauth2 credentials: cached access tokens (name → {accessToken, expiresAt,
    // refreshToken}) and one in-flight refresh per credential. Cleared on lock.
    oauthTokens: new Map(),
    oauthInFlight: new Map(),
    // Vault handles retained only while an already-sent OAuth exchange may
    // return a provider-rotated refresh token. A lock removes the handle from
    // the data plane immediately, but final wipe is deferred until that token
    // chain is durably merged (or the exchange fails).
    oauthVaultRefs: new Map(),
    // Incremented whenever the vault locks. An OAuth refresh captures this
    // generation before crossing the network and may not publish token
    // material if a lock (even one followed by an unlock) happened meanwhile.
    oauthGeneration: 0,
    capabilityPending: new Map(),
    // Process-lifetime high-water marks catch an authenticated-but-older vault
    // file restored while this broker is alive. Durable rollback protection is
    // delegated to the future Frame/TEE monotonic state.
    capabilityEpochs: new Map(
      Object.entries(vault?.capabilityEpochs?.() || {}).map(([name, epoch]) => [name, epoch]),
    ),
    credentialRevisions: new Map(
      Object.entries(vault?.credentialRevisions?.() || {}).map(([name, revision]) => [
        name,
        revision,
      ]),
    ),
  };

  // Refresh an oauth2 access token this far before its stated expiry, so a token
  // that is valid when injected is still valid when it reaches the upstream.
  const OAUTH_SKEW_MS = 60 * 1000;

  const registry = controlEnabled
    ? createPendingRegistry({ now, timeoutMs: control.approvalTimeoutMs })
    : null;

  // Connect-time SSRF guard for every upstream request (both modes).
  const upstreamLookup = makeUpstreamLookup({ blockPrivate: blockPrivateHosts });

  function touchActivity() {
    state.lastRequestAt = now();
  }

  async function principalForRequest(req) {
    let resolved;
    try {
      resolved = resolvePrincipal ? await resolvePrincipal(req) : principal;
    } catch (err) {
      throw approvalError(err?.code || "principal_invalid", 401);
    }
    if (typeof resolved !== "string" || resolved.length === 0 || resolved.length > 256) {
      throw approvalError("principal_required", 401);
    }
    return resolved;
  }

  function doLock(reason) {
    if (state.locked) {
      registry?.cancelAll(reason || "vault_locked");
      return;
    }
    state.locked = true;
    state.lockedAt = now();
    state.lockedReason = reason;
    if (state.vault) {
      const lockingVault = state.vault;
      state.vault = null;
      if (!state.oauthVaultRefs.has(lockingVault)) lockingVault.lock();
    }
    // Drop cached oauth2 access tokens with the rest of the decrypted material.
    state.oauthGeneration += 1;
    state.oauthTokens.clear();
    state.oauthInFlight.clear();
    // A parked action cannot outlive the credential authority it was waiting
    // to use. Cancel capability/consent entries immediately instead of leaving
    // stale prompts visible until timeout.
    registry?.cancelAll("vault_locked");
    logAccess({ event: "vault_locked", reason }).catch(() => {});
    if (onLock) onLock(reason);
  }

  function retainOauthVault(vaultHandle) {
    state.oauthVaultRefs.set(
      vaultHandle,
      (state.oauthVaultRefs.get(vaultHandle) || 0) + 1,
    );
  }

  function releaseOauthVault(vaultHandle) {
    const remaining = (state.oauthVaultRefs.get(vaultHandle) || 1) - 1;
    if (remaining > 0) {
      state.oauthVaultRefs.set(vaultHandle, remaining);
      return;
    }
    state.oauthVaultRefs.delete(vaultHandle);
    if (state.locked || state.vault !== vaultHandle) vaultHandle.lock();
  }

  function applyUnlock(openedVault) {
    state.vault = openedVault;
    state.locked = false;
    state.lockedAt = null;
    state.lockedReason = null;
    touchActivity();
  }

  // ── Unlock-on-demand (control plane) ──────────────────────────────────────
  // Park the caller until the phone unseals a mobile slot and POSTs the master
  // key back. Concurrent callers share one in-flight unlock.
  async function requireUnlock() {
    if (!state.locked && state.vault) return;
    if (!controlEnabled) throw approvalError("vault_locked", 401);
    if (!state.unlockInFlight) {
      state.unlockInFlight = (async () => {
        // Two unlock methods can satisfy a parked request: a phone unsealing a
        // mobile slot, or an owner approving an SSO release of an owner-approval
        // slot. Surface whichever the vault carries; the approver POSTs the
        // recovered master key to /approve in both cases.
        const challenges = await readMobileSlotChallenges(stateDir);
        const ownerApproval = await readOwnerApprovalChallenge(stateDir);
        if (!challenges.length && !ownerApproval) {
          throw approvalError("no_unlock_method", 401);
        }
        const { id, promise } = registry.create({
          action: "unlock",
          reason: state.lockedReason || "locked",
          challenges,
          ownerApproval,
        });
        logAccess({ event: "unlock_requested", requestId: id }).catch(() => {});
        await promise; // resolved by onApprove once the vault is open
      })().finally(() => {
        state.unlockInFlight = null;
      });
    }
    await state.unlockInFlight;
  }

  // ── Per-credential consent (control plane) ────────────────────────────────
  function grantKey(name, host) {
    return `${name}\x00${host}`;
  }

  async function requireGrant(name, host) {
    if (!requireConsent) return;
    const key = grantKey(name, host);
    const exp = state.grants.get(key);
    if (exp != null && (exp === Infinity || exp > now())) return;
    if (!controlEnabled) throw approvalError("consent_required", 403);

    let inFlight = state.grantInFlight.get(key);
    if (!inFlight) {
      const { id, promise } = registry.create({
        action: "authorize",
        credential: name,
        host,
      });
      logAccess({ event: "consent_requested", requestId: id, credential: name, host }).catch(
        () => {},
      );
      inFlight = promise
        .then(() => {
          state.grants.set(key, Number.isFinite(grantTtlMs) ? now() + grantTtlMs : Infinity);
        })
        .finally(() => state.grantInFlight.delete(key));
      state.grantInFlight.set(key, inFlight);
    }
    await inFlight;
  }

  async function auditCapability(event) {
    await logAccess(event);
    if (capabilityAudit) await capabilityAudit(event);
  }

  // Park exactly ONE request for an exact, body-bound capability approval.
  // No de-duplication: two identical purchases are two independent asks.
  async function requireCapabilityApproval({ req, res, credential, requestContext, decision }) {
    if (!controlEnabled || !registry) {
      throw approvalError("approval_unavailable", 503);
    }
    const info = {
      action: "capability",
      actionDigest: decision.actionDigest,
      principal: requestContext.principal,
      credential: credential.name,
      capability: decision.capability,
      capabilities: decision.capabilities,
      grants: decision.grants,
      preview: decision.preview,
      policyEpoch: decision.policyEpoch,
      policyHash: decision.policyHash,
      expiresAtMs: decision.envelope.expiresAtMs,
    };
    const { id, promise } = registry.create(info);
    // The entry becomes visible to the simulator immediately; it may deny while
    // the signed request audit is still being appended. Mark the rejection as
    // observed now, while retaining the original promise for the later await.
    promise.catch(() => {});
    state.capabilityPending.set(id, decision.actionDigest);
    // Install disconnect handling before the first await after publishing the
    // pending entry. Otherwise a fast client close can occur while the signed
    // request audit is appending and its event would be missed, leaving an
    // orphan entry visible to an approver.
    const onAborted = () => registry.reject(id, "client_aborted");
    req.once("aborted", onAborted);
    res.once("close", onAborted);
    // IncomingMessage.destroyed is also true after a normally consumed body,
    // so only its explicit `aborted` flag indicates a lost caller here.
    if (req.aborted || res.destroyed) onAborted();
    try {
      // The approval UI receives the explicitly configured preview through
      // /pending. Audit records deliberately keep only commitments and policy
      // metadata so ordinary logs never become a second store for request data.
      await auditCapability({
        event: "capability_requested",
        requestId: id,
        action: info.action,
        actionDigest: info.actionDigest,
        principal: info.principal,
        credential: info.credential,
        capability: info.capability,
        capabilities: info.capabilities,
        grantIds: decision.grantIds,
        policyEpoch: info.policyEpoch,
        policyHash: info.policyHash,
        expiresAtMs: info.expiresAtMs,
      });
    } catch (error) {
      registry.reject(id, "capability_audit_failed");
      req.removeListener("aborted", onAborted);
      res.removeListener("close", onAborted);
      state.capabilityPending.delete(id);
      throw error;
    }

    let approval;
    try {
      approval = await promise;
    } finally {
      req.removeListener("aborted", onAborted);
      res.removeListener("close", onAborted);
      state.capabilityPending.delete(id);
    }
    if (
      !approval ||
      approval.scope !== "once" ||
      approval.actionDigest !== decision.actionDigest
    ) {
      throw approvalError("approval_digest_mismatch", 409);
    }
    if (now() >= decision.envelope.expiresAtMs) {
      throw approvalError("approval_expired", 409);
    }
    if (res.destroyed) throw approvalError("client_aborted", 409);

    // Re-evaluate immediately before any OAuth refresh, key signing, credential
    // injection, or upstream socket creation. A policy/epoch/request mutation
    // changes the digest and invalidates the one-shot ticket.
    await state.vault?.reload?.();
    observeCapabilityEpoch(credential.name);
    const live = lookup(credential.name);
    if (!live) throw approvalError("approval_stale_policy", 409);
    const rechecked = evaluateCapabilityAccess(live, { ...requestContext, nowMs: now() });
    if (
      rechecked.actionDigest !== decision.actionDigest ||
      rechecked.policyEpoch !== decision.policyEpoch ||
      rechecked.policyHash !== decision.policyHash ||
      rechecked.verdict === "deny"
    ) {
      throw approvalError("approval_stale_policy", 409);
    }
    await auditCapability({
      event: "capability_approved",
      requestId: id,
      actionDigest: decision.actionDigest,
      principal: requestContext.principal,
      credential: credential.name,
      capability: decision.capability,
      capabilities: decision.capabilities,
      grantIds: decision.grantIds,
      policyEpoch: decision.policyEpoch,
      policyHash: decision.policyHash,
      scope: "once",
    });
    return rechecked;
  }

  // ── oauth2: refresh-on-demand access tokens ───────────────────────────────
  // Return a currently-valid access token for an `oauth2` credential, refreshing
  // from the stored refresh token when the cached one is missing or near expiry.
  // Concurrent requests for the same credential share one in-flight refresh.
  async function resolveOauth2Bearer(cred) {
    const oauthMaterialHash = oauthCacheBindingHash(cred);
    const oauthRefreshHash = oauthRefreshBindingHash(cred);
    const oauthGeneration = state.oauthGeneration;
    const fresh = (entry, expectedHash = oauthMaterialHash) =>
      entry &&
      entry.oauthMaterialHash === expectedHash &&
      entry.accessToken &&
      entry.expiresAt - OAUTH_SKEW_MS > now();

    const cachedEntry = state.oauthTokens.get(cred.name);
    const cached = cachedEntry?.oauthMaterialHash === oauthMaterialHash ? cachedEntry : null;
    if (fresh(cached)) return cached.accessToken;

    // Honor a seeded access token on the record (skips the first refresh).
    if (
      !cached &&
      cred.accessToken &&
      cred.accessTokenExpiresAt &&
      cred.accessTokenExpiresAt - OAUTH_SKEW_MS > now()
    ) {
      state.oauthTokens.set(cred.name, {
        accessToken: cred.accessToken,
        expiresAt: cred.accessTokenExpiresAt,
        refreshToken: cred.refreshToken,
        oauthMaterialHash,
      });
      return cred.accessToken;
    }

    let inFlight = state.oauthInFlight.get(cred.name);
    if (!inFlight || inFlight.oauthRefreshHash !== oauthRefreshHash) {
      const refreshLockDir = state.vault?.stateDir || stateDir;
      const promise = withOauthRefreshLock(refreshLockDir, cred.name, async () => {
        if (
          state.oauthGeneration !== oauthGeneration ||
          state.locked ||
          !state.vault
        ) {
          throw approvalError("oauth_refresh_stale", 409);
        }

        // Another broker may have rotated the chain while we waited. Reload and
        // refresh the current token, never the predecessor captured by this
        // request. Infrastructure rotation preserves credentialRevision; a
        // user replacement that changes the token forces this request to retry.
        await state.vault.reload();
        observeCapabilityEpoch(cred.name);
        const leasedCredential = state.vault.get(cred.name);
        if (
          !leasedCredential ||
          leasedCredential.type !== "oauth2" ||
          oauthClientBindingHash(leasedCredential) !== oauthClientBindingHash(cred) ||
          (leasedCredential.refreshToken !== cred.refreshToken &&
            leasedCredential.credentialRevision !== cred.credentialRevision)
        ) {
          throw approvalError("oauth_credential_changed", 409);
        }

        const leasedCacheHash = oauthCacheBindingHash(leasedCredential);
        const leaseCached = state.oauthTokens.get(cred.name);
        if (fresh(leaseCached, leasedCacheHash)) return leaseCached.accessToken;
        if (
          leasedCredential.accessToken &&
          leasedCredential.accessTokenExpiresAt &&
          leasedCredential.accessTokenExpiresAt - OAUTH_SKEW_MS > now()
        ) {
          const seeded = {
            accessToken: leasedCredential.accessToken,
            expiresAt: leasedCredential.accessTokenExpiresAt,
            refreshToken: leasedCredential.refreshToken,
            oauthMaterialHash: leasedCacheHash,
          };
          if (
            state.oauthGeneration !== oauthGeneration ||
            state.locked ||
            !state.vault
          ) {
            throw approvalError("oauth_refresh_stale", 409);
          }
          state.oauthTokens.set(cred.name, seeded);
          return seeded.accessToken;
        }

        const refreshToken = leasedCredential.refreshToken;
        const leasedRefreshHash = oauthRefreshBindingHash(
          leasedCredential,
          refreshToken,
        );
        const oauthVault = state.vault;
        retainOauthVault(oauthVault);
        try {
        let res;
        try {
          res = await refreshAccessToken({
            tokenEndpoint: leasedCredential.tokenEndpoint,
            clientId: leasedCredential.clientId,
            clientSecret: leasedCredential.clientSecret || null,
            refreshToken,
            scope: leasedCredential.scope || null,
          });
        } catch (err) {
          // invalid_grant means the refresh token is revoked/expired → the owner
          // must re-mint it; surface 401. Anything else is an upstream fault → 502.
          const isAuth = err instanceof OAuthError && err.oauthError === "invalid_grant";
          const e = new Error(
            isAuth
              ? `oauth2 credential '${cred.name}' refresh token rejected (invalid_grant) — re-mint it`
              : `oauth2 credential '${cred.name}' refresh failed: ${err.message}`,
          );
          e.code = isAuth ? "oauth_refresh_token_invalid" : "oauth_refresh_failed";
          e.status = isAuth ? 401 : 502;
          logAccess({ event: "oauth_refresh_failed", credential: cred.name, reason: e.code }).catch(
            () => {},
          );
          throw e;
        }

        // A rotating response must be durably merged even if an idle/manual
        // lock happened after the exchange was sent; otherwise a single-use
        // provider can invalidate the only token stored on disk. The retained
        // handle is no longer reachable from the data plane and will be wiped
        // in finally. Cache/injection still fail below on generation mismatch.
        const current = oauthVault.get(cred.name);
        if (
          !current ||
          (oauthRefreshBindingHash(current) !== leasedRefreshHash &&
            (!res.refreshToken ||
              oauthRefreshBindingHash(current) !==
                oauthRefreshBindingHash(leasedCredential, res.refreshToken)))
        ) {
          throw approvalError("oauth_credential_changed", 409);
        }

        // Merge a rotated refresh token into the newest vault revision. The
        // vault method permits metadata/policy edits but compares the exact
        // OAuth identity and old token under its file lock.
        let persistedCredential = current;
        if (res.refreshToken && res.refreshToken !== refreshToken) {
          try {
            persistedCredential = await oauthVault.rotateOauthRefreshToken({
              name: cred.name,
              expectedCredential: leasedCredential,
              expectedRefreshToken: refreshToken,
              nextRefreshToken: res.refreshToken,
            });
          } catch (err) {
            if (err?.code === "OAUTH_CREDENTIAL_CHANGED") {
              throw approvalError("oauth_credential_changed", 409);
            }
            const persistenceError = approvalError("oauth_refresh_persist_failed", 409);
            persistenceError.cause = err;
            throw persistenceError;
          }
        } else {
          if (
            state.oauthGeneration !== oauthGeneration ||
            state.locked ||
            state.vault !== oauthVault
          ) {
            throw approvalError("oauth_refresh_stale", 409);
          }
          // Observe seed/client metadata edits that landed during an exchange
          // even when the provider did not rotate the refresh token.
          await oauthVault.reload();
          persistedCredential = oauthVault.get(cred.name);
          if (
            !persistedCredential ||
            oauthRefreshBindingHash(persistedCredential, refreshToken) !==
              leasedRefreshHash
          ) {
            throw approvalError("oauth_credential_changed", 409);
          }
        }
        if (
          state.oauthGeneration !== oauthGeneration ||
          state.locked ||
          state.vault !== oauthVault
        ) {
          throw approvalError("oauth_refresh_stale", 409);
        }
        const finalRefreshToken = res.refreshToken || refreshToken;
        const finalCacheHash = oauthCacheBindingHash(
          persistedCredential,
          finalRefreshToken,
        );
        if (
          finalCacheHash !==
          oauthCacheBindingHash(leasedCredential, finalRefreshToken)
        ) {
          // A concurrently installed seeded access token must win. The refresh
          // token rotation is already durably merged, but this old response is
          // neither cached nor injected under the new seed identity.
          throw approvalError("oauth_credential_changed", 409);
        }
        const entry = {
          accessToken: res.accessToken,
          expiresAt: now() + res.expiresInSec * 1000,
          refreshToken: finalRefreshToken,
          oauthMaterialHash: finalCacheHash,
        };
        if (
          state.oauthGeneration !== oauthGeneration ||
          state.locked ||
          state.vault !== oauthVault
        ) {
          throw approvalError("oauth_refresh_stale", 409);
        }
        state.oauthTokens.set(cred.name, entry);
        logAccess({ event: "oauth_refreshed", credential: cred.name }).catch(() => {});
        return entry.accessToken;
        } finally {
          releaseOauthVault(oauthVault);
        }
      });
      inFlight = { oauthRefreshHash, promise };
      state.oauthInFlight.set(cred.name, inFlight);
      const cleanup = () => {
        if (state.oauthInFlight.get(cred.name)?.promise === promise) {
          state.oauthInFlight.delete(cred.name);
        }
      };
      promise.then(cleanup, cleanup);
    }
    return inFlight.promise;
  }

  // ── Control-plane approval handlers (called by the control server) ────────
  async function onApprove(id, body) {
    const entry = registry.get(id);
    if (!entry) return { ok: false, error: "unknown_request", status: 404 };

    if (entry.action === "unlock") {
      // The master key is ALWAYS delivered sealed to the proxy's control-plane
      // public key — never in cleartext — so it stays confidential even over a
      // plain-HTTP control plane on a LAN. The approver gets that public key
      // out-of-band (the pairing QR), so an on-path attacker can't substitute it.
      if (!body.sealedMasterKey) {
        return { ok: false, error: "sealed_master_key_required", status: 400 };
      }
      let mk;
      try {
        mk = unsealFromPublicKey(body.sealedMasterKey, controlEcdh.getPrivateKey());
      } catch {
        return { ok: false, error: "unseal_failed", status: 400 };
      }
      let opened;
      try {
        opened = await openVaultWithMasterKey({ stateDir, masterKey: mk });
      } catch {
        return { ok: false, error: "unlock_failed", status: 400 };
      } finally {
        mk.fill(0);
      }
      // Async unseal/open may race a deny, timeout, or duplicate approval. Win
      // the registry exactly once before publishing the opened handle; a loser
      // immediately zeroes its private copy instead of unlocking late.
      if (!registry.resolve(id, { unlocked: true })) {
        opened.lock();
        return { ok: false, error: "approval_already_settled", status: 409 };
      }
      applyUnlock(opened);
      logAccess({ event: "vault_unlocked", via: "control_plane", requestId: id }).catch(() => {});
      if (onUnlock) onUnlock(entry);
      return { ok: true, body: { action: "unlock", unlocked: true } };
    }

    if (entry.action === "authorize") {
      if (!registry.resolve(id, { approved: true })) {
        return { ok: false, error: "approval_already_settled", status: 409 };
      }
      logAccess({
        event: "consent_granted",
        requestId: id,
        credential: entry.credential,
        host: entry.host,
      }).catch(() => {});
      return { ok: true, body: { action: "authorize", approved: true } };
    }

    if (entry.action === "capability") {
      if (!body.actionDigest) {
        return { ok: false, error: "action_digest_required", status: 400 };
      }
      if (body.scope !== "once") {
        return { ok: false, error: "approval_scope_must_be_once", status: 400 };
      }
      if (body.actionDigest !== entry.actionDigest) {
        return { ok: false, error: "action_digest_mismatch", status: 409 };
      }
      if (now() >= entry.expiresAtMs) {
        registry.reject(id, "approval_expired");
        return { ok: false, error: "approval_expired", status: 409 };
      }
      const resolved = registry.resolve(id, {
        approved: true,
        actionDigest: entry.actionDigest,
        scope: "once",
      });
      if (!resolved) {
        return { ok: false, error: "approval_already_settled", status: 409 };
      }
      logAccess({
        event: "capability_approval_received",
        requestId: id,
        actionDigest: entry.actionDigest,
        principal: entry.principal,
        credential: entry.credential,
        capability: entry.capability,
      }).catch(() => {});
      return {
        ok: true,
        body: {
          action: "capability",
          approved: true,
          actionDigest: entry.actionDigest,
          scope: "once",
        },
      };
    }

    return { ok: false, error: "unknown_action", status: 400 };
  }

  function onDeny(id, body) {
    const entry = registry.get(id);
    if (
      entry?.action === "capability" &&
      body.actionDigest &&
      body.actionDigest !== entry.actionDigest
    ) {
      return false;
    }
    if (entry) {
      logAccess({ event: `${entry.action}_denied`, requestId: id }).catch(() => {});
    }
    return registry.reject(id, body.reason || "denied");
  }

  // ── Pairing: a phone self-registers its public key (no CLI rekey) ─────────
  // The vault must be unlocked (so we can seal the master key to the device).
  // The normal setup is: proxy starts unlocked via the agent key, phone taps
  // "Pair" once; thereafter idle-lock → phone slide-to-unlock.
  async function onRegister(body) {
    const pub = body.devicePubKey;
    if (!/^04[0-9a-fA-F]{128}$/.test(pub || "")) {
      return { ok: false, error: "bad_device_pubkey", status: 400 };
    }
    const existing = await readMobileSlotChallenges(stateDir);
    if (existing.some((c) => c.devicePubKey === pub)) {
      return { ok: true, body: { alreadyPaired: true } };
    }
    if (state.locked || !state.vault) {
      return { ok: false, error: "vault_locked", status: 409 };
    }
    const slot = state.vault.addMobileSlot(pub, body.deviceId || null);
    await state.vault.save();
    logAccess({ event: "mobile_registered", slotId: slot.id, deviceId: body.deviceId || null }).catch(
      () => {},
    );
    return { ok: true, body: { slotId: slot.id, deviceId: body.deviceId || null } };
  }

  async function deviceList() {
    try {
      return (await readMobileSlotChallenges(stateDir)).map((c) => ({
        slotId: c.slotId,
        deviceId: c.deviceId,
        devicePubKey: c.devicePubKey,
      }));
    } catch {
      return [];
    }
  }

  // Idle ticker. unref()'d so it never holds the process open by itself.
  let ticker = null;
  if (Number.isFinite(idleTimeoutMs) && idleTimeoutMs > 0) {
    ticker = setInterval(() => {
      if (state.locked) return;
      if (now() - state.lastRequestAt > idleTimeoutMs) {
        doLock("idle_timeout");
      }
    }, Math.min(IDLE_TICK_MS, idleTimeoutMs));
    if (ticker.unref) ticker.unref();
  }

  const lookup = (name) => (state.vault ? state.vault.get(name) : null);

  function observeCapabilityEpoch(name) {
    const persisted = state.vault?.capabilityEpochs?.()?.[name] || 0;
    const record = lookup(name);
    const epoch = Math.max(
      persisted,
      record?.capabilityPolicyEpoch || 0,
      record?.capabilityPolicy?.epoch || 0,
    );
    const highWater = state.capabilityEpochs.get(name) || 0;
    if (epoch < highWater) throw approvalError("capability_epoch_rollback", 409);
    if (epoch > highWater) state.capabilityEpochs.set(name, epoch);
    const persistedRevision = state.vault?.credentialRevisions?.()?.[name] || 0;
    const revision = Math.max(persistedRevision, record?.credentialRevision || 0);
    const revisionHighWater = state.credentialRevisions.get(name) || 0;
    if (revision < revisionHighWater) {
      throw approvalError("credential_revision_rollback", 409);
    }
    if (revision > revisionHighWater) state.credentialRevisions.set(name, revision);
    return record;
  }

  async function logAccess(entry) {
    try {
      await appendJsonl(logPath, { ts: new Date().toISOString(), ...entry });
    } catch {
      // never let logging break a request
    }
  }

  // Stream the agent's request through to the configured upstream. Shared
  // by both URL-rewrite and stub-injection paths.
  function forwardUpstream({
    req,
    res,
    upstreamScheme,
    upstreamHostname,
    upstreamPort,
    upstreamPath,
    upstreamHost,
    headers,
    credentialNames,
    logHost,
    logPath,
    start,
    // When set, this Buffer is sent as the request body instead of piping the
    // agent's (already-consumed) stream — used by the solana signing step.
    bodyOverride = null,
  }) {
    let bytesIn = 0;
    let bytesOut = 0;

    // SSRF guard, layer 1: a literal-IP upstream is checked synchronously, since
    // Node skips `lookup` for IP literals (so the connect-time guard below only
    // covers hostnames / DNS rebinding). 169.254.169.254 et al. are refused here.
    const literalBlock = blockedAddressReason(upstreamHostname, {
      blockPrivate: blockPrivateHosts,
    });
    if (literalBlock) {
      structuredError(res, 403, {
        error: "upstream_blocked",
        message: `blocked upstream address: ${upstreamHostname} (${literalBlock})`,
      });
      logAccess({
        method: req.method,
        host: logHost,
        path: logPath,
        status: 403,
        credentials: credentialNames,
        durationMs: Date.now() - start,
        error: "upstream_blocked",
      });
      return;
    }

    const client = upstreamScheme === "https" ? https : http;
    const port = upstreamPort || (upstreamScheme === "https" ? 443 : 80);

    const finalHeaders = { ...headers, host: upstreamHost };
    if (bodyOverride != null) {
      finalHeaders["content-length"] = String(bodyOverride.length);
    }

    const upstreamReq = client.request({
      protocol: `${upstreamScheme}:`,
      hostname: upstreamHostname,
      port,
      method: req.method,
      path: upstreamPath,
      headers: finalHeaders,
      lookup: upstreamLookup,
    });

    upstreamReq.on("error", (err) => {
      // SSRF guard rejected the resolved address → 403, not a generic 502.
      const blocked = err.code === "ESSRFBLOCKED";
      if (!res.headersSent) {
        if (blocked) {
          structuredError(res, 403, { error: "upstream_blocked", message: err.message });
        } else {
          structuredError(res, 502, { error: "upstream_error", message: err.message });
        }
      } else {
        res.destroy();
      }
      logAccess({
        method: req.method,
        host: logHost,
        path: logPath,
        status: 502,
        credentials: credentialNames,
        bytesIn,
        bytesOut,
        durationMs: Date.now() - start,
        error: err.code || err.message,
      });
    });

    upstreamReq.on("response", (upstreamRes) => {
      res.writeHead(upstreamRes.statusCode, stripHopByHop(upstreamRes.headers));
      upstreamRes.on("data", (chunk) => {
        bytesOut += chunk.length;
      });
      upstreamRes.pipe(res);
      upstreamRes.on("end", () => {
        logAccess({
          method: req.method,
          host: logHost,
          path: logPath,
          status: upstreamRes.statusCode,
          credentials: credentialNames,
          bytesIn,
          bytesOut,
          durationMs: Date.now() - start,
        });
      });
    });

    if (bodyOverride != null) {
      bytesIn = bodyOverride.length;
      upstreamReq.end(bodyOverride);
    } else {
      req.on("data", (chunk) => {
        bytesIn += chunk.length;
      });
      req.pipe(upstreamReq);
    }
  }

  // ── URL-rewrite mode (recommended) ────────────────────────────────────────
  async function handleUrlRewrite(req, res, parsed, start, requestPrincipal) {
    // Vault locked? Park the request and ask the phone to unlock. Throws an
    // approvalError (mapped to a status by the caller) on deny / timeout.
    await requireUnlock();
    await state.vault?.reload?.();
    observeCapabilityEpoch(parsed.credname);

    let cred;
    try {
      cred = resolveCredential({
        credname: parsed.credname,
        host: parsed.host,
        lookup,
      });
    } catch (err) {
      if (err instanceof RewriteError) {
        const status = err.code === "credential_not_found" ? 400 : 403;
        return structuredError(res, status, {
          error: err.code,
          message: err.message,
          credential: err.credential || null,
          host: err.host || null,
          allowed: err.allowed || null,
        });
      }
      throw err;
    }

    // ── Capability/access gate ───────────────────────────────────────────────
    // Capability-managed requests are committed to their exact target, headers,
    // query, and raw body before any secret is materialized. The legacy ro/rw
    // classifier remains byte-for-byte compatible when no capability policy is
    // attached.
    const targetForPolicy = new URL(
      `${cred.upstreamScheme || "https"}://${parsed.host}${parsed.restAndQuery}`,
    );
    const bareHost = targetForPolicy.hostname;
    const reqPathname = targetForPolicy.pathname;
    const normalizedAgentSearch = targetForPolicy.searchParams.toString();
    const agentHeadersForPolicy = prepareUpstreamHeaders({
      incoming: req.headers,
      upstreamHost: targetForPolicy.host,
    });
    let accessBody = null; // set when the gate had to consume the request stream
    const contentLength = Number(req.headers["content-length"] || 0);
    const mayHaveBody =
      !["GET", "HEAD", "OPTIONS"].includes(String(req.method || "GET").toUpperCase()) ||
      contentLength > 0 ||
      req.headers["transfer-encoding"] != null;
    if (cred.capabilityPolicy && mayHaveBody) {
      accessBody = await readRequestBody(req, ACCESS_MAX_BODY_BYTES);
    }

    const capabilityContext = cred.capabilityPolicy
      ? {
          principal: requestPrincipal,
          credential: cred.name,
          method: req.method,
          scheme: cred.upstreamScheme || "https",
          host: bareHost,
          port: targetForPolicy.port,
          path: reqPathname,
          query: normalizedAgentSearch ? `?${normalizedAgentSearch}` : "",
          // Commit the same agent-controlled header view that forwarding uses:
          // hop-by-hop/local Origin/Referer are stripped and Host is normalized.
          // Credential material is injected only after authorization.
          headers: agentHeadersForPolicy,
          body: accessBody || Buffer.alloc(0),
          nonce: randomUUID(),
          nowMs: now(),
          expiresAtMs: now() + (control?.approvalTimeoutMs || 120_000),
        }
      : null;

    let decision = cred.capabilityPolicy
      ? evaluateCapabilityAccess(cred, capabilityContext)
      : evaluateAccess(cred, {
          method: req.method,
          host: bareHost,
          path: reqPathname,
        });
    if (
      cred.capabilityPolicy &&
      mayHaveBody &&
      (cred.type === "solana-keypair" || cred.type === "evm-keypair")
    ) {
      await auditCapability({
        event: "capability_adapter_required",
        credential: cred.name,
        principal: requestPrincipal,
        actionDigest: decision.actionDigest,
        capability: decision.capability,
        capabilities: decision.capabilities,
        grantIds: decision.grantIds,
        policyEpoch: decision.policyEpoch,
        policyHash: decision.policyHash,
      });
      return structuredError(res, 403, {
        error: "capability_adapter_required",
        message:
          "Capability-controlled wallet POSTs require a versioned transaction adapter; " +
          "generic HTTP approval cannot cover the signed body transformation.",
        credential: cred.name,
      });
    }
    if (!decision.allowed && decision.needsBody) {
      accessBody = await readRequestBody(req, ACCESS_MAX_BODY_BYTES);
      decision = evaluateAccess(cred, {
        method: req.method,
        host: bareHost,
        path: reqPathname,
        body: accessBody.toString("utf8"),
      });
    }
    const capabilityWasApproved = decision.verdict === "ask";
    if (capabilityWasApproved) {
      decision = await requireCapabilityApproval({
        req,
        res,
        credential: cred,
        requestContext: capabilityContext,
        decision,
      });
    } else if (!decision.allowed) {
      // Drain any unconsumed request body (a write's payload) so the HTTP
      // framing stays clean before we send the denial on this connection.
      if (accessBody == null) req.resume();
      const event = decision.actionDigest ? "capability_denied" : "access_denied";
      const denial = {
        event,
        credential: cred.name,
        principal: requestPrincipal,
        host: parsed.host,
        method: req.method,
        path: reqPathname,
        access: effectiveAccess(cred),
        reason: decision.reason,
        ...(decision.actionDigest
          ? {
              actionDigest: decision.actionDigest,
              capability: decision.capability,
              capabilities: decision.capabilities,
              grantIds: decision.grantIds,
              policyEpoch: decision.policyEpoch,
              policyHash: decision.policyHash,
            }
          : {}),
      };
      if (decision.actionDigest) await auditCapability(denial);
      else logAccess(denial);
      return structuredError(res, 403, {
        error: decision.actionDigest ? "capability_denied" : "access_denied",
        message:
          `credential '${cred.name}' does not permit ${req.method} ${reqPathname} ` +
          `on ${parsed.host} (${decision.reason}).`,
        credential: cred.name,
        host: parsed.host,
        access: effectiveAccess(cred),
        reason: decision.reason,
        ...(decision.actionDigest
          ? {
              actionDigest: decision.actionDigest,
              capability: decision.capability,
              capabilities: decision.capabilities,
              policyEpoch: decision.policyEpoch,
            }
          : {}),
      });
    }

    if (decision.actionDigest && !capabilityWasApproved) {
      await auditCapability({
        event: "capability_allowed",
        credential: cred.name,
        principal: requestPrincipal,
        host: parsed.host,
        method: req.method,
        path: reqPathname,
        actionDigest: decision.actionDigest,
        capability: decision.capability,
        capabilities: decision.capabilities,
        grantIds: decision.grantIds,
        policyEpoch: decision.policyEpoch,
        policyHash: decision.policyHash,
      });
    }

    const ensureCurrentCapability = async () => {
      await state.vault?.reload?.();
      observeCapabilityEpoch(parsed.credname);
      let liveCred;
      try {
        liveCred = resolveCredential({
          credname: parsed.credname,
          host: parsed.host,
          lookup,
        });
      } catch {
        throw approvalError("capability_policy_changed", 409);
      }
      if (!cred.capabilityPolicy && liveCred.capabilityPolicy) {
        throw approvalError("capability_policy_changed", 409);
      }
      if (!cred.capabilityPolicy) return { credential: liveCred, finalDecision: decision };
      if (!liveCred.capabilityPolicy) {
        throw approvalError("capability_policy_changed", 409);
      }
      const finalDecision = evaluateCapabilityAccess(liveCred, {
        ...capabilityContext,
        nowMs: now(),
      });
      const expectedVerdict = capabilityWasApproved ? "ask" : "allow";
      if (
        finalDecision.actionDigest !== decision.actionDigest ||
        finalDecision.policyEpoch !== decision.policyEpoch ||
        finalDecision.policyHash !== decision.policyHash ||
        finalDecision.verdict !== expectedVerdict
      ) {
        await auditCapability({
          event: "capability_stale",
          credential: cred.name,
          principal: requestPrincipal,
          actionDigest: decision.actionDigest,
          policyEpoch: decision.policyEpoch,
          policyHash: decision.policyHash,
        });
        throw approvalError("capability_policy_changed", 409);
      }
      return { credential: liveCred, finalDecision };
    };

    // Optional legacy first-use consent remains an independent outer gate.
    await requireGrant(cred.name, parsed.host);

    // Observe owner-confirmed changes made by a separate vault CLI process and
    // re-resolve the record immediately before any secret refresh, signing, or
    // injection. A newly added policy makes an already-started legacy request
    // retry under that policy; a changed/removed policy invalidates an approval.
    ({ credential: cred, finalDecision: decision } = await ensureCurrentCapability());

    // oauth2 credentials refresh an access token here, then inject as a bearer.
    // Refresh failures throw an error carrying an HTTP status (mapped by the
    // top-level handler), so they short-circuit before we touch the upstream.
    let injectCred = cred;
    if (cred.type === "oauth2") {
      const oauthCredentialBindingHash = capabilityCredentialBindingHash(cred);
      const accessToken = await resolveOauth2Bearer(cred);
      // Token refresh is an asynchronous infrastructure call. Re-check once
      // more after it returns so a policy revoked during refresh cannot reach
      // the protected upstream.
      ({ credential: cred, finalDecision: decision } = await ensureCurrentCapability());
      if (capabilityCredentialBindingHash(cred) !== oauthCredentialBindingHash) {
        throw approvalError("oauth_credential_changed", 409);
      }
      injectCred = { ...cred, type: "bearer", value: accessToken };
    }

    // Wallet credentials (solana-keypair / evm-keypair) materialize INSIDE the
    // body: buffer the JSON-RPC request, sign any transaction-submitting call
    // with the vaulted key, and forward the re-encoded body. The agent submits
    // unsigned transactions and never sees the key — only the (public)
    // signature / tx hash that lands on chain anyway.
    let bodyOverride = null;
    if (cred.type === "solana-keypair" || cred.type === "evm-keypair") {
      const raw = accessBody ?? (await readRequestBody(req, WALLET_MAX_BODY_BYTES));
      if (raw.length > 0) {
        let result;
        let event;
        try {
          if (cred.type === "solana-keypair") {
            result = signSolanaRpcBody(raw.toString("utf8"), cred.secretSeed, {
              programAllowlist: cred.programAllowlist,
            });
            event = { event: "solana_signed", signatures: result.signatures };
          } else {
            result = signEvmRpcBody(raw.toString("utf8"), cred.privateKey, cred.address, {
              chainIdAllowlist: cred.chainIdAllowlist,
              toAllowlist: cred.toAllowlist,
            });
            event = { event: "evm_signed", txHashes: result.hashes };
          }
        } catch (err) {
          return structuredError(res, 400, {
            error: cred.type === "solana-keypair" ? "solana_sign_failed" : "evm_sign_failed",
            message: err.message,
            credential: cred.name,
          });
        }
        bodyOverride = Buffer.from(result.body, "utf8");
        if (result.signed) {
          logAccess({ ...event, credential: cred.name, host: parsed.host });
        }
      } else {
        bodyOverride = raw; // bodyless request (e.g. GET) — stream already consumed
      }
    } else if (accessBody != null) {
      // The access gate consumed the stream; forward what it buffered.
      bodyOverride = accessBody;
    }

    // Build upstream URL (default https; credential may opt into http).
    const upstreamScheme = cred.upstreamScheme || "https";
    const upstreamUrl = new URL(`${upstreamScheme}://${parsed.host}${parsed.restAndQuery}`);

    const incoming = { ...req.headers };
    const { headers, search } = injectCredential({
      headers: prepareUpstreamHeaders({ incoming, upstreamHost: upstreamUrl.host }),
      search: upstreamUrl.searchParams,
      cred: injectCred,
    });
    upstreamUrl.search = search.toString();

    if (state.vault) state.vault.touchLastUsed(cred.name);

    // Approval never outlives the caller. In particular, an OAuth refresh or
    // legacy consent prompt may have taken time after the phone responded.
    if (res.destroyed) throw approvalError("client_aborted", 409);
    if (
      decision.actionDigest &&
      decision.envelope?.expiresAtMs != null &&
      now() >= decision.envelope.expiresAtMs
    ) {
      throw approvalError("approval_expired", 409);
    }

    forwardUpstream({
      req,
      res,
      upstreamScheme,
      upstreamHostname: upstreamUrl.hostname,
      upstreamPort: upstreamUrl.port ? Number(upstreamUrl.port) : null,
      upstreamPath: `${upstreamUrl.pathname}${upstreamUrl.search}`,
      upstreamHost: upstreamUrl.host,
      headers,
      credentialNames: [cred.name],
      logHost: upstreamUrl.host,
      logPath: upstreamUrl.pathname,
      start,
      bodyOverride,
    });
  }

  // ── HTTP_PROXY stub-injection mode (legacy) ───────────────────────────────
  async function handleStubInjection(req, res, target, start, requestPrincipal) {
    await requireUnlock();
    await state.vault?.reload?.();
    let credentialsUsed = [];
    const parsed = new URL(target);

    if (parsed.protocol === "https:") {
      return structuredError(res, 501, {
        error: "https_not_supported_yet",
        message:
          "Stub-injection mode supports HTTP only. Use the URL-rewrite form " +
          "(http://<proxy>/<credname>/<host>/<path>) for HTTPS upstream.",
      });
    }

    let injectedUrl;
    try {
      const rewrittenUrl = rewriteUrl(target, { lookup, host: parsed.hostname });
      injectedUrl = new URL(rewrittenUrl.url);
      credentialsUsed = credentialsUsed.concat(rewrittenUrl.used);
    } catch (err) {
      return handleStubError(res, err);
    }

    let injectedHeaders;
    try {
      const headerRewrite = rewriteHeaders(req.headers, {
        lookup,
        host: parsed.hostname,
      });
      injectedHeaders = stripHopByHop(headerRewrite.headers);
      credentialsUsed = credentialsUsed.concat(headerRewrite.used);
    } catch (err) {
      return handleStubError(res, err);
    }

    // Access-level gate (method/host/path only — legacy stub mode does not
    // classify bodies, so a non-read method on an "ro" credential is denied
    // unless an accessRule explicitly allows it; use URL-rewrite mode for
    // POST-tunneled reads).
    for (const u of credentialsUsed) {
      observeCapabilityEpoch(u.name);
      const rec = lookup(u.name);
      if (!rec) continue; // already resolved by the rewrite step
      if (rec.capabilityPolicy) {
        req.resume();
        return structuredError(res, 403, {
          error: "capability_requires_url_rewrite",
          message:
            `credential '${u.name}' has semantic capabilities; legacy stub mode cannot ` +
            "bind an approval to the exact request body. Use URL-rewrite mode.",
          credential: u.name,
          principal: requestPrincipal,
        });
      }
      const decision = evaluateAccess(rec, {
        method: req.method,
        host: parsed.hostname,
        path: parsed.pathname,
        body: null,
      });
      if (!decision.allowed) {
        logAccess({
          event: "access_denied",
          credential: u.name,
          host: parsed.hostname,
          method: req.method,
          path: parsed.pathname,
          access: effectiveAccess(rec),
          reason: decision.reason,
        });
        return structuredError(res, 403, {
          error: "access_denied",
          message:
            `credential '${u.name}' has access level '${effectiveAccess(rec)}' — ` +
            `${req.method} ${parsed.pathname} on ${parsed.hostname} is not permitted (${decision.reason}).`,
          credential: u.name,
          host: parsed.hostname,
          access: effectiveAccess(rec),
          reason: decision.reason,
        });
      }
    }

    if (state.vault) {
      for (const u of credentialsUsed) state.vault.touchLastUsed(u.name);
    }

    forwardUpstream({
      req,
      res,
      upstreamScheme: "http",
      upstreamHostname: injectedUrl.hostname,
      upstreamPort: injectedUrl.port ? Number(injectedUrl.port) : null,
      upstreamPath: `${injectedUrl.pathname}${injectedUrl.search || ""}`,
      upstreamHost: injectedUrl.host,
      headers: injectedHeaders,
      credentialNames: credentialsUsed.map((u) => u.name),
      logHost: injectedUrl.host,
      logPath: injectedUrl.pathname,
      start,
    });
  }

  const server = http.createServer(async (req, res) => {
    const start = Date.now();

    // Locked with no control plane to re-unlock → refuse immediately. When the
    // control plane is enabled the handlers park the request and ask the phone
    // to unlock, so we fall through.
    if (state.locked && !controlEnabled) {
      return structuredError(res, 401, {
        error: "vault_locked",
        reason: state.lockedReason,
        lockedAt: state.lockedAt,
        message:
          "Vault auto-locked after idle timeout. " +
          "Restart the proxy (`agent-id-proxy stop && start`) to re-unlock.",
      });
    }

    if (!state.locked) touchActivity();

    try {
      const target = req.url || "";
      const requestPrincipal = await principalForRequest(req);
      // Absolute-URI request → legacy stub-injection (HTTP_PROXY mode).
      if (/^https?:\/\//i.test(target)) {
        return await handleStubInjection(req, res, target, start, requestPrincipal);
      }
      // Origin-form path → URL-rewrite mode.
      const parsed = parseRewritePath(target);
      if (parsed) return await handleUrlRewrite(req, res, parsed, start, requestPrincipal);

      return structuredError(res, 400, {
        error: "bad_request",
        message:
          "Expected either /<credname>/<host>/<path> (URL-rewrite mode) " +
          "or absolute URI (HTTP_PROXY mode).",
      });
    } catch (err) {
      if (res.headersSent) {
        res.destroy();
        return;
      }
      // Approval failures (locked/denied/timeout) carry an HTTP status.
      if (err && err.status) {
        return structuredError(res, err.status, {
          error: err.code || "approval_failed",
          message: err.message,
        });
      }
      structuredError(res, 500, { error: "proxy_internal", message: err.message });
    }
  });

  // CONNECT tunneling for HTTPS. No MITM in v1.
  server.on("connect", (req, clientSocket, head) => {
    const start = Date.now();
    const [host, portStr] = (req.url || "").split(":");
    const port = parseInt(portStr || "443", 10);

    if (state.locked) {
      clientSocket.write(
        "HTTP/1.1 401 Vault Locked\r\n" +
          "X-AgentVault-Proxy-Error: vault_locked\r\n" +
          "Content-Length: 0\r\n\r\n",
      );
      clientSocket.destroy();
      return;
    }

    if (!host) {
      clientSocket.write("HTTP/1.1 400 Bad Request\r\n\r\n");
      clientSocket.destroy();
      return;
    }

    touchActivity();

    const upstream = net.connect(port, host, () => {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length) upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
      logAccess({
        method: "CONNECT",
        host,
        path: null,
        status: 200,
        credentials: [],
        bytesIn: 0,
        bytesOut: 0,
        durationMs: Date.now() - start,
        note: "tunneled (no TLS MITM in v1)",
      });
    });

    upstream.on("error", (err) => {
      clientSocket.write(`HTTP/1.1 502 Bad Gateway\r\n\r\n`);
      clientSocket.destroy();
      logAccess({
        method: "CONNECT",
        host,
        path: null,
        status: 502,
        credentials: [],
        bytesIn: 0,
        bytesOut: 0,
        durationMs: Date.now() - start,
        error: err.code || err.message,
      });
    });

    clientSocket.on("error", () => upstream.destroy());
  });

  function handleStubError(res, err) {
    if (err instanceof StubError) {
      const status = err.code === "credential_not_found" ? 400 : 403;
      return structuredError(res, status, {
        error: err.code,
        message: err.message,
        credential: err.credential || null,
        host: err.host || null,
        allowed: err.allowed || null,
      });
    }
    throw err;
  }

  let controlServer = null;
  let controlAddr = null;
  if (controlEnabled) {
    controlServer = createControlServer({
      registry,
      getStatus: async () => ({
        locked: state.locked,
        lockedReason: state.lockedReason,
        pending: registry.list().length,
        capabilityPending: state.capabilityPending.size,
        grants: state.grants.size,
        idleTimeoutMs: Number.isFinite(state.idleTimeoutMs) ? state.idleTimeoutMs : null,
        devices: await deviceList(),
      }),
      onApprove,
      onDeny,
      onRegister,
      authToken: controlToken,
      tls: controlTls,
      listen: control.listen || { port: 0, host: "127.0.0.1" },
    });
  }

  return {
    server,
    async listen() {
      const dataAddr = await new Promise((resolve) => {
        server.listen(listen.port, listen.host, () => {
          const addr = server.address();
          resolve({ host: addr.address, port: addr.port });
        });
      });
      if (controlServer) controlAddr = await controlServer.listen();
      return dataAddr;
    },
    async close() {
      if (ticker) clearInterval(ticker);
      if (registry) registry.cancelAll("proxy_shutdown");
      doLock("proxy_shutdown");
      if (controlServer) await controlServer.close();
      await new Promise((resolve) => server.close(() => resolve()));
    },
    get locked() {
      return state.locked;
    },
    get lastRequestAt() {
      return state.lastRequestAt;
    },
    get idleTimeoutMs() {
      return state.idleTimeoutMs;
    },
    get controlAddress() {
      return controlAddr;
    },
    get controlToken() {
      return controlToken;
    },
    get controlPublicKey() {
      return controlPublicKey;
    },
    get controlScheme() {
      return controlScheme;
    },
    get controlCertFingerprint() {
      return controlCertFingerprint;
    },
    get pendingCount() {
      return registry ? registry.list().length : 0;
    },
    forceLock(reason = "manual") {
      doLock(reason);
    },
  };
}

// Suppress unused-import warning during static analysis
void https;
