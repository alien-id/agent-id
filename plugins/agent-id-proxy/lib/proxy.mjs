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
import { createECDH, createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { URL } from "node:url";

import { rewriteHeaders, rewriteUrl, StubError } from "./stub.mjs";
import {
  injectCredential,
  parseRewritePath,
  prepareUpstreamHeaders,
  PROXY_AUTH_HEADER,
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
import { unsealFromPublicKey } from "@alien-id/agent-id-vault/lib/format.mjs";
import { fingerprintOfCertPem, generateControlCert } from "./control-tls.mjs";
import { appendJsonl } from "@alien-id/agent-id-core/lib/state.mjs";

export { PROXY_AUTH_HEADER };

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  // Terminates at this proxy by definition — the legacy stub path forwards
  // whatever the agent sent, so the strip has to be explicit here too.
  PROXY_AUTH_HEADER,
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

// Coalescing window for rejected-request logging (see logAuthFailure).
const AUTH_FAIL_LOG_WINDOW_MS = 60 * 1000;

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
  // Per-connector OAuth client secrets: clientId → clientSecret, from the
  // host's 0600 secrets file (see loadOauthSecretsFile). Consulted only when
  // an oauth2 credential carries no clientSecret of its own, so
  // personal/standalone creds behave exactly as before.
  oauthClientSecrets = null,
  // Self-reopen: an optional async () => Vault, supplied only when the vault
  // can be unsealed without a human (the agent-key auto-unlock path). Lets an
  // unattended proxy (e.g. a supervisor spawning one proxy per principal)
  // recover from a credential written after spawn or from its own idle lock
  // instead of requiring a restart. Omitted, behavior is unchanged.
  reopenVault = null,
  // Opt-in shared secret for the DATA plane (the control plane has its own
  // bearer token). Set, every data-plane request and CONNECT must present it
  // in the PROXY_AUTH_HEADER; unset, behavior is unchanged. Loopback alone is
  // a weak boundary wherever the network namespace is shared — a container,
  // or a machine also running a browser that renders untrusted pages.
  authToken = null,
}) {
  const controlEnabled = !!control;
  if (controlEnabled && !stateDir) {
    throw new Error("createProxy: control plane requires `stateDir` to unlock the vault");
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
  };

  // Refresh an oauth2 access token this far before its stated expiry, so a token
  // that is valid when injected is still valid when it reaches the upstream.
  const OAUTH_SKEW_MS = 60 * 1000;

  const accessTokenUsable = (entry) =>
    !!entry && !!entry.accessToken && entry.expiresAt - OAUTH_SKEW_MS > now();

  const registry = controlEnabled
    ? createPendingRegistry({ now, timeoutMs: control.approvalTimeoutMs })
    : null;

  // Connect-time SSRF guard for every upstream request (both modes).
  const upstreamLookup = makeUpstreamLookup({ blockPrivate: blockPrivateHosts });

  function touchActivity() {
    state.lastRequestAt = now();
  }

  // Constant-time token check. Both sides are hashed first so the digests are
  // always 32 bytes and timingSafeEqual can never throw on a length mismatch
  // (which would also leak the expected length).
  function authOk(req) {
    if (authToken === null) return true;
    const presented = req.headers[PROXY_AUTH_HEADER];
    if (typeof presented !== "string" || presented.length === 0) return false;
    return timingSafeEqual(
      createHash("sha256").update(presented).digest(),
      createHash("sha256").update(authToken).digest(),
    );
  }

  function doLock(reason) {
    if (state.locked) return;
    state.locked = true;
    state.lockedAt = now();
    state.lockedReason = reason;
    if (state.vault) {
      state.vault.lock();
      state.vault = null;
    }
    // Drop cached oauth2 access tokens with the rest of the decrypted material.
    state.oauthTokens.clear();
    logAccess({ event: "vault_locked", reason }).catch(() => {});
    if (onLock) onLock(reason);
  }

  // Shared by every path that hands the proxy a freshly opened vault (control-
  // plane unlock, self-reopen): swap it in and clear the locked state. Idle
  // tracking is timestamp-based (see the ticker below), so touching activity
  // here is what "restarts" the idle window.
  function adoptVault(openedVault) {
    const displaced = state.vault;
    state.vault = openedVault;
    state.locked = false;
    state.lockedAt = null;
    state.lockedReason = null;
    // Only the cached REFRESH tokens belong to the handle being replaced: an
    // owner who re-authorizes out of band lands a NEW refresh token in
    // `vault.enc`, and a cached older one would keep winning over it (see
    // resolveOauth2Bearer) until it expired — invalid_grant, 401, forever.
    // The ACCESS tokens were minted by the authorization server, not read from
    // this vault, so they stay: flushing them made every reopen (each rotation,
    // every credential miss) re-run the token endpoint for every credential.
    for (const [name, entry] of state.oauthTokens) {
      // A rotated refresh token the vault refused to store lives ONLY here —
      // dropping it would brick the credential on its next refresh, since the
      // record on disk still holds the token the server has already retired.
      if (!entry.refreshTokenUnpersisted) delete entry.refreshToken;
      if (!accessTokenUsable(entry) && !entry.refreshToken) state.oauthTokens.delete(name);
    }
    // Zero the handle we just replaced instead of leaving a second decrypted
    // copy of the vault in the heap for the life of the process.
    if (displaced && displaced !== openedVault) displaced.lock();
    touchActivity();
  }

  // Self-reopen (agent-key auto-unlock only): a single in-flight reopen shared
  // by every concurrent caller, so a burst of requests hitting a lock/miss at
  // once triggers one `reopenVault()`, not one per request.
  let reopenInFlight = null;
  // `reason` describes the reopen, not the caller: callers that join an
  // in-flight attempt are served by the one that triggered it, and that
  // trigger is what the single `vault_reopened` entry records.
  async function tryReopenVault(reason) {
    if (!reopenVault) return false;
    if (!reopenInFlight) {
      reopenInFlight = (async () => {
        try {
          const opened = await reopenVault();
          if (!opened) return false;
          adoptVault(opened);
          logAccess({ event: "vault_reopened", reason }).catch(() => {});
          return true;
        } catch {
          return false;
        } finally {
          reopenInFlight = null;
        }
      })();
    }
    return reopenInFlight;
  }

  // Shared retry for the data-plane lookup helpers: a `credential_not_found`
  // gets one vault-reopen attempt, then one retry of the same lookup, before
  // the caller's usual not-found handling applies — covers a credential
  // written to `vault.enc` by another process after this proxy unlocked (e.g.
  // a vault CLI run following an out-of-band OAuth flow).
  async function withCredMissRetry(run) {
    try {
      return run();
    } catch (err) {
      if (err && err.code === "credential_not_found" && (await tryReopenVault("cred_miss"))) {
        return run();
      }
      throw err;
    }
  }

  // Write a rotated refresh token back to `vault.enc`, reporting whether it
  // landed. `save()` re-encrypts this process's WHOLE in-memory payload, so
  // writing from the handle opened at startup would erase everything another
  // process has added since — including a vault-generated wallet key that
  // exists nowhere else. So: re-read the vault from disk first and rotate on
  // that handle, and when it cannot be re-read (no reopen callback, or the
  // reopen failed) refuse to write at all. Losing a rotated token is
  // recoverable — it stays in this process's cache and the owner can re-mint —
  // destroying another writer's credential is not.
  async function persistRotatedRefreshToken(name, refreshToken) {
    if (!(await tryReopenVault("oauth_rotate"))) {
      logAccess({
        event: "oauth_rotate_persist_skipped",
        credential: name,
        reason: "vault_not_rereadable",
      }).catch(() => {});
      return false;
    }
    try {
      const live = state.vault?.get(name);
      if (!live) {
        logAccess({
          event: "oauth_rotate_persist_skipped",
          credential: name,
          reason: "credential_not_in_reread_vault",
        }).catch(() => {});
        return false;
      }
      live.refreshToken = refreshToken;
      await state.vault.save();
      return true;
    } catch (err) {
      logAccess({
        event: "oauth_rotate_persist_failed",
        credential: name,
        reason: (err && err.code) || "save_failed",
        message: (err && err.message) || null,
      }).catch(() => {});
      return false;
    }
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

  // ── oauth2: refresh-on-demand access tokens ───────────────────────────────
  // Return a currently-valid access token for an `oauth2` credential, refreshing
  // from the stored refresh token when the cached one is missing or near expiry.
  // Concurrent requests for the same credential share one in-flight refresh.
  async function resolveOauth2Bearer(cred) {
    const cached = state.oauthTokens.get(cred.name);
    if (accessTokenUsable(cached)) return cached.accessToken;

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
      });
      return cred.accessToken;
    }

    let inFlight = state.oauthInFlight.get(cred.name);
    if (!inFlight) {
      inFlight = (async () => {
        const refreshToken = cached?.refreshToken || cred.refreshToken;
        // The cred's own secret wins (personal/standalone use); a
        // platform-managed cred carries none and resolves via the host's
        // per-connector config. Hard boundary: user secrets in the vault,
        // platform secrets in host config — never both in one place.
        const clientSecret =
          cred.clientSecret ||
          (oauthClientSecrets && cred.clientId ? oauthClientSecrets[cred.clientId] : null) ||
          null;
        let res;
        try {
          res = await refreshAccessToken({
            tokenEndpoint: cred.tokenEndpoint,
            clientId: cred.clientId,
            clientSecret,
            refreshToken,
            scope: cred.scope || null,
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

        const entry = {
          accessToken: res.accessToken,
          expiresAt: now() + res.expiresInSec * 1000,
          refreshToken: res.refreshToken || refreshToken,
          refreshTokenUnpersisted: false,
        };

        // Persist a rotated refresh token so it survives proxy restart /
        // re-unlock. Runs BEFORE the cache write: the persist may swap in a
        // re-read vault handle, which prunes the token cache. When the write
        // was refused, the cache is the only place this token exists — mark it
        // so a later reopen keeps it (adoptVault).
        if (res.refreshToken && res.refreshToken !== cred.refreshToken) {
          entry.refreshTokenUnpersisted = !(await persistRotatedRefreshToken(
            cred.name,
            res.refreshToken,
          ));
        }
        state.oauthTokens.set(cred.name, entry);
        logAccess({ event: "oauth_refreshed", credential: cred.name }).catch(() => {});
        return entry.accessToken;
      })().finally(() => state.oauthInFlight.delete(cred.name));
      state.oauthInFlight.set(cred.name, inFlight);
    }
    return inFlight;
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
      adoptVault(opened);
      registry.resolve(id, { unlocked: true });
      logAccess({ event: "vault_unlocked", via: "control_plane", requestId: id }).catch(() => {});
      if (onUnlock) onUnlock(entry);
      return { ok: true, body: { action: "unlock", unlocked: true } };
    }

    if (entry.action === "authorize") {
      registry.resolve(id, { approved: true });
      logAccess({
        event: "consent_granted",
        requestId: id,
        credential: entry.credential,
        host: entry.host,
      }).catch(() => {});
      return { ok: true, body: { action: "authorize", approved: true } };
    }

    return { ok: false, error: "unknown_action", status: 400 };
  }

  function onDeny(id, body) {
    const entry = registry.get(id);
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
    // Pairing writes `vault.enc`, and `save()` re-encrypts this process's whole
    // in-memory payload — see persistRotatedRefreshToken. Add the slot to a
    // freshly re-read handle, and when the vault cannot be re-read refuse: a
    // pairing the owner can retry is cheaper than erasing a credential another
    // process wrote after this proxy started.
    if (!(await tryReopenVault("pairing"))) {
      logAccess({ event: "mobile_register_refused", reason: "vault_not_rereadable" }).catch(
        () => {},
      );
      return { ok: false, error: "vault_reread_unavailable", status: 409 };
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

  // Every access-log write in flight. Callers fire these and forget, so
  // close() is the only place that can promise the log is on disk — an
  // operator reading it after a stop, and every test tearing a state dir down,
  // relies on that.
  const pendingLogWrites = new Set();

  async function logAccess(entry) {
    const write = (async () => {
      try {
        const owed = entry.event === "auth_failed" ? 0 : takeSuppressedAuthFailures();
        if (owed > 0) {
          await appendJsonl(logPath, {
            ts: new Date().toISOString(),
            event: "auth_failed_suppressed",
            suppressed: owed,
          });
        }
        await appendJsonl(logPath, { ts: new Date().toISOString(), ...entry });
      } catch {
        // never let logging break a request
      }
    })();
    pendingLogWrites.add(write);
    try {
      await write;
    } finally {
      pendingLogWrites.delete(write);
    }
  }

  // An unauthenticated caller must not be able to grow the access log at will —
  // the refusal is written before any other check, so anything that can reach
  // the port could otherwise fill the disk one line per request. Policy: log
  // the first failure of a window verbatim, count the rest, and let the first
  // failure after the window carry that count as `suppressed`. Never silent:
  // there is always a record, only its resolution degrades under a flood.
  const authFailLog = { windowStartedAt: -Infinity, suppressed: 0 };

  // The counter must not die with its window: a flood that simply stops leaves
  // its tail owed a record. Any later log pays the debt, and close() pays
  // whatever is left, so a suppressed count is never merely forgotten.
  function takeSuppressedAuthFailures() {
    const suppressed = authFailLog.suppressed;
    authFailLog.suppressed = 0;
    return suppressed;
  }

  function logAuthFailure(entry) {
    if (now() - authFailLog.windowStartedAt < AUTH_FAIL_LOG_WINDOW_MS) {
      authFailLog.suppressed += 1;
      return;
    }
    const suppressed = takeSuppressedAuthFailures();
    authFailLog.windowStartedAt = now();
    logAccess({ event: "auth_failed", ...entry, suppressed });
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
  async function handleUrlRewrite(req, res, parsed, start) {
    // Vault locked? Park the request and ask the phone to unlock. Throws an
    // approvalError (mapped to a status by the caller) on deny / timeout.
    await requireUnlock();

    let cred;
    try {
      cred = await withCredMissRetry(() =>
        resolveCredential({
          credname: parsed.credname,
          host: parsed.host,
          lookup,
        }),
      );
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
    // Detach from the vault's payload: adopting a re-read vault locks the
    // displaced handle, which scrubs its records in place — and this request
    // still holds one across awaits (consent, token refresh, body buffering).
    // A SHALLOW copy suffices only because the vault's wipe is shallow too: it
    // deletes each secret field off the record without recursing (see
    // `wipePayload` in the vault's store module, whose comment states that
    // contract). Should that wipe ever recurse into nested objects, this copy
    // must deep-clone them — otherwise an in-flight request injects the emptied
    // value (`Bearer undefined`).
    cred = { ...cred };

    // Host is on the credential allowlist (resolveCredential enforced it).
    // First use of this (credential, host) pair? Ask for human consent.
    await requireGrant(cred.name, parsed.host);

    // ── Access-level gate ────────────────────────────────────────────────────
    // A restricted credential (access:"ro" and/or accessRules) is checked
    // against method + host + pathname first; when only the body can decide
    // (a POST that might be a tunneled read), buffer it and re-evaluate.
    const bareHost = parsed.host.includes(":")
      ? parsed.host.slice(0, parsed.host.indexOf(":"))
      : parsed.host;
    const reqPathname = parsed.restAndQuery.split("?")[0];
    let accessBody = null; // set when the gate had to consume the request stream
    let decision = evaluateAccess(cred, {
      method: req.method,
      host: bareHost,
      path: reqPathname,
    });
    if (!decision.allowed && decision.needsBody) {
      accessBody = await readRequestBody(req, ACCESS_MAX_BODY_BYTES);
      decision = evaluateAccess(cred, {
        method: req.method,
        host: bareHost,
        path: reqPathname,
        body: accessBody.toString("utf8"),
      });
    }
    if (!decision.allowed) {
      // Drain any unconsumed request body (a write's payload) so the HTTP
      // framing stays clean before we send the denial on this connection.
      if (accessBody == null) req.resume();
      logAccess({
        event: "access_denied",
        credential: cred.name,
        host: parsed.host,
        method: req.method,
        path: reqPathname,
        access: effectiveAccess(cred),
        reason: decision.reason,
      });
      return structuredError(res, 403, {
        error: "access_denied",
        message:
          `credential '${cred.name}' has access level '${effectiveAccess(cred)}' — ` +
          `${req.method} ${reqPathname} on ${parsed.host} is not permitted (${decision.reason}). ` +
          "Only the owner can raise it: `agent-id-vault set-access` (human-confirmed).",
        credential: cred.name,
        host: parsed.host,
        access: effectiveAccess(cred),
        reason: decision.reason,
      });
    }

    // oauth2 credentials refresh an access token here, then inject as a bearer.
    // Refresh failures throw an error carrying an HTTP status (mapped by the
    // top-level handler), so they short-circuit before we touch the upstream.
    let injectCred = cred;
    if (cred.type === "oauth2") {
      const accessToken = await resolveOauth2Bearer(cred);
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
  async function handleStubInjection(req, res, target, start) {
    await requireUnlock();
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
      const rewrittenUrl = await withCredMissRetry(() =>
        rewriteUrl(target, { lookup, host: parsed.hostname }),
      );
      injectedUrl = new URL(rewrittenUrl.url);
      credentialsUsed = credentialsUsed.concat(rewrittenUrl.used);
    } catch (err) {
      return handleStubError(res, err);
    }

    let injectedHeaders;
    try {
      const headerRewrite = await withCredMissRetry(() =>
        rewriteHeaders(req.headers, {
          lookup,
          host: parsed.hostname,
        }),
      );
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
      const rec = lookup(u.name);
      if (!rec) continue; // already resolved by the rewrite step
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

    // Auth runs before EVERYTHING — before the lock check and its self-reopen,
    // before activity is touched, before routing, the vault, the approval flow
    // or any upstream socket. An unauthenticated caller must not be able to
    // observe or drive proxy state, only to be refused.
    if (!authOk(req)) {
      logAuthFailure({ method: req.method, path: (req.url || "").split("?")[0] });
      return structuredError(res, 401, {
        error: "unauthorized",
        message: `Missing or invalid ${PROXY_AUTH_HEADER} header.`,
      });
    }
    // Defense in depth: the strip lists in prepareUpstreamHeaders and
    // stripHopByHop are the guarantee, this makes the token unreachable from
    // every downstream path regardless.
    delete req.headers[PROXY_AUTH_HEADER];

    // A browser cannot attach a custom header on a simple request, so a
    // preflight is the only way it could reach an authenticated data plane —
    // and relaying one upstream would hand a page the upstream's CORS answer.
    // Refuse locally, with no Access-Control-Allow-* of our own, in both modes.
    if (req.method === "OPTIONS" && req.headers["access-control-request-method"]) {
      logAccess({
        event: "preflight_refused",
        path: (req.url || "").split("?")[0],
      });
      return structuredError(res, 403, {
        error: "cross_origin_refused",
        message: "The proxy data plane is not a browser-reachable origin; preflights are refused.",
      });
    }

    // Locked with no control plane to re-unlock → refuse immediately. When the
    // control plane is enabled the handlers park the request and ask the phone
    // to unlock, so we fall through.
    if (state.locked && !controlEnabled) {
      const reopened = await tryReopenVault("idle_lock");
      if (!reopened) {
        return structuredError(res, 401, {
          error: "vault_locked",
          reason: state.lockedReason,
          lockedAt: state.lockedAt,
          message:
            "Vault auto-locked after idle timeout. " +
            "Restart the proxy (`agent-id-proxy stop && start`) to re-unlock.",
        });
      }
    }

    if (!state.locked) touchActivity();

    try {
      const target = req.url || "";
      // Absolute-URI request → legacy stub-injection (HTTP_PROXY mode).
      if (/^https?:\/\//i.test(target)) {
        return await handleStubInjection(req, res, target, start);
      }
      // Origin-form path → URL-rewrite mode.
      const parsed = parseRewritePath(target);
      if (parsed) return await handleUrlRewrite(req, res, parsed, start);

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

  // Every CONNECT refusal shares one wire shape — status line, a machine-
  // readable error header, explicit zero-length body — so a tunnel client can
  // tell the refusals apart without parsing prose.
  function refuseConnect(clientSocket, statusLine, error) {
    // The refusal can land after an await (the reopen attempt) or after the
    // tunnel broke, so the client may already be gone — writing to it must not
    // surface as an unhandled socket error.
    clientSocket.on("error", () => {});
    if (clientSocket.destroyed) return;
    clientSocket.write(
      `HTTP/1.1 ${statusLine}\r\n` +
        `X-AgentVault-Proxy-Error: ${error}\r\n` +
        "Content-Length: 0\r\n\r\n",
    );
    clientSocket.destroy();
  }

  // A CONNECT request-target is authority-form — `host:port`, port mandatory
  // (RFC 9110 §9.3.6). Returns null for anything else, including a port that
  // isn't a number in range: `net.connect` THROWS on such a port
  // (ERR_SOCKET_BAD_PORT), and one malformed line must not be able to take the
  // proxy down.
  function parseConnectTarget(target) {
    const m = /^(\[[0-9A-Fa-f:.]+\]|[^:[\]]+):(\d{1,5})$/.exec(target || "");
    if (!m) return null;
    const port = Number(m[2]);
    if (port < 1 || port > 65535) return null;
    // An IPv6 literal arrives bracketed; the SSRF guard and net.connect both
    // want it bare.
    return { host: m[1].replace(/^\[|\]$/g, ""), port };
  }

  // CONNECT tunneling for HTTPS. No MITM in v1.
  server.on("connect", (req, clientSocket, head) => {
    // The handler is async, so anything it throws would surface as an
    // unhandled rejection — process death for a proxy that is supposed to
    // answer a bad request, not die of it.
    handleConnect(req, clientSocket, head).catch((err) => {
      refuseConnect(clientSocket, "500 Internal Server Error", "proxy_internal");
      logAccess({
        method: "CONNECT",
        host: null,
        path: null,
        status: 500,
        credentials: [],
        error: (err && (err.code || err.message)) || "proxy_internal",
      });
    });
  });

  async function handleConnect(req, clientSocket, head) {
    const start = Date.now();

    if (!authOk(req)) {
      logAuthFailure({ method: "CONNECT" });
      refuseConnect(clientSocket, "401 Unauthorized", "unauthorized");
      return;
    }
    delete req.headers[PROXY_AUTH_HEADER];

    // Before the lock check: a malformed target is refused on its own terms,
    // never a reason to reopen a vault.
    const target = parseConnectTarget(req.url);
    if (!target) {
      refuseConnect(clientSocket, "400 Bad Request", "bad_request");
      logAccess({
        method: "CONNECT",
        host: null,
        path: null,
        status: 400,
        credentials: [],
        durationMs: Date.now() - start,
        error: "bad_request",
      });
      return;
    }
    const { host, port } = target;

    // Same self-heal the request handler gets on an idle lock, under the same
    // gate: on the unattended auto-unlock path (no control plane) a reopen
    // needs no human. With the control plane on, the unlock is the owner's
    // decision — and a tunnel has no parked-request path to fall through to,
    // so there it stays a refusal.
    if (state.locked) {
      const reopened = !controlEnabled && (await tryReopenVault("idle_lock"));
      if (!reopened) {
        refuseConnect(clientSocket, "401 Vault Locked", "vault_locked");
        return;
      }
    }

    // SSRF guard, same two layers as forwardUpstream: a literal-IP target is
    // checked here (node skips `lookup` for literals), a hostname at connect
    // time via the shared lookup below — so a tunnel can no more reach
    // 169.254.169.254 (or, under --block-private-hosts, a loopback/RFC1918
    // target) than a forwarded request can.
    const literalBlock = blockedAddressReason(host, { blockPrivate: blockPrivateHosts });
    if (literalBlock) {
      refuseConnect(clientSocket, "403 Forbidden", "upstream_blocked");
      logAccess({
        method: "CONNECT",
        host,
        path: null,
        status: 403,
        credentials: [],
        durationMs: Date.now() - start,
        error: "upstream_blocked",
        reason: literalBlock,
      });
      return;
    }

    touchActivity();

    const upstream = net.connect({ host, port, lookup: upstreamLookup }, () => {
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
      // The connect-time lookup rejected a resolved address → the same 403 the
      // literal check gives, not a generic 502.
      const blocked = err.code === "ESSRFBLOCKED";
      refuseConnect(
        clientSocket,
        blocked ? "403 Forbidden" : "502 Bad Gateway",
        blocked ? "upstream_blocked" : "upstream_error",
      );
      logAccess({
        method: "CONNECT",
        host,
        path: null,
        status: blocked ? 403 : 502,
        credentials: [],
        bytesIn: 0,
        bytesOut: 0,
        durationMs: Date.now() - start,
        error: err.code || err.message,
      });
    });

    clientSocket.on("error", () => upstream.destroy());
  }

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
      const owed = takeSuppressedAuthFailures();
      if (owed > 0) await logAccess({ event: "auth_failed_suppressed", suppressed: owed });
      doLock("proxy_shutdown");
      if (controlServer) await controlServer.close();
      await new Promise((resolve) => server.close(() => resolve()));
      // The log is written fire-and-forget everywhere else; a closed proxy owes
      // the caller a settled log (nothing still writing into a state dir that
      // is about to go).
      await Promise.allSettled([...pendingLogWrites]);
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
