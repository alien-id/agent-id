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
import {
  openVaultWithMasterKey,
  readMobileSlotChallenges,
} from "../../agent-id-vault/lib/vault.mjs";
import { appendJsonl } from "../../agent-id-core/lib/state.mjs";

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

function structuredError(res, status, body) {
  const payload = JSON.stringify({ ok: false, ...body });
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload),
    "X-AgentVault-Proxy-Error": body.error || "unknown",
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
  // How long an approved (credential, host) grant stays valid. Infinity = for
  // the life of the process.
  grantTtlMs = 60 * 60 * 1000,
}) {
  const controlEnabled = !!control;
  if (controlEnabled && !stateDir) {
    throw new Error("createProxy: control plane requires `stateDir` to unlock the vault");
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

  const registry = controlEnabled
    ? createPendingRegistry({ now, timeoutMs: control.approvalTimeoutMs })
    : null;

  function touchActivity() {
    state.lastRequestAt = now();
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
        const challenges = await readMobileSlotChallenges(stateDir);
        if (!challenges.length) throw approvalError("no_mobile_slot", 401);
        const { id, promise } = registry.create({
          action: "unlock",
          reason: state.lockedReason || "locked",
          challenges,
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
    const fresh = (entry) =>
      entry && entry.accessToken && entry.expiresAt - OAUTH_SKEW_MS > now();

    const cached = state.oauthTokens.get(cred.name);
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
      });
      return cred.accessToken;
    }

    let inFlight = state.oauthInFlight.get(cred.name);
    if (!inFlight) {
      inFlight = (async () => {
        const refreshToken = cached?.refreshToken || cred.refreshToken;
        let res;
        try {
          res = await refreshAccessToken({
            tokenEndpoint: cred.tokenEndpoint,
            clientId: cred.clientId,
            clientSecret: cred.clientSecret || null,
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
        };
        state.oauthTokens.set(cred.name, entry);

        // Persist a rotated refresh token so it survives proxy restart / re-unlock.
        if (res.refreshToken && res.refreshToken !== cred.refreshToken && state.vault) {
          try {
            const live = state.vault.get(cred.name);
            if (live) {
              live.refreshToken = res.refreshToken;
              await state.vault.save();
            }
          } catch {
            // best effort — the in-memory cache already carries the new token
          }
        }
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
      if (!body.masterKey) return { ok: false, error: "master_key_required", status: 400 };
      let opened;
      const mk = Buffer.from(body.masterKey, "hex");
      try {
        opened = await openVaultWithMasterKey({ stateDir, masterKey: mk });
      } catch {
        return { ok: false, error: "unlock_failed", status: 400 };
      } finally {
        mk.fill(0);
      }
      applyUnlock(opened);
      registry.resolve(id, { unlocked: true });
      logAccess({ event: "vault_unlocked", via: "mobile", requestId: id }).catch(() => {});
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
  }) {
    let bytesIn = 0;
    let bytesOut = 0;
    const client = upstreamScheme === "https" ? https : http;
    const port = upstreamPort || (upstreamScheme === "https" ? 443 : 80);

    const upstreamReq = client.request({
      protocol: `${upstreamScheme}:`,
      hostname: upstreamHostname,
      port,
      method: req.method,
      path: upstreamPath,
      headers: { ...headers, host: upstreamHost },
    });

    upstreamReq.on("error", (err) => {
      if (!res.headersSent) {
        structuredError(res, 502, { error: "upstream_error", message: err.message });
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

    req.on("data", (chunk) => {
      bytesIn += chunk.length;
    });
    req.pipe(upstreamReq);
  }

  // ── URL-rewrite mode (recommended) ────────────────────────────────────────
  async function handleUrlRewrite(req, res, parsed, start) {
    // Vault locked? Park the request and ask the phone to unlock. Throws an
    // approvalError (mapped to a status by the caller) on deny / timeout.
    await requireUnlock();

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

    // Host is on the credential allowlist (resolveCredential enforced it).
    // First use of this (credential, host) pair? Ask for human consent.
    await requireGrant(cred.name, parsed.host);

    // oauth2 credentials refresh an access token here, then inject as a bearer.
    // Refresh failures throw an error carrying an HTTP status (mapped by the
    // top-level handler), so they short-circuit before we touch the upstream.
    let injectCred = cred;
    if (cred.type === "oauth2") {
      const accessToken = await resolveOauth2Bearer(cred);
      injectCred = { ...cred, type: "bearer", value: accessToken };
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
        grants: state.grants.size,
        idleTimeoutMs: Number.isFinite(state.idleTimeoutMs) ? state.idleTimeoutMs : null,
        devices: await deviceList(),
      }),
      onApprove,
      onDeny,
      onRegister,
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
