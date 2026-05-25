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
  vault,
  logPath,
  listen = { port: 0, host: "127.0.0.1" },
  idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS,
  now = () => Date.now(),
  onLock = null,
}) {
  // Mutable state — vault gets nulled on idle lock; the request handler
  // checks `locked` first and refuses with 401.
  const state = {
    vault,
    locked: false,
    lockedAt: null,
    lockedReason: null,
    lastRequestAt: now(),
    idleTimeoutMs,
  };

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
    logAccess({ event: "vault_locked", reason }).catch(() => {});
    if (onLock) onLock(reason);
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
  function handleUrlRewrite(req, res, parsed, start) {
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

    // Build upstream URL (default https; credential may opt into http).
    const upstreamScheme = cred.upstreamScheme || "https";
    const upstreamUrl = new URL(`${upstreamScheme}://${parsed.host}${parsed.restAndQuery}`);

    const incoming = { ...req.headers };
    const { headers, search } = injectCredential({
      headers: prepareUpstreamHeaders({ incoming, upstreamHost: upstreamUrl.host }),
      search: upstreamUrl.searchParams,
      cred,
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
  function handleStubInjection(req, res, target, start) {
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

    if (state.locked) {
      return structuredError(res, 401, {
        error: "vault_locked",
        reason: state.lockedReason,
        lockedAt: state.lockedAt,
        message:
          "Vault auto-locked after idle timeout. " +
          "Restart the proxy (`agent-id-proxy stop && start`) to re-unlock.",
      });
    }

    touchActivity();

    try {
      const target = req.url || "";
      // Absolute-URI request → legacy stub-injection (HTTP_PROXY mode).
      if (/^https?:\/\//i.test(target)) {
        return handleStubInjection(req, res, target, start);
      }
      // Origin-form path → URL-rewrite mode.
      const parsed = parseRewritePath(target);
      if (parsed) return handleUrlRewrite(req, res, parsed, start);

      return structuredError(res, 400, {
        error: "bad_request",
        message:
          "Expected either /<credname>/<host>/<path> (URL-rewrite mode) " +
          "or absolute URI (HTTP_PROXY mode).",
      });
    } catch (err) {
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

  return {
    server,
    listen() {
      return new Promise((resolve) => {
        server.listen(listen.port, listen.host, () => {
          const addr = server.address();
          resolve({ host: addr.address, port: addr.port });
        });
      });
    },
    close() {
      if (ticker) clearInterval(ticker);
      doLock("proxy_shutdown");
      return new Promise((resolve) => server.close(() => resolve()));
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
    forceLock(reason = "manual") {
      doLock(reason);
    },
  };
}

// Suppress unused-import warning during static analysis
void https;
