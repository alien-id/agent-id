// Alien Agent ID — Stub-translating local HTTP proxy.
//
// Listens on localhost. Speaks standard HTTP_PROXY semantics:
//
//   GET http://api.example.com/path HTTP/1.1     ← absolute-URI request
//   CONNECT api.example.com:443 HTTP/1.1         ← tunnel for HTTPS
//
// For absolute-URI requests it parses headers + URL for `AgentVault <name>`
// stubs, materializes them against the unlocked vault, enforces per-credential
// host allowlist, and forwards upstream. The agent never sees the value.
//
// CONNECT tunneling is transparent (no MITM); HTTPS stub injection requires
// the local-CA + per-host MITM spike described in the proposal. The agent
// receives unmodified TLS bytes — any stub left in an HTTPS request will go
// to the upstream as-is.

import http from "node:http";
import https from "node:https";
import net from "node:net";
import { URL } from "node:url";

import { rewriteHeaders, rewriteUrl, StubError } from "./stub.mjs";
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

  const server = http.createServer(async (req, res) => {
    const start = Date.now();
    let bytesIn = 0;
    let bytesOut = 0;
    let credentialsUsed = [];
    let host = null;
    let path = null;

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
      // HTTP_PROXY requests have an absolute URI on the request line.
      const target = req.url;
      if (!/^https?:\/\//i.test(target || "")) {
        return structuredError(res, 400, {
          error: "bad_request",
          message:
            "Proxy expects absolute URI (use HTTP_PROXY semantics: GET http://host/path)",
        });
      }
      const parsed = new URL(target);
      host = parsed.host;
      path = parsed.pathname;

      if (parsed.protocol === "https:") {
        // Without TLS MITM we cannot inject into HTTPS absolute-URI requests
        // either (they're rare — most clients use CONNECT for https). Reject
        // explicitly so the agent gets a structured error instead of a
        // silent passthrough of a stub.
        return structuredError(res, 501, {
          error: "https_not_supported_yet",
          message:
            "HTTPS injection requires the local-CA MITM spike; v1 supports HTTP only. " +
            "Use http:// for now or wait for the proxy TLS milestone.",
        });
      }

      // Inject into URL query params.
      let injectedUrl;
      try {
        const rewrittenUrl = rewriteUrl(target, { lookup, host: parsed.hostname });
        injectedUrl = new URL(rewrittenUrl.url);
        credentialsUsed = credentialsUsed.concat(rewrittenUrl.used);
      } catch (err) {
        return handleStubError(res, err);
      }

      // Inject into headers.
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

      // Mark every used credential's lastUsedAt (volatile until next vault.save()).
      if (state.vault) {
        for (const u of credentialsUsed) state.vault.touchLastUsed(u.name);
      }

      // Forward.
      const upstreamReq = http.request({
        protocol: injectedUrl.protocol,
        hostname: injectedUrl.hostname,
        port: injectedUrl.port || 80,
        method: req.method,
        path: `${injectedUrl.pathname}${injectedUrl.search || ""}`,
        headers: { ...injectedHeaders, host: injectedUrl.host },
      });

      upstreamReq.on("error", (err) => {
        structuredError(res, 502, {
          error: "upstream_error",
          message: err.message,
        });
        logAccess({
          method: req.method,
          host,
          path,
          status: 502,
          credentials: credentialsUsed.map((u) => u.name),
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
            host,
            path,
            status: upstreamRes.statusCode,
            credentials: credentialsUsed.map((u) => u.name),
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
