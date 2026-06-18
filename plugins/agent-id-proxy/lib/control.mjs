// Alien Agent ID — Proxy control plane.
//
// A second localhost-only HTTP listener the phone polls to drive
// human-in-the-loop approvals: vault unlock (sealed-box, the phone returns the
// recovered master key) and per-credential consent ("agent wants <cred> →
// <host>"). The data plane (proxy.mjs) parks a blocked request in the pending
// registry and awaits its promise; the phone resolves it via /approve or /deny.
//
// Routes (all 127.0.0.1):
//   GET  /status   → { ok, locked, pending, devices, idleTimeout, ... }
//   GET  /pending  → { ok, pending: [ {id, action, ...} ] }
//   POST /approve  → { id, masterKey? }   resolves the parked request
//   POST /deny     → { id, reason? }      rejects the parked request (→ 403)
//   POST /register → { devicePubKey, deviceId }  pairs a phone (vault must be
//                    unlocked); the proxy seals a mobile slot to the device key
//
// The pending entries for an unlock carry only the sealed box (ephemeral pub,
// salt, ciphertext) — never the master key. Only the phone, holding the enclave
// private key, can turn that into the master key it POSTs back to /approve.

import http from "node:http";
import { randomUUID, timingSafeEqual } from "node:crypto";

const MAX_BODY_BYTES = 256 * 1024;

// Constant-time bearer-token check. /status stays open (liveness only); the
// pending/approve/deny/register routes carry or act on credential material and
// require the token, so a co-resident process or LAN host that can reach the
// control port still cannot drive an approval or read pending requests.
function tokenMatches(provided, expected) {
  if (typeof provided !== "string" || provided.length !== expected.length) return false;
  return timingSafeEqual(Buffer.from(provided), Buffer.from(expected));
}

function presentedToken(req) {
  const auth = req.headers.authorization || "";
  const m = /^Bearer\s+(.+)$/i.exec(auth);
  if (m) return m[1];
  const hdr = req.headers["x-agentvault-control-token"];
  return typeof hdr === "string" ? hdr : null;
}

export function approvalError(reason, status = 403) {
  const err = new Error(reason);
  err.code = reason;
  err.status = status;
  return err;
}

// In-memory registry of parked, awaiting-approval requests.
export function createPendingRegistry({
  now = () => Date.now(),
  timeoutMs = 120_000,
} = {}) {
  const pending = new Map();

  function create(info) {
    const id = randomUUID();
    let resolveFn;
    let rejectFn;
    const promise = new Promise((resolve, reject) => {
      resolveFn = resolve;
      rejectFn = reject;
    });
    const timer =
      Number.isFinite(timeoutMs) && timeoutMs > 0
        ? setTimeout(() => {
            const entry = pending.get(id);
            if (entry) {
              pending.delete(id);
              entry._reject(approvalError("approval_timeout", 504));
            }
          }, timeoutMs)
        : null;
    if (timer && timer.unref) timer.unref();

    const settle = () => {
      if (timer) clearTimeout(timer);
      pending.delete(id);
    };
    pending.set(id, {
      id,
      info,
      createdAt: now(),
      _resolve: resolveFn,
      _reject: rejectFn,
      resolve(value) {
        settle();
        resolveFn(value);
      },
      reject(err) {
        settle();
        rejectFn(err);
      },
    });
    return { id, promise };
  }

  function resolve(id, value) {
    const entry = pending.get(id);
    if (!entry) return false;
    entry.resolve(value);
    return true;
  }

  function reject(id, reason) {
    const entry = pending.get(id);
    if (!entry) return false;
    entry.reject(approvalError(reason || "denied"));
    return true;
  }

  function get(id) {
    const entry = pending.get(id);
    if (!entry) return null;
    return { id: entry.id, createdAt: entry.createdAt, ...entry.info };
  }

  function list() {
    return [...pending.values()].map((e) => ({
      id: e.id,
      createdAt: e.createdAt,
      ...e.info,
    }));
  }

  function cancelAll(reason) {
    for (const id of [...pending.keys()]) reject(id, reason);
  }

  return {
    create,
    resolve,
    reject,
    get,
    list,
    cancelAll,
    get size() {
      return pending.size;
    },
  };
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(approvalError("body_too_large", 413));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(approvalError("invalid_json", 400));
      }
    });
    req.on("error", reject);
  });
}

function sendJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

// onApprove(id, body) and onDeny(id, body) are supplied by the proxy. onApprove
// may be async and may throw an approvalError (e.g. the returned master key
// doesn't open the vault) — the server maps that to its HTTP status.
export function createControlServer({
  registry,
  getStatus,
  onApprove,
  onDeny,
  onRegister,
  authToken = null,
  listen = { port: 0, host: "127.0.0.1" },
}) {
  // Routes that read or act on credential material require the token; /status
  // (and GET /) are liveness-only and stay open.
  const requireToken = (req) => !authToken || tokenMatches(presentedToken(req), authToken);

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, "http://127.0.0.1");
      const route = `${req.method} ${url.pathname}`;

      if (route === "GET /status" || route === "GET /") {
        return sendJson(res, 200, { ok: true, ...(await getStatus()) });
      }
      if (!requireToken(req)) {
        return sendJson(res, 401, { ok: false, error: "control_unauthorized" });
      }
      if (route === "GET /pending") {
        return sendJson(res, 200, { ok: true, pending: registry.list() });
      }
      if (route === "POST /register" && onRegister) {
        const body = await readJsonBody(req);
        const result = await onRegister(body);
        if (!result.ok) {
          return sendJson(res, result.status || 400, { ok: false, error: result.error });
        }
        return sendJson(res, 200, { ok: true, ...result.body });
      }
      if (route === "POST /approve") {
        const body = await readJsonBody(req);
        if (!body.id) return sendJson(res, 400, { ok: false, error: "id_required" });
        const result = await onApprove(body.id, body);
        if (!result.ok) {
          return sendJson(res, result.status || 404, { ok: false, error: result.error });
        }
        return sendJson(res, 200, { ok: true, ...result.body });
      }
      if (route === "POST /deny") {
        const body = await readJsonBody(req);
        if (!body.id) return sendJson(res, 400, { ok: false, error: "id_required" });
        const found = onDeny(body.id, body);
        return sendJson(res, found ? 200 : 404, {
          ok: found,
          ...(found ? {} : { error: "unknown_request" }),
        });
      }
      return sendJson(res, 404, { ok: false, error: "not_found" });
    } catch (err) {
      const status = err.status || 500;
      sendJson(res, status, { ok: false, error: err.code || "control_error", message: err.message });
    }
  });

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
      return new Promise((resolve) => server.close(() => resolve()));
    },
  };
}
