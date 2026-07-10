// Alien Agent ID — development-only phone approval simulator.
//
// This adapter deliberately has a very small authority surface: it connects to
// a loopback control plane, polls pending requests, and resolves ONLY semantic
// capability approvals. It never unlocks a vault and never grants the legacy
// per-(credential, host) `authorize` consent. Production approval belongs on a
// separately-held phone key; this helper exists solely for local development
// and deterministic tests of the capability-broker flow.

import http from "node:http";

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "localhost"]);

function delay(ms, state) {
  if (state.stopping) return Promise.resolve();
  return new Promise((resolve) => {
    state.wake = resolve;
    state.timer = setTimeout(() => {
      state.timer = null;
      state.wake = null;
      resolve();
    }, ms);
    if (state.timer.unref) state.timer.unref();
  });
}

function requestJson(state, { method, path, body = null }) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      fn(value);
    };
    const payload = body == null ? null : JSON.stringify(body);
    const headers = { Authorization: `Bearer ${state.controlToken}` };
    if (payload != null) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = Buffer.byteLength(payload);
    }

    const req = http.request(
      {
        host: state.controlHost,
        port: state.controlPort,
        method,
        path,
        headers,
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("aborted", () => {
          state.requests.delete(req);
          finish(reject, new Error("dev phone control response aborted"));
        });
        res.on("error", (err) => {
          state.requests.delete(req);
          finish(reject, err);
        });
        res.on("end", () => {
          state.requests.delete(req);
          const raw = Buffer.concat(chunks).toString("utf8");
          let parsed = {};
          try {
            parsed = raw ? JSON.parse(raw) : {};
          } catch {
            const err = new Error(`dev phone control plane returned invalid JSON (${res.statusCode})`);
            err.code = "invalid_control_response";
            err.status = res.statusCode;
            finish(reject, err);
            return;
          }
          if (res.statusCode < 200 || res.statusCode >= 300 || parsed.ok === false) {
            const err = new Error(
              `dev phone control request failed (${res.statusCode}): ${parsed.error || "control_error"}`,
            );
            err.code = parsed.error || "control_error";
            err.status = res.statusCode;
            finish(reject, err);
            return;
          }
          finish(resolve, parsed);
        });
      },
    );
    state.requests.add(req);
    req.on("error", (err) => {
      state.requests.delete(req);
      finish(reject, err);
    });
    req.end(payload);
  });
}

/**
 * Start an explicitly development-only phone simulator.
 *
 * Returns immediately with a handle whose async `stop()` waits for the polling
 * loop to finish and aborts any in-flight loopback request. A pending entry is
 * handled at most once after a successful control response. Transient failures
 * remain retryable on a later poll.
 */
export function startDevPhoneSimulator({
  controlHost = "127.0.0.1",
  controlPort,
  controlToken,
  decision = "approve",
  pollIntervalMs = 50,
  onError = null,
} = {}) {
  if (!LOOPBACK_HOSTS.has(controlHost)) {
    throw new Error("dev phone simulator requires a loopback control host");
  }
  if (!Number.isInteger(controlPort) || controlPort <= 0 || controlPort > 65535) {
    throw new Error("dev phone simulator requires a valid controlPort");
  }
  if (typeof controlToken !== "string" || !controlToken) {
    throw new Error("dev phone simulator requires controlToken");
  }
  if (decision !== "approve" && decision !== "deny") {
    throw new Error("dev phone simulator decision must be 'approve' or 'deny'");
  }
  if (!Number.isFinite(pollIntervalMs) || pollIntervalMs < 1) {
    throw new Error("dev phone simulator pollIntervalMs must be a positive number");
  }
  if (onError != null && typeof onError !== "function") {
    throw new Error("dev phone simulator onError must be a function");
  }

  const state = {
    controlHost,
    controlPort,
    controlToken,
    stopping: false,
    timer: null,
    wake: null,
    requests: new Set(),
    handled: new Set(),
  };

  const reportError = (err) => {
    if (!state.stopping && onError) {
      try {
        onError(err);
      } catch {
        // Diagnostic hooks must never terminate the simulator loop.
      }
    }
  };

  const loop = (async () => {
    while (!state.stopping) {
      try {
        const result = await requestJson(state, { method: "GET", path: "/pending" });
        for (const entry of Array.isArray(result.pending) ? result.pending : []) {
          if (state.stopping) break;
          // Never simulate vault unlock or broad legacy credential consent.
          if (entry?.action !== "capability") continue;
          if (typeof entry.id !== "string" || !entry.id) continue;
          if (typeof entry.actionDigest !== "string" || !entry.actionDigest) continue;
          if (state.handled.has(entry.id)) continue;

          const body = {
            id: entry.id,
            actionDigest: entry.actionDigest,
            scope: "once",
          };
          try {
            await requestJson(state, {
              method: "POST",
              path: decision === "approve" ? "/approve" : "/deny",
              body,
            });
            state.handled.add(entry.id);
          } catch (err) {
            reportError(err);
          }
        }
      } catch (err) {
        reportError(err);
      }
      await delay(pollIntervalMs, state);
    }
  })();

  return {
    async stop() {
      if (!state.stopping) {
        state.stopping = true;
        if (state.timer) clearTimeout(state.timer);
        state.timer = null;
        if (state.wake) state.wake();
        state.wake = null;
        for (const req of state.requests) req.destroy();
      }
      await loop;
    },
    get handledCount() {
      return state.handled.size;
    },
  };
}
