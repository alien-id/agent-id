// Alien Agent ID — one-way notices to the host.
//
// The secure-prompt socket normally means "ask the owner to type something and
// block until they do". A notice is the other half: tell the owner something and
// carry on. It exists for challenges answered somewhere the harness cannot see —
// a "tap Yes on your phone" prompt is approved in Google's own app, so the
// browser child must surface a card and keep polling the page, not ask for a
// value that will never be typed here.
//
// The host raises the named event on its client stream and replies 200
// immediately. Event names are namespaced (`browser.*`) and the host enforces
// that, so a child cannot forge identity or secure-input lifecycle events.
//
// Best effort by construction: a missing socket, a refusing host, or a slow
// reply must never fail the operation being reported on. Every path resolves.

import http from "node:http";
import { statSync } from "node:fs";

const HOSTED_SOCK_ENV = "AGENT_ID_SECURE_PROMPT_SOCK";
const NOTICE_TIMEOUT_MS = 3000;

function hostedSocketPath(env) {
  const p = env[HOSTED_SOCK_ENV];
  if (!p || typeof p !== "string" || p.includes("://")) return null;
  try {
    return statSync(p).isSocket() ? p : null;
  } catch {
    return null;
  }
}

/**
 * Raise `event` (must be under `browser.`) with `data` on the host's client
 * stream. Resolves true when the host accepted it, false in every other case —
 * including when there is no host at all, which is the normal standalone case.
 */
export function notifyHost(event, data = {}, { env = process.env } = {}) {
  const socketPath = hostedSocketPath(env);
  if (!socketPath) return Promise.resolve(false);
  const payload = JSON.stringify({ kind: "notice", event, data });
  return new Promise((resolve) => {
    let settled = false;
    const done = (value) => {
      if (!settled) {
        settled = true;
        resolve(value);
      }
    };
    const req = http.request(
      {
        socketPath,
        path: "/",
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload),
        },
      },
      (res) => {
        res.resume(); // drain so the socket can close
        res.on("end", () => done(res.statusCode === 200));
      },
    );
    req.on("error", () => done(false));
    req.setTimeout(NOTICE_TIMEOUT_MS, () => {
      req.destroy();
      done(false);
    });
    req.end(payload);
  });
}
