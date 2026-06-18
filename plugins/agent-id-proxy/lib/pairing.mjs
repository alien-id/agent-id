// Alien Agent ID — Phone pairing payload.
//
// The control plane's credential-bearing routes (/pending, /approve, /deny,
// /register) require a bearer token. The in-process owner-approval approver
// holds it in memory, but an external phone (mobile-slot unlock) has to learn
// it out-of-band. This module builds the QR/deep-link payload the host shows and
// the phone scans — it carries the reachable control URL and the token, so the
// phone can then register its enclave key and drive approvals.
//
// `parsePairingPayload` is the canonical phone-side reference (mirrors what the
// Alien app implements), and the round-trip is what the tests pin.

import os from "node:os";

export const PAIRING_SCHEME = "alien-vault";

const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost"]);
const WILDCARD = new Set(["0.0.0.0", "::"]);

// Resolve a host the phone can actually reach from the address the control
// server bound to. A specific routable host is used as-is; a wildcard bind
// (0.0.0.0 / ::) is resolved to the first non-internal IPv4; a loopback bind
// returns null (a separate device can't reach it — the caller should tell the
// operator to restart with --control-host <lan-ip>).
export function pickReachableHost(boundHost, interfaces = os.networkInterfaces()) {
  if (boundHost && !LOOPBACK.has(boundHost) && !WILDCARD.has(boundHost)) return boundHost;
  if (boundHost && LOOPBACK.has(boundHost)) return null;
  for (const name of Object.keys(interfaces || {})) {
    for (const ni of interfaces[name] || []) {
      if (ni.family === "IPv4" && !ni.internal) return ni.address;
    }
  }
  return null;
}

export function buildPairingPayload({ controlUrl, token, version = 1 }) {
  if (!controlUrl || !token) throw new Error("controlUrl and token are required");
  const q = new URLSearchParams({ v: String(version), control: controlUrl, token });
  return `${PAIRING_SCHEME}://pair?${q.toString()}`;
}

// Phone-side reference: turn a scanned pairing URI back into
// { version, control, token }. Throws on anything that isn't a well-formed
// alien-vault://pair payload.
export function parsePairingPayload(uri) {
  let u;
  try {
    u = new URL(uri);
  } catch {
    throw new Error("invalid pairing payload (not a URL)");
  }
  if (u.protocol !== `${PAIRING_SCHEME}:` || u.hostname !== "pair") {
    throw new Error(`not an ${PAIRING_SCHEME}://pair payload`);
  }
  const control = u.searchParams.get("control");
  const token = u.searchParams.get("token");
  if (!control || !token) throw new Error("pairing payload missing control or token");
  // The control URL must be an absolute http(s) URL.
  try {
    const c = new URL(control);
    if (c.protocol !== "http:" && c.protocol !== "https:") throw new Error("bad scheme");
  } catch {
    throw new Error("pairing payload has an invalid control URL");
  }
  return { version: Number(u.searchParams.get("v") || 1), control, token };
}
