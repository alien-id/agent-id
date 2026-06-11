// Alien Agent ID — Credential store: schema + in-memory record table.
//
// The vault payload is a single JSON document holding all credential
// records. This module owns:
//   - the schema (allowed types, required fields per type)
//   - in-memory CRUD on the record array
//   - domain allowlist matching used by the proxy at injection time
//
// Records:
//   {
//     name: "github-pat",
//     type: "bearer" | "basic" | "header" | "query" | "cookie" | "totp" | "cookie-jar",
//     domains: ["*.github.com"],
//     description: "...",
//     createdAt, updatedAt, lastUsedAt,
//     ...type-specific fields
//   }

import { nowMs } from "../../agent-id-core/lib/crypto.mjs";

export const CREDENTIAL_TYPES = Object.freeze([
  "bearer",
  "basic",
  "header",
  "query",
  "cookie",
  "totp",
  "cookie-jar",
  "oauth2",
  "solana-keypair",
  "evm-keypair",
]);

// A token endpoint must be reached over TLS — the refresh token + client secret
// travel in its request body. The only carve-out is loopback (local dev / tests),
// where there is no network to eavesdrop.
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);

function isLoopbackUrl(u) {
  return LOOPBACK_HOSTS.has(u.hostname);
}

const NAME_RE = /^[a-zA-Z0-9._-]{1,64}$/;

function requireNonEmpty(rec, fields) {
  for (const f of fields) {
    if (typeof rec[f] !== "string" || rec[f].length === 0) {
      throw new Error(`Credential ${rec.name}: '${f}' is required for type ${rec.type}`);
    }
  }
}

export const UPSTREAM_SCHEMES = Object.freeze(["https", "http"]);

export function validateRecord(rec) {
  if (!rec || typeof rec !== "object") {
    throw new Error("Record must be an object");
  }
  if (!NAME_RE.test(rec.name || "")) {
    throw new Error(
      `Invalid credential name: ${rec.name} (must match ${NAME_RE.source})`,
    );
  }
  if (!CREDENTIAL_TYPES.includes(rec.type)) {
    throw new Error(`Unknown credential type: ${rec.type}`);
  }
  if (!Array.isArray(rec.domains) || rec.domains.length === 0) {
    throw new Error(
      `Credential ${rec.name}: 'domains' must be a non-empty array (default-deny)`,
    );
  }
  for (const d of rec.domains) {
    if (typeof d !== "string" || d.length === 0) {
      throw new Error(`Credential ${rec.name}: invalid domain entry`);
    }
  }
  if (rec.upstreamScheme != null && !UPSTREAM_SCHEMES.includes(rec.upstreamScheme)) {
    throw new Error(
      `Credential ${rec.name}: upstreamScheme must be one of ${UPSTREAM_SCHEMES.join(", ")}`,
    );
  }
  switch (rec.type) {
    case "bearer":
      requireNonEmpty(rec, ["value"]);
      break;
    case "basic":
      requireNonEmpty(rec, ["username", "password"]);
      break;
    case "header":
      requireNonEmpty(rec, ["headerName", "value"]);
      break;
    case "query":
      requireNonEmpty(rec, ["paramName", "value"]);
      break;
    case "cookie":
      requireNonEmpty(rec, ["cookieName", "value"]);
      break;
    case "totp":
      requireNonEmpty(rec, ["secret"]);
      break;
    case "cookie-jar":
      if (!rec.cookies || typeof rec.cookies !== "object") {
        throw new Error(`Credential ${rec.name}: 'cookies' object is required`);
      }
      break;
    case "oauth2": {
      // The proxy refreshes an access token from the stored refresh token at
      // injection time, then materializes it as `Authorization: Bearer …`. The
      // agent never sees any of these fields. clientSecret is optional (public /
      // PKCE clients omit it); scope and the seeded accessToken are optional.
      requireNonEmpty(rec, ["tokenEndpoint", "clientId", "refreshToken"]);
      let endpoint;
      try {
        endpoint = new URL(rec.tokenEndpoint);
      } catch {
        throw new Error(`Credential ${rec.name}: tokenEndpoint is not a valid URL`);
      }
      if (endpoint.protocol !== "https:" && !isLoopbackUrl(endpoint)) {
        throw new Error(
          `Credential ${rec.name}: tokenEndpoint must be https (or loopback) — ` +
            "it carries the refresh token and client secret",
        );
      }
      if (rec.clientSecret != null && typeof rec.clientSecret !== "string") {
        throw new Error(`Credential ${rec.name}: clientSecret must be a string`);
      }
      if (rec.scope != null && typeof rec.scope !== "string") {
        throw new Error(`Credential ${rec.name}: scope must be a string`);
      }
      if (rec.accessTokenExpiresAt != null && typeof rec.accessTokenExpiresAt !== "number") {
        throw new Error(`Credential ${rec.name}: accessTokenExpiresAt must be epoch ms`);
      }
      break;
    }
    case "solana-keypair": {
      // Generated INSIDE the vault (`agent-id-vault generate`) — the seed never
      // crosses a process boundary. The proxy signs transactions with it; the
      // agent only ever sees the public key (the wallet address).
      requireNonEmpty(rec, ["secretSeed", "publicKey"]);
      if (!/^[0-9a-fA-F]{64}$/.test(rec.secretSeed)) {
        throw new Error(`Credential ${rec.name}: secretSeed must be 32 bytes of hex`);
      }
      if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(rec.publicKey)) {
        throw new Error(`Credential ${rec.name}: publicKey must be a base58 Solana address`);
      }
      break;
    }
    case "evm-keypair": {
      // Same sealed treatment as solana-keypair: generated in-vault, the
      // secp256k1 key signs EIP-1559 transactions inside the proxy. Only the
      // EIP-55 address is public.
      requireNonEmpty(rec, ["privateKey", "address"]);
      if (!/^[0-9a-fA-F]{64}$/.test(rec.privateKey)) {
        throw new Error(`Credential ${rec.name}: privateKey must be 32 bytes of hex`);
      }
      if (!/^0x[0-9a-fA-F]{40}$/.test(rec.address)) {
        throw new Error(`Credential ${rec.name}: address must be a 0x-prefixed EVM address`);
      }
      break;
    }
  }
}

// ─── Payload serializer ─────────────────────────────────────────────────────────

export function emptyPayload() {
  return { version: 1, credentials: [] };
}

export function parsePayload(jsonString) {
  if (!jsonString || jsonString === "{}") return emptyPayload();
  const parsed = JSON.parse(jsonString);
  if (!parsed.credentials) return emptyPayload();
  for (const rec of parsed.credentials) validateRecord(rec);
  return parsed;
}

export function serializePayload(payload) {
  return JSON.stringify(payload);
}

// ─── CRUD ───────────────────────────────────────────────────────────────────────

export function addCredential(payload, record) {
  validateRecord(record);
  const idx = payload.credentials.findIndex((c) => c.name === record.name);
  const now = nowMs();
  const finalRecord = {
    ...record,
    createdAt: idx >= 0 ? payload.credentials[idx].createdAt : now,
    updatedAt: now,
    lastUsedAt: idx >= 0 ? payload.credentials[idx].lastUsedAt || null : null,
  };
  if (idx >= 0) {
    payload.credentials[idx] = finalRecord;
  } else {
    payload.credentials.push(finalRecord);
  }
  return finalRecord;
}

export function removeCredential(payload, name) {
  const idx = payload.credentials.findIndex((c) => c.name === name);
  if (idx < 0) return null;
  const [removed] = payload.credentials.splice(idx, 1);
  return removed;
}

export function getCredential(payload, name) {
  return payload.credentials.find((c) => c.name === name) || null;
}

export function listMetadata(payload) {
  return payload.credentials.map((c) => ({
    name: c.name,
    type: c.type,
    domains: c.domains,
    description: c.description || null,
    // The wallet address is public by design — agents need it to build
    // transactions and check balances without opening the record.
    ...(c.publicKey ? { publicKey: c.publicKey } : {}),
    ...(c.address ? { address: c.address } : {}),
    createdAt: c.createdAt,
    updatedAt: c.updatedAt,
    lastUsedAt: c.lastUsedAt || null,
  }));
}

export function touchLastUsed(payload, name) {
  const rec = getCredential(payload, name);
  if (rec) rec.lastUsedAt = nowMs();
}

// ─── Domain allowlist matching ──────────────────────────────────────────────────

// Supports literal hostnames and a single leading "*." wildcard.
// `*.github.com` matches `github.com`, `api.github.com`, `x.y.github.com`.
export function hostMatchesAllowlist(host, allowlist) {
  if (!host || !Array.isArray(allowlist)) return false;
  const hostLower = host.toLowerCase();
  for (const entry of allowlist) {
    const e = entry.toLowerCase();
    if (e.startsWith("*.")) {
      const suffix = e.slice(1); // ".github.com"
      const bare = e.slice(2); // "github.com"
      if (hostLower === bare) return true;
      if (hostLower.endsWith(suffix)) return true;
    } else if (hostLower === e) {
      return true;
    }
  }
  return false;
}
