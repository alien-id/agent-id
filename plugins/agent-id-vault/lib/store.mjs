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
//     type: one of CREDENTIAL_TYPES below (bearer | basic | header | query |
//           cookie | totp | cookie-jar | oauth2 | solana-keypair | evm-keypair |
//           browser-profile | secret | login),
//     domains: ["*.github.com"],
//     description: "...",
//     createdAt, updatedAt, lastUsedAt,
//     ...type-specific fields
//   }

import { nowMs } from "@alien-id/agent-id-core/lib/crypto.mjs";
import { isLoopbackHost } from "@alien-id/agent-id-core/lib/http.mjs";
import { hostMatchesAllowlist, validateAccessFields } from "./access.mjs";

// Domain matching lives in access.mjs (access rules share the syntax); kept
// exported here for the proxy/browser consumers that import it from store.
export { hostMatchesAllowlist };

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
  "browser-profile",
  "secret",
  "login",
]);

// Allowed `otp` policies on a `login` credential.
export const LOGIN_OTP_MODES = Object.freeze(["none", "totp", "interactive"]);

// The recipe step vocabulary auto-login can execute (runRecipe's switch). Declared
// here so writing a recipe and running one agree on the same closed set.
export const LOGIN_RECIPE_ACTIONS = Object.freeze([
  "navigate",
  "fill",
  "type",
  "click",
  "press",
  "wait",
]);

// A token endpoint must be reached over TLS — the refresh token + client secret
// travel in its request body. The only carve-out is loopback (local dev / tests),
// where there is no network to eavesdrop (isLoopbackHost, shared with the OIDC stack).
const NAME_RE = /^[a-zA-Z0-9._-]{1,64}$/;

function requireNonEmpty(rec, fields) {
  for (const f of fields) {
    if (typeof rec[f] !== "string" || rec[f].length === 0) {
      throw new Error(`Credential ${rec.name}: '${f}' is required for type ${rec.type}`);
    }
  }
}

export const UPSTREAM_SCHEMES = Object.freeze(["https", "http"]);

// ─── Wallet signing-constraint validators (all optional / default-allow) ──────

function validateChainIdAllowlist(rec) {
  if (rec.chainIdAllowlist == null) return;
  if (!Array.isArray(rec.chainIdAllowlist) || rec.chainIdAllowlist.length === 0) {
    throw new Error(`Credential ${rec.name}: chainIdAllowlist must be a non-empty array`);
  }
  for (const c of rec.chainIdAllowlist) {
    if (!Number.isInteger(c) || c <= 0) {
      throw new Error(`Credential ${rec.name}: chainIdAllowlist entries must be positive integers`);
    }
  }
}

function validateToAllowlist(rec) {
  if (rec.toAllowlist == null) return;
  if (!Array.isArray(rec.toAllowlist) || rec.toAllowlist.length === 0) {
    throw new Error(`Credential ${rec.name}: toAllowlist must be a non-empty array`);
  }
  for (const a of rec.toAllowlist) {
    if (typeof a !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(a)) {
      throw new Error(`Credential ${rec.name}: toAllowlist entries must be 0x EVM addresses`);
    }
  }
}

function validateProgramAllowlist(rec) {
  if (rec.programAllowlist == null) return;
  if (!Array.isArray(rec.programAllowlist) || rec.programAllowlist.length === 0) {
    throw new Error(`Credential ${rec.name}: programAllowlist must be a non-empty array`);
  }
  for (const p of rec.programAllowlist) {
    if (typeof p !== "string" || !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(p)) {
      throw new Error(`Credential ${rec.name}: programAllowlist entries must be base58 program ids`);
    }
  }
}

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
  // Optional per-credential access level + rules (enforced by the proxy and
  // the browser session server; see access.mjs).
  validateAccessFields(rec);
  switch (rec.type) {
    case "bearer":
      requireNonEmpty(rec, ["value"]);
      break;
    case "secret":
      // Arbitrary secret blob — an SSH/RSA private key, a PEM, a service-account
      // JSON, or any token. NOT HTTP-injectable: it's consumed via `exec` (env)
      // or materialized to a temp file, never by the proxy. `domains` is unused
      // for this type (callers default it to ["*"]).
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
      if (endpoint.protocol !== "https:" && !isLoopbackHost(endpoint.hostname)) {
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
      // Optional signing constraint: every instruction's program must be on this
      // allowlist (e.g. restrict to the System Program for transfers only).
      validateProgramAllowlist(rec);
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
      // Optional signing constraints (default-allow when absent): bound which
      // chains and recipients the in-vault key will sign for.
      validateChainIdAllowlist(rec);
      validateToAllowlist(rec);
      break;
    }
    case "browser-profile": {
      // Used by `agent-id-browser`, NOT the HTTP proxy. The vault holds only the
      // data-encryption key (DEK) + the sidecar filename; the actual browser
      // profile (cookies, tokens) is sealed at <stateDir>/browser-profiles/<file>
      // with this DEK. `domains` is required by the schema but unused for this
      // type (the profile is launched, not injected) — callers default to ["*"].
      requireNonEmpty(rec, ["dek", "profileFile"]);
      if (!/^[0-9a-fA-F]{64}$/.test(rec.dek)) {
        throw new Error(`Credential ${rec.name}: dek must be 32 bytes of hex`);
      }
      if (/[\\/]/.test(rec.profileFile)) {
        throw new Error(`Credential ${rec.name}: profileFile must be a bare filename (no path)`);
      }
      if (rec.headless != null && typeof rec.headless !== "boolean") {
        throw new Error(`Credential ${rec.name}: headless must be a boolean`);
      }
      break;
    }
    case "login": {
      // A direct service login the sealed browser (agent-id-browser) drives — NOT
      // proxy-injected. `otp` chooses how a one-time code is answered: `none` (no
      // code step), `totp` (generate from a stored seed; requires `totpSecret`), or
      // `interactive` (ask the human for the current code over the secure-prompt
      // channel).
      //
      // `domains` is NOT advisory here, unlike browser-profile / secret: the browser
      // gates fill-secret / fill-otp on it, and auto-login gates every recipe step
      // and navigation on it. A login credential scoped to a host it will never be
      // used on simply cannot be typed.
      //
      // `passwordless` marks a site with no password at all — an identifier is
      // submitted and a code arrives out of band (mail, SMS). It is deliberately a
      // separate axis from `otp`, so "password AND an e-mailed code" stays
      // expressible; collapsing the two would make the pair indistinguishable.
      requireNonEmpty(rec, ["username"]);
      if (!rec.passwordless) requireNonEmpty(rec, ["password"]);
      const otp = rec.otp == null ? "none" : rec.otp;
      if (!LOGIN_OTP_MODES.includes(otp)) {
        throw new Error(
          `Credential ${rec.name}: otp must be one of ${LOGIN_OTP_MODES.join(", ")}`,
        );
      }
      if (rec.passwordless && otp === "none") {
        throw new Error(
          `Credential ${rec.name}: a passwordless login needs otp=interactive or totp — ` +
            "with no password and no code step there is nothing to sign in with",
        );
      }
      if (otp === "totp") requireNonEmpty(rec, ["totpSecret"]);
      if (rec.loginUrl != null) {
        try {
          new URL(rec.loginUrl);
        } catch {
          throw new Error(`Credential ${rec.name}: loginUrl is not a valid URL`);
        }
      }
      if (rec.profile != null && (typeof rec.profile !== "string" || rec.profile.length === 0)) {
        throw new Error(`Credential ${rec.name}: profile must be a non-empty string`);
      }
      if (rec.recipe != null) {
        if (!Array.isArray(rec.recipe)) {
          throw new Error(`Credential ${rec.name}: recipe must be an array of steps`);
        }
        // Validated on the way IN, not on the way out: an unknown action used to
        // surface as a mid-login throw from runRecipe, after the browser was open
        // and possibly after the owner had typed a code.
        rec.recipe.forEach((step, i) => {
          if (!step || typeof step !== "object" || Array.isArray(step)) {
            throw new Error(`Credential ${rec.name}: recipe step ${i} must be an object`);
          }
          if (!LOGIN_RECIPE_ACTIONS.includes(step.action)) {
            throw new Error(
              `Credential ${rec.name}: recipe step ${i} has action "${step.action}" — ` +
                `must be one of ${LOGIN_RECIPE_ACTIONS.join(", ")}`,
            );
          }
        });
      }
      if (
        rec.selectors != null &&
        (typeof rec.selectors !== "object" || Array.isArray(rec.selectors))
      ) {
        throw new Error(`Credential ${rec.name}: selectors must be an object`);
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
    // Access level is metadata, not a secret — agents need to see it to know
    // which operations a credential permits (and how to ask for more).
    ...(c.access ? { access: c.access } : {}),
    ...(Array.isArray(c.accessRules) ? { accessRules: c.accessRules } : {}),
    // The wallet address is public by design — agents need it to build
    // transactions and check balances without opening the record.
    ...(c.publicKey ? { publicKey: c.publicKey } : {}),
    ...(c.address ? { address: c.address } : {}),
    // browser-profile: surface the (non-secret) account label + headless default
    // so an agent can see which profile is which without opening the record.
    ...(c.account ? { account: c.account } : {}),
    ...(c.type === "browser-profile" ? { headless: c.headless !== false } : {}),
    // login: the non-secret shape of the sign-in, so a caller can tell what a
    // stored credential will ask for before driving it — whether a password
    // exists at all, how a code is answered, where to start, and whether an
    // explicit recipe is on file. Without these, re-using a stored login means
    // guessing.
    ...(c.type === "login"
      ? {
          otp: c.otp || "none",
          passwordless: c.passwordless === true,
          loginUrl: c.loginUrl || null,
          hasRecipe: Array.isArray(c.recipe) && c.recipe.length > 0,
        }
      : {}),
    createdAt: c.createdAt,
    updatedAt: c.updatedAt,
    lastUsedAt: c.lastUsedAt || null,
  }));
}

export function touchLastUsed(payload, name) {
  const rec = getCredential(payload, name);
  if (rec) rec.lastUsedAt = nowMs();
}

// Every per-type field that holds secret material — the single source of truth.
// Used in three places that MUST agree, so they all import this one list:
//   - wipePayload (here): scrub decrypted secrets when the vault locks
//   - `show` (cli): redact these on sealed/non-exportable records
//   - `exec` (cli): refuse to inject a sealed record's secret field into a child
// Adding a new secret-bearing field/type means editing ONLY this array; forget
// it and a secret either survives idle-lock or escapes via `show`.
export const SECRET_FIELDS = Object.freeze([
  "value", // bearer / header / query / cookie
  "username",
  "password", // basic
  "secret", // totp
  "cookies", // cookie-jar (object of name → value)
  "refreshToken",
  "clientSecret",
  "accessToken", // oauth2
  "secretSeed", // solana-keypair
  "privateKey", // evm-keypair
  "dek", // browser-profile (data-encryption key for the sealed profile)
  "totpSecret", // login (the stored 2FA seed; username + password already listed above)
]);

// Best-effort scrub of decrypted secret material when the vault locks. JS
// strings are immutable and cannot be overwritten in place, so the strongest
// achievable guarantee is to drop every reference (Buffers are zero-filled) so
// the values become GC-eligible immediately instead of lingering in the live
// object graph (and any later heap dump / core file) until the next GC.
export function wipePayload(payload) {
  if (!payload || !Array.isArray(payload.credentials)) return;
  for (const cred of payload.credentials) {
    if (!cred || typeof cred !== "object") continue;
    for (const f of SECRET_FIELDS) {
      const v = cred[f];
      if (Buffer.isBuffer(v)) v.fill(0);
      // Drop the vault's reference to the secret (string or nested object) so it
      // becomes GC-eligible. We deliberately do NOT recurse into nested objects
      // to delete their keys: a record's object fields (e.g. a cookie-jar's
      // `cookies`) may be aliased by the caller that supplied them via
      // vault.add(), and the vault must not destroy objects it doesn't
      // exclusively own. Releasing the reference is the achievable guarantee.
      if (f in cred) delete cred[f];
    }
  }
  payload.credentials.length = 0;
}

