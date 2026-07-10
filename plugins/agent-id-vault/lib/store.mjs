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
import { validateCapabilityPolicy } from "./capability.mjs";

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
  if (
    rec.capabilityPolicyEpoch != null &&
    (!Number.isSafeInteger(rec.capabilityPolicyEpoch) || rec.capabilityPolicyEpoch < 1)
  ) {
    throw new Error(`Credential ${rec.name}: capabilityPolicyEpoch must be a positive integer`);
  }
  if (rec.capabilityPolicy != null) {
    validateCapabilityPolicy(rec.capabilityPolicy, rec.name);
    if (rec.capabilityPolicyEpoch == null) {
      throw new Error(
        `Credential ${rec.name}: capabilityPolicyEpoch is required with capabilityPolicy`,
      );
    }
    if (rec.capabilityPolicyEpoch !== rec.capabilityPolicy.epoch) {
      throw new Error(
        `Credential ${rec.name}: capabilityPolicyEpoch must match capabilityPolicy.epoch`,
      );
    }
  }
  if (
    rec.credentialRevision != null &&
    (!Number.isSafeInteger(rec.credentialRevision) || rec.credentialRevision < 1)
  ) {
    throw new Error(`Credential ${rec.name}: credentialRevision must be a positive safe integer`);
  }
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
      // proxy-injected (`domains` is advisory for this type, like browser-profile /
      // secret). `otp` chooses how a 2FA step is answered: `none` (no 2FA), `totp`
      // (generate from a stored seed; requires `totpSecret`), or `interactive`
      // (ask the human for the current code over the secure-prompt channel).
      requireNonEmpty(rec, ["username", "password"]);
      const otp = rec.otp == null ? "none" : rec.otp;
      if (!LOGIN_OTP_MODES.includes(otp)) {
        throw new Error(
          `Credential ${rec.name}: otp must be one of ${LOGIN_OTP_MODES.join(", ")}`,
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
      if (rec.recipe != null && !Array.isArray(rec.recipe)) {
        throw new Error(`Credential ${rec.name}: recipe must be an array of steps`);
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
  return {
    version: 1,
    credentials: [],
    capabilityEpochs: Object.create(null),
    credentialRevisions: Object.create(null),
  };
}

export function parsePayload(jsonString) {
  if (!jsonString || jsonString === "{}") return emptyPayload();
  const parsed = JSON.parse(jsonString);
  if (!parsed.credentials) return emptyPayload();
  if (
    parsed.capabilityEpochs != null &&
    (typeof parsed.capabilityEpochs !== "object" || Array.isArray(parsed.capabilityEpochs))
  ) {
    throw new Error("Vault capabilityEpochs must be an object");
  }
  const epochEntries = Object.entries(parsed.capabilityEpochs || {});
  parsed.capabilityEpochs = Object.create(null);
  for (const [name, epoch] of epochEntries) {
    if (!NAME_RE.test(name) || !Number.isSafeInteger(epoch) || epoch < 1) {
      throw new Error(`Vault capabilityEpochs has invalid entry '${name}'`);
    }
    parsed.capabilityEpochs[name] = epoch;
  }
  const revisionEntries = Object.entries(parsed.credentialRevisions || {});
  parsed.credentialRevisions = Object.create(null);
  for (const [name, revision] of revisionEntries) {
    if (!NAME_RE.test(name) || !Number.isSafeInteger(revision) || revision < 1) {
      throw new Error(`Vault credentialRevisions has invalid entry '${name}'`);
    }
    parsed.credentialRevisions[name] = revision;
  }
  for (const rec of parsed.credentials) {
    validateRecord(rec);
    const knownEpoch = parsed.capabilityEpochs[rec.name] || 0;
    const recordEpoch = rec.capabilityPolicyEpoch || 0;
    if (recordEpoch < knownEpoch) {
      throw new Error(
        `Credential ${rec.name}: capability epoch rollback (${recordEpoch} < ${knownEpoch})`,
      );
    }
    if (recordEpoch > knownEpoch) parsed.capabilityEpochs[rec.name] = recordEpoch;
    const knownRevision = parsed.credentialRevisions[rec.name] || 0;
    const recordRevision = rec.credentialRevision || 0;
    if (recordRevision < knownRevision) {
      throw new Error(
        `Credential ${rec.name}: credential revision rollback ` +
          `(${recordRevision} < ${knownRevision})`,
      );
    }
    if (recordRevision > knownRevision) {
      parsed.credentialRevisions[rec.name] = recordRevision;
    }
  }
  return parsed;
}

export function serializePayload(payload) {
  return JSON.stringify(payload);
}

// ─── CRUD ───────────────────────────────────────────────────────────────────────

export function addCredential(payload, record) {
  // The store exclusively owns every nested object it retains. Without a deep
  // copy, a caller could mutate domains/rules/policy/cookies after validation
  // and save the change without advancing credentialRevision.
  const ownedRecord = structuredClone(record);
  const idx = payload.credentials.findIndex((c) => c.name === ownedRecord.name);
  if (!payload.credentialRevisions) payload.credentialRevisions = Object.create(null);
  const knownRevision = Object.prototype.hasOwnProperty.call(
    payload.credentialRevisions,
    ownedRecord.name,
  )
    ? payload.credentialRevisions[ownedRecord.name]
    : payload.credentials[idx]?.credentialRevision || 0;
  const nextRevision = knownRevision + 1;
  const revisedRecord = { ...ownedRecord, credentialRevision: nextRevision };
  validateRecord(revisedRecord);
  if (!payload.capabilityEpochs) payload.capabilityEpochs = Object.create(null);
  const knownEpoch = Object.prototype.hasOwnProperty.call(payload.capabilityEpochs, revisedRecord.name)
    ? payload.capabilityEpochs[revisedRecord.name]
    : 0;
  const recordEpoch = revisedRecord.capabilityPolicyEpoch || 0;
  if (knownEpoch > 0 && recordEpoch < knownEpoch) {
    throw new Error(
      `Credential ${revisedRecord.name}: capability epoch rollback (${recordEpoch} < ${knownEpoch})`,
    );
  }
  if (recordEpoch > knownEpoch) payload.capabilityEpochs[revisedRecord.name] = recordEpoch;
  payload.credentialRevisions[revisedRecord.name] = nextRevision;
  const now = nowMs();
  const finalRecord = {
    ...revisedRecord,
    createdAt: idx >= 0 ? payload.credentials[idx].createdAt : now,
    updatedAt: now,
    lastUsedAt: idx >= 0 ? payload.credentials[idx].lastUsedAt || null : null,
  };
  if (idx >= 0) {
    payload.credentials[idx] = finalRecord;
  } else {
    payload.credentials.push(finalRecord);
  }
  return structuredClone(finalRecord);
}

export function removeCredential(payload, name) {
  const idx = payload.credentials.findIndex((c) => c.name === name);
  if (idx < 0) return null;
  const [removed] = payload.credentials.splice(idx, 1);
  if (removed.capabilityPolicyEpoch != null) {
    payload.capabilityEpochs ||= Object.create(null);
    payload.capabilityEpochs[name] =
      Math.max(payload.capabilityEpochs[name] || 0, removed.capabilityPolicyEpoch) + 1;
  }
  payload.credentialRevisions ||= Object.create(null);
  payload.credentialRevisions[name] =
    Math.max(payload.credentialRevisions[name] || 0, removed.credentialRevision || 0) + 1;
  return removed;
}

export function getCredential(payload, name) {
  return payload.credentials.find((c) => c.name === name) || null;
}

export function listMetadata(payload) {
  return structuredClone(payload.credentials.map((c) => ({
    name: c.name,
    type: c.type,
    domains: c.domains,
    description: c.description || null,
    // Access level is metadata, not a secret — agents need to see it to know
    // which operations a credential permits (and how to ask for more).
    ...(c.access ? { access: c.access } : {}),
    ...(Array.isArray(c.accessRules) ? { accessRules: c.accessRules } : {}),
    ...(c.capabilityPolicy
      ? {
          capabilityPolicy: {
            version: c.capabilityPolicy.version,
            epoch: c.capabilityPolicy.epoch,
            onUnmatched: c.capabilityPolicy.onUnmatched,
            grants: c.capabilityPolicy.grants.map((grant) => ({
              id: grant.id,
              principal: grant.principal,
              capability: grant.capability,
              decision: grant.decision,
              ...(grant.label ? { label: grant.label } : {}),
            })),
          },
        }
      : {}),
    ...(c.capabilityPolicyEpoch != null
      ? { capabilityPolicyEpoch: c.capabilityPolicyEpoch }
      : {}),
    ...(c.credentialRevision != null ? { credentialRevision: c.credentialRevision } : {}),
    // The wallet address is public by design — agents need it to build
    // transactions and check balances without opening the record.
    ...(c.publicKey ? { publicKey: c.publicKey } : {}),
    ...(c.address ? { address: c.address } : {}),
    // browser-profile: surface the (non-secret) account label + headless default
    // so an agent can see which profile is which without opening the record.
    ...(c.account ? { account: c.account } : {}),
    ...(c.type === "browser-profile" ? { headless: c.headless !== false } : {}),
    createdAt: c.createdAt,
    updatedAt: c.updatedAt,
    lastUsedAt: c.lastUsedAt || null,
  })));
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
      // becomes GC-eligible. Store ingress is deep-cloned, so these objects are
      // exclusively owned; deleting the root reference cannot mutate caller
      // data. JavaScript strings themselves still cannot be overwritten.
      if (f in cred) delete cred[f];
    }
  }
  payload.credentials.length = 0;
}
