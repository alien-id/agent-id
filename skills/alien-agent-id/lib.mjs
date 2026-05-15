// Alien Agent ID — Portable library for agent identity management.
// Zero npm dependencies. Requires Node.js 18+ (built-in crypto, fetch, fs).
//
// Consolidated from openclaw-alienid-signature-demo/src/{canonical,crypto,state,oidc,signer,verify}.js

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  hkdfSync,
  randomBytes,
} from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

// Re-export crypto primitives from agent-id-core. During the split refactor
// the canonical home is plugins/agent-id-core/lib/crypto.mjs; this re-export
// keeps existing imports from skills/alien-agent-id/lib.mjs working.
export * from "../../plugins/agent-id-core/lib/crypto.mjs";

// Re-export the v3 bundle module from agent-id-core. Bundles are the
// universal provenance unit — git commits today, signed tool calls
// tomorrow — so the constructor + parser + universal verifier live in
// core, not in the git plugin.
export * from "../../plugins/agent-id-core/lib/bundle.mjs";

// Re-export state I/O helpers from agent-id-core.
export * from "../../plugins/agent-id-core/lib/state.mjs";

import {
  appendJsonl,
  ensureDir,
  readJsonFile,
  readJsonl,
  setPrivateFilePermissions,
  statePaths,
  writeJsonFile,
} from "../../plugins/agent-id-core/lib/state.mjs";

// Re-export typed error classes from agent-id-core.
export * from "../../plugins/agent-id-core/lib/errors.mjs";

import {
  AuthRevokedError,
  SubjectMismatchError,
} from "../../plugins/agent-id-core/lib/errors.mjs";

// Re-export the OIDC stack: discovery, authorize/poll/exchange, refresh,
// userinfo, JWKS, id_token verifiers (verifyIdToken / verifyIdTokenSignatureOnly).
export * from "../../plugins/agent-id-core/lib/oidc.mjs";

import {
  parseJwt,
  refreshSession,
  verifyIdToken,
} from "../../plugins/agent-id-core/lib/oidc.mjs";

import {
  b64url,
  canonicalJSONString,
  createDPoPProof,
  ed25519PublicKeyToJwk,
  fingerprintPublicKeyPem,
  fromB64url,
  generateEd25519PemPair,
  jwkThumbprint,
  newOperationId,
  nowMs,
  sha256B64url,
  sha256Hex,
  sha256HexCanonical,
  signEd25519Base64Url,
  verifyEd25519Base64Url,
  verifyJwtEdDsaSignature,
  verifyJwtRs256Signature,
} from "../../plugins/agent-id-core/lib/crypto.mjs";


// ════════════════════════════════════════════════════════════════════════════════
// Signing Engine
// ════════════════════════════════════════════════════════════════════════════════

function summarizePayload(payload, max = 220) {
  const raw = typeof payload === "string" ? payload : canonicalJSONString(payload);
  if (raw.length <= max) {
    return raw;
  }
  return `${raw.slice(0, max)}...`;
}

function safeName(input) {
  return (input || "unknown").replace(/[^a-zA-Z0-9._-]/g, "_");
}

function agentKeyFile(baseDir, agentId) {
  if (agentId === "main") {
    return path.join(baseDir, "keys", "main.json");
  }
  return path.join(baseDir, "keys", "subagents", `${safeName(agentId)}.json`);
}

function delegationFile(baseDir, childAgentId) {
  return path.join(baseDir, "delegations", `${safeName(childAgentId)}.json`);
}

// ════════════════════════════════════════════════════════════════════════════════
// Service manifest discovery — /.well-known/alien-agent-id.json
//
// Trust model: the manifest is third-party data. It is parsed, schema-validated,
// and reduced to a fixed set of fields before any value is returned. The only
// URLs the agent will subsequently touch are those that share the same authority
// as the user-provided service URL (exact host or a subdomain).
// ════════════════════════════════════════════════════════════════════════════════

export const SERVICE_MANIFEST_PATH = "/.well-known/alien-agent-id.json";
export const SERVICE_MANIFEST_MAX_BYTES = 8192;
export const SERVICE_MANIFEST_VERSION = 1;
export const SERVICE_MANIFEST_VERSIONS = new Set([1, 2]);
export const SUPPORT_SIGNAL_MAX_BYTES = 65536;
export const SUPPORT_SIGNAL_VERSIONS = new Set(["v1"]);

const HEADER_NAME_RE = /^[A-Za-z0-9-]{1,64}$/;
const ALLOWED_AUTH_SCHEMES = new Set(["DPoP", "Bearer", "none"]);
const ALLOWED_TOP_KEYS = new Set(["version", "service", "auth", "api"]);
const ALLOWED_SERVICE_KEYS = new Set(["name", "url"]);
const ALLOWED_AUTH_KEYS = new Set(["header", "scheme"]);
const ALLOWED_API_KEYS = new Set(["base", "specUrl", "operations"]);

// v2 operations[] — closed-key, capped, prompt-injection-bounded.
const OPERATIONS_MAX = 50;
const OP_DESC_MAX = 1024;
const OP_TITLE_MAX = 80;
const OP_PATH_MAX = 200;
const OP_PROP_DESC_MAX = 200;
const OP_PROPERTIES_MAX = 20;
const OP_ENUM_MAX = 32;
const OP_MAXLENGTH_MAX = 100000;
const OP_NAME_RE = /^[a-zA-Z][a-zA-Z0-9_]{0,63}$/;
const OP_PATH_RE = /^\/[^\s?#]*$/;
const OP_PATH_PARAM_RE = /\{([a-zA-Z][a-zA-Z0-9_]*)\}/g;
const OP_CONTROL_CHARS = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/;
const ALLOWED_OPERATION_KEYS = new Set(["name", "title", "description", "method", "path", "auth", "inputSchema", "outputSchema", "annotations"]);
const ALLOWED_ANNOTATION_KEYS = new Set(["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"]);
const ALLOWED_OP_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);
const ALLOWED_OP_AUTH = new Set(["required", "optional", "none"]);
const ALLOWED_OP_SCHEMA_KEYS = new Set(["type", "properties", "required", "additionalProperties", "description"]);
const ALLOWED_OP_PROPERTY_KEYS = new Set(["type", "description", "enum", "maxLength", "items"]);
const ALLOWED_OP_PROPERTY_TYPES = new Set(["string", "number", "integer", "boolean", "array"]);
const ALLOWED_OP_ARRAY_ITEM_TYPES = new Set(["string", "number", "integer", "boolean"]);

function rejectUnknownKeys(obj, allowed, where) {
  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) {
      throw new Error(`Manifest ${where}: unknown key "${key}"`);
    }
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isSameAuthority(host, allowedHost) {
  if (typeof host !== "string" || !host) return false;
  return host === allowedHost || host.endsWith(`.${allowedHost}`);
}

function validateManifestUrl(value, allowedHost, where, { allowInsecure = false } = {}) {
  if (typeof value !== "string" || !value) {
    throw new Error(`Manifest ${where}: must be a string URL`);
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`Manifest ${where}: invalid URL`);
  }
  const protoOk = url.protocol === "https:" || (allowInsecure && url.protocol === "http:");
  if (!protoOk) {
    throw new Error(`Manifest ${where}: must be https://`);
  }
  if (!isSameAuthority(url.host, allowedHost)) {
    throw new Error(`Manifest ${where}: host "${url.host}" is not within "${allowedHost}"`);
  }
  return url.toString();
}

function parseOperationProperty(raw, where) {
  if (!isPlainObject(raw)) throw new Error(`Manifest ${where}: must be an object`);
  rejectUnknownKeys(raw, ALLOWED_OP_PROPERTY_KEYS, where);
  if (typeof raw.type !== "string" || !ALLOWED_OP_PROPERTY_TYPES.has(raw.type)) {
    throw new Error(`Manifest ${where}.type: must be one of ${[...ALLOWED_OP_PROPERTY_TYPES].join(", ")}`);
  }
  const out = { type: raw.type };
  if (raw.description !== undefined) {
    if (typeof raw.description !== "string" || raw.description.length > OP_PROP_DESC_MAX) {
      throw new Error(`Manifest ${where}.description: must be a string ≤${OP_PROP_DESC_MAX} chars`);
    }
    if (OP_CONTROL_CHARS.test(raw.description)) {
      throw new Error(`Manifest ${where}.description: control characters forbidden`);
    }
    out.description = raw.description;
  }
  if (raw.enum !== undefined) {
    if (!Array.isArray(raw.enum) || raw.enum.length === 0 || raw.enum.length > OP_ENUM_MAX) {
      throw new Error(`Manifest ${where}.enum: must be a 1-${OP_ENUM_MAX} item array`);
    }
    out.enum = [...raw.enum];
  }
  if (raw.maxLength !== undefined) {
    if (!Number.isInteger(raw.maxLength) || raw.maxLength < 0 || raw.maxLength > OP_MAXLENGTH_MAX) {
      throw new Error(`Manifest ${where}.maxLength: must be an integer 0-${OP_MAXLENGTH_MAX}`);
    }
    out.maxLength = raw.maxLength;
  }
  if (raw.items !== undefined) {
    if (raw.type !== "array") {
      throw new Error(`Manifest ${where}.items: only valid when type is "array"`);
    }
    if (typeof raw.items !== "string" || !ALLOWED_OP_ARRAY_ITEM_TYPES.has(raw.items)) {
      throw new Error(`Manifest ${where}.items: must be one of ${[...ALLOWED_OP_ARRAY_ITEM_TYPES].join(", ")}`);
    }
    out.items = raw.items;
  }
  return out;
}

function parseOperationSchema(raw, where) {
  if (!isPlainObject(raw)) throw new Error(`Manifest ${where}: must be an object`);
  rejectUnknownKeys(raw, ALLOWED_OP_SCHEMA_KEYS, where);
  if (raw.type !== "object") {
    throw new Error(`Manifest ${where}.type: must be "object"`);
  }
  const out = { type: "object" };
  if (raw.description !== undefined) {
    if (typeof raw.description !== "string" || raw.description.length > OP_PROP_DESC_MAX) {
      throw new Error(`Manifest ${where}.description: must be a string ≤${OP_PROP_DESC_MAX} chars`);
    }
    out.description = raw.description;
  }
  if (raw.additionalProperties !== undefined) {
    if (typeof raw.additionalProperties !== "boolean") {
      throw new Error(`Manifest ${where}.additionalProperties: must be boolean`);
    }
    out.additionalProperties = raw.additionalProperties;
  }
  if (raw.required !== undefined) {
    if (!Array.isArray(raw.required) || raw.required.length > OP_PROPERTIES_MAX) {
      throw new Error(`Manifest ${where}.required: must be a string array ≤${OP_PROPERTIES_MAX}`);
    }
    for (const k of raw.required) {
      if (typeof k !== "string") throw new Error(`Manifest ${where}.required: items must be strings`);
    }
    out.required = [...raw.required];
  }
  if (raw.properties !== undefined) {
    if (!isPlainObject(raw.properties)) throw new Error(`Manifest ${where}.properties: must be an object`);
    const keys = Object.keys(raw.properties);
    if (keys.length > OP_PROPERTIES_MAX) {
      throw new Error(`Manifest ${where}.properties: max ${OP_PROPERTIES_MAX} entries`);
    }
    out.properties = {};
    for (const k of keys) {
      out.properties[k] = parseOperationProperty(raw.properties[k], `${where}.properties[${JSON.stringify(k)}]`);
    }
  }
  if (out.required && out.properties) {
    for (const r of out.required) {
      if (!Object.prototype.hasOwnProperty.call(out.properties, r)) {
        throw new Error(`Manifest ${where}.required: "${r}" not in properties`);
      }
    }
  }
  return out;
}

function parseOperation(raw, where) {
  if (!isPlainObject(raw)) throw new Error(`Manifest ${where}: must be an object`);
  rejectUnknownKeys(raw, ALLOWED_OPERATION_KEYS, where);
  if (typeof raw.name !== "string" || !OP_NAME_RE.test(raw.name)) {
    throw new Error(`Manifest ${where}.name: must match ^[a-zA-Z][a-zA-Z0-9_]{0,63}$`);
  }
  if (typeof raw.description !== "string" || raw.description.length === 0 || raw.description.length > OP_DESC_MAX) {
    throw new Error(`Manifest ${where}.description: must be a 1-${OP_DESC_MAX} char string`);
  }
  if (OP_CONTROL_CHARS.test(raw.description)) {
    throw new Error(`Manifest ${where}.description: control characters forbidden`);
  }
  if (typeof raw.method !== "string" || !ALLOWED_OP_METHODS.has(raw.method)) {
    throw new Error(`Manifest ${where}.method: must be one of ${[...ALLOWED_OP_METHODS].join(", ")}`);
  }
  if (typeof raw.path !== "string" || raw.path.length === 0 || raw.path.length > OP_PATH_MAX || !OP_PATH_RE.test(raw.path)) {
    throw new Error(`Manifest ${where}.path: must match ^/[^\\s?#]* (≤${OP_PATH_MAX} chars)`);
  }
  const out = {
    name: raw.name,
    description: raw.description,
    method: raw.method,
    path: raw.path,
    auth: "required",
  };
  if (raw.title !== undefined) {
    if (typeof raw.title !== "string" || raw.title.length === 0 || raw.title.length > OP_TITLE_MAX) {
      throw new Error(`Manifest ${where}.title: must be a 1-${OP_TITLE_MAX} char string`);
    }
    out.title = raw.title;
  }
  if (raw.auth !== undefined) {
    if (typeof raw.auth !== "string" || !ALLOWED_OP_AUTH.has(raw.auth)) {
      throw new Error(`Manifest ${where}.auth: must be one of ${[...ALLOWED_OP_AUTH].join(", ")}`);
    }
    out.auth = raw.auth;
  }
  if (raw.inputSchema !== undefined) {
    out.inputSchema = parseOperationSchema(raw.inputSchema, `${where}.inputSchema`);
  }
  if (raw.outputSchema !== undefined) {
    out.outputSchema = parseOperationSchema(raw.outputSchema, `${where}.outputSchema`);
  }
  if (raw.annotations !== undefined) {
    if (!isPlainObject(raw.annotations)) throw new Error(`Manifest ${where}.annotations: must be an object`);
    rejectUnknownKeys(raw.annotations, ALLOWED_ANNOTATION_KEYS, `${where}.annotations`);
    const ann = {};
    for (const k of Object.keys(raw.annotations)) {
      if (typeof raw.annotations[k] !== "boolean") {
        throw new Error(`Manifest ${where}.annotations.${k}: must be boolean`);
      }
      ann[k] = raw.annotations[k];
    }
    out.annotations = ann;
  }
  const placeholders = [...out.path.matchAll(OP_PATH_PARAM_RE)].map(m => m[1]);
  if (placeholders.length > 0) {
    const props = out.inputSchema?.properties ?? {};
    for (const p of placeholders) {
      if (!Object.prototype.hasOwnProperty.call(props, p)) {
        throw new Error(`Manifest ${where}.path: placeholder {${p}} has no matching inputSchema.properties.${p}`);
      }
    }
  }
  return out;
}

export function parseServiceManifest(raw, allowedHost, options = {}) {
  if (!isPlainObject(raw)) {
    throw new Error("Manifest: root must be a JSON object");
  }
  rejectUnknownKeys(raw, ALLOWED_TOP_KEYS, "root");

  if (!SERVICE_MANIFEST_VERSIONS.has(raw.version)) {
    throw new Error(`Manifest: unsupported version ${JSON.stringify(raw.version)} (expected one of ${[...SERVICE_MANIFEST_VERSIONS].join(", ")})`);
  }

  if (!isPlainObject(raw.auth)) {
    throw new Error("Manifest: missing required \"auth\" object");
  }
  if (!isPlainObject(raw.api)) {
    throw new Error("Manifest: missing required \"api\" object");
  }

  rejectUnknownKeys(raw.auth, ALLOWED_AUTH_KEYS, "auth");
  rejectUnknownKeys(raw.api, ALLOWED_API_KEYS, "api");

  if (raw.api.operations !== undefined && raw.version !== 2) {
    throw new Error("Manifest api.operations: requires version 2");
  }

  const out = { version: raw.version };

  if (raw.service !== undefined) {
    if (!isPlainObject(raw.service)) {
      throw new Error("Manifest: \"service\" must be an object");
    }
    rejectUnknownKeys(raw.service, ALLOWED_SERVICE_KEYS, "service");
    const service = {};
    if (raw.service.name !== undefined) {
      if (typeof raw.service.name !== "string" || raw.service.name.length === 0 || raw.service.name.length > 80) {
        throw new Error("Manifest service.name: must be a 1-80 char string");
      }
      service.name = raw.service.name;
    }
    if (raw.service.url !== undefined) {
      service.url = validateManifestUrl(raw.service.url, allowedHost, "service.url", options);
    }
    out.service = service;
  }

  out.auth = {
    header: (() => {
      if (typeof raw.auth.header !== "string" || !HEADER_NAME_RE.test(raw.auth.header)) {
        throw new Error("Manifest auth.header: must match [A-Za-z0-9-]{1,64}");
      }
      return raw.auth.header;
    })(),
    scheme: (() => {
      if (raw.auth.scheme === undefined) return "DPoP";
      if (typeof raw.auth.scheme !== "string" || !ALLOWED_AUTH_SCHEMES.has(raw.auth.scheme)) {
        throw new Error(`Manifest auth.scheme: must be one of ${[...ALLOWED_AUTH_SCHEMES].join(", ")}`);
      }
      return raw.auth.scheme;
    })(),
  };

  out.api = {
    base: validateManifestUrl(raw.api.base, allowedHost, "api.base", options),
  };
  if (raw.api.specUrl !== undefined) {
    out.api.specUrl = validateManifestUrl(raw.api.specUrl, allowedHost, "api.specUrl", options);
  }
  if (raw.api.operations !== undefined) {
    if (!Array.isArray(raw.api.operations)) {
      throw new Error("Manifest api.operations: must be an array");
    }
    if (raw.api.operations.length > OPERATIONS_MAX) {
      throw new Error(`Manifest api.operations: max ${OPERATIONS_MAX} entries`);
    }
    const seen = new Set();
    out.api.operations = raw.api.operations.map((op, i) => {
      const parsed = parseOperation(op, `api.operations[${i}]`);
      if (seen.has(parsed.name)) {
        throw new Error(`Manifest api.operations: duplicate name "${parsed.name}"`);
      }
      seen.add(parsed.name);
      return parsed;
    });
  }

  return out;
}

// renderCapabilities: turn a validated manifest into LLM-friendly markdown.
// Per-operation `Call:` lines name the CLI explicitly so an agent reading
// the rendered output reaches for `node CLI call` (which signs DPoP per
// request) instead of raw curl/fetch (which gets 401).
export function renderCapabilities(manifest) {
  if (!isPlainObject(manifest)) {
    throw new Error("renderCapabilities: manifest must be an object");
  }
  const base = manifest.api?.base ?? "";
  const ops = manifest.api?.operations ?? [];
  const name = manifest.service?.name ?? "Service";
  const scheme = manifest.auth?.scheme ?? "DPoP";

  if (ops.length === 0) {
    if (manifest.api?.specUrl) {
      return `# ${name}\n\nNo inline operations. See OpenAPI at ${manifest.api.specUrl}.`;
    }
    return `# ${name}\n\nNo operations declared. Ask the user.`;
  }

  const lines = [
    `# ${name} — operations`,
    "",
    `Base: \`${base}\` · Auth: \`${scheme}\``,
    "",
    "Invoke each operation with `node CLI call --url <base+path> --method <verb> [--body-file ./body.json]`. The CLI signs each request with DPoP; raw curl/fetch will get 401.",
    "",
  ];

  for (const op of ops) {
    lines.push(`## ${op.name}`);
    lines.push("");
    lines.push(op.description);
    lines.push("");
    const bodyHint = op.inputSchema && op.method !== "GET" && op.method !== "DELETE"
      ? " --body-file ./body.json"
      : "";
    lines.push(`Call: \`node CLI call --url ${base}${op.path} --method ${op.method}${bodyHint}\``);
    if (op.auth && op.auth !== "required") {
      lines.push(`Auth: ${op.auth}`);
    }

    const props = op.inputSchema?.properties ?? {};
    const required = new Set(op.inputSchema?.required ?? []);
    const keys = Object.keys(props);
    if (keys.length) {
      lines.push("", "Input:");
      for (const k of keys) {
        const p = props[k];
        const typeStr = p.type === "array" && p.items ? `array of ${p.items}` : p.type;
        const req = required.has(k) ? ", required" : "";
        const max = p.maxLength ? `, max ${p.maxLength}` : "";
        const enumStr = p.enum ? `, one of [${p.enum.map(v => JSON.stringify(v)).join(", ")}]` : "";
        const hint = p.description ? `: ${p.description}` : "";
        lines.push(`- \`${k}\` (${typeStr}${req}${max}${enumStr})${hint}`);
      }
    }

    const ann = op.annotations ?? {};
    const warns = [];
    if (ann.destructiveHint && !ann.readOnlyHint) warns.push("destructive — confirm before calling");
    if (ann.openWorldHint) warns.push("open-world — may affect external state");
    if (warns.length) {
      lines.push("", `⚠ ${warns.join("; ")}.`);
    }
    lines.push("");
  }
  return lines.join("\n").replace(/\n+$/, "\n");
}

async function readBoundedBody(res, maxBytes) {
  const reader = res.body?.getReader?.();
  if (!reader) {
    const text = await res.text();
    if (Buffer.byteLength(text, "utf8") > maxBytes) {
      throw new Error(`Manifest exceeds ${maxBytes} bytes`);
    }
    return text;
  }
  let received = 0;
  const chunks = [];
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    received += value.length;
    if (received > maxBytes) {
      try { await reader.cancel(); } catch {}
      throw new Error(`Manifest exceeds ${maxBytes} bytes`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString("utf8");
}

export async function fetchServiceManifest(serviceUrl, options = {}) {
  if (typeof serviceUrl !== "string" || !serviceUrl) {
    throw new Error("fetchServiceManifest: serviceUrl required");
  }
  let parsed;
  try {
    parsed = new URL(serviceUrl);
  } catch {
    throw new Error("fetchServiceManifest: invalid serviceUrl");
  }
  const allowInsecure = options.allowInsecure === true;
  if (parsed.protocol !== "https:" && !(allowInsecure && parsed.protocol === "http:")) {
    throw new Error("fetchServiceManifest: serviceUrl must be https://");
  }
  const allowedHost = parsed.host;
  const manifestUrl = `${parsed.protocol}//${parsed.host}${SERVICE_MANIFEST_PATH}`;

  const controller = new AbortController();
  const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : 5000;
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let res;
  try {
    res = await fetch(manifestUrl, {
      method: "GET",
      headers: { Accept: "application/json" },
      redirect: "error",
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }

  if (!res.ok) {
    throw new Error(`Manifest fetch failed: HTTP ${res.status} from ${manifestUrl}`);
  }
  const contentType = res.headers.get("content-type") || "";
  if (!/^application\/json\b/i.test(contentType)) {
    throw new Error(`Manifest fetch failed: expected application/json, got "${contentType}"`);
  }

  const body = await readBoundedBody(res, SERVICE_MANIFEST_MAX_BYTES);
  let json;
  try {
    json = JSON.parse(body);
  } catch {
    throw new Error("Manifest fetch failed: response is not valid JSON");
  }

  const manifest = parseServiceManifest(json, allowedHost, { allowInsecure });
  return { manifest, manifestUrl, allowedHost };
}

// Build the HTTP header pair for an API call to a service whose manifest
// has been validated. Pure: no network, no I/O.
export function buildServiceAuthHeader(manifest, agentToken) {
  if (!isPlainObject(manifest) || !isPlainObject(manifest.auth)) {
    throw new Error("buildServiceAuthHeader: invalid manifest");
  }
  if (typeof agentToken !== "string" || !agentToken) {
    throw new Error("buildServiceAuthHeader: agentToken required");
  }
  const value = manifest.auth.scheme === "none"
    ? agentToken
    : `${manifest.auth.scheme} ${agentToken}`;
  return { name: manifest.auth.header, value };
}

// Probe a page URL for the closed-enum support-signal meta tag:
//   <meta name="alien-agent-id" content="v1">
//
// This is purely a hint that the service advertises Alien Agent ID support.
// It NEVER carries the manifest path — the manifest always lives at
// SERVICE_MANIFEST_PATH on the same host. Anything other than a known version
// in the closed-enum content is rejected (no prose, no URLs).
//
// Any network/HTTP/parse failure resolves to { supported: false, version: null }
// so callers can use this as a yes/no signal without needing error handling.
export async function probeServiceSupportSignal(pageUrl, options = {}) {
  if (typeof pageUrl !== "string" || !pageUrl) {
    throw new Error("probeServiceSupportSignal: pageUrl required");
  }
  let parsed;
  try { parsed = new URL(pageUrl); } catch { throw new Error("probeServiceSupportSignal: invalid pageUrl"); }
  const allowInsecure = options.allowInsecure === true;
  if (parsed.protocol !== "https:" && !(allowInsecure && parsed.protocol === "http:")) {
    throw new Error("probeServiceSupportSignal: pageUrl must be https://");
  }

  const controller = new AbortController();
  const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : 5000;
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let res;
  try {
    res = await fetch(pageUrl, {
      method: "GET",
      headers: { Accept: "text/html" },
      redirect: "error",
      signal: controller.signal,
    });
  } catch {
    clearTimeout(timer);
    return { supported: false, version: null };
  }
  clearTimeout(timer);

  if (!res.ok) return { supported: false, version: null };
  const contentType = res.headers.get("content-type") || "";
  if (!/^text\/html\b/i.test(contentType)) return { supported: false, version: null };

  let html;
  try {
    html = await readBoundedBody(res, SUPPORT_SIGNAL_MAX_BYTES);
  } catch {
    return { supported: false, version: null };
  }

  const tagRe = /<meta\b[^>]*>/gi;
  const nameRe = /\bname\s*=\s*["']alien-agent-id["']/i;
  const contentRe = /\bcontent\s*=\s*["']([^"']*)["']/i;
  for (const m of html.matchAll(tagRe)) {
    const tag = m[0];
    if (!nameRe.test(tag)) continue;
    const cm = contentRe.exec(tag);
    if (!cm) return { supported: false, version: null };
    const value = cm[1];
    if (SUPPORT_SIGNAL_VERSIONS.has(value)) {
      return { supported: true, version: value };
    }
    return { supported: false, version: null };
  }
  return { supported: false, version: null };
}

// Resolve a request path against the manifest's api.base, refusing any path
// that escapes the base authority (e.g. "//evil.com/x" or a full https URL).
export function resolveServiceApiUrl(manifest, requestPath) {
  if (!isPlainObject(manifest) || !isPlainObject(manifest.api)) {
    throw new Error("resolveServiceApiUrl: invalid manifest");
  }
  if (typeof requestPath !== "string" || !requestPath) {
    throw new Error("resolveServiceApiUrl: requestPath required");
  }
  const base = new URL(manifest.api.base.endsWith("/") ? manifest.api.base : manifest.api.base + "/");
  const resolved = new URL(requestPath, base);
  if (resolved.host !== base.host || resolved.protocol !== base.protocol) {
    throw new Error(`resolveServiceApiUrl: path "${requestPath}" escapes api.base`);
  }
  return resolved.toString();
}

export function resolveAgentId(ctx = {}) {
  if (ctx.agentId && typeof ctx.agentId === "string") {
    return ctx.agentId;
  }
  return "main";
}

export class SignatureEngine {
  constructor(params) {
    this.baseDir = params.baseDir;
    this.ownerProfileUrl = params.ownerProfileUrl || null;
    this.paths = statePaths(this.baseDir);
    this.keys = new Map();
    this.delegations = new Map();
    this.nonces = null;
    this.sequence = null;
    this.idTokenJti = null;
    this.idTokenSub = null;
    this.writeQueue = Promise.resolve();
  }

  async init() {
    await ensureDir(this.baseDir);
    await ensureDir(path.dirname(this.paths.auditJsonl));

    this.nonces = (await readJsonFile(this.paths.nonces, { byAgent: {} })) || { byAgent: {} };
    this.sequence =
      (await readJsonFile(this.paths.seq, {
        nextSeq: 1,
        lastHash: null,
      })) || { nextSeq: 1, lastHash: null };

    // Parse the cached id_token (if any) for the audit-log anchor. The jti
    // (RFC 7519 §4.1.7) replaces the legacy ownerBindingId; sub is captured
    // for envelope fields that previously read it off the binding.
    const session = await readJsonFile(this.paths.ownerSession, null);
    if (session?.idToken) {
      try {
        const payload = parseJwt(session.idToken).payload;
        if (typeof payload?.jti === "string" && payload.jti) {
          this.idTokenJti = payload.jti;
        }
        if (typeof payload?.sub === "string" && payload.sub) {
          this.idTokenSub = payload.sub;
        }
      } catch {
        // Unparseable id_token — engine still functions for non-audit ops.
      }
    }

    await this.ensureMainKey();
  }

  isOwnerBound() {
    return Boolean(this.idTokenJti);
  }

  async ensureMainKey() {
    return await this.ensureAgentKey("main");
  }

  async ensureAgentKey(agentId) {
    const normalized = agentId || "main";
    if (this.keys.has(normalized)) {
      return this.keys.get(normalized);
    }

    const keyPath = agentKeyFile(this.baseDir, normalized);
    let key = await readJsonFile(keyPath, null);

    if (!key) {
      const pair = generateEd25519PemPair();
      key = {
        version: 1,
        agentId: normalized,
        keyNonce: 0,
        createdAt: nowMs(),
        publicKeyPem: pair.publicKeyPem,
        privateKeyPem: pair.privateKeyPem,
        fingerprint: fingerprintPublicKeyPem(pair.publicKeyPem),
      };
      await writeJsonFile(keyPath, key);
      await setPrivateFilePermissions(keyPath);
    }

    this.keys.set(normalized, key);

    if (normalized !== "main") {
      await this.ensureDelegation(normalized);
    }

    return key;
  }

  async ensureDelegation(childAgentId) {
    if (childAgentId === "main") {
      return null;
    }
    if (this.delegations.has(childAgentId)) {
      return this.delegations.get(childAgentId);
    }

    const filePath = delegationFile(this.baseDir, childAgentId);
    let cert = await readJsonFile(filePath, null);
    if (!cert) {
      const main = await this.ensureMainKey();
      const child = await this.ensureAgentKey(childAgentId);
      const payload = {
        version: 1,
        parentAgentId: "main",
        childAgentId,
        childPublicKeyPem: child.publicKeyPem,
        issuedAt: nowMs(),
      };
      const payloadCanonical = canonicalJSONString(payload);
      cert = {
        version: 1,
        payload,
        payloadHash: sha256Hex(payloadCanonical),
        signature: signEd25519Base64Url(payloadCanonical, main.privateKeyPem),
      };
      await writeJsonFile(filePath, cert);
      await setPrivateFilePermissions(filePath);
    }

    this.delegations.set(childAgentId, cert);
    return cert;
  }

  async bindOwnerSession(params) {
    await this.ensureMainKey();

    // v3 model: the SSO-signed id_token IS the binding (no agent-self-signed
    // ownerBinding envelope). Persist only the session; future operations
    // read the id_token directly and parse claims (sub, jti, cnf.jkt) at use.
    const ownerSessionRecord = {
      version: 1,
      issuer: params.issuer,
      ssoBaseUrl: params.ssoBaseUrl || params.issuer,
      providerAddress: params.providerAddress,
      ownerSessionSub: params.ownerSessionSub,
      idToken: params.idToken,
      accessToken: params.accessToken,
      refreshToken: params.refreshToken,
      savedAt: nowMs(),
    };
    await writeJsonFile(this.paths.ownerSession, ownerSessionRecord);
    await setPrivateFilePermissions(this.paths.ownerSession);

    // Refresh cached anchors so subsequent appendOperation calls work.
    try {
      const payload = parseJwt(params.idToken).payload;
      this.idTokenJti = typeof payload?.jti === "string" ? payload.jti : null;
      this.idTokenSub = typeof payload?.sub === "string" ? payload.sub : null;
    } catch {
      this.idTokenJti = null;
      this.idTokenSub = null;
    }

    return {
      ownerSessionSub: params.ownerSessionSub,
      issuer: params.issuer,
      providerAddress: params.providerAddress,
      idTokenJti: this.idTokenJti,
    };
  }

  async ensureValidSession(opts = {}) {
    const session = await readJsonFile(this.paths.ownerSession, null);
    if (!session?.accessToken) return null;

    const bufferSec = opts.bufferSec ?? 60;

    // Decode the access_token JWT to check expiry (no signature verification —
    // we just need to know if it's still fresh).
    let expired = false;
    try {
      const payload = parseJwt(session.accessToken).payload;
      const nowSec = Math.floor(Date.now() / 1000);
      expired = typeof payload.exp === "number" && payload.exp - bufferSec <= nowSec;
    } catch {
      // If the access_token isn't a JWT (opaque token), treat it as expired
      // so we attempt a refresh.
      expired = true;
    }

    if (!expired) return session;

    // No refresh_token — can't renew.
    if (!session.refreshToken) return null;

    // Resolve SSO base URL: explicit field, fall back to issuer.
    const ssoBaseUrl = session.ssoBaseUrl || session.issuer;
    if (!ssoBaseUrl) return null;

    // Forward the agent's main keypair so the refresh request carries a DPoP
    // proof bound to the same key the SSO advertises in `cnf.jkt`.
    const main = await this.ensureMainKey();

    const fresh = await refreshSession({
      ssoBaseUrl,
      refreshToken: session.refreshToken,
      providerAddress: session.providerAddress,
      agentPrivateKeyPem: main.privateKeyPem,
    });

    // Verify the refreshed token still belongs to the same owner.
    if (session.ownerSessionSub) {
      try {
        const freshPayload = parseJwt(fresh.access_token).payload;
        if (freshPayload.sub && freshPayload.sub !== session.ownerSessionSub) {
          throw new SubjectMismatchError(
            `Refreshed token subject mismatch: expected ${session.ownerSessionSub}, got ${freshPayload.sub}`,
          );
        }
      } catch (err) {
        if (err instanceof SubjectMismatchError) throw err;
        // Non-JWT or unparseable — skip subject check (opaque tokens have no sub).
      }
    }

    // RFC 9449 §6.1 + RFC 6749 §6: when the AS rotates the id_token, re-run
    // the full claim+signature+cnf.jkt check before persistence. A
    // compromised or buggy AS that rotates `sub` or `cnf.jkt` is caught
    // here rather than at the next chain verification.
    if (fresh.id_token) {
      const verified = await verifyIdToken({
        ssoBaseUrl,
        providerAddress: session.providerAddress,
        idToken: fresh.id_token,
        agentPublicKeyPem: main.publicKeyPem,
      });
      if (session.ownerSessionSub && verified.payload.sub !== session.ownerSessionSub) {
        throw new SubjectMismatchError(
          `Refreshed id_token sub mismatch: expected ${session.ownerSessionSub}, got ${verified.payload.sub}`,
        );
      }
    }

    session.accessToken = fresh.access_token;
    if (fresh.refresh_token) session.refreshToken = fresh.refresh_token;
    if (fresh.id_token) session.idToken = fresh.id_token;
    session.refreshedAt = nowMs();

    await writeJsonFile(this.paths.ownerSession, session);
    await setPrivateFilePermissions(this.paths.ownerSession);

    return session;
  }

  async nextNonce(agentId) {
    const key = agentId || "main";
    const current = Number(this.nonces.byAgent[key] || 0);
    const next = current + 1;
    this.nonces.byAgent[key] = next;
    await writeJsonFile(this.paths.nonces, this.nonces);
    return next;
  }

  async nextSequence() {
    const seq = Number(this.sequence.nextSeq || 1);
    this.sequence.nextSeq = seq + 1;
    await writeJsonFile(this.paths.seq, this.sequence);
    return seq;
  }

  async appendOperation(params) {
    this.writeQueue = this.writeQueue.then(async () => {
      if (!this.idTokenJti) {
        throw new Error("Owner session missing or id_token has no jti. Run `auth` and `bind` first.");
      }

      const agentId = resolveAgentId(params.ctx);
      const key = await this.ensureAgentKey(agentId);
      const delegation = agentId === "main" ? null : await this.ensureDelegation(agentId);

      const nonce = await this.nextNonce(agentId);
      const seq = await this.nextSequence();
      const payloadSummary = summarizePayload(params.payload);
      const payloadHash = sha256HexCanonical(params.payload);

      const unsignedEnvelope = {
        version: 1,
        operationId: newOperationId(),
        seq,
        hook: params.hook || null,
        operationType: params.operationType,
        action: params.action,
        timestamp: nowMs(),
        agentId,
        keyNonce: Number(key.keyNonce || 0),
        nonce,
        sessionKey: params.ctx?.sessionKey || null,
        idTokenJti: this.idTokenJti,
        ownerSessionSub: this.idTokenSub,
        agentPublicKeyPem: key.publicKeyPem,
        parentAgentId: delegation ? delegation.payload.parentAgentId : null,
        delegationPayloadHash: delegation ? delegation.payloadHash : null,
        delegationSignature: delegation ? delegation.signature : null,
        payloadHash,
        payloadSummary,
        meta: params.meta || null,
      };

      const canonicalUnsigned = canonicalJSONString(unsignedEnvelope);
      const envelope = {
        ...unsignedEnvelope,
        signature: signEd25519Base64Url(canonicalUnsigned, key.privateKeyPem),
      };

      const envelopeHash = sha256HexCanonical(canonicalJSONString(envelope));
      const auditEntry = {
        version: 1,
        prevHash: this.sequence.lastHash || null,
        envelopeHash,
        envelope,
        persistedAt: nowMs(),
      };

      this.sequence.lastHash = envelopeHash;
      await writeJsonFile(this.paths.seq, this.sequence);
      await appendJsonl(this.paths.auditJsonl, auditEntry);

      return {
        auditEntry,
        signatureShort: envelope.signature.slice(0, 18),
        envelopeHashShort: envelopeHash.slice(0, 16),
        agentId,
        nonce,
        seq,
      };
    });

    return await this.writeQueue;
  }
}

// ════════════════════════════════════════════════════════════════════════════════
// Verification
// ════════════════════════════════════════════════════════════════════════════════

async function readAllKeyRecords(paths) {
  const map = new Map();

  const main = await readJsonFile(paths.mainKey, null);
  if (main?.agentId && main?.publicKeyPem) {
    map.set(main.agentId, main);
  }

  try {
    const files = await fs.readdir(paths.subagentKeysDir);
    for (const file of files) {
      if (!file.endsWith(".json")) {
        continue;
      }
      const rec = await readJsonFile(path.join(paths.subagentKeysDir, file), null);
      if (rec?.agentId && rec?.publicKeyPem) {
        map.set(rec.agentId, rec);
      }
    }
  } catch {
    // No subagent dir yet.
  }

  return map;
}

async function readAllDelegations(paths) {
  const map = new Map();
  try {
    const files = await fs.readdir(paths.delegationsDir);
    for (const file of files) {
      if (!file.endsWith(".json")) {
        continue;
      }
      const rec = await readJsonFile(path.join(paths.delegationsDir, file), null);
      if (rec?.payload?.childAgentId) {
        map.set(rec.payload.childAgentId, rec);
      }
    }
  } catch {
    // No delegations yet.
  }
  return map;
}

function verifyDelegation(childAgentId, delegation, keyByAgent, errors) {
  if (!delegation) {
    errors.push(`missing delegation certificate for subagent ${childAgentId}`);
    return;
  }

  const main = keyByAgent.get("main");
  if (!main?.publicKeyPem) {
    errors.push("main key missing while verifying delegation");
    return;
  }

  const payloadCanonical = canonicalJSONString(delegation.payload);
  const payloadHash = sha256HexCanonical(payloadCanonical);
  if (payloadHash !== delegation.payloadHash) {
    errors.push(`delegation payload hash mismatch for ${childAgentId}`);
  }

  const sigOk = verifyEd25519Base64Url(payloadCanonical, delegation.signature, main.publicKeyPem);
  if (!sigOk) {
    errors.push(`delegation signature invalid for ${childAgentId}`);
  }
}

function verifyAuditRecord(record, prevHash, keyByAgent, delegationsByChild, idTokenJti, errors) {
  if ((record.prevHash || null) !== (prevHash || null)) {
    errors.push(`prevHash mismatch at seq=${record?.envelope?.seq ?? "?"}`);
  }

  if (!record?.envelope) {
    errors.push("audit record missing envelope");
    return prevHash;
  }

  const envelopeCanonical = canonicalJSONString(record.envelope);
  const expectedEnvelopeHash = sha256HexCanonical(envelopeCanonical);
  if (expectedEnvelopeHash !== record.envelopeHash) {
    errors.push(`envelopeHash mismatch at seq=${record.envelope.seq}`);
  }

  const { signature, ...unsignedEnvelope } = record.envelope;
  const unsignedCanonical = canonicalJSONString(unsignedEnvelope);

  const keyRecord = keyByAgent.get(record.envelope.agentId);
  if (!keyRecord?.publicKeyPem) {
    errors.push(`unknown agent key for ${record.envelope.agentId}`);
  } else {
    const ok = verifyEd25519Base64Url(unsignedCanonical, signature, keyRecord.publicKeyPem);
    if (!ok) {
      errors.push(`operation signature invalid at seq=${record.envelope.seq}`);
    }
  }

  // idTokenJti is the v3 audit-log anchor (RFC 7519 §4.1.7) — the audit chain
  // is consistent with whichever id_token was current at append time. Older
  // entries with a different jti just mean the session refreshed; that's not
  // a tamper signal, so only assert equality when both sides have a value.
  if (idTokenJti && record.envelope.idTokenJti && record.envelope.idTokenJti !== idTokenJti) {
    // Entries from a previous session — accept; verifyState only enforces
    // the chain-integrity (prevHash + envelopeHash + signature) invariants.
  }

  if (record.envelope.agentId !== "main") {
    const child = record.envelope.agentId;
    const cert = delegationsByChild.get(child);
    verifyDelegation(child, cert, keyByAgent, errors);

    if (cert && record.envelope.delegationPayloadHash !== cert.payloadHash) {
      errors.push(`delegationPayloadHash mismatch at seq=${record.envelope.seq}`);
    }
    if (cert && record.envelope.delegationSignature !== cert.signature) {
      errors.push(`delegationSignature mismatch at seq=${record.envelope.seq}`);
    }
  }

  return expectedEnvelopeHash;
}

export async function verifyState(baseDir) {
  const paths = statePaths(baseDir);
  const errors = [];

  const session = await readJsonFile(paths.ownerSession, null);
  const keyByAgent = await readAllKeyRecords(paths);
  const delegationsByChild = await readAllDelegations(paths);
  const auditRecords = await readJsonl(paths.auditJsonl);

  let currentJti = null;
  let ownerSub = null;
  if (session?.idToken) {
    try {
      const payload = parseJwt(session.idToken).payload;
      currentJti = typeof payload?.jti === "string" ? payload.jti : null;
      ownerSub = typeof payload?.sub === "string" ? payload.sub : null;
    } catch {
      errors.push("owner-session.json id_token is unparseable");
    }
  } else {
    errors.push("owner-session.json is missing");
  }

  let prevHash = null;
  for (const record of auditRecords) {
    prevHash = verifyAuditRecord(
      record,
      prevHash,
      keyByAgent,
      delegationsByChild,
      currentJti,
      errors,
    );
  }

  return {
    ok: errors.length === 0,
    errorCount: errors.length,
    errors,
    ownerSessionSub: ownerSub,
    operations: auditRecords.length,
    agents: Array.from(keyByAgent.keys()).sort(),
    subagentDelegations: Array.from(delegationsByChild.keys()).sort(),
  };
}

// ════════════════════════════════════════════════════════════════════════════════
// Vault — Encrypted credential storage linked to agent identity
// ════════════════════════════════════════════════════════════════════════════════

export function deriveVaultKey(privateKeyPem) {
  const privKey = createPrivateKey(privateKeyPem);
  const rawKey = privKey.export({ type: "pkcs8", format: "der" });
  return Buffer.from(
    hkdfSync("sha256", rawKey, "agent-id-vault-v1", "vault-encryption", 32),
  );
}

export function vaultEncrypt(key, plaintext) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString("hex"),
    data: encrypted.toString("hex"),
    tag: tag.toString("hex"),
  };
}

export function vaultDecrypt(key, entry) {
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(entry.iv, "hex"),
  );
  decipher.setAuthTag(Buffer.from(entry.tag, "hex"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(entry.data, "hex")),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}

