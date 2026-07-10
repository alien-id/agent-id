// Alien Agent ID — deterministic semantic capability-policy kernel.
//
// This module is deliberately free of storage, network, UI, and approval
// transport concerns. A local proxy, a browser adapter, or a future Frame TEE
// feeds it the actual request bytes and a cryptographic principal. It returns
// allow / deny / ask plus an exact, privacy-safe action commitment.

import { randomUUID } from "node:crypto";

import { canonicalJSONString, sha256Hex } from "@alien-id/agent-id-core/lib/crypto.mjs";
import { evaluateAccess, hostMatchesAllowlist, pathMatchesGlob } from "./access.mjs";

export const CAPABILITY_POLICY_VERSION = 1;
export const CAPABILITY_DECISIONS = Object.freeze(["allow", "deny", "ask"]);
export const CAPABILITY_UNMATCHED = Object.freeze(["legacy", "deny", "ask"]);

const POLICY_KEYS = new Set(["version", "epoch", "onUnmatched", "grants"]);
const GRANT_KEYS = new Set([
  "id",
  "principal",
  "capability",
  "label",
  "decision",
  "priority",
  "match",
  "constraints",
  "previewFields",
  "notBeforeMs",
  "expiresAtMs",
]);
const MATCH_KEYS = new Set(["methods", "hosts", "ports", "path", "query", "json"]);
const FIELD_RULE_KEYS = new Set(["path", "op", "value", "values"]);
const FIELD_OPS = new Set([
  "exists",
  "eq",
  "neq",
  "in",
  "contains",
  "lte",
  "gte",
  "lengthLte",
  "domainIn",
  "subsetOf",
]);
const CAPABILITY_RE = /^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9_-]*)*$/;
const ID_RE = /^[A-Za-z0-9._:-]{1,96}$/;
const PRINCIPAL_RE = /^[^\x00-\x1f\x7f]{1,256}$/;
const METHOD_RE = /^[A-Z]+$/;
const MAX_GRANTS = 200;
const MAX_FIELD_RULES = 32;
const MAX_PREVIEW_FIELDS = 24;
const CREDENTIAL_BINDING_EXCLUDED_KEYS = new Set([
  "capabilityPolicy",
  "capabilityPolicyEpoch",
  "credentialBindingHash",
  "lastUsedAt",
  // Never expose a public, unsalted hash oracle for low-entropy credentials.
  // Official credential replacements update `updatedAt`, which is included as
  // the material/config revision while these raw fields stay out of the hash.
  "value",
  "username",
  "password",
  "secret",
  "cookies",
  "refreshToken",
  "clientSecret",
  "accessToken",
  "secretSeed",
  "privateKey",
  "dek",
  "totpSecret",
]);

// Language-neutral ordering for envelope arrays derived from maps/sets. Header
// names, grant IDs, and capability names are UTF-8 strings; byte order is
// explicit so ICU locale settings cannot change a Frame-compatible digest.
function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function rejectUnknownKeys(obj, allowed, where) {
  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) throw new Error(`${where}: unknown key '${key}'`);
  }
}

function validateStringArray(value, where, { max = 64 } = {}) {
  if (!Array.isArray(value) || value.length === 0 || value.length > max) {
    throw new Error(`${where}: must be a non-empty array (max ${max})`);
  }
  for (const item of value) {
    if (typeof item !== "string" || item.length === 0 || item.length > 512) {
      throw new Error(`${where}: entries must be non-empty strings`);
    }
  }
}

function validateFieldRule(rule, where) {
  if (!isPlainObject(rule)) throw new Error(`${where}: must be an object`);
  rejectUnknownKeys(rule, FIELD_RULE_KEYS, where);
  if (typeof rule.path !== "string" || !rule.path.startsWith("/") || rule.path.length > 256) {
    throw new Error(`${where}.path: must be an RFC 6901 pointer starting with '/'`);
  }
  if (!FIELD_OPS.has(rule.op)) {
    throw new Error(`${where}.op: must be one of ${[...FIELD_OPS].join(", ")}`);
  }
  if (["in", "domainIn", "subsetOf"].includes(rule.op)) {
    validateStringArray(rule.values, `${where}.values`, { max: 100 });
  } else if (rule.op === "exists") {
    if (rule.value != null && typeof rule.value !== "boolean") {
      throw new Error(`${where}.value: exists expects a boolean`);
    }
  } else if (!("value" in rule)) {
    throw new Error(`${where}.value: required for op '${rule.op}'`);
  } else if (
    ["lte", "gte", "lengthLte"].includes(rule.op) &&
    (typeof rule.value !== "number" || !Number.isFinite(rule.value))
  ) {
    throw new Error(`${where}.value: op '${rule.op}' expects a finite number`);
  } else if (rule.op === "lengthLte" && (!Number.isInteger(rule.value) || rule.value < 0)) {
    throw new Error(`${where}.value: lengthLte expects a non-negative integer`);
  }
  if ("value" in rule) validateJsonValue(rule.value, `${where}.value`);
}

function validateJsonValue(value, where, seen = new Set()) {
  if (value == null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error(`${where}: must contain only finite JSON numbers`);
    return;
  }
  if (typeof value !== "object") throw new Error(`${where}: must be a JSON value`);
  if (seen.has(value)) throw new Error(`${where}: cyclic JSON values are not allowed`);
  seen.add(value);
  if (Array.isArray(value)) {
    value.forEach((item, index) => validateJsonValue(item, `${where}[${index}]`, seen));
  } else {
    for (const [key, item] of Object.entries(value)) {
      validateJsonValue(item, `${where}.${key}`, seen);
    }
  }
  seen.delete(value);
}

function validateFieldRules(rules, where) {
  if (!Array.isArray(rules) || rules.length === 0 || rules.length > MAX_FIELD_RULES) {
    throw new Error(`${where}: must be a non-empty array (max ${MAX_FIELD_RULES})`);
  }
  rules.forEach((rule, i) => validateFieldRule(rule, `${where}[${i}]`));
}

function validateMatch(match, where) {
  if (!isPlainObject(match)) throw new Error(`${where}: must be an object`);
  rejectUnknownKeys(match, MATCH_KEYS, where);
  if (Object.keys(match).length === 0) throw new Error(`${where}: cannot be empty`);
  if (match.methods != null) {
    validateStringArray(match.methods, `${where}.methods`);
    for (const method of match.methods) {
      if (!METHOD_RE.test(method)) throw new Error(`${where}.methods: '${method}' is invalid`);
    }
  }
  if (match.hosts != null) validateStringArray(match.hosts, `${where}.hosts`);
  if (match.ports != null) {
    validateStringArray(match.ports, `${where}.ports`);
    for (const port of match.ports) {
      if (
        port !== "default" &&
        (!/^[1-9]\d{0,4}$/.test(port) || Number(port) > 65535)
      ) {
        throw new Error(`${where}.ports: '${port}' must be 'default' or 1..65535`);
      }
    }
  }
  if (match.path != null && (typeof match.path !== "string" || !match.path.startsWith("/"))) {
    throw new Error(`${where}.path: must start with '/'`);
  }
  if (match.query != null && typeof match.query !== "string") {
    throw new Error(`${where}.query: must be a glob string`);
  }
  if (match.json != null) validateFieldRules(match.json, `${where}.json`);
}

export function validateCapabilityPolicy(policy, resourceName = "credential") {
  const where = `Capability policy for ${resourceName}`;
  if (!isPlainObject(policy)) throw new Error(`${where}: must be an object`);
  rejectUnknownKeys(policy, POLICY_KEYS, where);
  if (policy.version !== CAPABILITY_POLICY_VERSION) {
    throw new Error(`${where}.version: expected ${CAPABILITY_POLICY_VERSION}`);
  }
  if (!Number.isSafeInteger(policy.epoch) || policy.epoch < 1) {
    throw new Error(`${where}.epoch: must be a positive safe integer`);
  }
  if (!CAPABILITY_UNMATCHED.includes(policy.onUnmatched)) {
    throw new Error(`${where}.onUnmatched: must be one of ${CAPABILITY_UNMATCHED.join(", ")}`);
  }
  if (!Array.isArray(policy.grants) || policy.grants.length === 0 || policy.grants.length > MAX_GRANTS) {
    throw new Error(`${where}.grants: must be a non-empty array (max ${MAX_GRANTS})`);
  }
  const ids = new Set();
  for (let i = 0; i < policy.grants.length; i++) {
    const grant = policy.grants[i];
    const gw = `${where}.grants[${i}]`;
    if (!isPlainObject(grant)) throw new Error(`${gw}: must be an object`);
    rejectUnknownKeys(grant, GRANT_KEYS, gw);
    if (!ID_RE.test(grant.id || "")) throw new Error(`${gw}.id: invalid or missing`);
    if (ids.has(grant.id)) throw new Error(`${where}.grants: duplicate id '${grant.id}'`);
    ids.add(grant.id);
    if (grant.principal !== "*" && !PRINCIPAL_RE.test(grant.principal || "")) {
      throw new Error(`${gw}.principal: must be '*' or a non-empty canonical principal`);
    }
    if (!CAPABILITY_RE.test(grant.capability || "")) {
      throw new Error(`${gw}.capability: invalid semantic action name`);
    }
    if (!CAPABILITY_DECISIONS.includes(grant.decision)) {
      throw new Error(`${gw}.decision: must be one of ${CAPABILITY_DECISIONS.join(", ")}`);
    }
    if (grant.label != null && (typeof grant.label !== "string" || grant.label.length > 120)) {
      throw new Error(`${gw}.label: must be a string up to 120 characters`);
    }
    if (
      grant.priority != null &&
      (!Number.isInteger(grant.priority) || grant.priority < -1000 || grant.priority > 1000)
    ) {
      throw new Error(`${gw}.priority: must be an integer from -1000 to 1000`);
    }
    if (grant.match != null) validateMatch(grant.match, `${gw}.match`);
    if (grant.constraints != null) validateFieldRules(grant.constraints, `${gw}.constraints`);
    if (grant.previewFields != null) {
      validateStringArray(grant.previewFields, `${gw}.previewFields`, { max: MAX_PREVIEW_FIELDS });
      for (const pointer of grant.previewFields) {
        if (!pointer.startsWith("/")) throw new Error(`${gw}.previewFields: pointers must start with '/'`);
      }
    }
    for (const field of ["notBeforeMs", "expiresAtMs"]) {
      if (grant[field] != null && (!Number.isInteger(grant[field]) || grant[field] < 0)) {
        throw new Error(`${gw}.${field}: must be a non-negative epoch millisecond integer`);
      }
    }
    if (
      grant.notBeforeMs != null &&
      grant.expiresAtMs != null &&
      grant.notBeforeMs >= grant.expiresAtMs
    ) {
      throw new Error(`${gw}: notBeforeMs must be before expiresAtMs`);
    }
  }
  return policy;
}

function pointerValue(root, pointer) {
  if (root == null) return { exists: false, value: undefined };
  const parts = pointer
    .slice(1)
    .split("/")
    .map((part) => part.replace(/~1/g, "/").replace(/~0/g, "~"));
  let value = root;
  for (const part of parts) {
    if (
      value == null ||
      typeof value !== "object" ||
      !Object.prototype.hasOwnProperty.call(value, part)
    ) {
      return { exists: false, value: undefined };
    }
    value = value[part];
  }
  return { exists: true, value };
}

function emailDomain(value) {
  const s = String(value || "").trim().toLowerCase();
  const at = s.lastIndexOf("@");
  return at >= 0 ? s.slice(at + 1) : s;
}

function fieldRuleMatches(root, rule) {
  const got = pointerValue(root, rule.path);
  const value = got.value;
  if (rule.op !== "exists" && !got.exists) return false;
  switch (rule.op) {
    case "exists":
      return got.exists === (rule.value !== false);
    case "eq":
      return canonicalJSONString(value) === canonicalJSONString(rule.value);
    case "neq":
      return canonicalJSONString(value) !== canonicalJSONString(rule.value);
    case "in":
      return rule.values.some((v) => canonicalJSONString(value) === canonicalJSONString(v));
    case "contains":
      return typeof value === "string"
        ? value.includes(String(rule.value))
        : Array.isArray(value) && value.some((v) => canonicalJSONString(v) === canonicalJSONString(rule.value));
    case "lte":
      return typeof value === "number" && value <= Number(rule.value);
    case "gte":
      return typeof value === "number" && value >= Number(rule.value);
    case "lengthLte":
      return (typeof value === "string" || Array.isArray(value)) && value.length <= Number(rule.value);
    case "domainIn": {
      const values = Array.isArray(value) ? value : [value];
      const allowed = rule.values.map((v) => v.toLowerCase());
      return values.length > 0 && values.every((v) => allowed.includes(emailDomain(v)));
    }
    case "subsetOf": {
      if (!Array.isArray(value)) return false;
      const allowed = new Set(rule.values.map((v) => canonicalJSONString(v)));
      return value.every((v) => allowed.has(canonicalJSONString(v)));
    }
    default:
      return false;
  }
}

function rulesMatch(root, rules) {
  return !rules || rules.every((rule) => fieldRuleMatches(root, rule));
}

function requestMatches(match, request, bodyJson) {
  // Different TCP ports can be different services even on the same hostname.
  // A grant that omits ports is default-port-only; non-default ports must be
  // named explicitly instead of inheriting a broad host match.
  if (!match) return request.port === "";
  if (match.methods && !match.methods.includes(request.method)) return false;
  if (match.hosts && !hostMatchesAllowlist(request.host, match.hosts)) return false;
  if (match.ports) {
    if (!match.ports.includes(request.port || "default")) return false;
  } else if (request.port !== "") {
    return false;
  }
  if (match.path && !pathMatchesGlob(request.path, match.path)) return false;
  if (match.query && !pathMatchesGlob(request.query || "", match.query)) return false;
  if (match.json && !rulesMatch(bodyJson, match.json)) return false;
  return true;
}

function scanUnambiguousJson(raw) {
  let index = 0;
  const whitespace = () => {
    while (/[\u0009\u000a\u000d\u0020]/.test(raw[index] || "")) index++;
  };
  const stringToken = () => {
    const start = index++;
    let escaped = false;
    while (index < raw.length) {
      const ch = raw[index++];
      if (!escaped && ch === '"') return JSON.parse(raw.slice(start, index));
      if (!escaped && ch === "\\") escaped = true;
      else escaped = false;
    }
    throw new Error("unterminated JSON string");
  };
  const value = () => {
    whitespace();
    if (raw[index] === "{") {
      index++;
      whitespace();
      const keys = new Set();
      if (raw[index] === "}") {
        index++;
        return;
      }
      while (index < raw.length) {
        if (raw[index] !== '"') throw new Error("object key expected");
        const key = stringToken();
        if (keys.has(key)) throw new Error(`duplicate JSON key '${key}'`);
        keys.add(key);
        whitespace();
        if (raw[index++] !== ":") throw new Error("object colon expected");
        value();
        whitespace();
        const separator = raw[index++];
        if (separator === "}") return;
        if (separator !== ",") throw new Error("object comma expected");
        whitespace();
      }
      throw new Error("unterminated JSON object");
    }
    if (raw[index] === "[") {
      index++;
      whitespace();
      if (raw[index] === "]") {
        index++;
        return;
      }
      while (index < raw.length) {
        value();
        whitespace();
        const separator = raw[index++];
        if (separator === "]") return;
        if (separator !== ",") throw new Error("array comma expected");
      }
      throw new Error("unterminated JSON array");
    }
    if (raw[index] === '"') {
      stringToken();
      return;
    }
    const start = index;
    while (index < raw.length && !/[\u0009\u000a\u000d\u0020,\]}]/.test(raw[index])) index++;
    const token = raw.slice(start, index);
    if (token === "true" || token === "false" || token === "null") return;
    if (!/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/.test(token)) {
      throw new Error("invalid JSON token");
    }
    const numeric = Number(token);
    if (!Number.isFinite(numeric)) throw new Error("non-finite JSON number");
    if (Number.isInteger(numeric) && !Number.isSafeInteger(numeric)) {
      throw new Error("unsafe JSON integer");
    }
  };
  whitespace();
  value();
  whitespace();
  if (index !== raw.length) throw new Error("trailing JSON data");
}

export function parseCapabilityPolicyJSON(raw) {
  const text = String(raw);
  scanUnambiguousJson(text);
  return JSON.parse(text);
}

function parseBodyJson(body) {
  if (body == null || body.length === 0) return { value: null, valid: true };
  try {
    const raw = Buffer.isBuffer(body)
      ? new TextDecoder("utf-8", { fatal: true }).decode(body)
      : String(body);
    scanUnambiguousJson(raw);
    const value = JSON.parse(raw);
    validateJsonValue(value, "request JSON");
    return { value, valid: true };
  } catch {
    return { value: null, valid: false };
  }
}

function hasJsonContentType(headers) {
  for (const [name, value] of Object.entries(headers || {})) {
    if (name.toLowerCase() !== "content-type") continue;
    const contentType = String(Array.isArray(value) ? value[0] : value).split(";", 1)[0].trim().toLowerCase();
    return contentType === "application/json" || contentType.endsWith("+json");
  }
  return false;
}

function normalizedHeaders(headers) {
  const entries = [];
  for (const [rawName, rawValue] of Object.entries(headers || {})) {
    const name = rawName.toLowerCase();
    if (name === "connection" || name === "proxy-authorization") continue;
    const value = Array.isArray(rawValue) ? rawValue.map(String) : String(rawValue ?? "");
    entries.push([name, value]);
  }
  return entries.sort(([a], [b]) => compareUtf8(a, b));
}

function hashBytes(value) {
  if (value == null) return sha256Hex("");
  return sha256Hex(Buffer.isBuffer(value) ? value : Buffer.from(String(value), "utf8"));
}

function safePreviewValue(value, depth = 0) {
  if (value == null || typeof value === "boolean" || typeof value === "number") return value;
  if (typeof value === "string") return value.length > 256 ? `${value.slice(0, 253)}...` : value;
  if (depth >= 2) return "[nested]";
  if (Array.isArray(value)) return value.slice(0, 10).map((v) => safePreviewValue(v, depth + 1));
  if (isPlainObject(value)) {
    const out = Object.create(null);
    for (const key of Object.keys(value).slice(0, 12)) out[key] = safePreviewValue(value[key], depth + 1);
    return out;
  }
  return String(value).slice(0, 256);
}

function buildPreview(grants, bodyJson, request) {
  const fields = new Set(grants.flatMap((grant) => grant.previewFields || []));
  const parameters = {};
  for (const pointer of fields) {
    const got = pointerValue(bodyJson, pointer);
    if (got.exists) parameters[pointer] = safePreviewValue(got.value);
  }
  return {
    method: request.method,
    scheme: request.scheme,
    host: request.host,
    port: request.port,
    origin: `${request.scheme}://${request.host}${request.port ? `:${request.port}` : ""}`,
    path: request.path,
    ...(Object.keys(parameters).length ? { parameters } : {}),
  };
}

function decisionRank(decision) {
  return { allow: 1, ask: 2, deny: 3 }[decision] || 0;
}

export function capabilityPolicyHash(policy) {
  validateCapabilityPolicy(policy);
  return `sha256:${sha256Hex(canonicalJSONString(policy))}`;
}

// Commit the effective resource/materialization configuration without exposing
// it. This catches same-name swaps between bearer, query, wallet, OAuth, or
// browser records (including secret rotation and wallet constraints) while
// keeping volatile timestamps and the separately-hashed policy out.
export function capabilityCredentialBindingHash(record) {
  const bound = Object.create(null);
  for (const [key, value] of Object.entries(record || {})) {
    if (!CREDENTIAL_BINDING_EXCLUDED_KEYS.has(key)) bound[key] = value;
  }
  return `sha256:${sha256Hex(canonicalJSONString(bound))}`;
}

/**
 * Evaluate one real HTTP request under a credential's capability policy.
 * `nonce` must be unique per request in an enforcement process; a generated
 * default is convenient for direct callers, while revalidation must reuse it.
 */
export function evaluateCapabilityPolicy(policy, context) {
  validateCapabilityPolicy(policy, context?.credential || "credential");
  const principal = String(context?.principal || "");
  if (!PRINCIPAL_RE.test(principal)) throw new Error("capability principal is required");
  const now = Number.isFinite(context.nowMs) ? context.nowMs : Date.now();
  const body = context.body == null ? Buffer.alloc(0) : Buffer.isBuffer(context.body) ? context.body : Buffer.from(String(context.body));
  const parsedBody = parseBodyJson(body);
  const bodyJson = parsedBody.value;
  const invalidJsonBody = body.length > 0 && hasJsonContentType(context.headers) && !parsedBody.valid;
  const request = {
    method: String(context.method || "GET").toUpperCase(),
    scheme: String(context.scheme || "https").toLowerCase(),
    host: String(context.host || "").toLowerCase(),
    port: String(context.port || ""),
    path: context.path || "/",
    query: context.query || "",
  };

  const requestMatched = policy.grants.filter(
    (grant) =>
      (grant.notBeforeMs == null || now >= grant.notBeforeMs) &&
      (grant.expiresAtMs == null || now < grant.expiresAtMs) &&
      requestMatches(grant.match, request, bodyJson),
  );
  const principalMatched = requestMatched.filter(
    (grant) =>
      (grant.principal === "*" || grant.principal === principal) &&
      rulesMatch(bodyJson, grant.constraints),
  );

  const byCapability = new Map();
  for (const grant of principalMatched) {
    const current = byCapability.get(grant.capability) || [];
    current.push(grant);
    byCapability.set(grant.capability, current);
  }
  const selected = [];
  for (const grants of byCapability.values()) {
    const maxPriority = Math.max(...grants.map((grant) => grant.priority || 0));
    const samePriority = grants.filter((grant) => (grant.priority || 0) === maxPriority);
    samePriority.sort((a, b) => decisionRank(b.decision) - decisionRank(a.decision));
    selected.push(samePriority[0]);
  }

  let verdict;
  let reason;
  if (selected.length === 0) {
    verdict = policy.onUnmatched;
    reason = requestMatched.length ? "principal_or_constraints_unmatched" : "capability_unmatched";
  } else {
    selected.sort((a, b) => decisionRank(b.decision) - decisionRank(a.decision));
    verdict = selected[0].decision;
    reason = `capability_${verdict}`;
  }
  if (invalidJsonBody) {
    verdict = "deny";
    reason = "invalid_or_ambiguous_json";
  }
  if (selected.length === 0 && request.port && verdict === "legacy") {
    verdict = "deny";
    reason = "non_default_port_unmatched";
  }

  const policyHash = capabilityPolicyHash(policy);
  const capabilities = [
    ...new Set((selected.length ? selected : requestMatched).map((g) => g.capability)),
  ].sort(compareUtf8);
  const selectedGrants = selected
    .map((grant) => ({
      id: grant.id,
      capability: grant.capability,
      ...(grant.label ? { label: grant.label } : {}),
    }))
    .sort((a, b) => compareUtf8(a.id, b.id));
  const preview = buildPreview(selected.length ? selected : requestMatched, bodyJson, request);
  const nonce = context.nonce || randomUUID();
  const envelope = {
    version: 1,
    principal,
    credential: String(context.credential || ""),
    credentialBindingHash:
      context.credentialBindingHash ||
      `sha256:${sha256Hex(canonicalJSONString({ name: String(context.credential || "") }))}`,
    capabilities,
    grants: selectedGrants.map(({ id, capability }) => ({ id, capability })),
    policy: { version: policy.version, epoch: policy.epoch, hash: policyHash },
    adapter: { id: String(context.adapterId || "http"), version: Number(context.adapterVersion || 1) },
    request: {
      method: request.method,
      scheme: request.scheme,
      host: request.host,
      port: request.port,
      path: request.path,
      queryHash: hashBytes(request.query),
      headersHash: hashBytes(canonicalJSONString(normalizedHeaders(context.headers))),
      bodyHash: hashBytes(body),
      bodyLength: body.length,
    },
    preview,
    nonce,
    expiresAtMs: Number.isFinite(context.expiresAtMs) ? context.expiresAtMs : now + 120_000,
  };
  const actionDigest = `sha256:${sha256Hex(canonicalJSONString(envelope))}`;
  return {
    verdict,
    allowed: verdict === "allow",
    reason,
    capability: capabilities.length === 1 ? capabilities[0] : null,
    capabilities,
    grantIds: selectedGrants.map((grant) => grant.id),
    grants: selectedGrants,
    policyEpoch: policy.epoch,
    policyHash,
    preview,
    envelope,
    actionDigest,
    nonce,
  };
}

// Combined compatibility entry point used by the proxy/browser. A semantic
// policy replaces the coarse level for matched actions; an explicit legacy
// deny remains a hard outer guard. `onUnmatched:'legacy'` preserves v7 behavior.
export function evaluateCapabilityAccess(record, context) {
  if (!record?.capabilityPolicy) return evaluateAccess(record || {}, context);
  const legacy = evaluateAccess(record, context);
  if (legacy.reason && /^rule_\d+_deny$/.test(legacy.reason)) return legacy;
  const semantic = evaluateCapabilityPolicy(record.capabilityPolicy, {
    ...context,
    credential: context.credential || record.name || "",
    // The enforcement record, never a caller-supplied context field, owns this
    // commitment. Re-evaluation against a changed record therefore changes the
    // exact action digest before any new materialization logic can run.
    credentialBindingHash:
      context.credentialBindingHash || capabilityCredentialBindingHash(record),
  });
  if (semantic.verdict === "legacy") return legacy;
  return semantic;
}

export function isCapabilityPolicyRelaxation(before, after) {
  return canonicalJSONString(before || null) !== canonicalJSONString(after || null);
}
