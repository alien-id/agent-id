// Alien Agent ID — Service manifest discovery and validation.
//
// /.well-known/alien-agent-id.json. Trust model: the manifest is third-party
// data. It is parsed, schema-validated, and reduced to a fixed set of fields
// before any value is returned. The only URLs the agent will subsequently
// touch are those that share the same authority as the user-provided
// service URL (exact host or a subdomain).
//
// Plugin-private to agent-id-auth: only this plugin needs to discover,
// parse, and render manifests. Other plugins reach for core primitives.

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
