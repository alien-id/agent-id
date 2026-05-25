// Alien Agent ID — Stub parsing + injection.
//
// Stubs use the recognizable token "AgentVault <name>" wherever a
// credential value would normally go. The proxy:
//   1. Scans request line + headers for `AgentVault <name>` tokens
//   2. Looks up <name> in the vault payload
//   3. Verifies the request host matches the credential's domain allowlist
//   4. Substitutes the materialized credential value
//
// Materialization rules per credential type:
//   bearer     → "Bearer <value>"
//   basic      → "Basic <b64(user:pass)>"
//   header     → "<value>"
//   query      → "<value>"  (caller URL-encodes if in a query string)
//   cookie     → "<cookieName>=<value>"  (when used inside a Cookie header)
//   totp       → 6-digit code (RFC 6238)
//   cookie-jar → "k1=v1; k2=v2"  (when used inside a Cookie header)
//
// A stub anywhere in a header value or query parameter is replaced. The
// agent decides the location; the proxy decides the format.

import { generateTotp } from "./totp.mjs";
import { hostMatchesAllowlist } from "../../agent-id-vault/lib/store.mjs";

// Match `AgentVault <name>` where name is the credential identifier syntax.
const STUB_RE = /AgentVault\s+([a-zA-Z0-9._-]{1,64})/g;

export class StubError extends Error {
  constructor(code, message, extra = {}) {
    super(message);
    this.code = code;
    Object.assign(this, extra);
  }
}

export function materializeCredential(cred) {
  switch (cred.type) {
    case "bearer":
      return `Bearer ${cred.value}`;
    case "basic":
      return `Basic ${Buffer.from(`${cred.username}:${cred.password}`, "utf8").toString("base64")}`;
    case "header":
      return cred.value;
    case "query":
      return cred.value;
    case "cookie":
      return `${cred.cookieName}=${cred.value}`;
    case "totp":
      return generateTotp(cred);
    case "cookie-jar":
      return Object.entries(cred.cookies)
        .map(([k, v]) => `${k}=${v}`)
        .join("; ");
    default:
      throw new StubError("unknown_type", `Unknown credential type: ${cred.type}`);
  }
}

export function findStubsInString(s) {
  if (typeof s !== "string") return [];
  const out = [];
  STUB_RE.lastIndex = 0;
  let m;
  while ((m = STUB_RE.exec(s)) !== null) {
    out.push({ match: m[0], name: m[1], index: m.index });
  }
  return out;
}

export function hasStub(s) {
  if (typeof s !== "string") return false;
  STUB_RE.lastIndex = 0;
  return STUB_RE.test(s);
}

/**
 * Replace all stubs in a string. `lookup(name)` returns either a credential
 * record or null. `host` is checked against each credential's allowlist.
 * Throws StubError on missing credential or disallowed host.
 *
 * `encode` is applied to each materialized replacement (e.g. encodeURIComponent
 * for query-string substitutions).
 */
export function replaceStubs(s, { lookup, host, encode = (v) => v }) {
  if (!hasStub(s)) return { value: s, used: [] };
  const used = [];
  const replaced = s.replace(STUB_RE, (_full, name) => {
    const cred = lookup(name);
    if (!cred) {
      throw new StubError(
        "credential_not_found",
        `Credential not found: ${name}`,
        { credential: name },
      );
    }
    if (!hostMatchesAllowlist(host, cred.domains)) {
      throw new StubError(
        "host_not_allowed",
        `Host ${host} not on allowlist for credential ${name} (allowed: ${cred.domains.join(", ")})`,
        { credential: name, host, allowed: cred.domains },
      );
    }
    used.push({ name, type: cred.type });
    return encode(materializeCredential(cred));
  });
  return { value: replaced, used };
}

/**
 * Rewrite a URL: replaces stubs in any query parameter value. URLSearchParams
 * handles encoding of the substituted value. Returns { url, used }.
 */
export function rewriteUrl(rawUrl, { lookup, host }) {
  const url = new URL(rawUrl);
  let used = [];
  let touched = false;
  const newParams = new URLSearchParams();
  for (const [k, v] of url.searchParams.entries()) {
    if (hasStub(v)) {
      touched = true;
      const result = replaceStubs(v, { lookup, host });
      newParams.append(k, result.value);
      used = used.concat(result.used);
    } else {
      newParams.append(k, v);
    }
  }
  if (touched) url.search = newParams.toString();
  return { url: url.toString(), used };
}

/**
 * Rewrite all header values: replaces stubs in each header value. Returns
 * { headers, used }. The headers parameter is a plain object of
 * lowercased-name → value (single value per name; multi-valued headers
 * should be joined first or handled by caller).
 */
export function rewriteHeaders(headers, { lookup, host }) {
  const out = {};
  let used = [];
  for (const [k, v] of Object.entries(headers)) {
    if (!hasStub(v)) {
      out[k] = v;
      continue;
    }
    const result = replaceStubs(v, { lookup, host });
    out[k] = result.value;
    used = used.concat(result.used);
  }
  return { headers: out, used };
}
