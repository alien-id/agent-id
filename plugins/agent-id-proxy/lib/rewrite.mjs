// Alien Agent ID — URL-rewrite mode.
//
// The agent calls `http://localhost:PORT/<credname>/<upstream-host>/<path>`
// instead of the upstream URL directly. The proxy:
//   1. Extracts credname + upstream-host + path from the URL
//   2. Looks up the credential, enforces the domain allowlist
//   3. Materializes the credential into the appropriate request location
//      based on the credential type (Authorization / named header / query
//      param / Cookie / OTP header)
//   4. Forwards to the real upstream over HTTPS (or HTTP if the credential
//      opts in via `upstreamScheme: "http"`)
//
// This sidesteps the TLS-MITM problem entirely: the agent stops doing TLS
// to the upstream and the proxy becomes the HTTPS client. The system CA
// bundle verifies the upstream cert; we never touch trust stores or mint
// leaf certs.

import { generateTotp } from "./totp.mjs";
import { hostMatchesAllowlist } from "../../agent-id-vault/lib/store.mjs";

const CREDNAME_RE = /^[a-zA-Z0-9._-]{1,64}$/;
const HOST_RE = /^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,253}[a-zA-Z0-9])?(?::\d{1,5})?$/;

export class RewriteError extends Error {
  constructor(code, message, extra = {}) {
    super(message);
    this.code = code;
    Object.assign(this, extra);
  }
}

/**
 * Parse `/credname/host/rest?query` into its parts. Returns null if the URL
 * does not match the URL-rewrite shape (caller falls back to other paths).
 */
export function parseRewritePath(rawUrl) {
  if (typeof rawUrl !== "string" || !rawUrl.startsWith("/")) return null;
  const noLead = rawUrl.slice(1);
  const firstSlash = noLead.indexOf("/");
  if (firstSlash <= 0) return null;
  const credname = noLead.slice(0, firstSlash);
  if (!CREDNAME_RE.test(credname)) return null;

  const afterCred = noLead.slice(firstSlash + 1);
  let host;
  let restAndQuery;
  const secondSlash = afterCred.indexOf("/");
  const questionMark = afterCred.indexOf("?");
  if (secondSlash < 0 && questionMark < 0) {
    host = afterCred;
    restAndQuery = "/";
  } else if (secondSlash < 0 || (questionMark >= 0 && questionMark < secondSlash)) {
    host = afterCred.slice(0, questionMark);
    restAndQuery = "/" + afterCred.slice(questionMark);
  } else {
    host = afterCred.slice(0, secondSlash);
    restAndQuery = "/" + afterCred.slice(secondSlash + 1);
  }

  if (!host || !HOST_RE.test(host)) return null;

  return { credname, host, restAndQuery };
}

/**
 * Mutate a headers object + URL search-params to inject the materialized
 * credential. Returns { headers, search } where `search` is the (possibly
 * updated) URLSearchParams instance.
 *
 *   bearer     → Authorization: Bearer <value>
 *   basic      → Authorization: Basic <b64(user:pass)>
 *   header     → <cred.headerName>: <value>
 *   query      → URL: ?<cred.paramName>=<value>
 *   cookie     → Cookie: <cred.cookieName>=<value>  (appended if Cookie present)
 *   totp       → <cred.otpHeader || "X-OTP-Code">: <code>
 *   cookie-jar → Cookie: k1=v1; k2=v2; …  (appended if Cookie present)
 */
export function injectCredential({ headers, search, cred }) {
  const out = { ...headers };
  switch (cred.type) {
    case "bearer":
      out.authorization = `Bearer ${cred.value}`;
      break;
    case "basic": {
      const enc = Buffer.from(`${cred.username}:${cred.password}`, "utf8").toString("base64");
      out.authorization = `Basic ${enc}`;
      break;
    }
    case "header":
      out[cred.headerName.toLowerCase()] = cred.value;
      break;
    case "query":
      search.set(cred.paramName, cred.value);
      break;
    case "cookie":
      out.cookie = appendCookie(out.cookie, `${cred.cookieName}=${cred.value}`);
      break;
    case "totp": {
      const headerName = (cred.otpHeader || "X-OTP-Code").toLowerCase();
      out[headerName] = generateTotp(cred);
      break;
    }
    case "cookie-jar": {
      const jar = Object.entries(cred.cookies)
        .map(([k, v]) => `${k}=${v}`)
        .join("; ");
      out.cookie = appendCookie(out.cookie, jar);
      break;
    }
    case "oauth2":
      // The proxy refreshes oauth2 to an access token and passes a synthesized
      // `bearer` cred here. A raw oauth2 record reaching this point is a bug.
      throw new RewriteError(
        "oauth2_not_materialized",
        "oauth2 credential must be resolved to an access token before injection",
      );
    default:
      throw new RewriteError("unknown_type", `Unknown credential type: ${cred.type}`);
  }
  return { headers: out, search };
}

function appendCookie(existing, addition) {
  if (!existing) return addition;
  // Cookie headers may be a string or array (Node mostly gives string).
  if (Array.isArray(existing)) existing = existing.join("; ");
  return `${existing}; ${addition}`;
}

/**
 * Strip headers the upstream should not see from the agent.
 *
 *   - Host: will be set to the upstream's host below.
 *   - Origin / Referer: leak the proxy's localhost URL; strip.
 *   - Connection-class hop-by-hop headers: per RFC 9110 §7.6.1.
 *   - Authorization: only when the credential doesn't itself materialize
 *     into Authorization — otherwise the inject step replaces it anyway.
 */
const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

export function prepareUpstreamHeaders({ incoming, upstreamHost }) {
  const out = {};
  for (const [k, v] of Object.entries(incoming)) {
    const lk = k.toLowerCase();
    if (HOP_BY_HOP.has(lk)) continue;
    if (lk === "host") continue;
    if (lk === "origin" || lk === "referer") continue;
    out[lk] = v;
  }
  out.host = upstreamHost;
  return out;
}

/**
 * Look up a credential by name + validate the host. Throws RewriteError on
 * any failure; returns the credential record on success.
 */
export function resolveCredential({ credname, host, lookup }) {
  const cred = lookup(credname);
  if (!cred) {
    throw new RewriteError(
      "credential_not_found",
      `Credential not found: ${credname}`,
      { credential: credname },
    );
  }
  const bareHost = host.includes(":") ? host.slice(0, host.indexOf(":")) : host;
  if (!hostMatchesAllowlist(bareHost, cred.domains)) {
    throw new RewriteError(
      "host_not_allowed",
      `Host ${host} not on allowlist for credential ${credname} (allowed: ${cred.domains.join(", ")})`,
      { credential: credname, host, allowed: cred.domains },
    );
  }
  return cred;
}
