// Alien Agent ID — Per-credential access levels ("read my email, not write it").
//
// A credential record may carry:
//
//   access: "ro" | "rw"        (absent = "rw", backward compatible)
//   accessRules: [ { effect: "allow"|"deny",
//                    methods?: ["POST", …],       // HTTP methods (upper-cased)
//                    hosts?:   ["*.example.com"], // same syntax as `domains`
//                    path?:    "/api/v1/*" },     // pathname glob (* = any chars)
//                  … ]                            // first match wins
//
// Evaluation order (evaluateAccess):
//   1. accessRules, in order — an explicit rule always decides.
//   2. The level default: "rw" allows everything; "ro" allows read-shaped
//      requests only: GET/HEAD/OPTIONS, plus POST bodies that classify as reads
//      on protocols that tunnel reads through POST (GraphQL query / JMAP
//      */get,*/query / JSON-RPC non-submitting calls).
//
// WHO ENFORCES: the vault stores the policy; the processes that hold live
// credential material enforce it on every use — agent-id-proxy for HTTP
// injection and agent-id-browser's session server for sealed web sessions.
// The policy is only as strong as the vault's unlock boundary: with an
// agent-key slot the agent can open the vault itself, so for hard enforcement
// pair `access: "ro"` with a vault the agent cannot self-unlock (passkey /
// owner-approval slots).
//
// This module is dependency-free within the vault so both the proxy and the
// browser plugin can import it (store.mjs imports it for validation, so it
// must not import store.mjs back). hostMatchesAllowlist lives here for that
// reason and is re-exported by store.mjs for its existing consumers.

export const ACCESS_LEVELS = Object.freeze(["ro", "rw"]);

// Methods that are read-shaped on their own, regardless of body.
export const READ_METHODS = Object.freeze(["GET", "HEAD", "OPTIONS"]);

const RULE_EFFECTS = Object.freeze(["allow", "deny"]);
const METHOD_RE = /^[A-Z]+$/;

// ─── Domain allowlist matching ────────────────────────────────────────────────
// Supports literal hostnames and a single leading "*." wildcard.
// `*.github.com` matches `github.com`, `api.github.com`, `x.y.github.com`.
// (Moved from store.mjs so access rules and `domains` share one matcher
// without a circular import; store.mjs re-exports it.)
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

// The level in force for a record — absent means unrestricted ("rw").
export function effectiveAccess(rec) {
  return rec && rec.access != null ? rec.access : "rw";
}

// ─── Validation (called from store.mjs validateRecord) ────────────────────────

export function validateAccessFields(rec) {
  if (rec.access != null && !ACCESS_LEVELS.includes(rec.access)) {
    throw new Error(
      `Credential ${rec.name}: access must be one of ${ACCESS_LEVELS.join(", ")}`,
    );
  }
  if (rec.accessRules == null) return;
  if (!Array.isArray(rec.accessRules) || rec.accessRules.length === 0) {
    throw new Error(`Credential ${rec.name}: accessRules must be a non-empty array`);
  }
  for (const rule of rec.accessRules) {
    if (!rule || typeof rule !== "object" || Array.isArray(rule)) {
      throw new Error(`Credential ${rec.name}: each access rule must be an object`);
    }
    if (!RULE_EFFECTS.includes(rule.effect)) {
      throw new Error(
        `Credential ${rec.name}: rule effect must be one of ${RULE_EFFECTS.join(", ")}`,
      );
    }
    if (rule.methods != null) {
      if (!Array.isArray(rule.methods) || rule.methods.length === 0) {
        throw new Error(`Credential ${rec.name}: rule methods must be a non-empty array`);
      }
      for (const m of rule.methods) {
        if (typeof m !== "string" || !METHOD_RE.test(m.toUpperCase())) {
          throw new Error(`Credential ${rec.name}: invalid rule method '${m}'`);
        }
      }
    }
    if (rule.hosts != null) {
      if (!Array.isArray(rule.hosts) || rule.hosts.length === 0) {
        throw new Error(`Credential ${rec.name}: rule hosts must be a non-empty array`);
      }
      for (const h of rule.hosts) {
        if (typeof h !== "string" || h.length === 0) {
          throw new Error(`Credential ${rec.name}: invalid rule host entry`);
        }
      }
    }
    if (rule.path != null && (typeof rule.path !== "string" || !rule.path.startsWith("/"))) {
      throw new Error(`Credential ${rec.name}: rule path must be a string starting with '/'`);
    }
  }
}

// ─── Rule matching ────────────────────────────────────────────────────────────

// Pathname glob: `*` matches any run of characters (including `/`). Anchored.
export function pathMatchesGlob(pathname, glob) {
  const re = new RegExp(
    "^" + glob.split("*").map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("[^]*") + "$",
  );
  return re.test(pathname);
}

function ruleMatches(rule, { method, host, path }) {
  if (rule.methods && !rule.methods.map((m) => m.toUpperCase()).includes(method)) return false;
  if (rule.hosts && !hostMatchesAllowlist(host, rule.hosts)) return false;
  if (rule.path && !pathMatchesGlob(path || "/", rule.path)) return false;
  return true;
}

// ─── Read classification of POST-tunneled protocols ───────────────────────────
// Several protocols tunnel reads through POST; a method-only "ro" gate would
// either block those reads or force per-service rules everywhere. These
// classifiers recognize the common read shapes. Anything unrecognized stays
// blocked (default-deny for non-read methods under "ro").

const JMAP_READ_METHOD_RE = /\/(get|query|queryChanges|changes|echo|parse)$/;

// JSON-RPC calls that submit/sign state changes (EVM + Solana vocabularies).
const JSONRPC_WRITE_RE =
  /^(eth_send|eth_sign|personal_|sendTransaction$|signTransaction$|signAllTransactions$|requestAirdrop$)/;

function classifyGraphql(doc) {
  // { query: "query { … }" } or "{ … }" (shorthand query). Mutations and
  // subscriptions are writes. Operation type is the first keyword.
  const q = String(doc.query).trimStart();
  return /^(query\b|\{)/.test(q) ? "read" : "write";
}

function classifyOne(obj) {
  if (!obj || typeof obj !== "object") return "unknown";
  if (typeof obj.query === "string") return classifyGraphql(obj);
  if (Array.isArray(obj.methodCalls)) {
    // JMAP request: every invocation must be a read method.
    const allRead = obj.methodCalls.every(
      (c) => Array.isArray(c) && typeof c[0] === "string" && JMAP_READ_METHOD_RE.test(c[0]),
    );
    return allRead ? "read" : "write";
  }
  if (typeof obj.method === "string" && (obj.jsonrpc != null || obj.id !== undefined)) {
    return JSONRPC_WRITE_RE.test(obj.method) ? "write" : "read";
  }
  return "unknown";
}

// Classify a request body as "read" | "write" | "unknown". Accepts a UTF-8
// string; batched arrays (GraphQL/JSON-RPC) are reads only if every item is.
export function classifyBodyRead(body) {
  if (body == null || body === "") return "unknown";
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch {
    return "unknown";
  }
  const items = Array.isArray(parsed) ? parsed : [parsed];
  if (items.length === 0) return "unknown";
  let sawRead = false;
  for (const item of items) {
    const c = classifyOne(item);
    if (c === "write") return "write";
    if (c === "unknown") return "unknown";
    sawRead = true;
  }
  return sawRead ? "read" : "unknown";
}

// ─── The evaluator ────────────────────────────────────────────────────────────

/**
 * Decide whether a request may use this credential.
 *
 *   evaluateAccess(rec, { method, host, path, body })
 *     → { allowed: boolean, reason: string, needsBody?: true }
 *
 * `path` is the pathname only (no query string). `body` is the UTF-8 request
 * body, or undefined when the caller has not buffered it. When the decision
 * would require the body to classify (a non-read method under "ro" with no
 * matching rule), the result carries `needsBody: true` and `allowed: false`;
 * the caller may buffer the body and re-evaluate.
 */
export function evaluateAccess(rec, { method, host, path, body }) {
  const m = String(method || "GET").toUpperCase();
  const h = String(host || "").toLowerCase();
  const p = path || "/";

  if (Array.isArray(rec.accessRules)) {
    for (let i = 0; i < rec.accessRules.length; i++) {
      const rule = rec.accessRules[i];
      if (ruleMatches(rule, { method: m, host: h, path: p })) {
        return { allowed: rule.effect === "allow", reason: `rule_${i}_${rule.effect}` };
      }
    }
  }

  if (effectiveAccess(rec) === "rw") return { allowed: true, reason: "level_rw" };

  if (READ_METHODS.includes(m)) return { allowed: true, reason: "read_method" };

  if (body === undefined) {
    return { allowed: false, reason: "write_blocked", needsBody: true };
  }
  if (classifyBodyRead(body) === "read") {
    return { allowed: true, reason: "read_classified" };
  }
  return { allowed: false, reason: "write_blocked" };
}

// ─── Relaxation detection (gates the human ceremony in `set-access`) ──────────

const ACCESS_RANK = { ro: 0, rw: 1 };

// Strictest of two levels ("ro" beats "rw").
export function strictestAccess(a, b) {
  return ACCESS_RANK[a] <= ACCESS_RANK[b] ? a : b;
}

function ruleSet(rec, effect) {
  return new Set(
    (Array.isArray(rec.accessRules) ? rec.accessRules : [])
      .filter((r) => r && r.effect === effect)
      .map((r) => JSON.stringify({ methods: r.methods, hosts: r.hosts, path: r.path })),
  );
}

/**
 * Does `after` grant anything `before` did not? True when the level widens
 * (ro→rw), an allow rule appears that wasn't there, or a deny rule disappears.
 * Tightening (rw→ro, adding deny rules, dropping allow rules) is false.
 */
export function isAccessRelaxation(before, after) {
  if (ACCESS_RANK[effectiveAccess(after)] > ACCESS_RANK[effectiveAccess(before)]) return true;
  const beforeAllow = ruleSet(before, "allow");
  for (const r of ruleSet(after, "allow")) {
    if (!beforeAllow.has(r)) return true;
  }
  const afterDeny = ruleSet(after, "deny");
  for (const r of ruleSet(before, "deny")) {
    if (!afterDeny.has(r)) return true;
  }
  return false;
}
