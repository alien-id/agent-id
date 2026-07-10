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

// Is this credential restricted in ANY way (level or rules)? A rule-only
// restriction (access:"rw" + a deny rule) still means the proxy/browser gate
// the credential, so its plaintext must be sealed and the browser's
// route-bypass channels closed — otherwise the rule is theater.
export function isAccessRestricted(rec) {
  return (
    effectiveAccess(rec) === "ro" ||
    Array.isArray(rec && rec.accessRules) ||
    (rec && rec.capabilityPolicy != null)
  );
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

// JSON-RPC is default-DENY: a method is a read ONLY if it matches a known
// read-shaped vocabulary; anything unrecognized is "unknown" → blocked under
// ro (matching the GraphQL/JMAP classifiers). This inverts an earlier
// denylist that treated every non-EVM/Solana-write method as a read, so a
// generic `deleteUser` / Bitcoin `sendtoaddress` / `wallet_sendCalls` no
// longer slips through as a read.
const JSONRPC_READ_RE =
  /^(eth_(get\w+|call|blockNumber|chainId|gasPrice|estimateGas|feeHistory|maxPriorityFeePerGas|accounts|syncing|protocolVersion)|net_\w+|web3_\w+|get[A-Z]\w*|simulate\w+|isBlockhashValid|getHealth)$/;
// Explicit writes (kept for clarity / defense in depth; unknown is already denied).
const JSONRPC_WRITE_RE =
  /^(eth_send|eth_sign|personal_|wallet_send|sendTransaction$|sendRawTransaction$|signTransaction$|signAllTransactions$|requestAirdrop$)/;

// GraphQL operation-definition keyword at the start of a line (after stripping
// leading commas/whitespace). Used to detect ANY mutation/subscription in a
// multi-operation document — a request can name a later operation via
// `operationName`, so the leading keyword alone is not trustworthy.
const GQL_OP_RE = /(^|[\s,{}])(query|mutation|subscription)\b/g;

function classifyGraphql(doc) {
  // { query: "query { … }" } or "{ … }" (shorthand query). A document is a read
  // ONLY if it contains no mutation/subscription operation anywhere — otherwise
  // `operationName` could select a write even when the text starts with `query`.
  // Strip line comments first (a `#`-comment could otherwise hide a keyword or
  // fake a leading one). Shorthand `{ … }` with no keyword is an anonymous query.
  const raw = String(doc.query || "");
  const stripped = raw.replace(/#[^\n\r]*/g, "");
  let sawWrite = false;
  let sawQuery = false;
  let m;
  GQL_OP_RE.lastIndex = 0;
  while ((m = GQL_OP_RE.exec(stripped)) !== null) {
    if (m[2] === "query") sawQuery = true;
    else sawWrite = true;
  }
  if (sawWrite) return "write";
  if (sawQuery) return "read";
  // No operation keyword at all: a bare `{ … }` shorthand query is a read;
  // anything else (empty / unparseable) is unknown → blocked under ro.
  return /^\s*\{/.test(stripped) ? "read" : "unknown";
}

function classifyOne(obj) {
  if (!obj || typeof obj !== "object") return "unknown";
  if (typeof obj.query === "string") return classifyGraphql(obj);
  if (Array.isArray(obj.methodCalls)) {
    // JMAP request: every invocation must be a read method. An empty batch is a
    // no-op — classify as unknown (blocked under ro) rather than vacuously read.
    if (obj.methodCalls.length === 0) return "unknown";
    const allRead = obj.methodCalls.every(
      (c) => Array.isArray(c) && typeof c[0] === "string" && JMAP_READ_METHOD_RE.test(c[0]),
    );
    return allRead ? "read" : "write";
  }
  if (typeof obj.method === "string" && (obj.jsonrpc != null || obj.id !== undefined)) {
    if (JSONRPC_WRITE_RE.test(obj.method)) return "write";
    if (JSONRPC_READ_RE.test(obj.method)) return "read";
    return "unknown"; // default-deny: unrecognized RPC method is not a proven read
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
 * would require the body to classify (a POST that might be a tunneled read
 * under "ro" with no matching rule), the result carries `needsBody: true` and
 * `allowed: false`; the caller may buffer the body and re-evaluate.
 *
 * NOTE on `ro`: GET/HEAD/OPTIONS are treated as reads per the HTTP safe-method
 * contract (RFC 9110 §9.2.1) — `ro` does NOT defend against a server that
 * mutates on GET (unsubscribe/`?action=delete` links); constrain those with an
 * explicit deny accessRule if needed. Body classification runs ONLY for POST —
 * the sole method the read-through-POST protocols (GraphQL/JMAP/JSON-RPC) use —
 * so a read-shaped body can never promote a PUT/PATCH/DELETE to allowed.
 */
export function evaluateAccess(rec, { method, host, path, body }) {
  const m = String(method || "GET").toUpperCase();
  const h = String(host || "").toLowerCase();
  const p = path || "/";

  if (Array.isArray(rec.accessRules)) {
    for (let i = 0; i < rec.accessRules.length; i++) {
      const rule = rec.accessRules[i];
      if (ruleMatches(rule, { method: m, host: h, path: p })) {
        return {
          verdict: rule.effect === "allow" ? "allow" : "deny",
          allowed: rule.effect === "allow",
          reason: `rule_${i}_${rule.effect}`,
        };
      }
    }
  }

  if (effectiveAccess(rec) === "rw") {
    return { verdict: "allow", allowed: true, reason: "level_rw" };
  }

  if (READ_METHODS.includes(m)) {
    return { verdict: "allow", allowed: true, reason: "read_method" };
  }

  // Every non-read method other than POST is a write under "ro" — its body is
  // never consulted, so a read-shaped payload can't unlock a DELETE/PUT/PATCH.
  if (m !== "POST") {
    return { verdict: "deny", allowed: false, reason: "write_blocked" };
  }

  if (body === undefined) {
    return { verdict: "deny", allowed: false, reason: "write_blocked", needsBody: true };
  }
  if (classifyBodyRead(body) === "read") {
    return { verdict: "allow", allowed: true, reason: "read_classified" };
  }
  return { verdict: "deny", allowed: false, reason: "write_blocked" };
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

// Effect-qualified key for a rule (position handled separately). Two rules with
// the same {effect, methods, hosts, path} are interchangeable.
function ruleKey(r) {
  return JSON.stringify({ effect: r.effect, methods: r.methods, hosts: r.hosts, path: r.path });
}

// Do two rules overlap — i.e. could some request match BOTH? If so, their
// relative order decides the outcome (first-match-wins). Conservative: a null
// dimension means "matches anything" on that axis, so it overlaps unless the
// other side is a disjoint concrete set.
function rulesOverlap(a, b) {
  const dimOverlap = (x, y, eq) => {
    if (x == null || y == null) return true; // one is unconstrained on this axis
    return x.some((xi) => y.some((yi) => eq(xi, yi)));
  };
  const methodsOk = dimOverlap(
    a.methods && a.methods.map((m) => m.toUpperCase()),
    b.methods && b.methods.map((m) => m.toUpperCase()),
    (x, y) => x === y,
  );
  if (!methodsOk) return false;
  // hosts / path can't be proven disjoint cheaply (wildcards/globs), so treat
  // any host/path pairing as potentially overlapping — the safe direction.
  return true;
}

/**
 * Does `after` grant anything `before` did not? True when the level widens
 * (ro→rw), an allow rule appears that wasn't there, a deny rule disappears, OR
 * a reorder moves an allow ahead of an overlapping deny it previously lost to
 * (first-match-wins, so that widens). Pure tightening (rw→ro, adding deny
 * rules, dropping allow rules) and order-neutral reorders (deny↔deny,
 * allow↔allow, or a deny moved EARLIER) are false — tightening applies without
 * the owner ceremony.
 */
export function isAccessRelaxation(before, after) {
  // Capability policies are owner-authored authorization programs. Conservatively
  // treat every addition, removal, or edit as a potential relaxation; the
  // dedicated policy command can then require the owner ceremony uniformly.
  // This also prevents `add --overwrite` from silently dropping a policy.
  if (
    JSON.stringify(before && before.capabilityPolicy) !==
    JSON.stringify(after && after.capabilityPolicy)
  ) {
    return true;
  }
  if (ACCESS_RANK[effectiveAccess(after)] > ACCESS_RANK[effectiveAccess(before)]) return true;
  const beforeAllow = ruleSet(before, "allow");
  for (const r of ruleSet(after, "allow")) {
    if (!beforeAllow.has(r)) return true;
  }
  const afterDeny = ruleSet(after, "deny");
  for (const r of ruleSet(before, "deny")) {
    if (!afterDeny.has(r)) return true;
  }
  // Precedence reorder: among rules common to both, a widening happens only if
  // some allow rule A was AFTER an overlapping deny rule D in `before` but is
  // now BEFORE it in `after` (A can now win where D used to). Reordering rules
  // of the same effect, or moving a deny earlier, never widens.
  const beforeRules = Array.isArray(before.accessRules) ? before.accessRules : [];
  const afterRules = Array.isArray(after.accessRules) ? after.accessRules : [];
  const afterKeys = new Set(afterRules.map(ruleKey));
  const beforeKeys = new Set(beforeRules.map(ruleKey));
  const common = (rules, otherKeys) =>
    rules.map((r, i) => ({ r, i, key: ruleKey(r) })).filter((x) => otherKeys.has(x.key));
  const bCommon = common(beforeRules, afterKeys);
  const aPos = new Map(common(afterRules, beforeKeys).map((x) => [x.key, x.i]));
  for (const allow of bCommon) {
    if (allow.r.effect !== "allow") continue;
    for (const deny of bCommon) {
      if (deny.r.effect !== "deny") continue;
      if (!rulesOverlap(allow.r, deny.r)) continue;
      const denyBeforeAllow_before = deny.i < allow.i;
      const allowBeforeDeny_after = aPos.get(allow.key) < aPos.get(deny.key);
      if (denyBeforeAllow_before && allowBeforeDeny_after) return true;
    }
  }
  return false;
}
