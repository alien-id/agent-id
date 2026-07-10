// Alien Agent ID — Access-level guard for sealed browser sessions.
//
// A `browser-profile` record may carry `access: "ro"` (+ optional
// `accessRules`, see @alien-id/agent-id-vault/lib/access.mjs). The guard makes
// a read-only session hold at the NETWORK layer, inside the session-server
// process (the agent only reaches the browser through the session socket's
// fixed action vocabulary, so it cannot remove the guard):
//
//   - every request the page makes is classified by evaluateAccess() —
//     GET/HEAD/OPTIONS pass; POST-tunneled reads (GraphQL query, JMAP get/
//     query, JSON-RPC non-submitting) pass; everything else is aborted, so a
//     click on "Send" fails at the wire even though clicking is allowed;
//   - service workers are blocked (they would bypass route interception);
//   - WebSockets are disabled via an init script (frames can't be inspected);
//   - the un-auditable/secret-bearing/exfiltrating actions (`eval`,
//     `fill-secret`, `fill-otp`, `upload`) are refused at the action layer
//     (assertActionAllowed).
//
// The DOM stays fully interactive (navigate/click/type/scroll) — typing a
// search query is a read — because the wire, not the widget, is the boundary.

import {
  effectiveAccess,
  evaluateAccess,
  isAccessRestricted,
} from "@alien-id/agent-id-vault/lib/access.mjs";
import { evaluateCapabilityAccess } from "@alien-id/agent-id-vault/lib/capability.mjs";

// Actions refused on a read-only session. Everything observational or
// DOM-interactive stays available; mutations die at the network gate.
// `upload` is denied too: feeding the owner's local files into a page is a
// write in spirit (and page JS could exfiltrate the content over allowed GETs).
const RESTRICTED_DENIED_ACTIONS = Object.freeze(["eval", "fill-secret", "fill-otp", "upload"]);

// Pure — unit-tests without a browser. Throws on a denied action.
export function assertActionAllowed(rec, action) {
  if (!isAccessRestricted(rec)) return;
  if (RESTRICTED_DENIED_ACTIONS.includes(action)) {
    const mode = effectiveAccess(rec) === "ro" ? "read-only" : "access-restricted";
    throw new Error(
      `action '${action}' is not available on a ${mode} session — ` +
        "use an auditable browser action or ask the owner to change the policy",
    );
  }
}

// Extra context options for a restricted profile: service workers would
// answer fetches without touching our route handler, so block them for ANY
// active guard (ro OR rule-restricted) — a deny rule is otherwise bypassable
// via a service-worker-replayed fetch.
export function contextOptionsForAccess(rec) {
  // Start offline so restored tabs/background pages cannot race the guard
  // installation immediately after launch. applyAccessGuard enables networking
  // only after HTTP and non-HTTP channel gates are installed.
  return isAccessRestricted(rec) ? { serviceWorkers: "block", offline: true } : {};
}

// Decide one request. Exported for tests (no browser needed).
export function guardDecision(
  rec,
  { method, url, postData, headers = {}, principal = null, nonce, nowMs, expiresAtMs },
) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return { verdict: "deny", allowed: false, reason: "bad_url" };
  }
  // Non-HTTP(S) schemes (data:, blob:, chrome-extension:) carry no credentialed
  // side effects upstream; let the browser handle them.
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return { verdict: "allow", allowed: true, reason: "non_http" };
  }
  const context = {
    principal,
    credential: rec?.name || "browser-profile",
    method,
    scheme: u.protocol.slice(0, -1),
    host: u.hostname,
    port: u.port,
    path: u.pathname,
    query: u.search,
    headers,
    body: postData ?? null,
    ...(rec?.credentialBindingHash
      ? { credentialBindingHash: rec.credentialBindingHash }
      : {}),
    ...(nonce != null ? { nonce } : {}),
    ...(Number.isFinite(nowMs) ? { nowMs } : {}),
    ...(Number.isFinite(expiresAtMs) ? { expiresAtMs } : {}),
  };
  try {
    return rec?.capabilityPolicy
      ? evaluateCapabilityAccess(rec, context)
      : evaluateAccess(rec, context);
  } catch (err) {
    // A missing principal, malformed policy, or adapter failure must never turn
    // into an unguarded browser request.
    return {
      verdict: "deny",
      allowed: false,
      reason: "capability_evaluation_failed",
      message: err?.message || String(err),
    };
  }
}

// Browser requests cannot safely sit parked while page state, CSRF tokens, or
// checkout totals continue changing. An ask may therefore proceed only when a
// local callback returns an exact one-shot approval synchronously. Promises and
// digest-less booleans fail closed.
export function exactImmediateApproval(decision, onAsk) {
  if (typeof onAsk !== "function" || decision?.verdict !== "ask") return false;
  let answer;
  try {
    answer = onAsk(decision);
  } catch {
    return false;
  }
  if (answer && typeof answer.then === "function") return false;
  return !!(
    answer &&
    answer.approved === true &&
    answer.scope === "once" &&
    answer.actionDigest === decision.actionDigest &&
    (!decision.envelope?.expiresAtMs || Date.now() < decision.envelope.expiresAtMs)
  );
}

function safeRequestLabel(method, rawUrl) {
  try {
    const url = new URL(rawUrl);
    return `${method} ${url.protocol}//${url.host}${url.pathname}`.slice(0, 240);
  } catch {
    return `${method} (invalid URL)`;
  }
}

function safePolicyString(value, max = 160) {
  return typeof value === "string" ? value.slice(0, max) : null;
}

function denialExplanation(decision, grants) {
  const labels = grants
    .map((grant) => grant.label || grant.capability || grant.id)
    .filter(Boolean)
    .slice(0, 3);
  switch (decision?.reason) {
    case "capability_ask":
      return labels.length
        ? `Owner approval is required by ${labels.join(", ")}.`
        : "Owner approval is required for this browser request.";
    case "capability_deny":
      return labels.length
        ? `The request is denied by ${labels.join(", ")}.`
        : "A capability grant denies this browser request.";
    case "capability_unmatched":
      return "No capability grant matched this browser request.";
    case "principal_or_constraints_unmatched":
      return "The action matched a capability, but its principal or constraints did not.";
    case "invalid_or_ambiguous_json":
      return "The request body could not be interpreted unambiguously, so policy failed closed.";
    case "write_blocked":
      return "The profile is read-only and this request was not classified as a read.";
    case "bad_url":
      return "The request URL could not be evaluated safely.";
    case "capability_evaluation_failed":
      return "Capability evaluation failed, so the request was denied.";
    default:
      return /^rule_\d+_deny$/.test(String(decision?.reason || ""))
        ? "An explicit access deny rule matched this browser request."
        : "The browser access policy denied this request.";
  }
}

// Produce the only denial shape that may cross the session socket back to the
// agent. It deliberately excludes the URL query, request/response headers,
// body, preview, envelope, nonce, action digest, and evaluator error text. A
// URL's userinfo is also absent because URL.origin never contains it.
export function safePolicyFeedback(rec, decision, method, rawUrl) {
  let origin = null;
  let pathname = null;
  try {
    const url = new URL(rawUrl);
    if (url.protocol === "http:" || url.protocol === "https:") {
      origin = url.origin.slice(0, 240);
      pathname = url.pathname.slice(0, 240);
    }
  } catch {
    // bad_url is still useful feedback without reflecting attacker input.
  }

  const grants = (Array.isArray(decision?.grants) ? decision.grants : [])
    .slice(0, 16)
    .map((grant) => ({
      id: safePolicyString(grant?.id) || "(unnamed)",
      capability: safePolicyString(grant?.capability) || "(unknown)",
      ...(safePolicyString(grant?.label) ? { label: safePolicyString(grant.label) } : {}),
    }));
  const capabilities = [
    ...new Set(
      (Array.isArray(decision?.capabilities)
        ? decision.capabilities
        : decision?.capability
          ? [decision.capability]
          : grants.map((grant) => grant.capability)
      )
        .map((capability) => safePolicyString(capability))
        .filter(Boolean),
    ),
  ].slice(0, 16);
  const verdict = decision?.verdict === "ask" ? "ask" : "deny";
  const reason = safePolicyString(decision?.reason) || "policy_denied";
  const capabilityPolicy = rec?.capabilityPolicy;
  const policy = capabilityPolicy
    ? {
        kind: "capability",
        version: Number(capabilityPolicy.version),
        epoch: Number(decision?.policyEpoch ?? capabilityPolicy.epoch),
        hash: safePolicyString(decision?.policyHash, 96),
      }
    : {
        kind: "access",
        access: effectiveAccess(rec),
      };

  return {
    code: verdict === "ask" ? "BROWSER_APPROVAL_REQUIRED" : "BROWSER_POLICY_DENIED",
    verdict,
    reason,
    explanation: denialExplanation(decision, grants),
    capability: capabilities.length === 1 ? capabilities[0] : null,
    capabilities,
    grants,
    request: {
      method: String(method || "GET").toUpperCase().slice(0, 24),
      origin,
      path: pathname,
    },
    policy,
  };
}

// Install the network gate on a (patchright) BrowserContext. No-op unless the
// record is read-only or carries rules. Returns true when a guard is active.
export async function applyAccessGuard(
  ctx,
  rec,
  { log = () => {}, principal = null, onAsk = null, onBlocked = null } = {},
) {
  const restricted = isAccessRestricted(rec);
  if (!restricted) return false;

  // WebSocket frames bypass HTTP route interception, so a restricted session
  // must deny the channel or a page could drive a write over it. Block it at
  // the NETWORK layer (routeWebSocket, CDP-level) — evasion-proof, unlike a JS
  // shadow of window.WebSocket which a Web/Shared Worker (self.WebSocket) or a
  // fresh realm can recover. Feature-detected for older patchright; the
  // main-world override stays as defense-in-depth / fallback. Sites degrade to
  // HTTP polling, which the route gate does inspect.
  if (typeof ctx.routeWebSocket !== "function") {
    throw new Error("restricted browser sessions require network-level WebSocket routing");
  }
  await ctx.routeWebSocket("**/*", (ws) => {
    // Neither connectToServer() nor onMessage handlers are attached, so the
    // upstream socket is never opened; close the client side immediately.
    try {
      ws.close();
    } catch {
      /* route already resolved */
    }
  });
  await ctx.addInitScript(() => {
    // Defense in depth (covers any engine/version where routeWebSocket is
    // absent). Shadow the constructor in the main world AND, best-effort, in
    // Workers via a patched Worker that prepends the same shadow.
    try {
      Object.defineProperty(window, "WebSocket", {
        value: undefined,
        writable: false,
        configurable: false,
      });
    } catch {
      /* already locked down */
    }
    // HTTP routing cannot classify peer-to-peer/WebTransport frames. Dedicated
    // workers could also recover constructors from a fresh realm, so restricted
    // profiles trade compatibility for a closed set of inspected transports.
    for (const name of [
      "WebTransport",
      "RTCPeerConnection",
      "webkitRTCPeerConnection",
      "Worker",
      "SharedWorker",
    ]) {
      try {
        Object.defineProperty(window, name, {
          value: undefined,
          writable: false,
          configurable: false,
        });
      } catch {
        /* already locked down */
      }
    }
  });

  await ctx.route("**/*", async (route) => {
    const request = route.request();
    const decision = guardDecision(rec, {
      method: request.method(),
      url: request.url(),
      postData:
        typeof request.postDataBuffer === "function"
          ? request.postDataBuffer()
          : request.postData(),
      headers: typeof request.headers === "function" ? request.headers() : {},
      principal,
    });
    if (decision.allowed) {
      await route.continue();
      return;
    }
    if (decision.verdict === "ask" && exactImmediateApproval(decision, onAsk)) {
      log(
        `access-guard: immediately approved ${safeRequestLabel(request.method(), request.url())} ` +
          `(${decision.actionDigest})`,
      );
      await route.continue();
      return;
    }
    log(
      `access-guard: blocked ${safeRequestLabel(request.method(), request.url())} (${decision.reason})`,
    );
    await route.abort("accessdenied");
    if (typeof onBlocked === "function") {
      // Feedback is best-effort and must never weaken enforcement. Give the
      // session correlator the opaque browser Request separately; only the
      // sanitized first argument is eligible for the agent-facing response.
      try {
        onBlocked(
          safePolicyFeedback(rec, decision, request.method(), request.url()),
          request,
        );
      } catch {
        /* reporting failure cannot resurrect an aborted request */
      }
    }
  });

  // addInitScript affects future document realms only. Persistent Chrome can
  // restore a tab and run its page script while the context is still offline;
  // that old realm could retain WebTransport/WebRTC/Worker constructors and
  // use them after networking is enabled. Destroy every pre-guard page realm
  // before going online. Callers create a fresh about:blank page afterwards,
  // which receives the init script before any page code executes.
  if (typeof ctx.pages !== "function") {
    throw new Error("restricted browser sessions require page-realm enumeration");
  }
  for (const page of ctx.pages()) {
    if (typeof page.close !== "function") {
      throw new Error("restricted browser sessions require closeable restored pages");
    }
    await page.close();
  }
  if (typeof ctx.newPage !== "function") {
    throw new Error("restricted browser sessions require guarded page creation");
  }
  const guardedPage = await ctx.newPage();
  // The initial about:blank realm created by newPage may predate init-script
  // evaluation. A local data-document navigation creates a new document where
  // the script runs before any page code, still while the context is offline.
  // (Chromium can optimize a same-URL about:blank navigation without creating
  // the new realm we require.)
  const guardProbe = `<script>
    document.title = [
      "WebSocket", "WebTransport", "RTCPeerConnection",
      "webkitRTCPeerConnection", "Worker", "SharedWorker"
    ].every((name) => typeof globalThis[name] === "undefined")
      ? "agent-id-transports-blocked"
      : "agent-id-transport-guard-failed";
  </script>`;
  await guardedPage.goto(`data:text/html,${encodeURIComponent(guardProbe)}`);
  // patchright evaluates automation expressions in an isolated world; title is
  // deliberately set by main-world page code so this verifies the realm that
  // untrusted site JavaScript will actually inhabit.
  const transportsBlocked =
    (await guardedPage.title()) === "agent-id-transports-blocked";
  if (!transportsBlocked) {
    throw new Error("restricted browser transport guards did not initialize");
  }
  if (typeof ctx.setOffline !== "function") {
    throw new Error("restricted browser sessions require offline-first guard installation");
  }
  await ctx.setOffline(false);
  return true;
}
