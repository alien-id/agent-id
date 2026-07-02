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
//   - the un-auditable/secret-bearing actions (`eval`, `fill-secret`,
//     `fill-otp`) are refused at the action layer (assertActionAllowed).
//
// The DOM stays fully interactive (navigate/click/type/scroll) — typing a
// search query is a read — because the wire, not the widget, is the boundary.

import { effectiveAccess, evaluateAccess } from "@alien-id/agent-id-vault/lib/access.mjs";

// Actions refused on a read-only session. Everything observational or
// DOM-interactive stays available; mutations die at the network gate.
const RO_DENIED_ACTIONS = Object.freeze(["eval", "fill-secret", "fill-otp"]);

// Pure — unit-tests without a browser. Throws on a denied action.
export function assertActionAllowed(rec, action) {
  if (effectiveAccess(rec) !== "ro") return;
  if (RO_DENIED_ACTIONS.includes(action)) {
    throw new Error(
      `action '${action}' is not available on a read-only session — ` +
        "the owner can widen it with `agent-id-vault set-access`",
    );
  }
}

// Extra context options for a restricted profile: service workers would
// answer fetches without touching our route handler, so block them.
export function contextOptionsForAccess(rec) {
  return effectiveAccess(rec) === "ro" ? { serviceWorkers: "block" } : {};
}

// Decide one request. Exported for tests (no browser needed).
export function guardDecision(rec, { method, url, postData }) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return { allowed: false, reason: "bad_url" };
  }
  // Non-HTTP(S) schemes (data:, blob:, chrome-extension:) carry no credentialed
  // side effects upstream; let the browser handle them.
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return { allowed: true, reason: "non_http" };
  }
  return evaluateAccess(rec, {
    method,
    host: u.hostname,
    path: u.pathname,
    body: postData ?? null,
  });
}

// Install the network gate on a (patchright) BrowserContext. No-op unless the
// record is read-only or carries rules. Returns true when a guard is active.
export async function applyAccessGuard(ctx, rec, { log = () => {} } = {}) {
  const restricted = effectiveAccess(rec) === "ro" || Array.isArray(rec.accessRules);
  if (!restricted) return false;

  if (effectiveAccess(rec) === "ro") {
    // WebSocket frames bypass route interception — deny the channel up front;
    // sites degrade to HTTP polling, which the gate does inspect.
    await ctx.addInitScript(() => {
      try {
        Object.defineProperty(window, "WebSocket", {
          value: undefined,
          writable: false,
          configurable: false,
        });
      } catch {
        /* already locked down */
      }
    });
  }

  await ctx.route("**/*", async (route) => {
    const request = route.request();
    const decision = guardDecision(rec, {
      method: request.method(),
      url: request.url(),
      postData: request.postData(),
    });
    if (decision.allowed) {
      await route.continue();
      return;
    }
    log(
      `access-guard: blocked ${request.method()} ${request.url().slice(0, 200)} (${decision.reason})`,
    );
    await route.abort("accessdenied");
  });
  return true;
}
