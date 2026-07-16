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

// Actions refused on a read-only session. Everything observational or
// DOM-interactive stays available; mutations die at the network gate.
// `upload` is denied too: feeding the owner's local files into a page is a
// write in spirit (and page JS could exfiltrate the content over allowed GETs).
const RO_DENIED_ACTIONS = Object.freeze(["eval", "fill-secret", "fill-otp", "upload", "form-fill"]);

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
// answer fetches without touching our route handler, so block them for ANY
// active guard (ro OR rule-restricted) — a deny rule is otherwise bypassable
// via a service-worker-replayed fetch.
export function contextOptionsForAccess(rec) {
  return isAccessRestricted(rec) ? { serviceWorkers: "block" } : {};
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
  const restricted = isAccessRestricted(rec);
  if (!restricted) return false;

  // WebSocket frames bypass HTTP route interception, so a restricted session
  // must deny the channel or a page could drive a write over it. Block it at
  // the NETWORK layer (routeWebSocket, CDP-level) — evasion-proof, unlike a JS
  // shadow of window.WebSocket which a Web/Shared Worker (self.WebSocket) or a
  // fresh realm can recover. Feature-detected for older patchright; the
  // main-world override stays as defense-in-depth / fallback. Sites degrade to
  // HTTP polling, which the route gate does inspect.
  if (typeof ctx.routeWebSocket === "function") {
    try {
      await ctx.routeWebSocket("**/*", (ws) => {
        // Neither connectToServer() nor onMessage handlers are attached, so the
        // upstream socket is never opened; close the client side immediately.
        try {
          ws.close();
        } catch {
          /* route already resolved */
        }
      });
    } catch {
      /* routeWebSocket unavailable/removed — the init-script fallback covers it */
    }
  }
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
  });

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
