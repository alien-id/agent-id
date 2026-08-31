// Alien Agent ID — routing a read-style command to the live session.
//
// `read` / `fetch` exist both as session actions and as one-shot CLI commands.
// The one-shot unseals a COPY of the sealed profile, and a live session's
// cookies only reach the vault on `close` — so while a session is open the copy
// is stale, and reading a site the session is signed into reports `loggedOut`
// with a redirect to the login page. That feeds `sessionExpired`, so the stale
// copy could raise a "sign in again" card for a healthy session: the worst kind
// of false alarm, because it teaches the owner to ignore the real one.
//
// Kept in a pure module so it unit-tests without importing bin/cli.mjs (which
// runs the CLI on load), same as hints.mjs.

/**
 * Classify a reply from `callSession`.
 *
 * `callSession` RESOLVES with the session's reply, so an action-level failure
 * arrives as a value rather than a throw — spreading it into a success envelope
 * reports `ok:false` alongside `sessionExpired:false`, a failure dressed as a
 * clean read. Returns an Error to throw, or null when the reply is usable.
 */
export function sessionReplyError(result, { name, action } = {}) {
  if (!result || result.ok !== false) return null;
  const message = String(result.error || "session action failed");
  // A session started by an older build has no such action. The caller must NOT
  // fall back to the one-shot here: it would answer from the stale sealed copy,
  // which is the bug this routing exists to prevent.
  if (/unknown action/i.test(message)) {
    const error = new Error(
      `the open session '${name}' predates the '${action}' action — ` +
        `run \`close --name ${name}\` then \`open --name ${name}\` to pick it up`
    );
    error.code = "SESSION_TOO_OLD";
    return error;
  }
  return new Error(message);
}
