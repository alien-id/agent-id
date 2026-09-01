// Alien Agent ID — Session / logout detection.
//
// A universal heuristic: when a navigation or authenticated request ends up on a
// known identity-provider host (or the body reads like a sign-in page), the
// stored session is almost certainly logged out and the caller should re-run the
// headed `login` bootstrap. This is intentionally conservative — it keys mainly
// on being *redirected to an auth host*, the strongest signal — to avoid
// false-flagging a site's own legitimately-reached pages.

const AUTH_HOST_RE =
  /(^|\.)(accounts\.google\.com|login\.microsoftonline\.com|login\.live\.com|login\.yahoo\.com|appleid\.apple\.com|github\.com\/login|okta\.com|auth0\.com)/i;

const LOGIN_BODY_RE =
  /(couldn.?t sign you in|sign in to continue|your session has expired|please (sign|log) ?in|enter your password)/i;

export function looksLoggedOut({ finalUrl = "", bodyText = "", httpStatus = null } = {}) {
  if (httpStatus === 401 || httpStatus === 403) return true;
  if (finalUrl) {
    try {
      const u = new URL(finalUrl);
      if (AUTH_HOST_RE.test(u.hostname)) return true;
    } catch {
      /* not a parseable URL — fall through to body check */
    }
  }
  if (bodyText && LOGIN_BODY_RE.test(bodyText)) return true;
  return false;
}
