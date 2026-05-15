// Alien Agent ID — Typed error classes.
//
// These exist as named classes (not anonymous Error instances) so callers
// can distinguish security-relevant failures from incidental ones via
// instanceof. Use a structured error type whenever a caller might need to
// branch on the cause; bare Error is fine for fatal pre-condition checks.

/**
 * SubjectMismatchError marks a refresh-time security failure: the refreshed
 * token claims a different `sub` than the bound owner session. Callers use
 * `instanceof` to distinguish a security-relevant mismatch from incidental
 * parse errors on opaque tokens.
 */
export class SubjectMismatchError extends Error {
  constructor(message) {
    super(message);
    this.name = "SubjectMismatchError";
  }
}

/**
 * AuthRevokedError marks a token-endpoint failure where the AS has rejected
 * the supplied credential — HTTP 401, HTTP 403, or RFC 6749 §5.2
 * `invalid_grant`. Callers can catch this distinctly from network/parse
 * errors and prompt the user to re-authenticate.
 */
export class AuthRevokedError extends Error {
  constructor(message, { status, errorCode } = {}) {
    super(message);
    this.name = "AuthRevokedError";
    this.status = status ?? null;
    this.errorCode = errorCode ?? null;
  }
}
