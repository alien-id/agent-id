// Alien Agent ID — Typed error classes.
//
// These exist as named classes (not anonymous Error instances) so callers
// can distinguish security-relevant failures from incidental ones via
// instanceof. Use a structured error type whenever a caller might need to
// branch on the cause; bare Error is fine for fatal pre-condition checks.

export function errorMessage(err) {
  return err instanceof Error ? err.message : String(err);
}

export class SubjectMismatchError extends Error {
  constructor(message) {
    super(message);
    this.name = "SubjectMismatchError";
  }
}

export class AuthRevokedError extends Error {
  constructor(message, { status, errorCode } = {}) {
    super(message);
    this.name = "AuthRevokedError";
    this.status = status ?? null;
    this.errorCode = errorCode ?? null;
  }
}

export class BundleFormatError extends Error {
  constructor(message) {
    super(message);
    this.name = "BundleFormatError";
    this.code = "bundle-format";
  }
}

export class BundleVerifyError extends Error {
  constructor(message, code = "bundle-verify") {
    super(message);
    this.name = "BundleVerifyError";
    this.code = code;
  }
}
