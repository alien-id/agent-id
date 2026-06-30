// Alien Agent ID — login-outcome classifier.
//
// After the sealed browser submits a login form, the page can be in one of a few
// states. `looksLoggedOut` (session.mjs) is too coarse here: right after the
// password step you are usually STILL on the auth host — entering a 2FA code —
// which it would read as "logged out" for both "OTP required" and "wrong
// password". This is a focused 3-way classifier over a snapshot of the page:
//
//   "otp-required" — a second-factor affordance is present (a one-time-code input,
//                    an OTP-ish field name, or body copy describing 2FA)
//   "failed"       — a credential error is shown and there is no OTP affordance
//   "logged-in"    — no password field remains and nothing looks gated
//   "unknown"      — indeterminate (page may not have advanced yet; caller waits)
//
// Pure + dependency-free so it unit-tests without a browser. The browser side
// (auto-login.mjs) gathers the snapshot via page.evaluate and calls this.

// Field name/id/placeholder tokens that denote a one-time / 2FA code input.
// Deliberately specific — a bare "code" matches postal_code / promo_code, so it
// is excluded; the strong `autocomplete="one-time-code"` signal arrives via
// `hasOtpField` instead.
const OTP_FIELD_RE =
  /(otp|otc|totp|\bmfa\b|2fa|two[-_ ]?factor|one[-_ ]?time|verif(?:y|ication)|authenticator|auth[-_ ]?code|security[-_ ]?code|sms[-_ ]?code)/i;

// Body copy that describes a 2FA / verification step.
const OTP_BODY_RE =
  /(verification code|one[- ]?time (?:code|password|passcode)|two[- ]?factor|2-step|authenticator app|enter the code|security code|\b6[- ]?digit\b|check your phone|approve.*sign)/i;

// Body / inline text that signals the credentials were rejected.
const ERROR_RE =
  /(incorrect|invalid|wrong password|that password|couldn.?t (?:sign|log) ?you in|try again|doesn.?t match|not recognized|too many attempts|account.*lock)/i;

/**
 * Classify a login attempt's current page state.
 *
 *   hasPasswordField — a visible password input is still present
 *   hasOtpField      — a strong one-time-code input is present
 *                      (e.g. autocomplete="one-time-code")
 *   otpFieldNames    — candidate field name/id/placeholder strings to test against
 *                      the OTP token regex
 *   bodyText         — visible page text
 *   errorText        — optional focused error text (role=alert etc.)
 *
 * Returns "otp-required" | "failed" | "logged-in" | "unknown".
 */
export function classifyLogin({
  hasPasswordField = false,
  hasOtpField = false,
  otpFieldNames = [],
  bodyText = "",
  errorText = null,
} = {}) {
  const otpAffordance =
    hasOtpField ||
    (Array.isArray(otpFieldNames) && otpFieldNames.some((n) => OTP_FIELD_RE.test(String(n || "")))) ||
    OTP_BODY_RE.test(bodyText);
  const hasError = ERROR_RE.test(String(errorText || "")) || ERROR_RE.test(bodyText);

  // An OTP affordance is the strongest signal the password step succeeded and a
  // second factor is now being requested — check it first.
  if (otpAffordance) return "otp-required";
  // No second factor, but a credential error → the password was rejected.
  if (hasError) return "failed";
  // No password field left and nothing gated → we're through.
  if (!hasPasswordField) return "logged-in";
  // Password field still present, no error, no OTP → indeterminate.
  return "unknown";
}

export { OTP_FIELD_RE, OTP_BODY_RE, ERROR_RE };
