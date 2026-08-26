// Alien Agent ID — login-outcome classifier.
//
// After the sealed browser submits a login form, the page can be in one of a few
// states. `looksLoggedOut` (session.mjs) is too coarse here: right after the
// password step you are usually STILL on the auth host — entering a 2FA code —
// which it would read as "logged out" for both "OTP required" and "wrong
// password". This is a focused classifier over a snapshot of the page:
//
//   "blocked"      — a bot-block / human-verification interstitial (a network
//                    -security wall, CAPTCHA, "unusual traffic"). The form is
//                    gone but we are NOT in — must not be mistaken for success.
//   "confirm-on-device" — the owner must approve on another device (a push
//                    prompt); nothing is typed here, so the caller waits
//   "magic-link"   — the sign-in completes by clicking a link in an e-mail. There
//                    is no code to ask for and the link lands in whatever browser
//                    the owner opens it in, not this profile — the caller cannot
//                    finish it and must hand the browser over.
//   "otp-required" — a one-time-code affordance is present (a one-time-code input,
//                    an OTP-ish field name, or body copy naming a code)
//   "failed"       — a credential error is shown and there is no OTP affordance
//   "logged-in"    — no password field remains and nothing looks gated
//   "unknown"      — indeterminate (page may not have advanced yet; caller waits)
//
// The "blocked" state is checked FIRST and exists because of a real false
// positive: a "blocked by network security" wall has no password field, no OTP
// affordance, and no credential-error copy, so it was classified "logged-in" —
// and the caller sealed an UNauthenticated session (no auth cookie) while
// reporting success. A block wall never clears by waiting, so the caller stops.
//
// Pure + dependency-free so it unit-tests without a browser. The browser side
// (auto-login.mjs) gathers the snapshot via page.evaluate and calls this.

// Field name/id/placeholder tokens that denote a one-time / 2FA code input.
// Deliberately specific — a bare "code" matches postal_code / promo_code, so it
// is excluded; the strong `autocomplete="one-time-code"` signal arrives via
// `hasOtpField` instead.
const OTP_FIELD_RE =
  /(otp|otc|totp|\bmfa\b|2fa|two[-_ ]?factor|one[-_ ]?time|verif(?:y|ication)|authenticator|auth[-_ ]?code|security[-_ ]?code|sms[-_ ]?code)/i;

// Body copy that describes a one-time-code step. Every alternative names the code
// explicitly — a bare "code" would match promo/postal copy on an ordinary page.
// The vocabulary is deliberately wide on the QUALIFIER because sites disagree on
// what to call the same thing: Slack spells the digit count out ("six-digit"),
// Notion says "login code", others say confirmation / access / one-time. Missing a
// qualifier here is not a cosmetic gap — with no `autocomplete="one-time-code"` on
// the field, this regex is the only thing standing between a code screen and a
// false "logged-in".
//
// "code" is only ever matched with a qualifier attached, or as something that was
// SENT to you. A bare "enter your … code" would fire on "enter your promo code" on
// an ordinary post-login page and stall a sign-in that had already finished.
const CODE_WORD =
  "(?:verification|security|confirmation|access|login|sign[- ]?in|one[- ]?time|authentication|auth|otp|passcode|(?:\\d|four|five|six|seven|eight)[- ]?digit)";
const OTP_BODY_RE = new RegExp(
  [
    `${CODE_WORD}[- ]?code`,
    "one[- ]?time (?:code|password|passcode)",
    // A code described by where it came from — no promo/postal copy says this.
    "code (?:we |that we )?(?:just )?(?:sent|e-?mailed|texted)",
    `(?:sent|e-?mailed|texted) (?:you )?an? (?:${CODE_WORD}[- ]?)?code`,
    `check your (?:e-?mail|inbox|phone) for (?:a|the|your) (?:${CODE_WORD}[- ]?)?code`,
    "two[- ]?factor",
    "2-step",
    "authenticator app",
    "\\b(?:\\d|four|five|six|seven|eight)[- ]digit\\b",
    "check your phone",
    "approve.*sign",
  ].join("|"),
  "i",
);

// Body copy for a sign-in that completes by clicking a link in an e-mail. Nothing
// is typed on this page and there is no code to ask for, so it must never be
// mistaken for either an OTP step or a finished login. The agent cannot finish it:
// the link lands in whatever browser the owner opens it in, not this sealed
// profile — so the honest outcome is to hand the browser over.
// Every alternative ties the link to signing in: a bare "sent you a link" is
// ordinary chatter on a signed-in page ("Alice sent you a link"), and matching it
// would turn a successful login into a handover.
const MAGIC_LINK_RE =
  /((?:magic|login|sign[- ]?in|confirmation) link|link to (?:log|sign) ?in|(?:click|open) the link (?:in|we) |check your (?:e-?mail|inbox)[^.]{0,40}link)/i;

// Body copy for a challenge the owner answers on ANOTHER device: a push prompt
// ("tap Yes on your phone"), a number match ("tap 42"), or an app notification.
// Distinct from OTP because nothing is ever typed on this page — the sign-in
// completes by itself once the owner approves, so the caller must WAIT rather
// than hunt for a code that does not exist. Several of these phrases also live
// in OTP_BODY_RE, which is why the classifier checks this first and only when
// there is no code input on the page (an SMS step shows both).
const CONFIRM_BODY_RE =
  /(check your phone|tap (?:yes|\d{1,3})\b|approve (?:this |the )?sign[- ]?in|sent a (?:notification|prompt) to|open the .{0,24}app on your|confirm (?:it.?s|its) you on your|2-step verification.*(?:notification|prompt))/i;

// Body / inline text that signals the credentials were rejected.
const ERROR_RE =
  /(incorrect|invalid|wrong password|that password|couldn.?t (?:sign|log) ?you in|try again|doesn.?t match|not recognized|too many attempts|account.*lock)/i;

// Bot-block / human-verification interstitial copy. DISTINCT from ERROR_RE: these
// describe an anti-automation wall (network-security block, CAPTCHA, rate limit),
// not a bad password, and no retyping or waiting clears them. Every phrase is
// high-precision — near-exclusive to a block/challenge page — because a false
// match aborts an otherwise-successful login. Deliberately NOT here: a bare
// "cloudflare" (legit footers say "secured by Cloudflare") — the CF challenge is
// caught by "checking your browser" / "verify you are human" instead. Matching
// login path SEGMENTS is done separately in auto-login.mjs.
const BLOCK_RE =
  /(blocked by network security|you.?ve been blocked|access to this page (?:has been |is )?denied|verify (?:you are|you.?re) (?:a )?human|are you a (?:human|robot)|checking your browser before|unusual (?:traffic|activity) (?:from|detected|on)|automated (?:queries|traffic|requests)|too many requests|suspicious (?:traffic|network) activity)/i;

/**
 * Classify a login attempt's current page state.
 *
 *   hasPasswordField   — a visible password input is still present
 *   hasIdentifierField — a visible e-mail / username input is still present
 *   hasOtpField        — a strong one-time-code input is present
 *                        (e.g. autocomplete="one-time-code")
 *   otpFieldNames      — candidate field name/id/placeholder strings to test against
 *                        the OTP token regex
 *   bodyText           — visible page text
 *   errorText          — optional focused error text (role=alert etc.)
 *
 * Returns "blocked" | "confirm-on-device" | "magic-link" | "otp-required"
 *       | "failed" | "logged-in" | "unknown".
 */
export function classifyLogin({
  hasPasswordField = false,
  hasIdentifierField = false,
  hasOtpField = false,
  otpFieldNames = [],
  bodyText = "",
  errorText = null,
  blocked = false,
} = {}) {
  const isBlocked =
    blocked === true || BLOCK_RE.test(bodyText) || BLOCK_RE.test(String(errorText || ""));
  const codeInput =
    hasOtpField ||
    (Array.isArray(otpFieldNames) && otpFieldNames.some((n) => OTP_FIELD_RE.test(String(n || ""))));
  const otpAffordance = codeInput || OTP_BODY_RE.test(bodyText);
  // Device approval only when there is nothing to type: an SMS step can show
  // "check your phone" AND a code field, and that one is an ordinary OTP.
  const confirmAffordance = !codeInput && CONFIRM_BODY_RE.test(bodyText);
  // Same "nothing to type here" guard as the device prompt: a page that offers a
  // code input AND mentions a link (Slack does both) is an ordinary OTP step.
  const magicLinkAffordance = !codeInput && MAGIC_LINK_RE.test(bodyText);
  const hasError = ERROR_RE.test(String(errorText || "")) || ERROR_RE.test(bodyText);

  // A bot-block / human-verification wall: the form is gone but we are NOT in.
  // Checked FIRST — otherwise the missing password field reads as success and an
  // unauthenticated session gets sealed (the bug this outcome was added for).
  if (isBlocked) return "blocked";
  // Device approval before OTP: both share body copy, but this one has no input,
  // so treating it as "otp-required" sends the caller looking for a code that
  // will never appear and the login stalls until it times out.
  if (confirmAffordance) return "confirm-on-device";
  // A mailed link, before the OTP check for the same reason: there is no code on
  // this page to hunt for, and before "logged-in" because "we sent you a link" on
  // a page with no form left is otherwise indistinguishable from being signed in
  // — which would seal an unauthenticated profile and report success.
  if (magicLinkAffordance) return "magic-link";
  // An OTP affordance is the strongest signal the password step succeeded and a
  // second factor is now being requested — check it next.
  if (otpAffordance) return "otp-required";
  // No second factor, but a credential error → the password was rejected.
  if (hasError) return "failed";
  // An identifier prompt with no password beside it is a sign-in that has not
  // started, not one that finished: the e-mail-first step of a passwordless flow,
  // or the first screen of a two-step IdP. Without this the absent password field
  // below reads as success and an unauthenticated session gets sealed — the same
  // "the form is gone but we are NOT in" mistake the "blocked" outcome exists for.
  if (hasIdentifierField && !hasPasswordField) return "unknown";
  // No password field left and nothing gated → we're through.
  if (!hasPasswordField) return "logged-in";
  // Password field still present, no error, no OTP → indeterminate.
  return "unknown";
}

export { OTP_FIELD_RE, OTP_BODY_RE, CONFIRM_BODY_RE, MAGIC_LINK_RE, ERROR_RE, BLOCK_RE };
