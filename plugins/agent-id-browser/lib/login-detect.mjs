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
//   "qr-sign-in"   — the sign-in completes by scanning a QR code rendered on THIS
//                    page with the service's phone app. Nothing to type, and the
//                    owner cannot see the code unless the browser view is opened.
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
// "code" is matched only with a qualifier attached, as something that was SENT to
// you, or in the fixed phrase "enter the code" — never bare, which would fire on
// the promo/postal/coupon copy that ordinary signed-in pages are full of.
//
// `access` is deliberately NOT a qualifier: "meeting access code", "access code at
// checkout" are ordinary copy, and the sign-in sense of it is already covered by
// the "sent to you" clauses below.
const CODE_WORD =
  "(?:verification|security|confirmation|login|sign[- ]?in|one[- ]?time|authentication|auth|otp|passcode|(?:\\d|four|five|six|seven|eight)[- ]?digit)";
const OTP_BODY_RE = new RegExp(
  [
    `${CODE_WORD}[- ]?code`,
    "one[- ]?time (?:code|password|passcode)",
    // A code described by where it came from — no promo/postal copy says this.
    "code (?:we |that we )?(?:just )?(?:sent|e-?mailed|texted)",
    `(?:sent|e-?mailed|texted) (?:you )?an? (?:${CODE_WORD}[- ]?)?code`,
    `check your (?:e-?mail|inbox|phone) for (?:a|the|your) (?:${CODE_WORD}[- ]?)?code`,
    // Precise on its own: "enter your promo code" does not contain it. It was
    // dropped once on the opposite (and wrong) assumption, which cost the
    // unqualified code screens Notion and friends render.
    "enter the code\\b",
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
// Every alternative ties the link to signing in. A bare "sent you a link" is
// ordinary chatter on a signed-in page ("Alice sent you a link"), and so is
// "open the link in a new tab" — matching either turns a successful login into a
// handover, which is worse than the false success this outcome exists to prevent.
const MAGIC_LINK_RE =
  /((?:magic|login|sign[- ]?in|confirmation) link|link to (?:log|sign) ?in\b|(?:click|open) the (?:magic |login |sign[- ]?in )?link (?:in|we) [^.]{0,30}\b(?:e-?mail|inbox|message)\b)/i;

// Body copy for a sign-in whose credential is a QR code on THIS screen, scanned
// with the service's phone app (Telegram Web, WhatsApp Web, Discord). Like a magic
// link there is nothing to type — but unlike it, the thing the owner needs is
// rendered here, in a browser they cannot see unless the viewport is opened for
// them. Found by running the classifier against telegram.org's real markup, where
// a screen with NO input of any kind read as a finished login.
//
// Every alternative ties the code to signing in, on word boundaries: without them
// "signin" is found inside "designing" and "assigning", so a storefront page about
// QR codes classified as a sign-in screen.
//
// "…to sign in ON ANOTHER DEVICE" is excluded: that is the linked-devices panel of
// an account you are ALREADY signed into (WhatsApp, Telegram settings), where the
// QR signs in somewhere else. Same words, opposite meaning.
const QR_SIGN_IN_RE =
  /(\b(?:log|sign) ?in\b[^\n]{0,40}\bqr\b|\bqr\b[^\n]{0,40}\bto (?:log|sign) ?in\b(?! on (?:another|your|other|a second)\b)|\bscan (?:to|and) (?:log|sign) ?in\b|point your phone at this screen)/i;

// Body copy for a challenge the owner answers on ANOTHER device: a push prompt
// ("tap Yes on your phone"), a number match ("tap 42"), or an app notification.
// Distinct from OTP because nothing is ever typed on this page — the sign-in
// completes by itself once the owner approves, so the caller must WAIT rather
// than hunt for a code that does not exist. Several of these phrases also live
// in OTP_BODY_RE, which is why the classifier checks this first and only when
// there is no code input on the page (an SMS step shows both).
const CONFIRM_BODY_RE =
  /(check your phone|tap (?:yes|\d{1,3})\b|approve (?:this |the )?sign[- ]?in|sent a (?:notification|prompt) to|open the .{0,24}app on your|confirm (?:it.?s|its) you on your|2-step verification.*(?:notification|prompt))/i;

// Body / inline text that signals the credentials were rejected. English plus
// Russian: a datacenter-hosted browser gets the page in the site's language,
// and a rejection it cannot read degrades to `unknown` → `timeout` →
// `owner_must_drive`, which sends the owner to a browser for what is really a
// wrong password (seen on lk.eneva.ru: «Пользователь не найден или неверный
// пароль»). Keep each phrase specific to a failed sign-in.
const ERROR_RE =
  /(incorrect|invalid|wrong password|that password|couldn.?t (?:sign|log) ?you in|try again|doesn.?t match|not recognized|too many attempts|account.*lock|неверн[а-яё]*\s+(?:логин|парол|имя|номер|данные|код)|неправильн[а-яё]*\s+(?:логин|парол|имя|номер|данные)|пользователь не найден|не найден или неверн|ошибка (?:входа|авторизации|аутентификации)|попробуйте (?:ещё|еще) раз|слишком много попыток|учетн[а-яё]* запись заблокирована)/i;

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
 *   hasIdentifierField — a visible e-mail / username / phone input is still present
 *   onLoginPage        — the browser is still sitting on the credential's sign-in
 *                        page (the caller's `stillOnLoginPage`). Only there does an
 *                        identifier field mean "the sign-in has not started"
 *   hasOtpField        — a strong one-time-code input is present
 *                        (e.g. autocomplete="one-time-code")
 *   otpFieldNames      — candidate field name/id/placeholder strings to test against
 *                        the OTP token regex
 *   bodyText           — visible page text
 *   errorText          — optional focused error text (role=alert etc.)
 *
 * Returns "blocked" | "confirm-on-device" | "magic-link" | "qr-sign-in"
 *       | "otp-required" | "failed" | "logged-in" | "unknown".
 */
export function classifyLogin({
  hasPasswordField = false,
  hasIdentifierField = false,
  onLoginPage = false,
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
  // Both of these mean "there is nothing on this page to type", so they must yield
  // to any sign that a code is on offer — not merely to a strong code INPUT. A
  // six-box code screen whose fields carry no autocomplete hint sets `codeInput`
  // false, and those are exactly the screens this feature exists for: guarding on
  // the input alone sent them to a handover instead of raising the code card.
  const magicLinkAffordance = !otpAffordance && MAGIC_LINK_RE.test(bodyText);
  const qrAffordance = !otpAffordance && QR_SIGN_IN_RE.test(bodyText);
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
  // A QR sign-in, for the same reason and in the same place: a page whose only
  // affordance is a code to scan has no form left, so it is otherwise
  // indistinguishable from being signed in.
  if (qrAffordance) return "qr-sign-in";
  // An OTP affordance is the strongest signal the password step succeeded and a
  // second factor is now being requested — check it next.
  if (otpAffordance) return "otp-required";
  // No second factor, but a credential error → the password was rejected.
  if (hasError) return "failed";
  // An identifier prompt with no password beside it is a sign-in that has not
  // started, not one that finished: the e-mail-first step of a passwordless flow,
  // or the first screen of a two-step IdP.
  //
  // Only while we are still ON the sign-in page, though. `input[type=email]` is
  // also the newsletter box in the footer of an enormous number of ordinary
  // signed-in pages, and without this qualifier every one of them classified as
  // "the sign-in has not started" — turning a login that had actually succeeded,
  // password ones included, into a ten-round wait and a `timeout`.
  if (onLoginPage && hasIdentifierField && !hasPasswordField) return "unknown";
  // No password field left and nothing gated → we're through.
  if (!hasPasswordField) return "logged-in";
  // Password field still present, no error, no OTP → indeterminate.
  return "unknown";
}

// ─── Where the code went ──────────────────────────────────────────────────────
// The card asking for a code has to say where to look for it. Airbnb texted one
// to a phone while the card said only "airbnb.com sent you a code"; the owner
// watched a mail inbox and concluded nothing had arrived.
//
// The page has already said it — "We sent a code to +1 ••• ••• 4817" — so this
// reads that back instead of guessing. And it reads it back ONLY when the
// captured text is recognisably a destination: naming the wrong channel is worse
// than naming none, because it sends the owner somewhere the code is not and
// then convinces them it never came. Anything unrecognised fails closed to null,
// and the card falls back to wording that claims no channel at all.
// The capture ends at a clause boundary. A dash is one of them: "sent a code to
// d••@gmail.com — enter it below" otherwise runs the address together with the
// sentence after it and the whole destination is lost.
const SENT_TO_RE =
  /\b(?:sent|texted|e-?mailed|messaged)\b[^.\n]{0,40}?\bto\s+(.{2,38}?)(?=[,;!?\n—–]|\.(?:\s|$)|\s{2,}|$)/i;
const EMAIL_DESTINATION_RE = /^[\w.+•·*…-]{1,32}@[\w.•·*…-]{2,32}$/;
// The captured text is written by the page and ends up in a card the owner trusts.
// The loopback form escapes it, but the hosted prompt hands `description` on as it
// is, so nothing that could be read as markup gets that far: a destination is an
// address, a number or a named place, and none of those contain these.
const MARKUP_RE = /[<>&"'\\]/;
// Digits as a site masks them: bullets, stars, dots, dashes, parens, a leading +.
const PHONE_DESTINATION_RE = /^[+()\d\s.*\u00b7\u2022\u2026-]{4,26}$/;
const NAMED_DESTINATION_RE =
  /^your\s+(?:e-?mail(?:\s+address)?|phone(?:\s+number)?|mobile|messages|device)(?:\s+ending\s+(?:in|with)\s+[\d\u2022\u00b7*.\u2026-]{2,8})?$/i;
// The other half of how sites word it, and the half the `sent … to` shape cannot
// reach: "We texted your phone ending in 4817" names the destination with no `to`
// at all, and "sent to the number ending 4817" puts a word in front that stops it
// looking like a phone. Read second, so an address the page states outright still
// wins.
const ENDING_RE =
  /\b(?:(your|the)\s+)?(phone(?:\s+number)?|number|mobile|e-?mail(?:\s+address)?)\s+ending\s+(?:in\s+|with\s+)?([\d\u2022\u00b7*.\u2026-]{2,8})/i;

// How many characters the code has, when the page says so in words. The same
// vocabulary the OTP classifier matches on, read for its number this time.
//
// Only 4-8 is answered. Outside that a "code" is something else — an order
// reference, a discount, a year — and a wrong count is not a smaller version of
// no count: the card draws exactly that many cells and submits itself when they
// fill, so four cells for a six-digit code cannot be completed at all.
const SPELLED_DIGITS = { four: 4, five: 5, six: 6, seven: 7, eight: 8 };
const CODE_LENGTH_RE = /\b(\d|four|five|six|seven|eight)[- ]?digit\b/i;

export function codeLengthFromText(bodyText) {
  const match = CODE_LENGTH_RE.exec(String(bodyText || ""));
  if (!match) return null;

  const word = match[1].toLowerCase();
  const length = SPELLED_DIGITS[word] ?? Number(word);

  return length >= 4 && length <= 8 ? length : null;
}

export function codeDestination(bodyText) {
  const text = String(bodyText || "");
  const match = SENT_TO_RE.exec(text);
  const target = match ? match[1].trim().replace(/\s+/g, " ") : null;

  if (target && !MARKUP_RE.test(target)) {
    const recognised =
      EMAIL_DESTINATION_RE.test(target) ||
      PHONE_DESTINATION_RE.test(target) ||
      NAMED_DESTINATION_RE.test(target);

    if (recognised) return target;
  }

  const ending = ENDING_RE.exec(text);
  if (!ending) return null;

  const [, article, kind, tail] = ending;

  return `${(article || "your").toLowerCase()} ${kind.toLowerCase()} ending in ${tail}`;
}

export { OTP_FIELD_RE, OTP_BODY_RE, CONFIRM_BODY_RE, MAGIC_LINK_RE, QR_SIGN_IN_RE, ERROR_RE, BLOCK_RE };
