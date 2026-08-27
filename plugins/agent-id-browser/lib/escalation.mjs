// Alien Agent ID — what the agent should DO when a login does not complete.
//
// Every failed auto-login used to end with the same advice: "sign in yourself
// once with headed `login`". On a host with no display that is a dead end —
// headed login refuses without a GUI session and points back at auto-login, so
// the agent bounces between the two, or asks the owner for a password that does
// not exist (an account created through "Sign in with Google" has none).
//
// So an outcome maps to a machine-readable `action` instead of prose, and there
// are only three:
//
//   owner_must_drive   — no credential can fix this; a human has to work the
//                        page (bot challenge, an identity provider that refuses
//                        automation). The agent asks for the browser viewport.
//   owner_must_confirm — the credential is fine; the owner has to approve on
//                        another device and did not in time. Retrying is
//                        correct, once they are ready.
//   fix_credential     — the stored credential is wrong or incomplete. Neither
//                        a human at the browser nor a retry helps until it is
//                        corrected.
//
// Pure + dependency-free so it unit-tests without a browser.

export const OWNER_MUST_DRIVE = "owner_must_drive";
export const OWNER_MUST_CONFIRM = "owner_must_confirm";
export const FIX_CREDENTIAL = "fix_credential";

/**
 * Map an `autoLogin` outcome to the action the agent should take.
 *
 * Returns { action, reason, message }. `reason` is a stable slug for clients;
 * `message` is what the model reads, and says exactly one next step.
 */
export function escalationFor(outcome, { credName = "", profile = "" } = {}) {
  switch (outcome) {
    // The login handshake is exactly where anti-automation bites. No credential
    // clears it — only a human working the page.
    case "blocked":
      return {
        action: OWNER_MUST_DRIVE,
        reason: "bot_challenge",
        message:
          `Auto-login for '${credName}' hit an anti-automation wall (bot challenge / ` +
          "network-security block). No stored credential can clear this. Ask the owner to " +
          `finish the sign-in in the browser view for profile '${profile}', then continue.`,
      };
    // The owner never approved the push prompt. Their credentials are fine, so
    // re-checking them is wasted work and re-prompting for a password is wrong.
    case "confirm-timeout":
      return {
        action: OWNER_MUST_CONFIRM,
        reason: "device_approval_timeout",
        message:
          `Auto-login for '${credName}' reached the "approve on your phone" step, but no ` +
          "approval arrived in time. The stored credentials are FINE — do not re-check them " +
          "and do not ask for the password. Ask the owner to approve the prompt on their " +
          "device, then run auto-login again.",
      };
    // A mailed sign-in LINK, not a code. Nothing on the page can be typed, so
    // neither a stored secret nor a secure card helps — and the link authenticates
    // whichever browser the owner opens it in. In the browser view that is this
    // profile, which is the only place clicking it signs THIS session in.
    case "magic-link":
      return {
        action: OWNER_MUST_DRIVE,
        reason: "magic_link_sign_in",
        message:
          `'${credName}' signs in with a link e-mailed to the owner, not a code — there is ` +
          "nothing to type and no code to ask for. Do NOT raise a secure card and do NOT ask " +
          `for a password. Ask the owner to open the browser view for profile '${profile}' and ` +
          "click the link from their mail THERE: opening it anywhere else signs in that " +
          "browser instead of this one.",
      };
    // The credential is a QR code drawn on this page, scanned with the service's
    // phone app. Nothing to type, and the thing the owner needs is rendered inside
    // a browser they cannot see — so the viewport is not an escalation of last
    // resort here, it is the only way the sign-in can happen at all.
    case "qr-sign-in":
      return {
        action: OWNER_MUST_DRIVE,
        reason: "qr_code_sign_in",
        message:
          `'${credName}' signs in by scanning a QR code shown on the page — there is nothing ` +
          "to type, and no stored credential or secure card can help. Open the browser view " +
          `for profile '${profile}' so the owner can SEE the code, and ask them to scan it ` +
          "with the service's phone app. Some sites also offer a phone/e-mail option on the " +
          "same screen; if the owner prefers that, they can switch to it in the same view.",
      };
    // We answered the code challenge and the site asked again. Re-asking the owner
    // is both useless (the code was wrong or expired) and unaffordable (each ask is
    // ten minutes of a sixteen-minute budget), so the run stops and says why.
    case "otp-rejected":
      return {
        action: OWNER_MUST_CONFIRM,
        reason: "otp_not_accepted",
        message:
          `The code entered for '${credName}' was not accepted — mistyped, or it expired ` +
          "while it was being fetched. The stored credentials are FINE; do not re-check them " +
          "and do not ask for a password. Run auto-login again when the owner is ready: that " +
          "makes the site send a fresh code and starts a fresh window to enter it.",
      };
    // A second factor was demanded that the credential says it does not have.
    case "otp-unexpected":
      return {
        action: FIX_CREDENTIAL,
        reason: "otp_required_but_not_configured",
        message:
          `The site asked '${credName}' for a second factor, but the credential is set to ` +
          "`otp: none`. Update it with a TOTP seed (`vault set-totp`) or set `otp: interactive` " +
          "so the owner can be asked for the current code.",
      };
    case "failed":
      return {
        action: FIX_CREDENTIAL,
        reason: "credentials_rejected",
        message:
          `The site rejected the stored credentials for '${credName}'. Ask the owner to ` +
          "re-enter them (`vault_add` with overwrite) rather than retrying the same values.",
      };
    // Timed out or never resolved: could be a changed form, an unusual flow, or
    // an identity provider that refuses automation. A human at the page both
    // fixes it and reveals which it was.
    default:
      return {
        action: OWNER_MUST_DRIVE,
        reason: "login_did_not_complete",
        message:
          `Auto-login for '${credName}' did not complete (${outcome}). This is common for ` +
          "big-IdP sign-in (Google, Microsoft), which refuses automated credential entry. " +
          "Read `trace` and `pageError` first: a rejection message there means the stored " +
          "credential is wrong (fix it), not that a human is needed. Otherwise ask the owner " +
          `to sign in once in the browser view for profile '${profile}'; the session then ` +
          "seals and later visits are headless.",
      };
  }
}
