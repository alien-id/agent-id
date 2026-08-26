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
