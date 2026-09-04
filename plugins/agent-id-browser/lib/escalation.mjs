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
export function escalationFor(outcome, ctx = {}) {
  const escalation = escalationMessage(outcome, ctx);
  // Whether the stored values are in doubt, as a field a host can gate on
  // without reading the prose. Only a rejection by the site puts them in doubt;
  // every other way a sign-in ends leaves the credential exactly as typed, and
  // an agent that read "fix" as "delete" once cost the owner a card they had
  // just filled in.
  return { credential: outcome === "failed" ? "rejected" : "intact", ...escalation };
}

function escalationMessage(outcome, { credName = "", profile = "", pageError = null } = {}) {
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
          `The code for '${credName}' was not accepted, and a fresh one from the next time ` +
          "window was refused too. For a stored 2FA seed that points at the seed itself " +
          "(re-add it with `vault set-totp`) or at this machine's clock being out of step — " +
          "codes are time-derived, so a skew of more than one period makes every code wrong. " +
          "For an owner-entered code it was mistyped, or it expired while being fetched. " +
          "Either way the password is FINE: do not re-check it and do not ask for one. " +
          "Run auto-login again once the cause is addressed.",
      };
    // The owner pressed "use the browser instead". They are not refusing the
    // sign-in — they are asking to do it where they can see it, which is exactly
    // what the viewport is for. Anything else here (another card, a retry, a
    // question about the password) ignores what they just said.
    case "owner-will-drive":
      return {
        action: OWNER_MUST_DRIVE,
        reason: "owner_chose_the_browser",
        message:
          `The owner closed the secure card for '${credName}' and asked to sign in through the ` +
          `browser themselves. Open the browser view for profile '${profile}', parked on the ` +
          "sign-in page, and let them finish there — then continue. Do NOT raise another card, " +
          "do NOT ask for the password, and do NOT report the sign-in refused: they did not " +
          "refuse it, they took it over.",
      };
    // The owner closed the card. Nothing is broken and nothing timed out — they
    // were asked and declined, so the one thing that must not happen is the same
    // card going back up unbidden.
    case "otp-declined":
      return {
        action: OWNER_MUST_CONFIRM,
        reason: "otp_declined_by_owner",
        message:
          `The owner dismissed the code card for '${credName}' — they were asked and said no. ` +
          "The credential is FINE: do not re-add it, do not ask for a password, and do NOT run " +
          "auto-login again unless they ask for it. Say the sign-in was not completed and leave " +
          "it there.",
      };
    // The code card expired unanswered — the owner was away, not the sign-in
    // broken. The page is still sitting on the code screen, so the fix is a fresh
    // code, and nothing about the credential is in doubt.
    case "otp-timeout":
      return {
        action: OWNER_MUST_CONFIRM,
        reason: "otp_not_entered",
        message:
          `Nobody entered the sign-in code for '${credName}' before the secure card expired. ` +
          "The credential is FINE — do not re-add it, do not ask for a password, and do not " +
          "assume the site refused anything. The code that was mailed has probably expired too, " +
          "so ask the owner to be ready, then run auto-login again to have a fresh one sent.",
      };
    // A code was demanded that the credential says it does not have. This is also
    // where a passwordless site lands when it was stored as an ordinary login, so
    // the message has to name that possibility: the agent is here precisely
    // because its first guess about the site was wrong, and this is the only
    // sentence it gets to correct it from.
    case "otp-unexpected":
      return {
        action: FIX_CREDENTIAL,
        reason: "otp_required_but_not_configured",
        message:
          `The site asked '${credName}' for a one-time code, but the credential is set to ` +
          "`otp: none`. If the sign-in page has NO password field — it takes an e-mail or " +
          "phone number and sends a code — the credential is the wrong shape: re-add it with " +
          '`passwordless: true` and `otp: "interactive"`, passing `overwrite: true` (without ' +
          "that the call returns the stored entry and nothing changes). If the site does have " +
          "a password and this code is a second factor, keep the credential and set " +
          '`otp: "interactive"` so the owner can be asked, or attach a seed with ' +
          "`vault set-totp`. Do not retry as-is; it will ask again.",
      };
    case "failed":
      return {
        action: FIX_CREDENTIAL,
        reason: "credentials_rejected",
        message:
          `The site rejected the stored credentials for '${credName}'. Tell the owner, and ` +
          "re-store them with `vault_add` and `overwrite: true` only if they confirm the values " +
          "changed — that call raises the card again and replaces the record in place. Never " +
          "remove the credential to retry, and do not retry the same values.",
      };
    // The run stopped on its own fault — a recipe step that never found its
    // element, a browser that went away — before the site said anything about the
    // credential. Nothing about the stored values is in doubt.
    case "error":
      return {
        action: OWNER_MUST_DRIVE,
        reason: "auto_login_crashed",
        message:
          `Auto-login for '${credName}' stopped before it could finish` +
          `${pageError ? ` (${pageError})` : ""}. The stored credential was not rejected — ` +
          "leave it in the vault and do NOT remove it. Ask the owner to sign in once in the " +
          `browser view for profile '${profile}'. If the message names a recipe step, the ` +
          "recipe is wrong: clear the stored recipe before the next auto-login.",
      };
    // The sign-in reached a host the credential was never scoped to — a redirect
    // through an identity provider, a recipe step pointing off-site. The secret
    // was withheld, so nothing about it is in doubt, and no human at the page
    // changes what the allowlist says: the allowlist has to.
    case "domain-not-allowed":
      return {
        action: FIX_CREDENTIAL,
        reason: "host_not_in_domains",
        message:
          `The sign-in for '${credName}' reached a host outside the credential's domains` +
          `${pageError ? ` (${pageError})` : ""}, so the secret was withheld. Add that host to ` +
          "the credential's `domains` (wildcards like *.example.com are allowed) and run " +
          "auto-login again. The stored values are fine — never remove the credential for this.",
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
          "credential is wrong (tell the owner; re-store with `vault_add` and `overwrite: true` " +
          "only if they confirm), not that a human is needed. Otherwise ask the owner to sign " +
          `in once in the browser view for profile '${profile}'; the session then seals and ` +
          "later visits are headless. Either way the credential stays in the vault — never " +
          "remove it because a sign-in did not complete.",
      };
  }
}
