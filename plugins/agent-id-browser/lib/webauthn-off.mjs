// Alien Agent ID — WebAuthn off-switch for driven browser sessions (#99).
//
// The driven browser has no platform authenticator and no CTAP transport
// (headless Chrome, in the hosted case inside a container), so a passkey
// ceremony a site starts can never complete: navigator.credentials.get() hangs,
// and while it is pending the page's own fallback affordances ("Try another
// way") are inert — a sign-in against an account with a passkey enrolled
// (Google is the everyday case) dead-ends. Holding real passkeys via a virtual
// authenticator is a separate track (#99's proposal); until then the browser
// declares itself passkey-INCAPABLE — the exact surface of a legacy browser,
// which every passkey site already handles with a password/OTP path:
//
//   1. `delete window.PublicKeyCredential` before any page script runs. Sites
//      feature-detect it (and its statics — isUserVerifyingPlatformAuthenticator-
//      Available, isConditionalMediationAvailable — go with it) before pushing
//      a ceremony or the conditional-UI autofill, so they offer the fallback
//      path up front and no prompt ever appears.
//   2. CredentialsContainer.get/create with a `publicKey` argument reject
//      immediately with NotAllowedError — the cancellation outcome every
//      WebAuthn call site handles — covering sites that skip feature
//      detection. Deleting the interface object alone would NOT stop the
//      ceremony: the get/create implementation behind it still runs. Other
//      credential types (password, federated) pass through untouched.
//
// This is a UX measure, not a security boundary: the page could restore the
// natives from a fresh realm, but a sign-in page has no motive to — sites
// treat "no WebAuthn" as the ordinary legacy-browser case.
//
// The headed `login` flow keeps WebAuthn native (launchContext
// nativeWebAuthn:true): the owner sits at a real Chrome window there, where a
// platform authenticator may genuinely exist and complete the ceremony.

// Escape hatch for a site where a passkey is the ONLY way in (rare today):
// AGENT_ID_BROWSER_KEEP_WEBAUTHN=1 keeps WebAuthn native in driven sessions
// too. The ceremony will then hang as before — send Escape to cancel it and
// recover the page's fallback links. Exported for tests.
export function webauthnKept(env = process.env) {
  return env.AGENT_ID_BROWSER_KEEP_WEBAUTHN === "1";
}

// Install the off-switch on a (patchright) BrowserContext. Returns true when
// installed, false when the env keeps WebAuthn native.
export async function suppressWebAuthn(ctx, env = process.env) {
  if (webauthnKept(env)) return false;
  await ctx.addInitScript(() => {
    try {
      delete window.PublicKeyCredential;
    } catch {
      /* locked down — the reject path below still prevents the hang */
    }
    const proto = window.CredentialsContainer && window.CredentialsContainer.prototype;
    if (!proto) return;
    for (const name of ["get", "create"]) {
      const native = proto[name];
      if (typeof native !== "function") continue;
      proto[name] = function (options) {
        if (options && typeof options === "object" && "publicKey" in options) {
          return Promise.reject(
            new DOMException(
              "The operation either timed out or was not allowed.",
              "NotAllowedError",
            ),
          );
        }
        return native.apply(this, arguments);
      };
    }
  });
  return true;
}
