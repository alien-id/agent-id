---
"@alien-id/agent-id-browser": minor
---

Driven sessions now report WebAuthn as unsupported (#99). The driven browser
has no authenticator, so a passkey ceremony could only hang — and while one is
pending, the page's own fallback links ("Try another way") are inert, so a
sign-in against a passkey-enrolled account dead-ended. An init script now
removes `window.PublicKeyCredential` before any page script runs (sites
feature-detect it and offer their password/OTP path up front, exactly as for a
legacy browser) and rejects any `publicKey` get/create issued anyway with an
immediate `NotAllowedError` — the cancellation outcome every WebAuthn call
site already handles. Non-publicKey credential calls pass through untouched.
Headed `login` keeps WebAuthn native (the owner's real Chrome may hold a
platform authenticator), and `AGENT_ID_BROWSER_KEEP_WEBAUTHN=1` restores
native WebAuthn in driven sessions for the rare passkey-only site.
