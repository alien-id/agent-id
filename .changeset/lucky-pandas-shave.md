---
"@alien-id/agent-id-browser": minor
"@alien-id/agent-id-core": minor
---

auto-login waits for device-approval prompts instead of failing

A "tap Yes on your phone" challenge shares body copy with a 2FA step but has no
input — the sign-in completes when the owner approves on their own device. It was
classified `otp-required`, so auto-login went looking for a code that never
appears and stalled until the round budget ran out.

`classifyLogin` now returns `confirm-on-device` for a push prompt or number-match
challenge, checked before `otp-required` and only when the page has no code input
(an SMS step shows both). On that outcome auto-login raises a card through the
host and polls until the page advances, with its own budget rather than the
ordinary settle rounds.

Notices are a new one-way message on the existing secure-prompt socket
(`agent-id-core/lib/notice.mjs`): the host raises the named event and replies at
once. Event names are namespaced under `browser.` and the host enforces it, so a
child cannot forge identity or secure-input lifecycle events. Delivery is best
effort — with no host configured, `notifyHost` resolves `false` and the login is
unaffected.

Device approval is the cheapest challenge to satisfy: unlike a password or a TOTP
seed it needs no secret stored anywhere.

## a failed login says what to DO, not "try headed login"

Every auto-login failure ended with the same advice: sign in yourself with headed
`login`. On a host with no display that is a dead end — headed login refuses
without a GUI session and points back at auto-login. The two pointed at each
other, so the agent bounced between them, or asked the owner for a password that
an account created through "Sign in with Google" does not have.

Failures now carry a machine-readable `action` (`lib/escalation.mjs`), and there
are only three: `owner_must_drive` (a human has to work the page — bot challenge,
or an IdP that refuses automation), `owner_must_confirm` (the credential is fine;
an approval on another device never arrived), and `fix_credential` (the stored
values are wrong or incomplete). A device-approval timeout in particular no longer
tells the agent to re-check credentials that were never the problem.

## read/fetch no longer answer from a stale profile

`read` and `fetch` unsealed a *copy* of the sealed profile even when a session
was open. A live session's cookies only reach the vault on `close`, so the copy
was stale: reading a site the session was signed into returned `loggedOut` and a
redirect to the login page for a session that was working fine. Since that result
feeds `sessionExpired`, it could raise a "sign in again" prompt for a healthy
login — the worst kind of false alarm, because it teaches the owner to ignore the
real one.

Both now run as session actions when a session is open, falling back to the
one-shot only when there is none. A session started by an older build reports
`SESSION_TOO_OLD` naming the `close`/`open` cycle rather than falling back, since
falling back would reintroduce exactly the stale read.
