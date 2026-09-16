---
"@alien-id/agent-id-browser": patch
---

Read the status the login page answered with, instead of reading the error
document it returned.

A navigation resolves on a 404 as happily as on a 200, and auto-login discarded
what `goto` handed back — so a stored address that no longer reaches a sign-in
page was treated as a sign-in that would not go through. The run walked into
form detection on an error document, spent every round on it, re-navigated to
the same dead address, and ended by reporting whatever that document's copy
sounded like. On a page carrying "try again" that was a rejected credential.

The login page's status is now read from the navigation itself — `navStatus`
handles both page shapes — and a 4xx or 5xx ends the run immediately as
`login-url-dead`, before anything on the page is classified. An unknown status
condemns nothing.

The warm-up navigation is deliberately still not judged. It exists for sites
that wall a cold deep link and let it through once the origin has set a
clearance cookie, so the origin is allowed to answer badly; acting on its status
would break the case the warm-up was added for.

`login-url-dead` escalates as `fix_credential` / `login_url_unreachable` with
the credential `intact` — a wrong record with a right secret, which the three
actions previously had no reading for. The message says the values were never
offered to the site, tells the caller to find the real sign-in address by
looking rather than guessing a path, and points at `vault set-login-url`, which
corrects the one field without asking the owner for the secret again.
