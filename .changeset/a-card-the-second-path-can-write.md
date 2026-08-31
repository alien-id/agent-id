---
"@alien-id/agent-id-browser": minor
"@alien-id/agent-id-vault": minor
---

Raise the code card from either path, and let a wrong record be corrected.

A live sign-in on a phone found three ways this fell over, and they share a
shape: a decision made before anyone had seen the sign-in page, and no way back
once it turned out wrong.

**A credential that says the site has no codes now gets corrected instead of
ending the run.** `otp: "none"` is a claim about the site; the site asking for a
code is the evidence against it. Auto-login used to return `otp-unexpected` and
stop — password typed, code mailed, no card to type it into. Both paths that
reach a code (auto-login and a sign-in driven by hand through `fill-otp`) now
raise the card and write the corrected mode back.

**`fill-otp` passes the same hints auto-login does.** It called `resolveOtp` with
nothing at all, so a card raised that way carried neither the cell count nor
where the code went — which is why the code screen kept drawing a plain field.
The DOM read behind both is now one exported function.

**A row of code boxes is counted even when it says nothing.** Booking.com renders
six inputs and constrains them in script, with no `maxlength` anywhere; only
boxes that declared it were counted, so the site this was built for got no count
at all. A box now qualifies by taking a code — `one-time-code`, a numeric keypad,
or a declared single character.

**`set-otp` exists.** `set-totp`, `set-recipe`, `set-domains` and `set-access`
could all fix a stored credential; how it answers a code could not, and
`vault add` on an existing name refuses. There was no way to say "this site does
mail codes after all" without making the owner retype the secret.

**A silent `otp` now means `interactive`, not `none`.** Sites add second factors
far more often than they drop them, and the two mistakes do not cost the same: a
card can be dismissed, an abandoned sign-in leaves a password typed and a code
already sent.
