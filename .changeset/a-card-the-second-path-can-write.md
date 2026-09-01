---
"@alien-id/agent-id-browser": minor
"@alien-id/agent-id-vault": minor
"@alien-id/agent-id-core": minor
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
raise the card, and write the corrected mode back once the owner has supplied a
code. Not before: `otp-required` is also what a signed-in page inviting the owner
to switch on two-factor authentication classifies as, and correcting a record
from that would overwrite an explicit `--otp none` off a page that asked for
nothing.

**`fill-otp` passes the same hints auto-login does.** It called `resolveOtp` with
nothing at all, so a card raised that way carried neither the cell count nor
where the code went — which is why the code screen kept drawing a plain field.
The DOM read behind both is now one exported function.

**A row of code boxes is counted even when it says nothing.** Booking.com renders
six inputs and constrains them in script, with no `maxlength` anywhere; only
boxes that declared it were counted, so the site this was built for got no count
at all. A box now qualifies by taking a code — `one-time-code`, a numeric keypad,
or a declared single character — and the row it belongs to has to look like one:
siblings under a container of their own, nothing else in it, uniform shape, and
either a declared single character or the page's own word that a code was sent.
Four numeric inputs is a payment form, and a card drawn with four cells for it
submits on the fourth character with no button to recover.

**A code spread across a row is typed per box and checked per box.** Counting
characters could not tell six boxes holding one each from one box holding all
six, and the whole row is cleared first so a refused code leaves nothing behind
to splice into the next one.

**`set-otp` exists.** `set-totp`, `set-recipe`, `set-domains` and `set-access`
could all fix a stored credential; how it answers a code could not. Re-adding was
no answer: `vault add` on an existing name is a silent upsert that rebuilds the
record from that one invocation, so it would have taken the TOTP seed, the recipe
and the login URL with it — and asked the owner to retype the secret on the way.
A targeted edit is the whole point.

**A silent `otp` now means `interactive`, not `none`.** Sites add second factors
far more often than they drop them, and the two mistakes do not cost the same: a
card can be dismissed, an abandoned sign-in leaves a password typed and a code
already sent. This holds wherever the field is read, not only where it is
written — `add`, validation and `vault list` each used to resolve silence for
themselves, so a credential the sign-in would raise a card for was reported to
the agent as having no codes. One consequence worth stating: a stored
`passwordless` login that never carried an `otp` field now validates, where it
was previously refused for having neither a password nor a code step.

**A dismissed card is told from a broken one, on both paths.** Closing the card
answers 409, which arrived as a bare `HTTP 409` — a fault, and the sensible reply
to a fault is a retry, so the owner who had just dismissed it got it straight
back. The dismissal now carries its own code and becomes the `otp-declined`
outcome. That code is set in `agent-id-core`, which is why it is released here:
without the bump the browser plugin would resolve a published core that never
sets it, and the retry loop would be exactly as open as before. The hosted
provider's timeout gained its code for the same reason — `otp-timeout` was
unreachable whenever the card came from it.

**And the read-back guard covers the whole row.** A code spread across six boxes
was tagged on one of them, leaving five characters readable through
`get --what value` one at a time. Every box the code is written into is tagged
now, and tagged before the code goes in.
