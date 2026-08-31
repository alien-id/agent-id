---
"@alien-id/agent-id-browser": minor
---

Ask for the code instead of failing, and say where it went.

A `login` credential marked `otp: "totp"` whose seed was never stored threw
`otp=totp but no totpSecret stored` and failed the whole sign-in — while the owner
sat there with the code already on their phone. There is no reason that has to be
a dead end: the card is the same channel a mailed code uses. It now raises one,
worded for an authenticator rather than a mailbox (nothing was sent anywhere, so
"check your email or messages" would be a wrong instruction, not a vague one), and
sized for a glance rather than a trip to the inbox. A credential that HAS its seed
still generates the code and asks nobody.

And the card stops sending people to the wrong place. `codeDestination` only read
`sent … to X`, which misses how many sites word it — "We texted your phone ending
in 4817" names the destination with no `to` at all — and it lost an address the
page stated outright whenever a dash followed it. Both are read now. When the page
says nothing, the card names the identifier the sign-in was started with, masked
(`d•••@eti.co`, `••• 4817`), worded as the guess it is: "should reach", not "sent
to". A username that is neither an address nor a number still names no channel and
gets the old neutral copy.

The report this came from: a code went to a number attached to the account years
earlier, on a phone in another room, and the card said "check your email or
messages".

And the card now says how long the code is, when the page has said so: a row of
one-character boxes is counted, a single field's `maxlength` is read, and failing
both the copy is searched for "six-digit". It travels as the field's placeholder,
which the screen already reads as its cell count. Only 4-8 is passed on — an
unconstrained input states nothing about a code, and the screen submits itself
when its cells fill, so too many cells leave a correct code unsubmittable.
