---
"@alien-id/agent-id-browser": patch
"@alien-id/agent-id-vault": patch
"@alien-id/agent-id-core": patch
---

A card says what it is about, not only what it says. Every card now travels with
`purpose` (`sign_in` / `code` / `secret`) and `site`, and a code card adds
`codeChannel` (`email` / `sms` / `app`), `codeDestination` and `codeIsRetry`.
The prose travels unchanged beside them: a client that has never heard of
`purpose` renders exactly what it rendered before, which is what lets a client
draw the same sentence every time without anyone waiting for the other.

The channel was already being decided and thrown away. `codeDestination` tested
three recognisers — an address, a number, a place the page named — and collapsed
them into one boolean, while `ENDING_RE` captured the channel noun and spent it
on interpolation; `maskedIdentifier` decided address-or-number and returned only
a string. Both now return `{ channel, destination }`, and `codeTarget` puts the
two tiers behind one call: what the page said, else the identifier the sign-in
was started with, else nothing. An authenticator is not a tier — it reports
`app` and no destination, because nothing was sent anywhere.

The destination is masked at the source now rather than on the way to a log.
Most pages mask it themselves and masking twice is a no-op; the ones that do not
were putting a full address on a card through a gateway with no business holding
one. `maskDestination` goes with its only caller.

A recipe reads the page before it asks for a code, the way the ordinary path
does. `runRecipe` called `getOtp()` with nothing, so a recipe-driven sign-in
could never name where the code went — it fell to the identifier or to silence
even where the page said it outright.
