---
"@alien-id/agent-id-browser": patch
---

The code card no longer states how long the code is. `otpCardSpec` sends the
`otp` field with no `placeholder`, and the derivation behind it is gone:
`otpCardLength`, `declaredCodeFieldLength` and `codeLengthFromText`. The length
travelled as the placeholder's character count, which the phone read as a cell
count — and the screen now draws one box, so nothing reads it.

`otpCardHints` returns `{ destination }` only. The row detection stays: it is
what spreads a code across a row of one-character boxes when the code comes
back, and that runs on the page as it is by then rather than as it was when the
card went out.
