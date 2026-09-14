---
"@alien-id/agent-id-vault": minor
---

Add `set-login-url`, so moving a login's sign-in address does not ask the owner
for the secret again.

`loginUrl` is load-bearing for a `login` — auto-login has nowhere to start
without it — and whether it is right is only discovered by driving it. A site
moves its sign-in page, or the stored address was a guess at a path that never
existed. Either way the secret is still correct, and until now the only way to
change that one field was re-adding the credential, which raises the card and
asks the owner to retype a value they never got wrong.

It follows the other five correctors: `--name` and the one field, refusing a
type that has no sign-in address, and re-validating through the record's own
rules so a corrector cannot store an address `add` would have refused.
