---
"@alien-id/agent-id-vault": minor
"@alien-id/agent-id-browser": minor
---

Name the site on the secure card, and say where the code went.

Three things a live Airbnb sign-in showed the owner, none of them true or useful.

- **The card was titled with the credential's name.** The agent had named its
  record `airbnb-passwordless-again`, and that reached the screen verbatim —
  the owner was asked to "Add credential: airbnb-passwordless-again" while
  looking at Airbnb's sign-in page. The name is the vault's key and the agent's
  to choose; the title now names the site instead, taken from `loginUrl` or the
  narrowest literal entry in `domains` (a wildcard names a family of hosts, not
  a site). With nothing to derive a host from, the name is still better than
  nothing. The same swap applies to the code card, which had the same fault.
- **The identifier field promised a mailbox.** It was labelled
  "Username / email" for every login, while Airbnb's own first screen says
  "Phone number or email". The owner entered an address and waited for a letter
  the site had sent as an SMS. A passwordless login now says "Email or phone
  number"; a password login keeps the old label, where the field really can be a
  username.
- **The code card never said where the code went.** It read "airbnb.com sent
  you a code", so the channel was left to be guessed. The page has already said
  it — "We sent a code to +1 ••• ••• 4817" — and `codeDestination` reads that
  back. It reads it back only when the captured text is recognisably an address,
  a number, or a named place: naming the wrong channel is worse than naming
  none, because it sends the owner somewhere the code is not and then convinces
  them it never came. Unrecognised, the copy claims no channel and names both
  places to look.
