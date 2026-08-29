---
"@alien-id/agent-id-browser": major
"@alien-id/agent-id-vault": minor
---

Say what a sign-in page asks for, and write the card for the person reading it.

Both halves are corrections to the previous release, which shipped and did not
work.

**`form-inspect`'s output shape changed**, which is why the browser package takes a
major: a control the page has staged now arrives under `staged` instead of among
`controls`, and a sign-in page answers with `signIn`. lethe reads this contract in
its `vault_add` description, so the two move together.

**The staged password came back as a flag, and the flag was read straight past.**
`form-inspect` was reporting a control the page had taken out of the
accessibility tree with `hidden: true` rather than leaving it out. An agent
inspecting Booking.com's e-mail screen saw a password control, said as much —
"I saw a technical password field in the markup" — and stored a credential the
site has no use for. It moves to `staged` — not left among the fields on offer, and not dropped either.
Dropping was tried and was worse: "the page is asking for something else" is
satisfied by ANY live input anywhere, so a cookie banner carrying a checkbox took a
whole sign-in form out of reach with no ref left to recover it.

And the conclusion is stated rather than implied. On a page with an identifier
field and a submit beside it, `form-inspect` now answers with
`signIn: { identifier, passwordAsked }`. The submit is what keeps a newsletter box
in a footer from being reported as a site with no password.
A caller acts on a statement; a flag on one control among ten is something it
has to interpret, and interpretation is what failed.

**The card was written for the system, not the owner.** It read "Sign in to
account.booking.com / Identifier only — the sign-in code is asked for at
sign-in · login · *.booking.com / Sealed with AES-256-GCM (key via
HKDF-SHA256)". The type and the domain allowlist are how an agent addresses a
credential — `*.booking.com` reads to a person as a typo — and the cipher names
told them nothing they could act on while reading as a warning label on a screen
meant to reassure.

The title now says what is being asked and the line below says what it is for:

```
Enter it securely
Booking.com sign-in. You type it on a sealed screen. The code comes at sign-in.
I never see it and it isn't saved anywhere
```

The site is named as the owner would name it: a sign-in subdomain is dropped
from the front (`account.booking.com` → `Booking.com`), and only from the front,
because working out the registrable domain needs a public-suffix list and
guessing turns `example.co.uk` into `co.uk`. The access level survives the cut —
`ro` is a grant being made in the moment of typing.
