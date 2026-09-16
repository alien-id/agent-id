---
"@alien-id/agent-id-browser": patch
---

Say the site rejected a credential only when the site was given one to reject.

`AUTO_LOGIN_FAILED` reported `credential: "rejected"` from the outcome alone, and
the outcome reached `"failed"` whenever the page carried rejection copy. Error
documents carry it too — "invalid", "try again" — and a page that is not a
sign-in offers no form to weigh those phrases against. A sign-in URL that
answered an error document therefore came back as "the site rejected the stored
credentials", and the owner was told to retype an e-mail address that had been
correct all along, on a page nothing had ever been typed into.

The run now reports whether a stored value actually went into a visible field.
`heuristicLogin` already computed that and dropped it; it is returned, recorded
on every path including the one that filled nothing, and carried out with the
outcome as `valuesSubmitted`. A completed recipe counts as submitted — driving
the credential into the page is what its steps are for — and so does a recipe
that failed after a code card was answered, since the steps before it had run.

A `"failed"` outcome with nothing submitted is now `owner_must_drive` /
`no_values_submitted`, the credential stays `intact`, and the message forbids
the accusation rather than merely omitting it: the model relayed the old wording
to the owner verbatim. It also points at `finalUrl`, because a login URL that no
longer reaches a sign-in page is the likeliest way to arrive here. A caller that
reports nothing about the fill still gets the old reading, so a refused
credential is unaffected.
