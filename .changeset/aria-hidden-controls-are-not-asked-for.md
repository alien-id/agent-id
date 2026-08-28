---
"@alien-id/agent-id-browser": patch
---

Stop reading a staged password field as one the site is asking for.

An agent opened Booking.com's sign-in page, ran `alien_browser_inspect_form`,
saw a password control, and stored an ordinary login for a site that has no
password — the report this comes from. It was not careless: the control is
really there. On the e-mail step Booking builds the password step in full and
lays it out — 162x26, `visibility: visible`, `opacity: 1`, inside the viewport,
`offsetParent` set — and takes it out of the accessibility tree with
`aria-hidden` until it is the owner's turn to see it. Every ordinary visibility
test answers "visible".

Being asked for is narrower than being visible, so both places that judge a
control now exclude `aria-hidden` (and `inert`) subtrees:

- `form-inspect` no longer offers such a control, so the agent inspecting
  Booking's first screen sees one field — the e-mail — and has what it needs to
  store the credential as passwordless.
- `detectPageState` stops counting a staged password, so an identifier-first
  screen classifies as one.

Only the password reads it this way. The identifier keeps the looser test on
purpose: losing a password makes the page read as identifier-first, which is the
cautious reading, while losing the identifier as well would leave a page with no
form at all — and "no form" is the shape a finished login has.
