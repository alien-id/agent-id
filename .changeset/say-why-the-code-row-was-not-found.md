---
"@alien-id/agent-id-browser": patch
---

Find the code row on a page that wraps each box more than once, and say what
happened when it is still not found.

`otpRowInPage` grouped boxes by their parent and grandparent only. A page that
wraps each box twice therefore produced twelve groups of one, none reaching the
minimum of four, and the row was invisible — so `typeCodeInto` fell through to
`typeSecret` and put the whole six-character code into the first box. The page
never advanced, and the site looked like it had refused a correct code. The walk
now climbs up to `OTP_ROW_MAX_HOPS` ancestors; the "nothing else in it" check is
what keeps that honest, since an ancestor high enough to hold the rest of the
form fails it.

`otpBoxes` had one error path, `.catch(() => null)`, so a page exception, an
unreachable browser and "this page has no code row" all arrived as the same
silence. It now reports which of those happened, and when no row is found says
how many candidates it saw, the group sizes, and which check turned them away.

`AUTO_LOGIN_FAILED` no longer tells the caller an owner-entered code "was
mistyped" when the code never reached the page. A rejected code where no row was
ever driven is `owner_must_drive` / `code_field_not_driveable`, and the message
forbids the accusation outright — the model relayed the old wording to an owner
who had typed three correct codes.

The retry card no longer asks for "the current one" when the code came by mail;
there is no current one to read.
