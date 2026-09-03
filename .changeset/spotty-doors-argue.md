---
"@alien-id/agent-id-browser": major
---

The browser is now a separate process, reached over its RPC port, and this
plugin does one thing: sign it in.

`auto-login --cred CRED --rpc HOST:PORT` drives the sign-in form in a browser it
does not own, with the password going from the vault straight into the page as
real keystrokes — the reason this step cannot live in whoever drives the pages.
Recipes, the domain confinement on every navigation and every secret-bearing
step, the TOTP/interactive 2FA policy and the `owner_must_drive` /
`owner_must_confirm` / `fix_credential` contract are unchanged.

Everything else is gone, because the browser it was built on is: the in-process
engine and its launcher, the session daemon and its verbs (`open`, `close`,
`read`, `fetch`, `snapshot`, `click`, `type`, the form tools, screenshots,
tabs, downloads, `eval`), the vault-sealed profile store, the access guard, and
the viewport stream server with its codecs. A host that used those drives the
browser's own RPC port directly instead. With them go the `patchright` and
`werift` optional dependencies: this package now installs nothing but the two
shared libraries.

Two consequences worth naming:

- **Profiles are the browser's.** Nothing is sealed into the vault any more, so
  there is no `--name` profile to mint and no re-seal on close. The browser
  keeps its own profile; `auto-login` leaves it signed in.
- **A read-only `login` credential is refused.** `access: ro` used to be
  enforced at the wire by the process that owned the browser. This command does
  not own it, so signing in under one would hand out exactly the access the
  credential was restricted from.
