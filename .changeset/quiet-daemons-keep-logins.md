---
"@alien-id/agent-id-browser": patch
---

Sealing a login no longer loses it to a live session daemon

`auto-login` (and headed `login`) sealed the new session into the vault while a
daemon opened earlier on the same profile kept running. That daemon holds the
copy it unsealed at `open` time, so the next `open` reused it and showed the
login form, and its eventual close re-sealed that stale, logged-out copy over
the fresh login. Seen end to end: auto-login reported `logged-in`, `open main`
was still logged out, and the login was gone after the close.

Both commands now close a live session on the target profile first and wait for
its re-seal to finish (`closeLiveSession`). The success payload carries
`closedLiveSession` so the caller knows to open the profile again.

Also:

- `classifyLogin` recognizes Russian rejection copy («Пользователь не найден или
  неверный пароль», «Неверный логин или пароль», «Ошибка авторизации»). A
  rejection it could not read degraded to `unknown` every round, and the login
  ended as `timeout` / `owner_must_drive` — the owner was sent to the browser
  for a wrong password.
- `AUTO_LOGIN_FAILED` carries `trace` (what the engine saw each round: password
  field present or gone, challenge widget, URL) and `pageError` (the page's
  visible error copy), so a failure is diagnosable from the payload alone.
