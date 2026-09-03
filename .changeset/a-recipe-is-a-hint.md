---
"@alien-id/agent-id-browser": minor
---

A recipe is a hint, and a failed sign-in never costs the owner their credential.

`auto-login` used to die on the first recipe step that missed its element: the
error left `runRecipe` with the cause dropped, `autoLogin` rethrew it, and the
CLI printed a bare `{"ok":false,"error":…}` — no `outcome`, no `action`, no
`trace`. Read cold, that looked like a verdict on the stored values, and an agent
deleted the credential the owner had typed a minute earlier.

- A step that fails against the page (`RECIPE_STEP_FAILED`, naming the step and
  the redacted cause) sends the page back to the login URL and hands the run to
  the same form heuristics that sign a recipe-less credential in. The result
  carries `recipeFailed: { step, cause }` and the success message says to clear
  the recipe. Card outcomes inside the recipe are unchanged.
- A run that throws is reported as `AUTO_LOGIN_FAILED` with `outcome: "error"`,
  `action: owner_must_drive`, `pageError` and the `trace`, like every other
  ending.
- Every escalation carries `credential: "intact" | "rejected"`, and the messages
  for `failed` and the default no longer read as "re-add it": they say to
  re-store in place with `overwrite` only if the owner confirms, and never to
  remove.
- The `otp` write-back the 9.0.0 rewrite dropped is back: a stored `otp: none`
  corrected mid-run reaches the vault again.
