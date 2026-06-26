---
"@alien-id/agent-id-vault": patch
---

Use a caret range (`^7.0.0`) instead of an exact `7.0.0` pin for the
`agent-id-core` marketplace dependency in `.claude-plugin/plugin.json`. The exact
pin made Claude Code's plugin resolver reject any cross-minor update ("7.1.0 does
not satisfy 7.0.0"), so `claude plugin update` could not move the plugin from
7.0.0 to 7.1.0 while a dependent was installed. The range mirrors the npm
`package.json` dependency semantics and lets in-range updates resolve. The same
fix is applied to the private `auth`/`git`/`proxy`/`browser` plugin manifests
(not release-tracked).
