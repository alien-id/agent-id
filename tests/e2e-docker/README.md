# Vault p2p sync — Docker full e2e

Proves the real multi-device vault sync story across real process/network
boundaries: three containers each run the actual `agent-id-core` +
`agent-id-vault` CLIs, bootstrap + owner-bind against a real `examples/dev-sso.mjs`
(auto-approve, one shared owner), then sync an encrypted credential vault
peer-to-peer. Only credential VALUES are mock (e.g. `mock-token-a1`).

Scenarios: setup, transfer (A→B), beacon discovery (best-effort/SKIP),
conflict + `resolve --restore`, headless approval (`sync devices add --jkt`),
and revoke.

Run locally (needs Docker + Compose; CI runs this as the blocking `docker-e2e` job — it is not part of `bun run test`):

```bash
./run.sh              # build image + run the whole sequence, prints PASS/FAIL/SKIP
./run.sh --no-build   # reuse the existing image
```

Always tears the stack down (`compose down -v`) and exits non-zero on any FAIL.
