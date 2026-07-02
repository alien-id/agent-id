---
"@alien-id/agent-id-vault": minor
---

Per-credential access levels: records can carry `access: "ro" | "rw"` (default
`rw`) plus ordered `accessRules` (`{effect, methods, hosts, path}`), evaluated
by the new `lib/access.mjs` policy engine. Read-only credentials permit
GET/HEAD/OPTIONS and POST-tunneled reads (GraphQL query, JMAP get/query,
JSON-RPC non-submitting calls); `show` redacts and `exec` refuses their secret
fields. New `set-access` CLI command changes the level — tightening applies
immediately, widening requires the owner's out-of-band confirmation via the
secure prompt, and `add`/`generate` refuse to widen an existing record.
Enforcement happens in agent-id-proxy (structured `403 access_denied`) and
agent-id-browser (network-layer route gate for sealed sessions).

Hardening: body classification runs only for POST (a read-shaped body can't
promote a DELETE/PUT/PATCH); JSON-RPC is default-deny (unrecognized methods are
not treated as reads); rule reordering counts as a relaxation (owner ceremony);
rule-restricted `rw` credentials are sealed and their browser sessions block
WebSockets/service-workers too; multi-operation GraphQL documents are writes if
they contain any mutation/subscription. The proxy closes the connection on
early denials so an unconsumed request body can't corrupt the response status.
