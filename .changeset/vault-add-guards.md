---
"@alien-id/agent-id-vault": minor
---

`vault add` takes `--if-absent` and `--expect-kind <kind>`. An add is an upsert by name, so a caller
that stores what the owner just typed could swap an unrelated record for it. `--if-absent` refuses a
name that is taken. `--expect-kind` refuses a name taken by anything but a personal record of that
kind, which is how a caller says it replaces that very record. Either refusal stores nothing.
