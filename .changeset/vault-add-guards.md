---
"@alien-id/agent-id-vault": minor
---

`vault add` takes `--if-absent` and `--expect-kind <kind>`. An add is an upsert by name, so a caller
that stores what the owner just typed could swap an unrelated record for it. `--if-absent` refuses a
name that is taken. `--expect-kind` refuses a name taken by anything but a personal record of that
kind, which is how a caller says it replaces that very record; it takes one of the personal kinds,
and the record being added must be `--type personal --kind` that kind. Either refusal stores
nothing, and where the vault unlocks without asking the owner, it comes before the form is raised.
