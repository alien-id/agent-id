---
"@alien-id/agent-id-vault": minor
---

The vault keeps the owner's own details. `vault add --type personal --kind <phone|date_of_birth|passport|visa|national_id|driving_licence|residence_permit|tax_id|bank_account|health_insurance> --form` raises a secure card with fixed labels and stores the values sealed under `fields`, read back with `vault read-personal --name N`. `--type address --form` stores an address that belongs to no card, read with `vault read-address --name N`. Both are form-only, read-only and take no `--domains`. A new `confirm` field on a record says whether the owner is asked before it is typed into a website: on by default, turned off only by the owner on the card, and shown by `vault list` with a personal record's `kind` and field names, never its values.
