---
"@alien-id/agent-id-vault": minor
"@alien-id/agent-id-mcp": patch
---

A payment card the owner can store, typed only into the secure form.

`card` joins the credential types: four fields (`cardNumber`, `cardExpiry`,
`cardSecurityCode`, `cardholderName`), validated where they are stored — 12-19
digits and Luhn on the number, `MMYY` still ahead on the expiry, three or four
digits on the security code. A number mistyped by one digit is otherwise only
reported by the merchant, after the owner has approved a payment.

Every one of the four is in `SECRET_FIELDS`, so a lock wipes all of it and
`show` redacts all of it. The record is `access: "ro"` rather than
`exportable: false` — the latter means "generated in-vault, never typed into a
page", which is the one thing a card exists to do.

The four names are a wire contract, not labels: the secure-input envelope
carries no field type, so the name a value is sealed under is what picks the
keyboard and the paired expiry/code row on the phone.

`add --type card` is form-only. A PAN passed as a flag is a PAN in the process
table, in `ps` output and in the shell history. It also takes no `--domains`:
where a card may be used is what the owner's approvals write, one payment at a
time, so the allowlist starts empty and default-deny holds literally.

The form's own sentence says the card asks for approval on every payment. It
drops the `ro` line that a login card carries — "the agent can read this" is
the opposite of the promise being made to somebody typing a card number.

`read-card --name N` is the one path that hands the four values over, for the
process that types them into a checkout — `show` keeps sealing a card, so the
values are not what an agent gets back when it asks what it has stored. The
command is not a privilege boundary (the vault opens with the agent key, and
anything that can run it can import the library); it is a named, greppable path
in place of a flag on `show`. What guards a card is the owner's per-payment
approval, enforced in lethe.
