---
"@alien-id/agent-id-vault": minor
---

A login keeps the owner's replies to a website's secret questions. `vault set-answer --name N --key K [--question Q] --form` raises a secure card showing the question, stores the reply under `answers.K`, and the browser types it as `N.answers.K`. `vault list` shows a login's `answerKeys`, never the replies, and `answers` is a secret field: it is scrubbed on lock and sealed on an access-restricted record.
