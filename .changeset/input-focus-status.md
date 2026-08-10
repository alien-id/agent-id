---
"@alien-id/agent-id-browser": patch
---

The viewport stream now reports the page's input-focus state: while a viewer
is attached, a poller (250 ms, isolated-world evaluate — no Runtime domain,
no page-visible side effects, CSP-immune) walks the page's frames for a
focused editable element and broadcasts `input_focus {editable, type?,
inputmode?}` status messages, deduped, suppressed during credential-fill
blackouts, and snapshotted into the join status so a late viewer learns an
already-focused field immediately. Viewers can auto-open their keyboard (and
pick a layout from type/inputmode) instead of relying on a manual toggle.
Covered by wire-contract tests and a local-only real-browser e2e
(tests/integration/browser-focus-e2e.mjs) including an iframe fixture.
