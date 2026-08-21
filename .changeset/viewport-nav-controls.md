---
"@alien-id/agent-id-browser": minor
---

The viewport stream now carries viewer navigation. Server → client: a `nav`
status object (`url`, `canGoBack`, `canGoForward`), polled on the same 250 ms
cadence as `input_focus`, deduped the same way, and handed to a joining
viewer in its join status. Client → server: `{"type":"nav","action":"back"
|"forward"|"reload"}`, suspend-gated and queued behind pending input like
every other viewer command.

Navigation executes over CDP (`Page.getNavigationHistory` +
`Page.navigateToHistoryEntry`, or `Page.reload`) on a fresh, short-lived CDP
session opened and detached per command — never `page.goBack`/`goForward`/
`reload`, which wait for a load event a single-page app may never fire and
would stall the shared input queue, and never the long-lived cast session,
which carries the scaled-capture device-metrics override and must not be
disturbed by navigation. There is no free-URL entry — only the three
history-relative actions.
