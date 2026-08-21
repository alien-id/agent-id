status: draft
base: pending

# Viewport stream: navigation state and viewer navigation commands

Closes alien-id/agent-id#124. Two additive protocol extensions in
`plugins/agent-id-browser/lib/stream-server.mjs`: the server reports the
current tab's navigation state (`nav` in status) and accepts viewer
navigation commands (`{"type":"nav","action":…}`) under the same suspend gate
as every other viewer event. Display policy stays a viewer concern; free URL
entry is deliberately not part of the protocol.

```json wave-plan
{ "waves": [
  { "wave": 1,
    "supervisor": { "model": "opus", "effort": "high" },
    "tasks": [
      { "id": "daemon-nav",
        "branch": "wave/daemon-nav",
        "executor": { "model": "sonnet", "effort": "high" },
        "ladder": ["opus"],
        "contract": {
          "files_allowed": [
            "plugins/agent-id-browser/lib/stream-server.mjs",
            "tests/test-browser-stream-nav.mjs",
            "docs/BROWSER-STREAM.md",
            ".changeset/viewport-nav-controls.md"
          ],
          "files_forbidden": [
            "plugins/agent-id-browser/lib/session-server.mjs",
            "plugins/agent-id-browser/lib/launch.mjs",
            "tests/test-browser-stream.mjs",
            "package.json"
          ],
          "must_run": [
            { "cmd": "node --test --test-force-exit tests/test-browser-stream-nav.mjs", "evidence": "required" },
            { "cmd": "node --test --test-force-exit tests/test-browser-stream.mjs tests/test-browser-stream-counters.mjs tests/test-stream-input-cal.mjs", "evidence": "required" }
          ],
          "forbidden_moves": [
            "weakening, deleting or skipping an existing test",
            "changing applyInput, calibratePointer, withPointerCal, the screencast/capture path, or the resize handler",
            "adding a dependency",
            "pushing to any remote or creating an issue/PR/comment (public repository)",
            "using Playwright navigation helpers (page.goBack/goForward/reload) instead of CDP",
            "accepting a viewer-supplied URL to navigate to"
          ],
          "report_must_answer": [
            "What exactly does the server send for nav state, when, and what suppresses it?",
            "Which CDP calls execute each action, and why not the Playwright helpers?",
            "Where is a nav command dropped while a credential fill is in flight — quote the code path",
            "What does a joining viewer receive before any navigation happens?"
          ] } } ] }
] }
```

## Task daemon-nav

Add viewer navigation to the viewport stream server, in
`plugins/agent-id-browser/lib/stream-server.mjs`. Two additive pieces, one new
test file, doc and changeset. Everything else in that file stays untouched.

### A. Navigation state in status

The stream already polls the page for input focus while viewers are attached
(`ensureFocusPoller`, `FOCUS_POLL_MS = 250`, `readInputFocus`, `inputFocus`,
`lastInputFocus`, `stopFocusPoller`). Add navigation state on that same
cadence, following the same shape — read it, dedupe it, remember it, broadcast
on change, hand it to a joining viewer.

Concretely:

1. Next to `lastInputFocus`, add `let lastNav = null;`.
2. Add a `navState(payload)` mirroring `inputFocus(payload)`: return early
   when `suspended > 0`; ignore a payload identical to `lastNav`
   (`JSON.stringify` comparison, exactly like the focus dedupe); otherwise
   store it and `broadcastStatus({ type: "status", source: "alien", nav: next })`.
3. Add `async function readNav()` returning
   `{ url, canGoBack, canGoForward }` or `null` when it cannot be read:
   - `const page = state.current;` guard exactly like `readInputFocus` does
     (`!page || page.isClosed?.()` → `null`);
   - `const url = typeof page.url === "function" ? page.url() : null;` — when
     it throws or yields nothing usable, return `null` (a navigation state
     without a URL is not worth broadcasting);
   - history flags come from the SAME cast CDP session the stream already
     owns (the module-level `cdp` variable): when `cdp` is null, report
     `canGoBack: false, canGoForward: false` alongside the url rather than
     skipping the update — a viewer with no history info still needs the
     address. When it exists:
     `const h = await cdp.send("Page.getNavigationHistory");` then
     `canGoBack = h.currentIndex > 0`,
     `canGoForward = h.currentIndex < h.entries.length - 1`. Wrap the send in
     try/catch and fall back to `false/false` on failure — a detached session
     must not kill the poll.
4. In `ensureFocusPoller`'s interval body, after the existing focus read, add
   the nav read under the same in-flight guard:
   `const nav = await readNav(); if (nav) navState(nav);`. Both reads share
   one interval; do not add a second timer.
5. In `stopFocusPoller`, also clear `lastNav = null` (the same reason the
   focus value is cleared: a new viewer must not inherit stale state).
6. In `statusFor(client)`, add `...(lastNav ? { nav: lastNav } : {})` next to
   the existing `input_focus` spread.

### B. Navigation commands from the viewer

In the client-message handler (the `parse` callback inside the connection
setup), the ordering is: control messages (`ack`, `config`, `status_request`,
webrtc) → `if (suspended > 0) return;` → `onActivity()` → the `resize`
branch → `mutatesPage(msg)` ref invalidation → the queued `applyInput` chain.

Insert a `nav` branch AFTER the `resize` branch and BEFORE the
`mutatesPage(msg)` line:

```js
      if (msg.type === "nav") {
        const action = msg.action;
        if (!["back", "forward", "reload"].includes(action)) return;
        state.invalidateRefs?.("owner navigated the live browser");
        // Queued behind pending input for the same reason input is queued: a
        // reload racing a click would apply to a page the click already left.
        inputChain = inputChain
          .then(async () => {
            if (suspended > 0) return;
            const page = state.current;
            if (!page || page.isClosed?.()) return;
            await applyNav(page, action);
          })
          .catch((err) => {
            sendText(client, {
              type: "status",
              source: "alien",
              error: err?.message || String(err),
              for: "nav",
            });
          });
        return;
      }
```

And add the exported executor next to `applyInput` (above it, so
`applyInput` keeps its position relative to the input section):

```js
// Exported for tests: navigation is executed over CDP rather than through
// page.goBack/goForward/reload, which WAIT for a load event — a single-page
// app that never fires one would stall the shared input queue behind it.
export async function applyNav(page, action) {
  const session = await page.context().newCDPSession(page);
  try {
    if (action === "reload") {
      await session.send("Page.reload");
      return;
    }
    const history = await session.send("Page.getNavigationHistory");
    const target = history.currentIndex + (action === "back" ? -1 : 1);
    const entry = history.entries?.[target];
    if (!entry) return;
    await session.send("Page.navigateToHistoryEntry", { entryId: entry.id });
  } finally {
    await session.detach().catch(() => {});
  }
}
```

A fresh short-lived CDP session is used deliberately: the long-lived cast
session carries the scaled-capture device-metrics override and its own
lifecycle, and navigation must not be able to disturb it.

### C. Tests — `tests/test-browser-stream-nav.mjs` (new file)

Model it on `tests/test-browser-stream.mjs`: read that file first and reuse
its fake/state/WS-client patterns (`makeFakeSession`, `makeFakeState`,
`connectStream`, `maskedFrame`). Do NOT edit it. `makeFakeState`'s fake page
has no `url()` or `context()` — extend your own local copy of the fake in the
new file (copy the helpers rather than importing across test files, which is
how the existing suite is written).

Cover at least:

1. `applyNav(page, "back")` sends `Page.getNavigationHistory` and then
   `Page.navigateToHistoryEntry` with the id of the entry BEFORE
   `currentIndex`; `"forward"` picks the entry AFTER it; `"reload"` sends
   `Page.reload` and no history call.
2. `applyNav` at the ends of history: at `currentIndex === 0` a `"back"`
   sends no `navigateToHistoryEntry`; at the last entry `"forward"` likewise.
3. `applyNav` always detaches the session it opened (fake records `detached`).
4. An unknown action (`{"type":"nav","action":"sideways"}`) reaches the server
   over a real socket and produces no CDP navigation call.
5. A `nav` command sent while the stream is suspended performs no navigation
   (drive suspend through the server handle the same way the existing suite
   does — read how `suspend()`/`resume()` are used there).

Print nothing extra; the tests assert. Exit code must be 0.

### D. Docs and changeset

- `docs/BROWSER-STREAM.md`: add the `nav` status object to the server→client
  example block and the `{ "type": "nav", "action": … }` line to the
  client→server block (both in `### Messages`), plus a short subsection
  (heading level `##`, placed after `## The resize message`) explaining:
  what the state contains, that it is polled on the focus cadence and deduped,
  that commands are suspend-gated and queued behind input, that navigation
  runs over CDP for the SPA reason above, and that free URL entry is
  deliberately absent.
- Also update the module header comment in `stream-server.mjs` where the
  client→server message shapes are listed, so the file documents itself.
- `.changeset/viewport-nav-controls.md`: a `minor` bump for
  `"@alien-id/agent-id-browser"` (new protocol surface), written in the style
  of the existing changesets in that directory — read one first.

### Boundaries

Do not touch: `applyInput`, `calibratePointer`, `withPointerCal`, the
screencast/capture/encoder paths, the resize handler, `session-server.mjs`,
`launch.mjs`, `package.json`, or any existing test file. No new dependencies.
No `page.goBack/goForward/reload`. Never accept a URL from the viewer.

This is the PUBLIC `alien-id/agent-id` repository: do not push your branch, do
not open issues/PRs/comments, and keep every comment you write free of
references to private repositories, internal service names or deployments.

### Dead-end protocol

If a fake, an export or a code path is not where this spec says it is — stop
and report exactly what you found instead. Do not invent an alternative
design, do not work around a restriction, do not pick an interpretation on
the user's behalf.

### Prohibitions (no qualifiers)

Do not spawn subagents. No destructive git operations (force-push,
reset --hard, rm outside the task). No pushes to any remote.

### Definition of done / response format

Changed files; the gist of each change; the FULL output of both must_run
commands pasted as evidence; explicit answers to every report_must_answer
question; the git delivery state (commit sha on the local branch
`wave/daemon-nav`; commits in this repository are unsigned, which is normal
here).
