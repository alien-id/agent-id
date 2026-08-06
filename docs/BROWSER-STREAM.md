# Browser viewport stream

Every open `agent-id-browser` session runs a live viewport stream — the
"watch the agent browse" / pair-browsing feed. A viewer (the host runtime's
relay to the owner's client, or any agent-browser-compatible client) connects
over WebSocket, sees what the sealed browser sees, and can optionally drive it
with mouse/keyboard input or reshape its viewport.

Implementation: `plugins/agent-id-browser/lib/stream-server.mjs`. No runtime
dependencies — the WebSocket server is hand-rolled, and frames come from a CDP
screencast over the existing patchright pipe (the seal is preserved: no CDP
debug port is ever opened).

## Discovery and authentication

The session process writes its session file to
`<stateDir>/browser-sessions/<name>.json`:

```json
{
  "profile": "work",
  "port": 41720,
  "token": "<48-hex>",
  "pid": 12345,
  "headless": true,
  "startedAt": 1754300000000,
  "streamPort": 41723,
  "streamToken": "<48-hex>"
}
```

- `profile` names the profile this session serves. Viewers scanning the
  sessions directory MUST select by `profile`, not by newest `startedAt` —
  with several sessions open, newest-wins attaches the feed to the wrong
  profile.
- `port`/`token` are the session's own line-JSON action socket;
  `streamPort`/`streamToken` are the stream's.
- WebSocket upgrade: `ws://127.0.0.1:<streamPort>/?token=<streamToken>`.
  Anything else on that port answers `426`; a bad token is refused before the
  upgrade completes. The server binds `127.0.0.1` — the intended remote path
  is the host runtime relaying the token-gated socket.

## Wire protocol

The message shapes match agent-browser's streaming protocol, so one viewer
client works against both browser stacks. `resize` is our one extension
beyond those shapes (agent-browser servers ignore unknown types, so a shared
client stays compatible).

Server → client (JSON text):

```jsonc
{ "type": "status", "source": "alien", "screencasting": true }  // on join
{ "type": "status", "source": "alien", "suspended": true }      // fill blackout
{ "type": "status", "source": "alien",                          // after resize
  "resized": { "width": 390, "height": 844 },                   //   request
  "viewport": { "width": 390, "height": 844 } }                 //   achieved
{ "type": "frame", "data": "<base64 jpeg>",
  "metadata": { "deviceWidth": 1440, "deviceHeight": 813, /* … */ } }
```

Client → server (JSON text):

```jsonc
{ "type": "input_mouse", "eventType": "mousePressed",
  "x": 100, "y": 200, "button": "left", "clickCount": 1 }
{ "type": "input_mouse", "eventType": "mouseMoved" | "mouseReleased" | "mouseWheel",
  "deltaX": 0, "deltaY": 120 }
{ "type": "input_keyboard", "eventType": "keyDown" | "keyUp" | "char",
  "key": "Enter", "text": "a" }
{ "type": "resize", "width": 390, "height": 844 }
```

Input coordinates are in `metadata.deviceWidth/Height` space (CSS viewport
pixels). Mutating input (click, wheel, keydown, char) invalidates the agent's
element refs, exactly like any page mutation.

## The `resize` message

`width`/`height` are the **viewer's** dimensions — the desired page
**viewport**, not the outer window size the session-protocol `resize` action
takes. This is how a phone-sized viewer gets the page's mobile layout instead
of a shrunken desktop one: send your own screen size and the page reflows.

The session converts viewport → outer window with one chrome-compensation
pass: resize the window to the requested size, measure how much the window
chrome ate, grow the window by that delta. The result lands on the exact
requested viewport (verified against headless Chrome: requesting 390×844
yields a 390×844 viewport).

Rules:

- Dimensions clamp to **200–4096** per axis. Non-numeric dimensions are
  ignored entirely (not resized-to-minimum).
- Requests are serialized behind pending viewer input, so a resize lands in
  arrival order relative to queued clicks and keys.
- The achieved viewport is broadcast to **every** watcher as the `status`
  message above — the request mirror in `resized`, the authoritative result
  in `viewport`. Do coordinate math against `viewport`.
- A resize does not invalidate element refs (the DOM is untouched; refs are
  sparse and stable) — but screenshot coordinates taken before the resize are
  stale, as after any reflow.

## Suspend (credential blackout)

While `fill-secret` / `fill-otp` inject a credential value, the session
suspends the feed: frames stop, and **all** viewer messages — input and
`resize` alike — are dropped at apply time, so a watcher can neither see nor
touch a form mid-injection. Suspension is depth-counted and announced with
`{"type":"status","suspended":true|false}`; on resume the screencast restarts
to force a fresh keyframe.
