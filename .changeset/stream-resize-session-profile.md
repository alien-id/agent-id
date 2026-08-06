---
"@alien-id/agent-id-browser": minor
---

Viewer `resize` in the stream protocol + profile name in the session file.

- The viewport stream now accepts `{"type":"resize","width":W,"height":H}`
  from viewers: the session reshapes the page viewport to the viewer's own
  dimensions (window-chrome-compensated, lands the exact size), so a phone
  watching the stream gets the page's mobile layout instead of a shrunken
  desktop one. The achieved viewport is broadcast to every watcher as a
  `status` message; requests are clamped to 200–4096 per axis and ignored
  while a credential fill has the stream suspended.
- Session files now name their `profile` in the body, so viewers scanning the
  sessions directory can attach to the right profile's stream instead of
  guessing by newest `startedAt`.
