---
"@alien-id/agent-id-browser": patch
---

Stream H.264 one access unit per WebSocket message

The viewport stream forwarded each encoder stdout chunk verbatim. A pipe read
is capped at 64 KiB, so any access unit above that was split across messages
and every message after the first carried no start code at all — a viewer that
parses one access unit per message could only discard it. Because the keyframe
is the largest access unit in the stream, it was the one most likely to be
split, so a viewer waiting for a keyframe never got a usable one: on content
that produces large frames the viewport froze or went black, while a static
page looked fine.

The stream is now framed on access unit delimiters and each unit is sent whole,
however large. A unit is known-complete when the next one's delimiter arrives;
when the encoder goes quiet, a 50 ms idle timer releases the last one, so an
idle page still updates promptly.
