---
"@alien-id/agent-id-browser": patch
---

Correct the JPEG screenshot rationale in the browser skill and code comments.
The shipped guidance claimed JPEG cut the dominant per-step cost of vision
actions; images are billed by pixel dimensions, not bytes, so encoding does not
change token cost. Point at the lever that does (shrinking the image), and drop
the stale "read the PNG" wording now that the default output is JPEG.
