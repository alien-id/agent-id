# @alien-id/agent-id-browser

## 7.3.2

### Patch Changes

- [#67](https://github.com/alien-id/agent-id/pull/67) [`b05a646`](https://github.com/alien-id/agent-id/commit/b05a646c144926c99bcbd81f7d3896655005058e) Thanks [@atemerev](https://github.com/atemerev)! - Correct the JPEG screenshot rationale in the browser skill and code comments.
  The shipped guidance claimed JPEG cut the dominant per-step cost of vision
  actions; images are billed by pixel dimensions, not bytes, so encoding does not
  change token cost. Point at the lever that does (shrinking the image), and drop
  the stale "read the PNG" wording now that the default output is JPEG.
