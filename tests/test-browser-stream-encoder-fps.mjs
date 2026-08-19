#!/usr/bin/env node

// The demuxer's nominal 25 fps becomes a constant output rate, so ffmpeg drops
// every screencast frame that misses the grid — measured 78 frames in, 2
// encoded, then silence. The argv is the contract: the drop is inside ffmpeg.
//
// Run: node --test tests/test-browser-stream-encoder-fps.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { createH264Encoder } from "../plugins/agent-id-browser/lib/stream-encoder.mjs";

const FFMPEG_STUB = `#!/usr/bin/env node
if (process.argv.includes("-encoders")) {
  process.stdout.write(" V....D libx264 stub\\n");
  process.exit(0);
}
require("node:fs").writeFileSync(process.env.ARGV_SINK, JSON.stringify(process.argv.slice(2)));
process.stdin.resume();
`;

function stub(dir) {
  const file = path.join(dir, "ffmpeg-stub.cjs");
  fs.writeFileSync(file, FFMPEG_STUB, { mode: 0o755 });
  return file;
}

test("the encoder passes frames through instead of resampling them to a fixed rate", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agentid-fps-"));
  const sink = path.join(dir, "argv.json");
  process.env.ARGV_SINK = sink;
  const enc = await createH264Encoder({ onChunk: () => {}, ffmpegPath: stub(dir) });
  try {
    for (let i = 0; i < 100 && !fs.existsSync(sink); i++) {
      await new Promise((r) => setTimeout(r, 20));
    }
    const argv = JSON.parse(fs.readFileSync(sink, "utf8"));
    const mode = argv[argv.indexOf("-fps_mode") + 1];
    assert.equal(mode, "passthrough", `frame-rate conversion is on: ${argv.join(" ")}`);
    assert.ok(argv.indexOf("-fps_mode") > argv.indexOf("-i"), "must be an output option");
  } finally {
    enc.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
