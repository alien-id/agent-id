#!/usr/bin/env node

// A closed encoder must not deliver another byte.
//
// close() destroyed stdin and SIGKILLed the process but left the stdout
// listener attached, and neither of those stops delivery: what the kernel
// pipe already holds is still read out and handed to onChunk (measured:
// ~17 KB in 9 chunks after close returned). The stream server replaces an
// encoder by closing the old one and spawning a new one onto the SAME sink,
// so that tail was written to live viewers interleaved into the replacement's
// output — slices referencing the dead encoder's parameter sets, which a
// decoder can only fail on. That replacement happens on every viewer join and
// every restart, so a viewport could go black right after reconnecting.
//
// Driven by a stub encoder binary (no ffmpeg), flooding stdout at the moment
// of close so there is always something in flight to leak.
//
// Run: node --test tests/test-browser-stream-encoder-close.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { createH264Encoder } from "../plugins/agent-id-browser/lib/stream-encoder.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Stands in for ffmpeg: answers the encoder probe, then writes Annex-B access
// units as fast as the pipe takes them, so the kernel pipe buffer is full when
// the test closes the encoder.
const FFMPEG_STUB = `#!/usr/bin/env node
if (process.argv.includes("-encoders")) {
  process.stdout.write(" V....D libx264 stub\\n");
  process.exit(0);
}
const aud = Buffer.from([0, 0, 0, 1, 0x09, 0x10]);
const slice = Buffer.concat([Buffer.from([0, 0, 0, 1, 0x65]), Buffer.alloc(8 * 1024, 0x41)]);
const unit = Buffer.concat([aud, slice]);
process.stdin.resume();
process.stdout.on("error", () => process.exit(0));
setInterval(() => { for (let i = 0; i < 8; i++) process.stdout.write(unit); }, 1);
`;

function writeFfmpegStub() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "stream-close-stub-"));
  const stub = path.join(dir, "ffmpeg-stub.mjs");
  fs.writeFileSync(stub, FFMPEG_STUB, { mode: 0o755 });
  return { dir, stub };
}

test("no chunk reaches the caller after close() returns", async () => {
  const { dir, stub } = writeFfmpegStub();
  let closed = false;
  const after = { chunks: 0, bytes: 0 };
  let before = 0;

  const enc = await createH264Encoder({
    ffmpegPath: stub,
    log: () => {},
    onChunk: (chunk) => {
      if (closed) {
        after.chunks++;
        after.bytes += chunk.length;
      } else before++;
    },
  });

  try {
    // Feed it like the stream server does, and wait until output is flowing —
    // the leak only exists while the encoder is mid-stream.
    const deadline = Date.now() + 10000;
    while (before === 0 && Date.now() < deadline) {
      enc.write(Buffer.alloc(1024, 0xff));
      await sleep(20);
    }
    assert.ok(before > 0, "the stub encoder is producing output at close time");

    closed = true;
    enc.close();

    // Long enough for the pipe drain the old code kept delivering.
    await sleep(500);
    assert.equal(
      after.chunks,
      0,
      `no onChunk after close (got ${after.chunks} chunks, ${after.bytes} bytes)`
    );

    // Idempotent: a second close must not throw or resurrect delivery.
    enc.close();
    await sleep(100);
    assert.equal(after.chunks, 0, "still nothing after a second close");
  } finally {
    enc.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
