#!/usr/bin/env node

// Tests for the stream's `seq` numbering contract. seq counts per codec: a
// client consumes exactly one codec, and every message that codec's
// subscribers receive is numbered consecutively, so a viewer can read a gap
// as loss. A shared counter would let jpeg deliveries punch holes into the
// h264 sequence, which viewers report as loss and answer with a reconnect.
//
// Driven end-to-end over real sockets against a FAKE CDP session (no
// browser). The contiguity tests drive a stub encoder binary so they always
// run; the real-encoder test needs an ffmpeg and self-skips without one.
//
// Run: node --test tests/test-browser-stream-seq.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { once } from "node:events";

import {
  startStreamServer,
  decodeFrameBinary,
  makeFrameParser,
} from "../plugins/agent-id-browser/lib/stream-server.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── fakes ────────────────────────────────────────────────────────────────────

function makeFakeSession(screenshotData) {
  const handlers = new Map();
  const session = {
    detached: false,
    on: (event, fn) => handlers.set(event, fn),
    async send(method) {
      if (method === "Page.captureScreenshot") return { data: screenshotData };
      return {};
    },
    async detach() {
      session.detached = true;
    },
    emitFrame(
      data,
      metadata = { deviceWidth: 640, deviceHeight: 480, timestamp: Date.now() }
    ) {
      handlers.get("Page.screencastFrame")?.({ data, metadata, sessionId: 1 });
    },
  };
  return session;
}

function makeFakeState({ screenshot } = {}) {
  let session = makeFakeSession(screenshot);
  const page = {
    isClosed: () => false,
    viewportSize: () => ({ width: 640, height: 480 }),
    mouse: {
      move: async () => {},
      down: async () => {},
      up: async () => {},
      wheel: async () => {},
    },
    keyboard: {
      down: async () => {},
      up: async () => {},
      insertText: async () => {},
    },
  };
  return {
    current: page,
    invalidateRefs() {},
    ctx: {
      newCDPSession: async () => {
        if (session.detached) session = makeFakeSession(screenshot);
        return session;
      },
    },
    get session() {
      return session;
    },
  };
}

// ── minimal WS client (receive-only: status + binary frames) ─────────────────

async function connectStream(port, token, params = "") {
  const sock = net.connect(port, "127.0.0.1");
  await once(sock, "connect");
  const key = crypto.randomBytes(16).toString("base64");
  sock.write(
    `GET /?token=${token}${params} HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\n` +
      `Connection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`
  );
  const queue = [];
  const waiters = [];
  const parse = makeFrameParser((m) => {
    const w = waiters.shift();
    if (w) w(m);
    else queue.push(m);
  });
  let head = Buffer.alloc(0);
  let upgraded = false;
  await new Promise((resolve, reject) => {
    sock.on("data", (d) => {
      if (upgraded) return parse(d);
      head = Buffer.concat([head, d]);
      const end = head.indexOf("\r\n\r\n");
      if (end < 0) return;
      upgraded = true;
      resolve();
      parse(head.subarray(end + 4));
    });
    sock.on("error", reject);
  });
  return {
    sock,
    next(timeout = 2000) {
      if (queue.length) return Promise.resolve(queue.shift());
      return new Promise((resolve, reject) => {
        const waiter = (m) => {
          clearTimeout(t);
          resolve(m);
        };
        const t = setTimeout(() => {
          const i = waiters.indexOf(waiter);
          if (i >= 0) waiters.splice(i, 1);
          reject(new Error("timeout waiting for ws message"));
        }, timeout);
        waiters.push(waiter);
      });
    },
    async nextJson(timeout) {
      const m = await this.next(timeout);
      assert.equal(m.opcode, 0x1, "expected a text frame");
      return JSON.parse(m.payload.toString());
    },
    async nextBinary(timeout) {
      const m = await this.next(timeout);
      assert.equal(m.opcode, 0x2, "expected a binary frame");
      return decodeFrameBinary(m.payload);
    },
    close() {
      sock.destroy();
    },
  };
}

async function startServer(opts = {}, stateOpts = {}) {
  const state = makeFakeState(stateOpts);
  const server = await startStreamServer(state, { log: () => {}, ...opts });
  return { state, server };
}

// ── tests ────────────────────────────────────────────────────────────────────

// Stands in for ffmpeg: answers the encoder probe, then emits one Annex-B
// chunk per write it receives. Keeps these tests off a real encoder so they
// always run and the chunk count follows the writes.
const FFMPEG_STUB = `#!/usr/bin/env node
if (process.argv.includes("-encoders")) {
  process.stdout.write(" V....D libx264 stub\\n");
  process.exit(0);
}
process.stdin.on("data", () => process.stdout.write(Buffer.from([0, 0, 0, 1, 0x65])));
process.stdin.on("end", () => process.exit(0));
`;

function writeFfmpegStub() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "stream-seq-stub-"));
  const stub = path.join(dir, "ffmpeg-stub.mjs");
  fs.writeFileSync(stub, FFMPEG_STUB, { mode: 0o755 });
  return { dir, stub };
}

// Next binary frame of `codec`, skipping the status text frames a viewer
// also receives.
async function nextSeq(c, codec, timeout = 4000) {
  const deadline = Date.now() + timeout;
  for (;;) {
    const left = deadline - Date.now();
    if (left <= 0) throw new Error(`timeout waiting for a ${codec} frame`);
    const m = await c.next(left);
    if (m.opcode !== 0x2) continue;
    const { header } = decodeFrameBinary(m.payload);
    if ((header.codec ?? "jpeg") === codec) return header.seq;
  }
}

function assertConsecutive(seqs, what) {
  for (let i = 1; i < seqs.length; i++) {
    assert.equal(
      seqs[i] - seqs[i - 1],
      1,
      `consecutive ${what} (got ${seqs.join(",")})`
    );
  }
}

// The regression: with no jpeg viewer attached, every screencast frame still
// runs a jpeg delivery, and the idle refinement adds one more plus a double
// encoder write. None of that may number the h264 stream — a viewer reads
// the resulting holes as frame loss and redials.
test("h264 seq is contiguous while jpeg frames are delivered", async () => {
  const { dir, stub } = writeFfmpegStub();
  const jpeg = Buffer.from("jpeg-payload").toString("base64");
  const { state, server } = await startServer(
    { h264Config: { ffmpegPath: stub, encoder: "libx264" } },
    { screenshot: jpeg }
  );
  const c = await connectStream(server.port, server.token, "&codec=h264");
  await c.nextJson(); // join status — this is the only client on the server

  const seqs = [];
  // Motion phase. The stub encoder spawns asynchronously, so keep feeding
  // until the first chunk comes back, then take a run of them.
  const warmup = Date.now() + 10000;
  while (seqs.length === 0 && Date.now() < warmup) {
    state.session.emitFrame(jpeg);
    try {
      seqs.push(await nextSeq(c, "h264", 300));
    } catch {
      /* encoder not up yet */
    }
  }
  assert.equal(seqs.length, 1, "the stub encoder produced a chunk");
  for (let i = 0; i < 5; i++) {
    state.session.emitFrame(jpeg);
    seqs.push(await nextSeq(c, "h264"));
  }
  // Idle phase: silence past the refinement threshold arms one high-quality
  // capture — a jpeg delivery plus two encoder writes.
  seqs.push(await nextSeq(c, "h264", 4000));

  assert.ok(seqs.length >= 7, `collected h264 chunks (got ${seqs.length})`);
  assertConsecutive(seqs, "h264 chunks");
  c.close();
  server.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

// Both codecs on one server: neither sequence may be disturbed by the other.
test("jpeg and h264 viewers each get their own contiguous seq", async () => {
  const { dir, stub } = writeFfmpegStub();
  const jpeg = Buffer.from("jpeg-payload").toString("base64");
  const { state, server } = await startServer(
    { h264Config: { ffmpegPath: stub, encoder: "libx264" } },
    { screenshot: jpeg }
  );
  const h = await connectStream(server.port, server.token, "&codec=h264");
  await h.nextJson();
  const j = await connectStream(server.port, server.token, "&binary=1");
  await j.nextJson();

  const h264 = [];
  const jpegs = [];
  const warmup = Date.now() + 10000;
  while (h264.length === 0 && Date.now() < warmup) {
    state.session.emitFrame(jpeg);
    jpegs.push(await nextSeq(j, "jpeg"));
    try {
      h264.push(await nextSeq(h, "h264", 300));
    } catch {
      /* encoder not up yet */
    }
  }
  assert.equal(h264.length, 1, "the stub encoder produced a chunk");
  for (let i = 0; i < 5; i++) {
    state.session.emitFrame(jpeg);
    jpegs.push(await nextSeq(j, "jpeg"));
    h264.push(await nextSeq(h, "h264"));
  }
  assertConsecutive(h264, "h264 chunks");
  assertConsecutive(jpegs, "jpeg frames");
  h.close();
  j.close();
  server.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

test("h264 seq stays contiguous under real encoding", async (t) => {
  const { detectH264Encoder } = await import(
    "../plugins/agent-id-browser/lib/stream-encoder.mjs"
  );
  if (!(await detectH264Encoder()))
    return t.skip("no ffmpeg h264 encoder on this machine");
  const { execFileSync } = await import("node:child_process");
  const os = await import("node:os");
  const path = await import("node:path");
  const fsSync = await import("node:fs");
  const dir = fsSync.mkdtempSync(path.join(os.tmpdir(), "stream-seq-"));
  execFileSync(process.env.AGENT_ID_FFMPEG || "ffmpeg", [
    "-hide_banner",
    "-loglevel",
    "error",
    "-f",
    "lavfi",
    "-i",
    "testsrc=size=320x240:rate=10",
    "-frames:v",
    "10",
    "-q:v",
    "5",
    path.join(dir, "f%02d.jpg"),
  ]);
  const jpegs = fsSync
    .readdirSync(dir)
    .sort()
    .map((f) => fsSync.readFileSync(path.join(dir, f)).toString("base64"));

  // Real jpeg for the refinement capture — the quiet phase below arms it, and
  // it feeds the encoder.
  const { state, server } = await startServer({}, { screenshot: jpegs[0] });
  const c = await connectStream(server.port, server.token, "&codec=h264");
  await c.nextJson();
  await sleep(150);
  const seqs = [];
  // Steady motion: each screencast frame is delivered as a jpeg frame AND
  // fed to the encoder, and only the encoder's chunks number the h264 stream.
  let n = 0;
  const feeder = setInterval(() => {
    state.session.emitFrame(jpegs[n++ % jpegs.length]);
  }, 50);
  try {
    const deadline = Date.now() + 8000;
    while (Date.now() < deadline && seqs.length < 8) {
      const { header } = await c.nextBinary(3000);
      if (header.codec !== "h264") continue;
      seqs.push(header.seq);
    }
  } finally {
    clearInterval(feeder);
  }
  assert.ok(
    seqs.length >= 8,
    `collected h264 chunks under motion (got ${seqs.length})`
  );
  // Burst then silence: the encoder drains its backlog.
  await sleep(200);
  for (let i = 0; i < 30; i++) state.session.emitFrame(jpegs[i % jpegs.length]);
  const drainDeadline = Date.now() + 4000;
  while (Date.now() < drainDeadline) {
    try {
      const { header } = await c.nextBinary(800);
      if (header.codec === "h264") seqs.push(header.seq);
    } catch {
      break; // drained
    }
  }
  // Consecutive across the whole connection — which is also the no-reset
  // guarantee.
  assertConsecutive(seqs, "h264 chunks");
  c.close();
  server.close();
  fsSync.rmSync(dir, { recursive: true, force: true });
});

test("a jpeg viewer's seq increments by one per delivered frame", async () => {
  const { state, server } = await startServer();
  const c = await connectStream(server.port, server.token, "&binary=1");
  await c.nextJson();
  await sleep(20);
  const seqs = [];
  for (const s of ["s1", "s2", "s3", "s4"]) {
    state.session.emitFrame(Buffer.from(s).toString("base64"));
    const { header } = await c.nextBinary();
    seqs.push(header.seq);
  }
  // A keeping-up jpeg viewer sees consecutive values; a viewer that falls
  // behind skips frames outright (latest-frame-wins), it does not see holes.
  for (let i = 1; i < seqs.length; i++) {
    assert.equal(
      seqs[i] - seqs[i - 1],
      1,
      `consecutive frames (got ${seqs.join(",")})`
    );
  }
  c.close();
  server.close();
});
