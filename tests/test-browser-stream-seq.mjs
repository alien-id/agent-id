#!/usr/bin/env node

// Tests for the stream's `seq` numbering contract. seq is a per-session
// stream-event counter shared across delivery paths (jpeg frame deliveries
// and h264 chunk sends both draw from it), not a per-message ordinal: an
// h264 viewer sees seq strictly increase but with holes, and that IS the
// contract — a consumer detecting loss must use a gap threshold, never
// `delta != 1`. A jpeg viewer that keeps up sees consecutive values because
// nothing else burns the counter between its frames.
//
// Driven end-to-end over real sockets against a FAKE CDP session (no
// browser); the h264 test additionally needs a real ffmpeg and self-skips
// without one.
//
// Run: node --test tests/test-browser-stream-seq.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import net from "node:net";
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
    async detach() { session.detached = true; },
    emitFrame(data, metadata = { deviceWidth: 640, deviceHeight: 480, timestamp: Date.now() }) {
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
    mouse: { move: async () => {}, down: async () => {}, up: async () => {}, wheel: async () => {} },
    keyboard: { down: async () => {}, up: async () => {}, insertText: async () => {} },
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
    get session() { return session; },
  };
}

// ── minimal WS client (receive-only: status + binary frames) ─────────────────

async function connectStream(port, token, params = "") {
  const sock = net.connect(port, "127.0.0.1");
  await once(sock, "connect");
  const key = crypto.randomBytes(16).toString("base64");
  sock.write(
    `GET /?token=${token}${params} HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\n` +
      `Connection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`,
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
        const waiter = (m) => { clearTimeout(t); resolve(m); };
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
    close() { sock.destroy(); },
  };
}

async function startServer(opts = {}, stateOpts = {}) {
  const state = makeFakeState(stateOpts);
  const server = await startStreamServer(state, { log: () => {}, ...opts });
  return { state, server };
}

// ── tests ────────────────────────────────────────────────────────────────────

test("h264 seq increases monotonically with holes allowed", async (t) => {
  const { detectH264Encoder } = await import("../plugins/agent-id-browser/lib/stream-encoder.mjs");
  if (!(await detectH264Encoder())) return t.skip("no ffmpeg h264 encoder on this machine");
  const { execFileSync } = await import("node:child_process");
  const os = await import("node:os");
  const path = await import("node:path");
  const fsSync = await import("node:fs");
  const dir = fsSync.mkdtempSync(path.join(os.tmpdir(), "stream-seq-"));
  execFileSync(process.env.AGENT_ID_FFMPEG || "ffmpeg", [
    "-hide_banner", "-loglevel", "error",
    "-f", "lavfi", "-i", "testsrc=size=320x240:rate=10",
    "-frames:v", "10", "-q:v", "5", path.join(dir, "f%02d.jpg"),
  ]);
  const jpegs = fsSync.readdirSync(dir).sort()
    .map((f) => fsSync.readFileSync(path.join(dir, f)).toString("base64"));

  // Real jpeg for the refinement capture — the quiet phase below arms it, and
  // it feeds the encoder.
  const { state, server } = await startServer({}, { screenshot: jpegs[0] });
  const c = await connectStream(server.port, server.token, "&codec=h264");
  await c.nextJson();
  await sleep(150);
  const seqs = [];
  // Steady motion: every screencast frame burns a counter value of its own,
  // so chunk-to-chunk deltas here are mostly ≥2 — the holes.
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
  assert.ok(seqs.length >= 8, `collected h264 chunks under motion (got ${seqs.length})`);
  // Burst then silence: the encoder drains its backlog with nothing else
  // burning the counter, so back-to-back chunks arrive with delta 1.
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
  // Strictly increasing across the whole connection — which is also the
  // no-reset guarantee.
  for (let i = 1; i < seqs.length; i++) {
    assert.ok(seqs[i] > seqs[i - 1], `seq strictly increases (${seqs[i - 1]} then ${seqs[i]})`);
  }
  const deltas = seqs.slice(1).map((s, i) => s - seqs[i]);
  assert.ok(deltas.includes(1), `a delta of 1 occurs (deltas: ${deltas.join(",")})`);
  assert.ok(deltas.some((d) => d >= 2), `a delta of ≥2 occurs (deltas: ${deltas.join(",")})`);
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
  // A keeping-up jpeg viewer sees consecutive values; holes appear only when
  // another delivery path burns the shared counter in between.
  for (let i = 1; i < seqs.length; i++) {
    assert.equal(seqs[i] - seqs[i - 1], 1, `consecutive frames (got ${seqs.join(",")})`);
  }
  c.close();
  server.close();
});
