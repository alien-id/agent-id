#!/usr/bin/env node

// Tests for the h264 wire framing: one WS binary message per ACCESS UNIT.
//
// The encoder writes an Annex-B byte stream to a pipe, and a pipe read is
// capped at 64 KiB below Node — so an access unit bigger than that arrives in
// several stdout chunks, and every chunk after the first carries no start
// code at all (emulation prevention keeps 00 00 01 out of NAL bodies).
// Forwarding chunks verbatim hands a viewer that parses one unit per message
// a fragment it can only discard, and because the IDR is the largest unit in
// the stream, the frame that clears a viewer's wait-for-keyframe state is the
// one most likely to be split: the viewport freezes or goes black.
//
// Driven end-to-end over real sockets against a fake CDP session and a stub
// encoder binary (no browser, no ffmpeg), so the byte stream under test is
// exact and the test always runs.
//
// Run: node --test tests/test-browser-stream-au-framing.mjs

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
import { createAccessUnitFramer } from "../plugins/agent-id-browser/lib/h264-framer.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── synthetic Annex-B ────────────────────────────────────────────────────────
// Only start codes and NAL types matter to the framer, so the payloads are
// filler — but filler that never contains 00, which is what emulation
// prevention guarantees about a real NAL body.

function nal(type, bodyLen, startCodeBytes = 4) {
  const start = startCodeBytes === 4 ? [0, 0, 0, 1] : [0, 0, 1];
  const buf = Buffer.alloc(start.length + 1 + bodyLen);
  buf.set(start);
  buf[start.length] = 0x60 | type; // forbidden_zero=0, nal_ref_idc=3
  for (let i = 0; i < bodyLen; i++) buf[start.length + 1 + i] = (i % 251) + 1;
  return buf;
}

function accessUnit({ sliceBytes, idr = false, startCodeBytes = 4 }) {
  const parts = [nal(9, 1, startCodeBytes)];
  if (idr) parts.push(nal(7, 24, startCodeBytes), nal(8, 8, startCodeBytes));
  parts.push(nal(idr ? 5 : 1, sliceBytes, startCodeBytes));
  return Buffer.concat(parts);
}

/** NAL types in stream order. A 4-byte start code matches once, at its tail. */
function nalTypes(buf) {
  const out = [];
  for (let i = 0; i + 3 < buf.length; ) {
    if (buf[i] === 0 && buf[i + 1] === 0 && buf[i + 2] === 1) {
      out.push(buf[i + 3] & 0x1f);
      i += 4;
    } else i++;
  }
  return out;
}

const startsWithStartCode = (b) =>
  b.length >= 4 && b[0] === 0 && b[1] === 0 && (b[2] === 1 || (b[2] === 0 && b[3] === 1));

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

// Stands in for ffmpeg: answers the encoder probe, then writes a canned
// Annex-B stream to stdout in one go — the pipe does the 64 KiB chunking, the
// same way a real encoder's output is chunked.
function writeFfmpegStub(stream) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "stream-au-stub-"));
  const streamFile = path.join(dir, "stream.h264");
  fs.writeFileSync(streamFile, stream);
  const stub = path.join(dir, "ffmpeg-stub.mjs");
  fs.writeFileSync(
    stub,
    `#!/usr/bin/env node
import fs from "node:fs";
if (process.argv.includes("-encoders")) {
  process.stdout.write(" V....D libx264 stub\\n");
  process.exit(0);
}
setTimeout(() => process.stdout.write(fs.readFileSync(${JSON.stringify(streamFile)})), 150);
setInterval(() => {}, 60000); // outlive the write; the server kills us
`,
    { mode: 0o755 },
  );
  return { dir, stub };
}

// ── minimal WS client (receive-only) ─────────────────────────────────────────

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
    close() { sock.destroy(); },
  };
}

// ── the regression ───────────────────────────────────────────────────────────

test("every h264 message is one whole access unit, however large", async () => {
  // The middle unit is far past the 64 KiB pipe read, so it can only reach a
  // viewer intact if the server frames the stream rather than the chunks.
  const units = [
    accessUnit({ sliceBytes: 900, idr: false }),
    accessUnit({ sliceBytes: 150_000, idr: true }),
    accessUnit({ sliceBytes: 1_200, idr: false }),
    accessUnit({ sliceBytes: 70_000, idr: false }),
    accessUnit({ sliceBytes: 800, idr: false }),
  ];
  const stream = Buffer.concat(units);
  const { dir, stub } = writeFfmpegStub(stream);
  const state = makeFakeState({ screenshot: Buffer.from("jpeg").toString("base64") });
  const server = await startStreamServer(state, {
    log: () => {},
    h264Config: { ffmpegPath: stub, encoder: "libx264" },
  });
  const c = await connectStream(server.port, server.token, "&codec=h264");

  const payloads = [];
  let got = 0;
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline && got < stream.length) {
    let m;
    try { m = await c.next(2000); } catch { break; }
    if (m.opcode !== 0x2) continue;
    const { header, payload } = decodeFrameBinary(m.payload);
    if (header.codec !== "h264") continue;
    payloads.push(payload);
    got += payload.length;
  }
  c.close();
  server.close();
  fs.rmSync(dir, { recursive: true, force: true });

  assert.ok(payloads.length > 0, "the viewer received h264 messages");
  for (const [i, p] of payloads.entries()) {
    assert.ok(
      startsWithStartCode(p),
      `payload ${i} begins with a start code (got ${p.subarray(0, 4).toString("hex")}, ` +
        `${p.length} bytes) — a mid-NAL fragment is undecodable`,
    );
    const types = nalTypes(p);
    assert.equal(types[0], 9, `payload ${i} opens with an access unit delimiter (${types})`);
    assert.equal(
      types.filter((t) => t === 9).length,
      1,
      `payload ${i} carries exactly one access unit (${types})`,
    );
  }
  // Whole units, in order, nothing added or lost.
  assert.deepEqual(payloads.map((p) => p.length), units.map((u) => u.length));
  assert.ok(Buffer.concat(payloads).equals(stream), "the byte stream is delivered intact");
  assert.ok(
    payloads.some((p) => p.length > 65536),
    "a unit larger than one pipe read was delivered in a single message",
  );
});

// ── framing edge cases (not observable through the socket) ───────────────────

function frameAll(stream, chunker, opts = {}) {
  const out = [];
  const framer = createAccessUnitFramer({ onAccessUnit: (au) => out.push(Buffer.from(au)), ...opts });
  for (const chunk of chunker(stream)) framer.push(chunk);
  return { out, framer };
}

test("units survive any chunk split, including one byte at a time", () => {
  const units = [
    accessUnit({ sliceBytes: 40, idr: true }),
    accessUnit({ sliceBytes: 70_000 }),
    accessUnit({ sliceBytes: 30 }),
  ];
  const stream = Buffer.concat(units);
  for (const size of [1, 2, 3, 4, 5, 7, 4096, 65536, stream.length]) {
    const { out } = frameAll(stream, function* (s) {
      for (let i = 0; i < s.length; i += size) yield s.subarray(i, i + size);
    });
    // The last unit waits for the next delimiter (or the idle flush).
    assert.deepEqual(
      out.map((u) => u.length),
      units.slice(0, -1).map((u) => u.length),
      `chunk size ${size}`,
    );
    assert.ok(Buffer.concat(out).equals(Buffer.concat(units.slice(0, -1))), `chunk size ${size}`);
  }
});

test("3-byte start codes frame the same as 4-byte ones", () => {
  const units = [
    accessUnit({ sliceBytes: 100, startCodeBytes: 3 }),
    accessUnit({ sliceBytes: 66_000, idr: true, startCodeBytes: 3 }),
    accessUnit({ sliceBytes: 100, startCodeBytes: 3 }),
  ];
  const { out } = frameAll(Buffer.concat(units), function* (s) {
    for (let i = 0; i < s.length; i += 65536) yield s.subarray(i, i + 65536);
  });
  assert.deepEqual(out.map((u) => u.length), units.slice(0, -1).map((u) => u.length));
  for (const u of out) assert.ok(startsWithStartCode(u));
});

test("the idle flush releases the last unit, and close drops a partial one", async () => {
  const unit = accessUnit({ sliceBytes: 200, idr: true });
  const { out, framer } = frameAll(unit, (s) => [s], { flushMs: 20 });
  assert.equal(out.length, 0, "held while the encoder might still be writing it");
  await sleep(60);
  assert.equal(out.length, 1, "released once the encoder went quiet");
  assert.ok(out[0].equals(unit));

  const late = [];
  const f2 = createAccessUnitFramer({ onAccessUnit: (au) => late.push(au), flushMs: 20 });
  f2.push(unit.subarray(0, 50));
  f2.close();
  await sleep(60);
  assert.equal(late.length, 0, "a dead encoder's partial unit is never emitted");
  framer.close();
});

test("a stream with no delimiters cannot grow the buffer without bound", () => {
  const out = [];
  const logged = [];
  const framer = createAccessUnitFramer({
    onAccessUnit: (au) => out.push(au),
    maxPending: 4096,
    log: (m) => logged.push(m),
  });
  for (let i = 0; i < 10; i++) framer.push(nal(1, 2000));
  framer.close();
  assert.equal(out.length, 0);
  assert.ok(logged.length > 0, "the resync is reported");
});
