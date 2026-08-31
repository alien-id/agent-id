#!/usr/bin/env node

// Tests for the viewport stream server's v2 wire protocol — negotiation,
// binary framing, latest-frame-wins delivery, ack pacing, fps capping,
// suspend blackout, idle refinement, and the h264 negotiation fallback.
// Driven end-to-end over real sockets against a FAKE CDP session (no
// browser): the screencast source is `session.emitFrame(...)`.
//
// Run: node --test tests/test-browser-stream.mjs

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import net from "node:net";
import { once } from "node:events";

import {
  startStreamServer,
  parseStreamParams,
  encodeFrameBinary,
  decodeFrameBinary,
  makeFrameParser,
  CLOSE_CODEC_UNAVAILABLE,
} from "../plugins/agent-id-browser/lib/stream-server.mjs";

const FRAME_B64 = Buffer.from("motion-frame-bytes").toString("base64");
const REFINE_B64 = Buffer.from("sharp-refinement-bytes").toString("base64");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── fakes ────────────────────────────────────────────────────────────────────

function makeFakeSession(screenshotData = REFINE_B64) {
  const handlers = new Map();
  const session = {
    sent: [],
    detached: false,
    on: (event, fn) => handlers.set(event, fn),
    async send(method, params) {
      session.sent.push({ method, params });
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
    invalidated: [],
    invalidateRefs(reason) {
      this.invalidated.push(reason);
    },
    ctx: {
      // resume() detaches and re-attaches; hand out a fresh fake each time
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

// ── minimal WS client (client → server frames are masked, RFC 6455) ──────────

function maskedFrame(opcode, payload) {
  const mask = crypto.randomBytes(4);
  const masked = Buffer.from(payload);
  for (let i = 0; i < masked.length; i++) masked[i] ^= mask[i & 3];
  let header;
  if (payload.length < 126)
    header = Buffer.from([0x80 | opcode, 0x80 | payload.length]);
  else {
    header = Buffer.alloc(4);
    header[0] = 0x80 | opcode;
    header[1] = 0x80 | 126;
    header.writeUInt16BE(payload.length, 2);
  }
  return Buffer.concat([header, mask, masked]);
}

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
  const status = await new Promise((resolve, reject) => {
    sock.on("data", (d) => {
      if (upgraded) return parse(d);
      head = Buffer.concat([head, d]);
      const end = head.indexOf("\r\n\r\n");
      if (end < 0) return;
      upgraded = true;
      const line = head.subarray(0, head.indexOf("\r\n")).toString();
      resolve(line);
      parse(head.subarray(end + 4));
    });
    sock.on("error", reject);
    sock.on("close", () => resolve("closed"));
  });
  return {
    sock,
    status,
    next(timeout = 2000) {
      if (queue.length) return Promise.resolve(queue.shift());
      return new Promise((resolve, reject) => {
        const waiter = (m) => {
          clearTimeout(t);
          resolve(m);
        };
        const t = setTimeout(() => {
          // Un-register, or the next real message would feed a dead promise.
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
    // Close frame: 2-byte big-endian code + UTF-8 reason (RFC 6455 §5.5.1).
    async nextClose(timeout) {
      const m = await this.next(timeout);
      assert.equal(m.opcode, 0x8, "expected a close frame");
      return {
        code: m.payload.length >= 2 ? m.payload.readUInt16BE(0) : null,
        reason: m.payload.subarray(2).toString("utf8"),
      };
    },
    idle(ms) {
      return this.next(ms).then(
        (m) => {
          throw new Error(
            `expected silence, got: ${m.payload.toString().slice(0, 80)}`
          );
        },
        () => {}
      );
    },
    sendJson(obj) {
      sock.write(maskedFrame(0x1, Buffer.from(JSON.stringify(obj))));
    },
    close() {
      sock.destroy();
    },
  };
}

async function startServer(opts = {}, stateOpts = {}) {
  const state = makeFakeState(stateOpts);
  const server = await startStreamServer(state, { log: () => {}, ...opts });
  // Let the async startScreencast settle once a client connects
  return { state, server };
}

// ── unit: negotiation + framing ──────────────────────────────────────────────

test("parseStreamParams: defaults match the v1 wire protocol", () => {
  const p = parseStreamParams(new URL("http://x/?token=t"));
  assert.deepEqual(p, {
    strict: false,
    binary: false,
    codec: "jpeg",
    pacing: "push",
    maxFps: 0,
  });
});

test("parseStreamParams: clamps and coerces", () => {
  const p = parseStreamParams(
    new URL("http://x/?binary=1&pacing=ack&maxFps=500")
  );
  assert.deepEqual(p, {
    strict: false,
    binary: true,
    codec: "jpeg",
    pacing: "ack",
    maxFps: 120,
  });
  assert.equal(parseStreamParams(new URL("http://x/?maxFps=junk")).maxFps, 0);
});

test("parseStreamParams: codec=h264 implies binary framing", () => {
  const p = parseStreamParams(new URL("http://x/?codec=h264"));
  assert.equal(p.binary, true);
  assert.equal(p.codec, "h264");
});

test("parseStreamParams: codec=auto is kept for join-time resolution, binary", () => {
  const p = parseStreamParams(new URL("http://x/?codec=auto"));
  assert.equal(p.binary, true);
  assert.equal(p.codec, "auto");
  assert.equal(parseStreamParams(new URL("http://x/?codec=vp9")).codec, "jpeg");
});

test("binary frame message roundtrips", () => {
  const payload = crypto.randomBytes(70000); // >64KB — exercises long WS frames
  const header = {
    type: "frame",
    seq: 7,
    codec: "jpeg",
    metadata: { deviceWidth: 1 },
  };
  const decoded = decodeFrameBinary(encodeFrameBinary(header, payload));
  assert.deepEqual(decoded.header, header);
  assert.deepEqual(decoded.payload, payload);
});

// ── integration over real sockets ────────────────────────────────────────────

test("token gate: wrong token is refused before the upgrade", async () => {
  const { server } = await startServer();
  const c = await connectStream(server.port, "nope");
  assert.match(c.status, /403|closed/);
  server.close();
});

test("default mode is wire-compatible with v1: text frame, base64 jpeg", async () => {
  const { state, server } = await startServer();
  const c = await connectStream(server.port, server.token);
  const status = await c.nextJson();
  assert.equal(status.type, "status");
  assert.equal(status.screencasting, true);
  assert.equal(status.binary, false);
  assert.equal(status.codec, "jpeg");
  await sleep(20); // startScreencast settles
  state.session.emitFrame(FRAME_B64);
  const frame = await c.nextJson();
  assert.equal(frame.type, "frame");
  assert.equal(frame.data, FRAME_B64);
  assert.equal(typeof frame.seq, "number");
  assert.ok(frame.metadata.deviceWidth);
  c.close();
  server.close();
});

test("binary=1: frames arrive as binary messages with decoded jpeg payload", async () => {
  const { state, server } = await startServer();
  const c = await connectStream(server.port, server.token, "&binary=1");
  await c.nextJson(); // status
  await sleep(20);
  state.session.emitFrame(FRAME_B64);
  const { header, payload } = await c.nextBinary();
  assert.equal(header.type, "frame");
  assert.equal(header.codec, "jpeg");
  assert.deepEqual(payload, Buffer.from(FRAME_B64, "base64"));
  c.close();
  server.close();
});

test("ack pacing: one frame in flight, stale frames are replaced not queued", async () => {
  const { state, server } = await startServer();
  const c = await connectStream(
    server.port,
    server.token,
    "&binary=1&pacing=ack"
  );
  await c.nextJson(); // status
  await sleep(20);
  state.session.emitFrame(Buffer.from("f1").toString("base64"));
  const first = await c.nextBinary();
  assert.equal(first.payload.toString(), "f1");
  // Three more frames while the ack is outstanding — none may be delivered…
  for (const s of ["f2", "f3", "f4"])
    state.session.emitFrame(Buffer.from(s).toString("base64"));
  await c.idle(150);
  // …and the ack releases exactly ONE frame: the latest.
  c.sendJson({ type: "ack", seq: first.header.seq });
  const second = await c.nextBinary();
  assert.equal(second.payload.toString(), "f4");
  await c.idle(150);
  c.close();
  server.close();
});

test("maxFps caps delivery and coalesces to the latest frame", async () => {
  const { state, server } = await startServer();
  const c = await connectStream(
    server.port,
    server.token,
    "&binary=1&maxFps=5"
  );
  await c.nextJson();
  await sleep(20);
  for (let i = 1; i <= 10; i++)
    state.session.emitFrame(Buffer.from(`f${i}`).toString("base64"));
  const got = [await c.nextBinary()];
  try {
    for (;;) got.push(await c.nextBinary(400));
  } catch {
    /* drained */
  }
  assert.ok(
    got.length <= 4,
    `expected ≤4 deliveries at 5fps, got ${got.length}`
  );
  assert.equal(
    got.at(-1).payload.toString(),
    "f10",
    "must end on the latest frame"
  );
  c.close();
  server.close();
});

test("config message switches pacing at runtime", async () => {
  const { state, server } = await startServer();
  const c = await connectStream(server.port, server.token, "&binary=1");
  await c.nextJson();
  await sleep(20);
  c.sendJson({ type: "config", pacing: "ack" });
  await sleep(20);
  state.session.emitFrame(Buffer.from("a1").toString("base64"));
  await c.nextBinary();
  state.session.emitFrame(Buffer.from("a2").toString("base64"));
  await c.idle(150); // held until ack
  c.close();
  server.close();
});

test("suspend blacks out frames, drops staged ones, and resumes with restart", async () => {
  const { state, server } = await startServer();
  const c = await connectStream(
    server.port,
    server.token,
    "&binary=1&pacing=ack"
  );
  await c.nextJson();
  await sleep(20);
  state.session.emitFrame(Buffer.from("pre").toString("base64"));
  const pre = await c.nextBinary();
  // Stage a pending frame behind the outstanding ack, then suspend.
  state.session.emitFrame(Buffer.from("staged").toString("base64"));
  server.suspend();
  const st = await c.nextJson();
  assert.equal(st.suspended, true);
  // The ack arriving mid-blackout must NOT flush the staged frame…
  c.sendJson({ type: "ack", seq: pre.header.seq });
  // …and frames emitted during the blackout must not deliver either.
  state.session.emitFrame(Buffer.from("secret").toString("base64"));
  await c.idle(200);
  server.resume();
  const st2 = await c.nextJson();
  assert.equal(st2.suspended, false);
  c.close();
  server.close();
});

test("idle refinement: one high-quality captureScreenshot after quiet", async () => {
  const { state, server } = await startServer();
  const c = await connectStream(server.port, server.token, "&binary=1");
  await c.nextJson();
  await sleep(20);
  state.session.emitFrame(FRAME_B64);
  const motion = await c.nextBinary();
  assert.ok(!motion.header.refinement);
  // >REFINE_AFTER_MS of screencast silence → exactly one refinement frame
  const refined = await c.nextBinary(2000);
  assert.equal(refined.header.refinement, true);
  assert.deepEqual(refined.payload, Buffer.from(REFINE_B64, "base64"));
  const shot = state.session.sent.find(
    (s) => s.method === "Page.captureScreenshot"
  );
  assert.ok(shot, "refinement uses Page.captureScreenshot");
  assert.equal(shot.params.quality, 90);
  await c.idle(500); // no second refinement without a new screencast frame
  c.close();
  server.close();
});

test("status_request is answered", async () => {
  const { server } = await startServer();
  const c = await connectStream(
    server.port,
    server.token,
    "&pacing=ack&maxFps=10"
  );
  await c.nextJson();
  c.sendJson({ type: "status_request" });
  const st = await c.nextJson();
  assert.equal(st.type, "status");
  assert.equal(st.pacing, "ack");
  assert.equal(st.maxFps, 10);
  c.close();
  server.close();
});

test("viewer input still applies and mutating input invalidates refs", async () => {
  const { state, server } = await startServer();
  const c = await connectStream(server.port, server.token);
  await c.nextJson();
  await sleep(20);
  c.sendJson({ type: "input_mouse", eventType: "mousePressed", x: 10, y: 10 });
  await sleep(50);
  assert.equal(state.invalidated.length, 1);
  c.close();
  server.close();
});

test("codec=auto on an unprovisioned host resolves to jpeg", async () => {
  const { state, server } = await startServer(); // no h264Config
  const c = await connectStream(server.port, server.token, "&codec=auto");
  const st = await c.nextJson();
  assert.equal(st.codec, "jpeg");
  assert.equal(st.h264Available, false);
  await sleep(20);
  state.session.emitFrame(FRAME_B64);
  const { header } = await c.nextBinary(); // binary framing still applies
  assert.equal(header.codec, "jpeg");
  c.close();
  server.close();
});

test("codec=auto on a provisioned host resolves to h264", async (t) => {
  const { detectH264Encoder } = await import(
    "../plugins/agent-id-browser/lib/stream-encoder.mjs"
  );
  const encoder = await detectH264Encoder();
  if (!encoder) return t.skip("no ffmpeg h264 encoder on this machine");
  const { server } = await startServer({
    h264Config: { ffmpegPath: "ffmpeg", encoder },
  });
  const c = await connectStream(server.port, server.token, "&codec=auto");
  const st = await c.nextJson();
  assert.equal(st.codec, "h264");
  assert.equal(st.h264Available, true);
  c.close();
  server.close();
});

test("install-codecs records a probed system ffmpeg", async (t) => {
  const { detectH264Encoder, installCodecs, loadCodecConfig } = await import(
    "../plugins/agent-id-browser/lib/stream-encoder.mjs"
  );
  if (!(await detectH264Encoder()))
    return t.skip("no ffmpeg h264 encoder on this machine");
  const os = await import("node:os");
  const path = await import("node:path");
  const fsSync = await import("node:fs");
  const stateDir = fsSync.mkdtempSync(path.join(os.tmpdir(), "codecs-"));
  const cfg = await installCodecs({ stateDir, allowDownload: false });
  assert.equal(cfg.source, "probed");
  assert.ok(cfg.encoder);
  const loaded = await loadCodecConfig(stateDir);
  assert.equal(loaded.ffmpegPath, cfg.ffmpegPath);
  // A bogus recorded binary must NOT validate (stale config self-heals)
  fsSync.writeFileSync(
    path.join(stateDir, "browser-codecs.json"),
    JSON.stringify({ ffmpegPath: "/nonexistent/ffmpeg", encoder: "libx264" })
  );
  assert.equal(await loadCodecConfig(stateDir), null);
  fsSync.rmSync(stateDir, { recursive: true, force: true });
});

test("loadCodecConfig falls back to AGENT_ID_FFMPEG when no record exists", async (t) => {
  const { detectH264Encoder, loadCodecConfig } = await import(
    "../plugins/agent-id-browser/lib/stream-encoder.mjs"
  );
  if (!(await detectH264Encoder()))
    return t.skip("no ffmpeg h264 encoder on this machine");
  const os = await import("node:os");
  const path = await import("node:path");
  const fsSync = await import("node:fs");
  const stateDir = fsSync.mkdtempSync(path.join(os.tmpdir(), "codecs-env-"));
  const prevEnv = process.env.AGENT_ID_FFMPEG;
  process.env.AGENT_ID_FFMPEG = prevEnv || "ffmpeg";
  try {
    const cfg = await loadCodecConfig(stateDir);
    assert.ok(cfg, "an env-provisioned host must load a codec config");
    assert.equal(cfg.source, "env");
    assert.ok(cfg.encoder);
    // The env override is per-process truth — it must NOT be written back as
    // a per-tenant record that would outlive an image whose ffmpeg moved.
    assert.equal(
      fsSync.existsSync(path.join(stateDir, "browser-codecs.json")),
      false
    );
  } finally {
    if (prevEnv === undefined) delete process.env.AGENT_ID_FFMPEG;
    else process.env.AGENT_ID_FFMPEG = prevEnv;
    fsSync.rmSync(stateDir, { recursive: true, force: true });
  }
});

test("loadCodecConfig stays null when neither record nor env provisions", async () => {
  const { loadCodecConfig } = await import(
    "../plugins/agent-id-browser/lib/stream-encoder.mjs"
  );
  const os = await import("node:os");
  const path = await import("node:path");
  const fsSync = await import("node:fs");
  const stateDir = fsSync.mkdtempSync(path.join(os.tmpdir(), "codecs-none-"));
  const prevEnv = process.env.AGENT_ID_FFMPEG;
  try {
    delete process.env.AGENT_ID_FFMPEG;
    assert.equal(await loadCodecConfig(stateDir), null);
    // A broken override is not provisioning: the probe re-verifies the
    // binary exactly like a stale record, and degrades to unprovisioned.
    process.env.AGENT_ID_FFMPEG = path.join(stateDir, "no-such-ffmpeg");
    assert.equal(await loadCodecConfig(stateDir), null);
  } finally {
    if (prevEnv === undefined) delete process.env.AGENT_ID_FFMPEG;
    else process.env.AGENT_ID_FFMPEG = prevEnv;
    fsSync.rmSync(stateDir, { recursive: true, force: true });
  }
});

test("codec=h264 end-to-end: Annex-B chunks with AUD/SPS/IDR arrive", async (t) => {
  const { detectH264Encoder } = await import(
    "../plugins/agent-id-browser/lib/stream-encoder.mjs"
  );
  if (!(await detectH264Encoder()))
    return t.skip("no ffmpeg h264 encoder on this machine");
  // Real JPEGs (the encoder decodes them): ffmpeg testsrc, 10 distinct frames.
  const { execFileSync } = await import("node:child_process");
  const os = await import("node:os");
  const path = await import("node:path");
  const fsSync = await import("node:fs");
  const dir = fsSync.mkdtempSync(path.join(os.tmpdir(), "stream-h264-"));
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

  const { state, server } = await startServer();
  const c = await connectStream(server.port, server.token, "&codec=h264");
  await c.nextJson(); // status (codec h264)
  await sleep(150); // screencast + encoder spawn settle
  const feeder = setInterval(() => {
    state.session.emitFrame(jpegs[Math.floor(Math.random() * jpegs.length)]);
  }, 50);
  const chunks = [];
  try {
    const deadline = Date.now() + 8000;
    while (
      Date.now() < deadline &&
      chunks.reduce((n, b) => n + b.length, 0) < 2000
    ) {
      const { header, payload } = await c.nextBinary(3000);
      assert.equal(header.codec, "h264");
      chunks.push(payload);
    }
  } finally {
    clearInterval(feeder);
  }
  const stream = Buffer.concat(chunks);
  const nalTypes = new Set();
  for (let i = 0; i + 4 < stream.length; i++) {
    if (stream[i] === 0 && stream[i + 1] === 0) {
      if (stream[i + 2] === 1) nalTypes.add(stream[i + 3] & 0x1f);
      else if (stream[i + 2] === 0 && stream[i + 3] === 1)
        nalTypes.add(stream[i + 4] & 0x1f);
    }
  }
  assert.ok(nalTypes.has(9), `AUD present (got NAL types ${[...nalTypes]})`);
  assert.ok(nalTypes.has(7), "SPS present");
  assert.ok(nalTypes.has(8), "PPS present");
  assert.ok(nalTypes.has(5), "IDR slice present");
  c.close();
  server.close();
  fsSync.rmSync(dir, { recursive: true, force: true });
});

// NAL unit types in stream order (Annex-B start-code scan). A 4-byte start
// code also matches as a 3-byte one — the duplicate entry lands at the same
// position, so first-occurrence ordering is unaffected.
function nalTypesInOrder(stream) {
  const out = [];
  for (let i = 0; i + 4 < stream.length; i++) {
    if (stream[i] === 0 && stream[i + 1] === 0) {
      if (stream[i + 2] === 1) out.push(stream[i + 3] & 0x1f);
      else if (stream[i + 2] === 0 && stream[i + 3] === 1)
        out.push(stream[i + 4] & 0x1f);
    }
  }
  return out;
}

test("a reconnecting h264 viewer's first chunks carry SPS PPS and an IDR", async (t) => {
  const { detectH264Encoder } = await import(
    "../plugins/agent-id-browser/lib/stream-encoder.mjs"
  );
  if (!(await detectH264Encoder()))
    return t.skip("no ffmpeg h264 encoder on this machine");
  const { execFileSync } = await import("node:child_process");
  const os = await import("node:os");
  const path = await import("node:path");
  const fsSync = await import("node:fs");
  const dir = fsSync.mkdtempSync(path.join(os.tmpdir(), "stream-rejoin-"));
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

  // The refinement capture must return a REAL jpeg: the feed keeps running
  // across the disconnect, and a refinement firing mid-test feeds the encoder.
  const { state, server } = await startServer({}, { screenshot: jpegs[0] });
  const a = await connectStream(server.port, server.token, "&codec=h264");
  await a.nextJson();
  await sleep(150);
  let n = 0;
  const feeder = setInterval(() => {
    state.session.emitFrame(jpegs[n++ % jpegs.length]);
  }, 50);
  try {
    // The stream is live: the first viewer is receiving h264 before it drops.
    let aBytes = 0;
    const aDeadline = Date.now() + 8000;
    while (Date.now() < aDeadline && aBytes < 500) {
      const { header, payload } = await a.nextBinary(3000);
      if (header.codec === "h264") aBytes += payload.length;
    }
    assert.ok(
      aBytes >= 500,
      `first viewer received h264 (got ${aBytes} bytes)`
    );
    a.close();
    await sleep(300); // the departed viewer's encoder teardown settles

    const b = await connectStream(server.port, server.token, "&codec=h264");
    await b.nextJson();
    // Collect until a non-IDR slice shows up (or a deadline): its position is
    // what proves the decoder-priming NALs came first.
    const chunks = [];
    const deadline = Date.now() + 8000;
    let ordered = [];
    while (Date.now() < deadline && !ordered.includes(1)) {
      const { header, payload } = await b.nextBinary(3000);
      if (header.codec !== "h264") continue;
      chunks.push(payload);
      ordered = nalTypesInOrder(Buffer.concat(chunks));
    }
    // A reconnecting viewer starts a fresh decoder: SPS (7), PPS (8) and an
    // IDR (5) must all arrive before any non-IDR slice (1).
    const firstNonIdr = ordered.indexOf(1);
    for (const [type, name] of [
      [7, "SPS"],
      [8, "PPS"],
      [5, "IDR"],
    ]) {
      const at = ordered.indexOf(type);
      assert.ok(
        at >= 0,
        `${name} present in the reconnected stream (got ${ordered.join(",")})`
      );
      if (firstNonIdr >= 0) {
        assert.ok(
          at < firstNonIdr,
          `${name} arrives before the first non-IDR slice`
        );
      }
    }
    b.close();
  } finally {
    clearInterval(feeder);
  }
  server.close();
  fsSync.rmSync(dir, { recursive: true, force: true });
});

test("codec=h264 on a STATIC page: refinement primes the encoder", async (t) => {
  const { detectH264Encoder } = await import(
    "../plugins/agent-id-browser/lib/stream-encoder.mjs"
  );
  if (!(await detectH264Encoder()))
    return t.skip("no ffmpeg h264 encoder on this machine");
  const { execFileSync } = await import("node:child_process");
  const os = await import("node:os");
  const path = await import("node:path");
  const fsSync = await import("node:fs");
  const dir = fsSync.mkdtempSync(path.join(os.tmpdir(), "stream-static-"));
  execFileSync(process.env.AGENT_ID_FFMPEG || "ffmpeg", [
    "-hide_banner",
    "-loglevel",
    "error",
    "-f",
    "lavfi",
    "-i",
    "testsrc=size=320x240:rate=1",
    "-frames:v",
    "1",
    "-q:v",
    "5",
    path.join(dir, "shot.jpg"),
  ]);
  const shot = fsSync
    .readFileSync(path.join(dir, "shot.jpg"))
    .toString("base64");

  // The screenshot fake returns a REAL jpeg — it is what feeds the encoder.
  const { state, server } = await startServer({}, { screenshot: shot });
  const c = await connectStream(server.port, server.token, "&codec=h264");
  await c.nextJson();
  await sleep(150); // encoder spawn settles
  // ONE frame (the join burst), then total screencast silence — the page is
  // static. The refinement pass must keep the h264 feed alive regardless.
  state.session.emitFrame(shot);
  let h264Bytes = 0;
  const deadline = Date.now() + 6000;
  while (Date.now() < deadline && h264Bytes < 500) {
    try {
      const { header, payload } = await c.nextBinary(2500);
      if (header.codec === "h264") h264Bytes += payload.length;
    } catch {
      break;
    }
  }
  assert.ok(
    h264Bytes >= 500,
    `h264 output on a static page (got ${h264Bytes} bytes)`
  );
  c.close();
  server.close();
  fsSync.rmSync(dir, { recursive: true, force: true });
});

test("codec=h264 without a usable ffmpeg falls back to jpeg with a status", async () => {
  process.env.AGENT_ID_FFMPEG = "/nonexistent/ffmpeg";
  try {
    const { state, server } = await startServer();
    const c = await connectStream(server.port, server.token, "&codec=h264");
    const st1 = await c.nextJson();
    assert.equal(st1.codec, "h264"); // optimistic join status
    const st2 = await c.nextJson(3000); // fallback notice
    assert.equal(st2.codec, "jpeg");
    await sleep(20);
    state.session.emitFrame(FRAME_B64);
    const { header, payload } = await c.nextBinary(); // binary framing survives
    assert.equal(header.codec, "jpeg");
    assert.deepEqual(payload, Buffer.from(FRAME_B64, "base64"));
    c.close();
    server.close();
  } finally {
    delete process.env.AGENT_ID_FFMPEG;
  }
});

test("a strict h264 request on an unprovisioned host closes 4002", async () => {
  process.env.AGENT_ID_FFMPEG = "/nonexistent/ffmpeg";
  try {
    const { server } = await startServer(); // no h264Config: unprovisioned
    const c = await connectStream(
      server.port,
      server.token,
      "&codec=h264&strict=1"
    );
    // The refusal is typed and immediate — at join time, before any encoder
    // work, and instead of the join status. Words first for a viewer that
    // logs text…
    const st = await c.nextJson();
    assert.equal(st.type, "status");
    assert.equal(st.code, CLOSE_CODEC_UNAVAILABLE);
    assert.match(st.error, /install-codecs/);
    // …then the proper close frame a strict client acts on.
    const close = await c.nextClose();
    assert.equal(close.code, CLOSE_CODEC_UNAVAILABLE);
    assert.equal(close.code, 4002);
    assert.match(close.reason, /strict=1/);
    assert.match(close.reason, /install-codecs/);
    c.close();
    server.close();
  } finally {
    delete process.env.AGENT_ID_FFMPEG;
  }
});

test("a joining viewer always restarts the screencast", async () => {
  // Frames are change-driven, so a viewer joining a running cast would wait
  // for the page to move before seeing anything. The join must force a fresh
  // capture epoch: stop + start the screencast so Chrome emits a first frame.
  const { state, server } = await startServer();
  const a = await connectStream(server.port, server.token, "&binary=1");
  await a.nextJson();
  await sleep(20);
  state.session.emitFrame(FRAME_B64);
  await a.nextBinary(); // the first viewer is connected and receiving
  const sessionA = state.session;
  assert.ok(sessionA.sent.some((s) => s.method === "Page.startScreencast"));
  assert.ok(!sessionA.sent.some((s) => s.method === "Page.stopScreencast"));

  const b = await connectStream(server.port, server.token, "&binary=1");
  await b.nextJson();
  await sleep(50);
  assert.ok(
    sessionA.sent.some((s) => s.method === "Page.stopScreencast"),
    "the join stops the running screencast"
  );
  const sessionB = state.session;
  assert.notEqual(
    sessionB,
    sessionA,
    "the join attaches a fresh capture session"
  );
  assert.ok(
    sessionB.sent.some((s) => s.method === "Page.startScreencast"),
    "the join starts a new screencast"
  );
  // The restarted cast feeds BOTH viewers.
  state.session.emitFrame(FRAME_B64);
  const af = await a.nextBinary();
  const bf = await b.nextBinary();
  assert.deepEqual(af.payload, Buffer.from(FRAME_B64, "base64"));
  assert.deepEqual(bf.payload, Buffer.from(FRAME_B64, "base64"));
  a.close();
  b.close();
  server.close();
});

test("a joining h264 viewer always restarts the screencast and encoder", async (t) => {
  const { detectH264Encoder } = await import(
    "../plugins/agent-id-browser/lib/stream-encoder.mjs"
  );
  if (!(await detectH264Encoder()))
    return t.skip("no ffmpeg h264 encoder on this machine");
  const { execFileSync } = await import("node:child_process");
  const os = await import("node:os");
  const path = await import("node:path");
  const fsSync = await import("node:fs");
  const dir = fsSync.mkdtempSync(path.join(os.tmpdir(), "stream-join-"));
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

  const { state, server } = await startServer({}, { screenshot: jpegs[0] });
  const a = await connectStream(server.port, server.token, "&codec=h264");
  await a.nextJson();
  await sleep(150);
  // Feed FEWER frames than one GOP, then go quiet. If the encoder survives
  // the join below, its next output can only be the running GOP's next
  // P-slice — so SPS/PPS + IDR at the head of what follows proves a respawn.
  let fed = 0;
  const feeder = setInterval(() => {
    if (fed < 15) state.session.emitFrame(jpegs[fed++ % jpegs.length]);
  }, 50);
  try {
    const pre = [];
    let ordered = [];
    const deadline = Date.now() + 8000;
    while (
      Date.now() < deadline &&
      !(ordered.includes(7) && ordered.includes(5))
    ) {
      const { header, payload } = await a.nextBinary(3000);
      if (header.codec !== "h264") continue;
      pre.push(payload);
      ordered = nalTypesInOrder(Buffer.concat(pre));
    }
    assert.ok(
      ordered.includes(7) && ordered.includes(8) && ordered.includes(5),
      "the first viewer is decoding a live h264 stream before the join"
    );
  } finally {
    clearInterval(feeder);
  }
  // Drain until well past the one idle-refinement pass (600ms after the last
  // frame), so the pre-join stream is fully quiet and everything observed
  // next is caused by the join.
  for (;;) {
    try {
      await a.next(900);
    } catch {
      break;
    }
  }
  const sessionA = state.session;
  assert.ok(!sessionA.sent.some((s) => s.method === "Page.stopScreencast"));

  const b = await connectStream(server.port, server.token, "&codec=h264");
  const st = await b.nextJson();
  assert.equal(st.codec, "h264");
  await sleep(50);
  assert.ok(
    sessionA.sent.some((s) => s.method === "Page.stopScreencast"),
    "the join stops the running screencast"
  );
  const sessionB = state.session;
  assert.notEqual(
    sessionB,
    sessionA,
    "the join attaches a fresh capture session"
  );
  assert.ok(
    sessionB.sent.some((s) => s.method === "Page.startScreencast"),
    "the join starts a new screencast"
  );
  // The restarted cast makes Chrome emit fresh frames; mimic that with
  // IDENTICAL images so a surviving encoder could never be pushed over a
  // scene cut or the GOP boundary into an IDR of its own — only a replaced
  // encoder can put SPS/PPS + an IDR ahead of the next slice.
  const rejoinFeeder = setInterval(() => {
    state.session.emitFrame(jpegs[0]);
  }, 50);
  const post = [];
  let ordered = [];
  try {
    const deadline = Date.now() + 6000;
    while (Date.now() < deadline && !ordered.some((n) => n === 1 || n === 5)) {
      const { header, payload } = await a.nextBinary(3000);
      if (header.codec !== "h264") continue;
      post.push(payload);
      ordered = nalTypesInOrder(Buffer.concat(post));
    }
  } finally {
    clearInterval(rejoinFeeder);
  }
  const firstSlice = ordered.find((n) => n === 1 || n === 5);
  assert.equal(
    firstSlice,
    5,
    `first slice after the join is an IDR — the encoder was replaced, not reused (got NAL order ${ordered.join(
      ","
    )})`
  );
  assert.ok(
    ordered.indexOf(7) >= 0 && ordered.indexOf(7) < ordered.indexOf(5),
    "fresh SPS precedes the post-join IDR"
  );
  assert.ok(
    ordered.indexOf(8) >= 0 && ordered.indexOf(8) < ordered.indexOf(5),
    "fresh PPS precedes the post-join IDR"
  );
  a.close();
  b.close();
  server.close();
  fsSync.rmSync(dir, { recursive: true, force: true });
});

// Frame dimensions coded in an H.264 SPS (Annex-B, baseline/constrained-
// baseline as our encoder emits). Minimal exp-Golomb walk — enough to prove
// what resolution the encoder was (re)configured for.
function spsDimensions(nal) {
  const rbsp = [];
  for (let i = 1; i < nal.length; i++) {
    // Strip emulation-prevention bytes (00 00 03 xx → 00 00 xx).
    if (nal[i] === 3 && nal[i - 1] === 0 && nal[i - 2] === 0) continue;
    rbsp.push(nal[i]);
  }
  let bit = 0;
  const u = (n) => {
    let v = 0;
    for (; n > 0; n--)
      (v = (v << 1) | ((rbsp[bit >> 3] >> (7 - (bit & 7))) & 1)), bit++;
    return v;
  };
  const ue = () => {
    let zeros = 0;
    while (u(1) === 0) zeros++;
    return (1 << zeros) - 1 + (zeros ? u(zeros) : 0);
  };
  const se = () => {
    const k = ue();
    return k & 1 ? (k + 1) / 2 : -(k / 2);
  };
  const profile = u(8);
  u(16); // constraint flags + reserved + level
  ue(); // sps id
  if (
    [100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135].includes(
      profile
    )
  ) {
    throw new Error("high-profile SPS unexpected from the baseline encoder");
  }
  ue(); // log2_max_frame_num_minus4
  const poc = ue();
  if (poc === 0) ue();
  else if (poc === 1) {
    u(1);
    se();
    se();
    const n = ue();
    for (let i = 0; i < n; i++) se();
  }
  ue(); // max_num_ref_frames
  u(1); // gaps_in_frame_num_value_allowed
  const widthMbs = ue() + 1;
  const heightMapUnits = ue() + 1;
  const frameMbsOnly = u(1);
  if (!frameMbsOnly) u(1);
  u(1); // direct_8x8_inference
  let width = widthMbs * 16;
  let height = (2 - frameMbsOnly) * heightMapUnits * 16;
  if (u(1)) {
    // frame_cropping (4:2:0 crop units: 2px horizontal, 2px·(2-fmo) vertical)
    const [l, r, t, b] = [ue(), ue(), ue(), ue()];
    width -= (l + r) * 2;
    height -= (t + b) * 2 * (2 - frameMbsOnly);
  }
  return { width, height };
}

// NAL payloads in stream order (start-code scan, 3- and 4-byte, deduped).
function nalPayloads(stream) {
  const starts = [];
  for (let i = 0; i + 3 < stream.length; i++) {
    if (stream[i] !== 0 || stream[i + 1] !== 0) continue;
    let s = null;
    if (stream[i + 2] === 1) s = i + 3;
    else if (stream[i + 2] === 0 && stream[i + 3] === 1) s = i + 4;
    if (s !== null && starts[starts.length - 1] !== s) starts.push(s);
  }
  return starts.map((s, k) =>
    stream.subarray(
      s,
      k + 1 < starts.length ? starts[k + 1] - 3 : stream.length
    )
  );
}

test("a scale change respawns the encoder with SPS/PPS/IDR at the scaled dimensions", async (t) => {
  const { detectH264Encoder } = await import(
    "../plugins/agent-id-browser/lib/stream-encoder.mjs"
  );
  if (!(await detectH264Encoder()))
    return t.skip("no ffmpeg h264 encoder on this machine");
  const { execFileSync } = await import("node:child_process");
  const os = await import("node:os");
  const path = await import("node:path");
  const fsSync = await import("node:fs");
  const dir = fsSync.mkdtempSync(path.join(os.tmpdir(), "stream-scale-"));
  // The same nominal viewport at 1× (320×240 screencast frames) and at a
  // viewer-requested 2× (640×480 device-pixel captures) — the dimension flip
  // a HiDPI resize causes on the wire. In scaled mode the delivered frames
  // come from captureScreenshot (the cast is only the damage tick), so the
  // 2× pixels ride the screenshot fake.
  for (const size of ["320x240", "640x480"]) {
    execFileSync(process.env.AGENT_ID_FFMPEG || "ffmpeg", [
      "-hide_banner",
      "-loglevel",
      "error",
      "-f",
      "lavfi",
      "-i",
      `testsrc=size=${size}:rate=10`,
      "-frames:v",
      "10",
      "-q:v",
      "5",
      path.join(dir, `${size}-f%02d.jpg`),
    ]);
  }
  const framesAt = (size) =>
    fsSync
      .readdirSync(dir)
      .filter((f) => f.startsWith(`${size}-`))
      .sort()
      .map((f) => fsSync.readFileSync(path.join(dir, f)).toString("base64"));
  const small = framesAt("320x240");
  const big = framesAt("640x480");

  const { state, server } = await startServer(
    {
      // The stream server owns all the scale bookkeeping under test; the
      // override lifecycle has its own fake-CDP coverage.
      resize: async (w, h) => ({ width: w, height: h }),
    },
    { screenshot: big[0] }
  );
  const c = await connectStream(server.port, server.token, "&codec=h264");
  await c.nextJson(); // status (codec h264)
  await sleep(150); // screencast + encoder spawn settle
  let n = 0;
  const feeder = setInterval(() => {
    state.session.emitFrame(small[n++ % small.length]);
  }, 50);
  try {
    // Phase 1: the 1× stream flows.
    let bytes = 0;
    const warmup = Date.now() + 8000;
    while (Date.now() < warmup && bytes < 500) {
      const m = await c.next(3000);
      if (m.opcode !== 0x2) continue;
      const { header, payload } = decodeFrameBinary(m.payload);
      if (header.codec === "h264") bytes += payload.length;
    }
    assert.ok(
      bytes >= 500,
      `1× h264 flowed before the resize (got ${bytes} bytes)`
    );

    // Phase 2: the viewer asks for the HiDPI stream; the delivered source
    // flips to device-pixel captures (the cast keeps ticking at CSS size as
    // the damage detector). Everything after the `resized` broadcast must
    // decode from scratch: fresh SPS/PPS + IDR, and the fresh SPS must code
    // the SCALED dimensions.
    c.sendJson({ type: "resize", width: 320, height: 240, scale: 2 });
    let resized = false;
    const post = [];
    let dims = null;
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline && !dims) {
      const m = await c.next(3000);
      if (m.opcode === 0x1) {
        const msg = JSON.parse(m.payload.toString("utf8"));
        if (msg.resized) {
          assert.equal(msg.resized.scale, 2);
          resized = true;
        }
        continue;
      }
      if (m.opcode !== 0x2 || !resized) continue;
      const { header, payload } = decodeFrameBinary(m.payload);
      if (header.codec !== "h264") continue;
      // EVERY post-resize h264 envelope must carry CSS geometry: the fake
      // cast reports 640×480 (device-pixel-shaped) metadata, and the h264
      // envelope builder used to pass it through raw — doubling scaled
      // viewers' tap coordinates.
      assert.equal(
        header.metadata.deviceWidth,
        320,
        "h264 envelope metadata is CSS width"
      );
      assert.equal(
        header.metadata.deviceHeight,
        240,
        "h264 envelope metadata is CSS height"
      );
      post.push(payload);
      const stream = Buffer.concat(post);
      const nals = nalPayloads(stream);
      const sps = nals.find((nl) => (nl[0] & 0x1f) === 7);
      if (!sps) continue;
      // Decoder-priming order across the respawn, like on a join.
      const order = nalTypesInOrder(stream);
      const firstSlice = order.find((x) => x === 1 || x === 5);
      assert.equal(
        firstSlice,
        5,
        `post-resize stream leads with an IDR (got ${order.join(",")})`
      );
      assert.ok(order.indexOf(7) < order.indexOf(5), "SPS precedes the IDR");
      assert.ok(order.indexOf(8) < order.indexOf(5), "PPS precedes the IDR");
      dims = spsDimensions(sps);
    }
    assert.ok(dims, "a fresh SPS arrived after the scaled resize");
    assert.deepEqual(
      dims,
      { width: 640, height: 480 },
      "the fresh SPS codes viewport × scale"
    );
  } finally {
    clearInterval(feeder);
  }
  c.close();
  server.close();
  fsSync.rmSync(dir, { recursive: true, force: true });
});
