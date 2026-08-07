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
    invalidated: [],
    invalidateRefs(reason) { this.invalidated.push(reason); },
    ctx: {
      // resume() detaches and re-attaches; hand out a fresh fake each time
      newCDPSession: async () => {
        if (session.detached) session = makeFakeSession(screenshot);
        return session;
      },
    },
    get session() { return session; },
  };
}

// ── minimal WS client (client → server frames are masked, RFC 6455) ──────────

function maskedFrame(opcode, payload) {
  const mask = crypto.randomBytes(4);
  const masked = Buffer.from(payload);
  for (let i = 0; i < masked.length; i++) masked[i] ^= mask[i & 3];
  let header;
  if (payload.length < 126) header = Buffer.from([0x80 | opcode, 0x80 | payload.length]);
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
        const waiter = (m) => { clearTimeout(t); resolve(m); };
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
    idle(ms) {
      return this.next(ms).then(
        (m) => { throw new Error(`expected silence, got: ${m.payload.toString().slice(0, 80)}`); },
        () => {},
      );
    },
    sendJson(obj) { sock.write(maskedFrame(0x1, Buffer.from(JSON.stringify(obj)))); },
    close() { sock.destroy(); },
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
  assert.deepEqual(p, { strict: false, binary: false, codec: "jpeg", pacing: "push", maxFps: 0 });
});

test("parseStreamParams: clamps and coerces", () => {
  const p = parseStreamParams(new URL("http://x/?binary=1&pacing=ack&maxFps=500"));
  assert.deepEqual(p, { strict: false, binary: true, codec: "jpeg", pacing: "ack", maxFps: 120 });
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
  const header = { type: "frame", seq: 7, codec: "jpeg", metadata: { deviceWidth: 1 } };
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
  const c = await connectStream(server.port, server.token, "&binary=1&pacing=ack");
  await c.nextJson(); // status
  await sleep(20);
  state.session.emitFrame(Buffer.from("f1").toString("base64"));
  const first = await c.nextBinary();
  assert.equal(first.payload.toString(), "f1");
  // Three more frames while the ack is outstanding — none may be delivered…
  for (const s of ["f2", "f3", "f4"]) state.session.emitFrame(Buffer.from(s).toString("base64"));
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
  const c = await connectStream(server.port, server.token, "&binary=1&maxFps=5");
  await c.nextJson();
  await sleep(20);
  for (let i = 1; i <= 10; i++) state.session.emitFrame(Buffer.from(`f${i}`).toString("base64"));
  const got = [await c.nextBinary()];
  try { for (;;) got.push(await c.nextBinary(400)); } catch { /* drained */ }
  assert.ok(got.length <= 4, `expected ≤4 deliveries at 5fps, got ${got.length}`);
  assert.equal(got.at(-1).payload.toString(), "f10", "must end on the latest frame");
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
  const c = await connectStream(server.port, server.token, "&binary=1&pacing=ack");
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
  const shot = state.session.sent.find((s) => s.method === "Page.captureScreenshot");
  assert.ok(shot, "refinement uses Page.captureScreenshot");
  assert.equal(shot.params.quality, 90);
  await c.idle(500); // no second refinement without a new screencast frame
  c.close();
  server.close();
});

test("status_request is answered", async () => {
  const { server } = await startServer();
  const c = await connectStream(server.port, server.token, "&pacing=ack&maxFps=10");
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
  const { detectH264Encoder } = await import("../plugins/agent-id-browser/lib/stream-encoder.mjs");
  const encoder = await detectH264Encoder();
  if (!encoder) return t.skip("no ffmpeg h264 encoder on this machine");
  const { server } = await startServer({ h264Config: { ffmpegPath: "ffmpeg", encoder } });
  const c = await connectStream(server.port, server.token, "&codec=auto");
  const st = await c.nextJson();
  assert.equal(st.codec, "h264");
  assert.equal(st.h264Available, true);
  c.close();
  server.close();
});

test("install-codecs records a probed system ffmpeg", async (t) => {
  const { detectH264Encoder, installCodecs, loadCodecConfig } =
    await import("../plugins/agent-id-browser/lib/stream-encoder.mjs");
  if (!(await detectH264Encoder())) return t.skip("no ffmpeg h264 encoder on this machine");
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
  fsSync.writeFileSync(path.join(stateDir, "browser-codecs.json"),
    JSON.stringify({ ffmpegPath: "/nonexistent/ffmpeg", encoder: "libx264" }));
  assert.equal(await loadCodecConfig(stateDir), null);
  fsSync.rmSync(stateDir, { recursive: true, force: true });
});

test("loadCodecConfig falls back to AGENT_ID_FFMPEG when no record exists", async (t) => {
  const { detectH264Encoder, loadCodecConfig } =
    await import("../plugins/agent-id-browser/lib/stream-encoder.mjs");
  if (!(await detectH264Encoder())) return t.skip("no ffmpeg h264 encoder on this machine");
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
    assert.equal(fsSync.existsSync(path.join(stateDir, "browser-codecs.json")), false);
  } finally {
    if (prevEnv === undefined) delete process.env.AGENT_ID_FFMPEG;
    else process.env.AGENT_ID_FFMPEG = prevEnv;
    fsSync.rmSync(stateDir, { recursive: true, force: true });
  }
});

test("loadCodecConfig stays null when neither record nor env provisions", async () => {
  const { loadCodecConfig } =
    await import("../plugins/agent-id-browser/lib/stream-encoder.mjs");
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
  const { detectH264Encoder } = await import("../plugins/agent-id-browser/lib/stream-encoder.mjs");
  if (!(await detectH264Encoder())) return t.skip("no ffmpeg h264 encoder on this machine");
  // Real JPEGs (the encoder decodes them): ffmpeg testsrc, 10 distinct frames.
  const { execFileSync } = await import("node:child_process");
  const os = await import("node:os");
  const path = await import("node:path");
  const fsSync = await import("node:fs");
  const dir = fsSync.mkdtempSync(path.join(os.tmpdir(), "stream-h264-"));
  execFileSync(process.env.AGENT_ID_FFMPEG || "ffmpeg", [
    "-hide_banner", "-loglevel", "error",
    "-f", "lavfi", "-i", "testsrc=size=320x240:rate=10",
    "-frames:v", "10", "-q:v", "5", path.join(dir, "f%02d.jpg"),
  ]);
  const jpegs = fsSync.readdirSync(dir).sort()
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
    while (Date.now() < deadline && chunks.reduce((n, b) => n + b.length, 0) < 2000) {
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
      else if (stream[i + 2] === 0 && stream[i + 3] === 1) nalTypes.add(stream[i + 4] & 0x1f);
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

test("codec=h264 on a STATIC page: refinement primes the encoder", async (t) => {
  const { detectH264Encoder } = await import("../plugins/agent-id-browser/lib/stream-encoder.mjs");
  if (!(await detectH264Encoder())) return t.skip("no ffmpeg h264 encoder on this machine");
  const { execFileSync } = await import("node:child_process");
  const os = await import("node:os");
  const path = await import("node:path");
  const fsSync = await import("node:fs");
  const dir = fsSync.mkdtempSync(path.join(os.tmpdir(), "stream-static-"));
  execFileSync(process.env.AGENT_ID_FFMPEG || "ffmpeg", [
    "-hide_banner", "-loglevel", "error",
    "-f", "lavfi", "-i", "testsrc=size=320x240:rate=1",
    "-frames:v", "1", "-q:v", "5", path.join(dir, "shot.jpg"),
  ]);
  const shot = fsSync.readFileSync(path.join(dir, "shot.jpg")).toString("base64");

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
    } catch { break; }
  }
  assert.ok(h264Bytes >= 500, `h264 output on a static page (got ${h264Bytes} bytes)`);
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
