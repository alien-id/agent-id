#!/usr/bin/env node

// Traffic/latency benchmark for the viewport stream protocol — NOT part of
// the test suite (bench-*, excluded from the test-*.mjs glob).
//
//   node tests/bench-browser-stream.mjs
//
// Feeds a synthetic 1280×720 screencast (ffmpeg testsrc JPEGs, 15fps) through
// a fake CDP session into a real stream server and measures, per mode, the
// bytes on the wire and the capture→deliver latency. The v1 baseline is the
// previous implementation taken from `git show main:` so old-vs-new is a real
// comparison, not a simulation. A slow-client scenario (socket paused 4s)
// shows the backpressure difference: v1 queues the backlog and replays stale
// frames; v2 drops to latest.

import crypto from "node:crypto";
import net from "node:net";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { once } from "node:events";
import { execFileSync } from "node:child_process";

import {
  startStreamServer as startV2,
  decodeFrameBinary,
  makeFrameParser,
} from "../plugins/agent-id-browser/lib/stream-server.mjs";

const FFMPEG = process.env.AGENT_ID_FFMPEG || "ffmpeg";
const FPS = 15;
const DURATION_MS = 6000;
const repoRoot = new URL("..", import.meta.url).pathname;
const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "stream-bench-"));

// ── fixtures ─────────────────────────────────────────────────────────────────

function makeFrames(prefix, filter) {
  execFileSync(FFMPEG, [
    "-hide_banner", "-loglevel", "error",
    "-f", "lavfi", "-i", `testsrc=size=1280x720:rate=10${filter}`,
    "-frames:v", "30", "-q:v", "7", path.join(workDir, `${prefix}%02d.jpg`),
  ]);
  return fs.readdirSync(workDir).filter((f) => f.startsWith(prefix) && f.endsWith(".jpg")).sort()
    .map((f) => fs.readFileSync(path.join(workDir, f)).toString("base64"));
}

async function loadV1() {
  const src = execFileSync("git", [
    "-C", repoRoot, "show", "main:plugins/agent-id-browser/lib/stream-server.mjs",
  ]);
  const file = path.join(workDir, "stream-server-v1.mjs");
  fs.writeFileSync(file, src);
  return (await import(file)).startStreamServer;
}

function makeFakeSession() {
  const handlers = new Map();
  return {
    on: (ev, fn) => handlers.set(ev, fn),
    async send(method) {
      if (method === "Page.captureScreenshot") return { data: "" };
      return {};
    },
    async detach() {},
    emitFrame(data) {
      handlers.get("Page.screencastFrame")?.({
        data,
        metadata: { deviceWidth: 1280, deviceHeight: 720, timestamp: Date.now() },
        sessionId: 1,
      });
    },
  };
}

function makeFakeState() {
  let session = makeFakeSession();
  return {
    current: {
      isClosed: () => false,
      viewportSize: () => ({ width: 1280, height: 720 }),
      mouse: {}, keyboard: {},
    },
    invalidateRefs: () => {},
    ctx: { newCDPSession: async () => session },
    get session() { return session; },
  };
}

// ── raw WS client (counts every byte on the wire) ────────────────────────────

function maskedFrame(opcode, payload) {
  const mask = crypto.randomBytes(4);
  const masked = Buffer.from(payload);
  for (let i = 0; i < masked.length; i++) masked[i] ^= mask[i & 3];
  const header = Buffer.from([0x80 | opcode, 0x80 | payload.length]);
  return Buffer.concat([header, mask, masked]);
}

async function connect(port, token, params, onMessage) {
  const sock = net.connect(port, "127.0.0.1");
  await once(sock, "connect");
  const key = crypto.randomBytes(16).toString("base64");
  sock.write(
    `GET /?token=${token}${params} HTTP/1.1\r\nHost: b\r\nUpgrade: websocket\r\n` +
      `Connection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`,
  );
  const stats = { rawBytes: 0 };
  const parse = makeFrameParser((m) => onMessage(m, sock));
  let head = Buffer.alloc(0);
  let upgraded = false;
  sock.on("data", (d) => {
    if (upgraded) {
      stats.rawBytes += d.length;
      return parse(d);
    }
    head = Buffer.concat([head, d]);
    const end = head.indexOf("\r\n\r\n");
    if (end < 0) return;
    upgraded = true;
    const rest = head.subarray(end + 4);
    stats.rawBytes += rest.length;
    parse(rest);
  });
  sock.on("error", () => {});
  await new Promise((r) => setTimeout(r, 50)); // handshake settle
  return { sock, stats, sendJson: (o) => sock.write(maskedFrame(0x1, Buffer.from(JSON.stringify(o)))) };
}

// ── scenarios ────────────────────────────────────────────────────────────────

const pct = (arr, p) => {
  if (!arr.length) return NaN;
  const s = [...arr].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))];
};
const mean = (arr) => (arr.length ? arr.reduce((a, b) => a + b) / arr.length : NaN);

async function runScenario({ label, start, params, ack = false, frames }) {
  const state = makeFakeState();
  const server = await start(state, { log: () => {} });
  const latencies = [];
  let delivered = 0;
  const client = await connect(server.port, server.token, params, (m, sock) => {
    let seq = null;
    let ts = null;
    if (m.opcode === 0x1) {
      const msg = JSON.parse(m.payload.toString());
      if (msg.type !== "frame") return;
      seq = msg.seq;
      ts = msg.metadata?.timestamp;
    } else if (m.opcode === 0x2) {
      const { header } = decodeFrameBinary(m.payload);
      if (header.type !== "frame") return;
      seq = header.seq;
      ts = header.metadata?.timestamp;
    } else return;
    delivered++;
    if (typeof ts === "number") latencies.push(Date.now() - ts);
    if (ack && seq != null) sock.write(maskedFrame(0x1, Buffer.from(JSON.stringify({ type: "ack", seq }))));
  });
  await new Promise((r) => setTimeout(r, 150)); // screencast/encoder settle
  let i = 0;
  const t0 = Date.now();
  const feeder = setInterval(() => state.session.emitFrame(frames[i++ % frames.length]), 1000 / FPS);
  await new Promise((r) => setTimeout(r, DURATION_MS));
  clearInterval(feeder);
  await new Promise((r) => setTimeout(r, 300)); // drain tail
  const wall = (Date.now() - t0) / 1000;
  client.sock.destroy();
  server.close();
  return {
    label,
    fed: i,
    delivered,
    kbps: client.stats.rawBytes / wall / 1024,
    bytesPerFrame: delivered ? client.stats.rawBytes / delivered : NaN,
    latMean: mean(latencies),
    latP95: pct(latencies, 95),
  };
}

async function runSlowClient({ label, start, params, frames }) {
  const state = makeFakeState();
  const server = await start(state, { log: () => {} });
  const postResume = [];
  let delivered = 0;
  let resumedAt = 0;
  const client = await connect(server.port, server.token, params, (m) => {
    let ts = null;
    if (m.opcode === 0x1) {
      const msg = JSON.parse(m.payload.toString());
      if (msg.type !== "frame") return;
      ts = msg.metadata?.timestamp;
    } else if (m.opcode === 0x2) {
      const { header } = decodeFrameBinary(m.payload);
      if (header.type !== "frame") return;
      ts = header.metadata?.timestamp;
    } else return;
    delivered++;
    if (resumedAt && typeof ts === "number") {
      postResume.push({ rel: Date.now() - resumedAt, age: Date.now() - ts });
    }
  });
  await new Promise((r) => setTimeout(r, 150));
  let i = 0;
  const feeder = setInterval(() => state.session.emitFrame(frames[i++ % frames.length]), 1000 / FPS);
  await new Promise((r) => setTimeout(r, 1000));
  client.sock.pause(); // viewer stalls (slow phone on the relay)
  await new Promise((r) => setTimeout(r, 6000));
  resumedAt = Date.now();
  client.sock.resume();
  await new Promise((r) => setTimeout(r, 2000));
  clearInterval(feeder);
  client.sock.destroy();
  server.close();
  // The kernel-buffered backlog (bytes already sent when the stall began) is
  // unavoidable for any server. What the server CAN control is how much stale
  // replay follows it — v1 queues the whole blackout, v2 jumps to live.
  const firstFresh = postResume.find((p) => p.age < 300);
  return {
    label,
    fed: i,
    delivered,
    staleReplayed: postResume.filter((p) => p.age > 1000).length,
    timeToLiveMs: firstFresh ? firstFresh.rel : NaN,
  };
}

// ── main ─────────────────────────────────────────────────────────────────────

const frames = makeFrames("clean", "");
// High-entropy frames for the stall scenario: big enough that a stalled
// viewer overflows the loopback kernel buffers and the server actually
// feels the backpressure (as a WAN relay would far sooner).
const noisy = makeFrames("noisy", ",noise=alls=40:allf=t");
const avgJpeg = frames.reduce((n, f) => n + Buffer.from(f, "base64").length, 0) / frames.length;
const avgNoisy = noisy.reduce((n, f) => n + Buffer.from(f, "base64").length, 0) / noisy.length;
console.log(
  `source: 1280x720 testsrc, ${frames.length} jpegs, avg ${(avgJpeg / 1024).toFixed(1)} KB raw ` +
    `(stall set: ${(avgNoisy / 1024).toFixed(1)} KB), fed at ${FPS}fps for ${DURATION_MS / 1000}s\n`,
);

const startV1 = await loadV1();

const rows = [];
rows.push(await runScenario({ label: "v1 text+base64 (main)", start: startV1, params: "", frames }));
rows.push(await runScenario({ label: "v2 text+base64 (compat)", start: startV2, params: "", frames }));
rows.push(await runScenario({ label: "v2 binary", start: startV2, params: "&binary=1", frames }));
rows.push(await runScenario({ label: "v2 binary+ack", start: startV2, params: "&binary=1&pacing=ack", ack: true, frames }));
rows.push(await runScenario({ label: "v2 h264", start: startV2, params: "&codec=h264", frames }));

console.log("mode                       fed  dlvd    kB/s  KB/frame  lat-mean  lat-p95");
for (const r of rows) {
  console.log(
    `${r.label.padEnd(26)} ${String(r.fed).padStart(4)} ${String(r.delivered).padStart(5)} ` +
      `${r.kbps.toFixed(0).padStart(7)} ${Number.isNaN(r.bytesPerFrame) ? "     n/a" : (r.bytesPerFrame / 1024).toFixed(1).padStart(8)} ` +
      `${Number.isNaN(r.latMean) ? "     n/a" : (r.latMean.toFixed(1) + "ms").padStart(8)} ${Number.isNaN(r.latP95) ? "     n/a" : (r.latP95.toFixed(0) + "ms").padStart(8)}`,
  );
}

console.log("\nslow client (socket paused 6s mid-stream, then resumed):");
console.log("mode                       fed  dlvd  stale-replayed  time-to-live");
for (const s of [
  await runSlowClient({ label: "v1 text+base64 (main)", start: startV1, params: "", frames: noisy }),
  await runSlowClient({ label: "v2 binary", start: startV2, params: "&binary=1", frames: noisy }),
]) {
  console.log(
    `${s.label.padEnd(26)} ${String(s.fed).padStart(4)} ${String(s.delivered).padStart(5)}  ` +
      `${String(s.staleReplayed).padStart(14)}  ${Number.isNaN(s.timeToLiveMs) ? "never".padStart(12) : (s.timeToLiveMs.toFixed(0) + "ms").padStart(12)}`,
  );
}

fs.rmSync(workDir, { recursive: true, force: true });
process.exit(0);
