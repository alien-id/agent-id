#!/usr/bin/env node

// Tests for the viewport stream's per-second counter rows.
//
// The daemon emits TWO rows — `daemon.capture` (screencast in, JPEG delivery
// out) and `daemon.h264` (encoder input, access units out) — because the two
// stages fail differently and that split is the whole diagnostic value: a
// healthy capture row beside a zeroed encode row means the encoder is holding
// the picture, while both at zero means the page stopped painting.
//
// What is proven here is the part that is easy to get subtly wrong and
// impossible to notice afterwards: a line is emitted even when everything is
// zero (a hop that goes silent must not look like a hop that died), the tick
// is aligned to the wall-clock second (`t` is the join key across stages), an
// edge line timestamps a freeze boundary to the millisecond, `drop` always
// equals the sum of its reasons, and the cumulative twins agree with the
// summed deltas. Both drop paths are driven deliberately rather than asserted
// as reachable: a stalled viewer for the latest-wins overwrite, a deaf encoder
// for the saturated-stdin run.
//
// Driven end-to-end over real sockets against a FAKE CDP session and stub
// encoder binaries — no browser, no ffmpeg — so the suite always runs.
//
// The H.264 fixtures under tests/fixtures/browser-stream/ are a VENDORED COPY
// of documentation/browser-stream/fixtures (stream.h264, manifest.json,
// chunks.json) plus counter-line.schema.json from its parent directory. A copy
// that drifts is worse than no fixture, so their SHA-256 is asserted below.
//
// Run: node --test tests/test-browser-stream-counters.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { once } from "node:events";
import { fileURLToPath } from "node:url";

import { createAccessUnitFramer } from "../plugins/agent-id-browser/lib/h264-framer.mjs";
import { createHopCounters, startCounterTicker } from "../plugins/agent-id-browser/lib/stream-counters.mjs";

// The idle refinement and the watchdog are frame sources of their own; muted
// so a window that should be zero is zero. Set before the import that reads
// them, which is why the stream server is pulled in dynamically.
process.env.AGENT_ID_STREAM_REFINE_QUALITY = "0";
process.env.AGENT_ID_STREAM_WATCHDOG_MS = "0";
const { startStreamServer, makeFrameParser } = await import(
  "../plugins/agent-id-browser/lib/stream-server.mjs"
);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const here = path.dirname(fileURLToPath(import.meta.url));
const fixtures = path.join(here, "fixtures", "browser-stream");
const read = (name) => fs.readFileSync(path.join(fixtures, name));

const SHA256 = {
  "stream.h264": "032180472dfa5ef158ae9d0cf8456478df706e073eec0125a4be4785eea4cc29",
  "manifest.json": "325287826525cf019d1e889d41456bd78dcfe6854cb61580bbfdac7540acefba",
  "chunks.json": "a869cf269def0da066743851b87ac6b06bd0418ed07dfb75d8a081f3de132ac8",
  "counter-line.schema.json": "a3570c016e4eccca1cb0e3917271e844eb6816609b07f430ef36b33399a88fe4",
};

const schema = JSON.parse(read("counter-line.schema.json"));

// ── a JSON Schema subset, big enough for the counter line ────────────────────
// No dependency for one schema. Everything the contract's schema actually
// uses: type/const/enum/required/properties/additionalProperties (boolean or
// schema)/minimum/minProperties/pattern.

function isType(t, v) {
  if (t === "object") return v !== null && typeof v === "object" && !Array.isArray(v);
  if (t === "integer") return Number.isInteger(v);
  if (t === "string") return typeof v === "string";
  if (t === "boolean") return typeof v === "boolean";
  if (t === "number") return typeof v === "number";
  return true;
}

function validate(s, v, where = "$", errs = []) {
  if ("const" in s && v !== s.const) errs.push(`${where}: expected ${JSON.stringify(s.const)}`);
  if (s.enum && !s.enum.includes(v)) errs.push(`${where}: ${JSON.stringify(v)} not in enum`);
  if (s.type && !isType(s.type, v)) errs.push(`${where}: expected ${s.type}, got ${JSON.stringify(v)}`);
  if (typeof s.minimum === "number" && !(v >= s.minimum)) errs.push(`${where}: ${v} below ${s.minimum}`);
  if (s.pattern && !(typeof v === "string" && new RegExp(s.pattern).test(v))) {
    errs.push(`${where}: ${JSON.stringify(v)} fails /${s.pattern}/`);
  }
  if (isType("object", v)) {
    const props = s.properties ?? {};
    for (const key of s.required ?? []) if (!(key in v)) errs.push(`${where}: missing "${key}"`);
    if (typeof s.minProperties === "number" && Object.keys(v).length < s.minProperties) {
      errs.push(`${where}: fewer than ${s.minProperties} properties`);
    }
    for (const [key, val] of Object.entries(v)) {
      if (props[key]) validate(props[key], val, `${where}.${key}`, errs);
      else if (s.additionalProperties === false) errs.push(`${where}: extra property "${key}"`);
      else if (isType("object", s.additionalProperties)) {
        validate(s.additionalProperties, val, `${where}.${key}`, errs);
      }
    }
  }
  return errs;
}

/** Every line validates, and every drop names a reason. */
function assertContract(lines) {
  assert.ok(lines.length > 0, "counter lines were emitted");
  for (const line of lines) {
    assert.deepEqual(validate(schema, line), [], `schema: ${JSON.stringify(line)}`);
    const reasons = Object.values(line.dr ?? {}).reduce((n, x) => n + x, 0);
    assert.equal(line.drop, reasons, `drop equals the sum of dr: ${JSON.stringify(line)}`);
    assert.equal(
      line.zero,
      line.fi === 0 && line.fo === 0 && line.drop === 0,
      `zero agrees with the counters: ${JSON.stringify(line)}`,
    );
  }
}

/** The cumulative twins are the running sum of every delta emitted so far. */
function assertCumulative(lines, hop) {
  const run = { fi: 0, fo: 0, bi: 0, bo: 0, drop: 0 };
  const mine = lines.filter((l) => l.hop === hop);
  assert.ok(mine.length > 0, `lines for ${hop}`);
  for (const line of mine) {
    for (const k of Object.keys(run)) run[k] += line[k];
    for (const k of Object.keys(run)) {
      assert.equal(line.c[k], run[k], `c.${k} tracks the summed deltas for ${hop}`);
    }
  }
}

// ── fakes (same shape as the seq suite: fake CDP, stub ffmpeg) ───────────────

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

/** Collects counter lines with the wall-clock instant each was emitted. */
function collector() {
  const rows = [];
  const prefix = "stream: counters ";
  return {
    rows,
    lines: () => rows.map((r) => r.line),
    hop: (name) => rows.map((r) => r.line).filter((l) => l.hop === name),
    log(msg) {
      if (typeof msg === "string" && msg.startsWith(prefix)) {
        rows.push({ at: Date.now(), line: JSON.parse(msg.slice(prefix.length)) });
      }
    },
  };
}

async function startServer(opts = {}, stateOpts = {}) {
  const sink = collector();
  const state = makeFakeState(stateOpts);
  const server = await startStreamServer(state, { log: (m) => sink.log(m), ...opts });
  return { state, server, sink };
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
    close() { sock.destroy(); },
  };
}

function writeStub(source, tag) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `stream-counters-${tag}-`));
  const stub = path.join(dir, "ffmpeg-stub.mjs");
  fs.writeFileSync(stub, source, { mode: 0o755 });
  return { dir, stub };
}

// Answers the encoder probe and then never reads stdin: the pipe fills, the
// writer's buffer passes its high-water mark, and write() refuses a RUN of
// frames until a drain that never comes.
const FFMPEG_DEAF = `#!/usr/bin/env node
if (process.argv.includes("-encoders")) {
  process.stdout.write(" V....D libx264 stub\\n");
  process.exit(0);
}
setInterval(() => {}, 1 << 30);
`;

// ── the vendored corpus ──────────────────────────────────────────────────────

test("the vendored corpus matches the source it was copied from", () => {
  for (const [name, want] of Object.entries(SHA256)) {
    const got = crypto.createHash("sha256").update(read(name)).digest("hex");
    assert.equal(got, want, `${name} drifted from documentation/browser-stream`);
  }
});

test("the schema check rejects what it is supposed to reject", () => {
  const good = {
    v: 1, hop: "daemon.h264", t: 1755603600, win_ms: 1000,
    fi: 1, fo: 1, bi: 10, bo: 10, drop: 0, zero: false,
    c: { fi: 1, fo: 1, bi: 10, bo: 10, drop: 0 },
  };
  assert.deepEqual(validate(schema, good), []);
  // A validator that passes everything proves nothing about the emitter.
  assert.ok(validate(schema, { ...good, v: 2 }).length, "wrong contract version");
  assert.ok(validate(schema, { ...good, nope: 1 }).length, "unknown top-level key");
  assert.ok(validate(schema, { ...good, drop: -1 }).length, "negative drop");
  assert.ok(validate(schema, { ...good, hop: "Daemon.H264" }).length, "hop pattern");
  assert.ok(validate(schema, { ...good, edge: "sideways" }).length, "unknown edge");
  assert.ok(validate(schema, { ...good, seq: { first: 1 } }).length, "incomplete seq");
  const { zero, ...noZero } = good;
  assert.ok(validate(schema, noZero).length, "missing required key");
});

// ── the four rules that are easy to get wrong ────────────────────────────────

test("a line is emitted for both stages every second, zero or not", async () => {
  const { server, sink } = await startServer();
  await sleep(2500);
  server.close();

  const lines = sink.lines();
  assertContract(lines);
  for (const hop of ["daemon.capture", "daemon.h264"]) {
    const mine = sink.hop(hop);
    assert.ok(mine.length >= 2, `${hop} kept emitting while idle (got ${mine.length})`);
    for (const l of mine) {
      assert.equal(l.zero, true, `${hop} idle window is marked zero`);
      assert.deepEqual([l.fi, l.fo, l.drop], [0, 0, 0]);
      assert.equal(l.dr, undefined, "no dr without a drop");
    }
    // Consecutive windows, so a gap in `t` reads as a dead emitter.
    for (let i = 1; i < mine.length; i++) {
      assert.equal(mine[i].t - mine[i - 1].t, 1, `${hop} windows are consecutive`);
    }
    assertCumulative(lines, hop);
  }
});

test("the tick is wall-clock aligned and win_ms reports the real window", async () => {
  // Start deliberately half a second off the boundary: an interval started at
  // connection time would then fire ~500 ms past every second, and both
  // assertions below would catch it.
  const now = Date.now();
  await sleep(((1500 - (now % 1000)) % 1000) || 1000);
  const { server, sink } = await startServer();
  await sleep(3300);
  server.close();

  const rows = sink.rows.filter((r) => r.line.hop === "daemon.capture");
  assert.ok(rows.length >= 3, `collected ticks (got ${rows.length})`);
  assertContract(sink.lines());

  for (const r of rows) {
    // The window [t, t+1) closed at its own boundary, not at an arbitrary
    // offset carried over from whenever the server happened to start.
    const skew = r.at - (r.line.t + 1) * 1000;
    assert.ok(skew >= 0 && skew < 250, `tick landed ${skew}ms past the second boundary`);
  }
  // The first window is the short one: it began mid-second, and win_ms says so
  // rather than claiming a nominal 1000.
  assert.ok(
    rows[0].line.win_ms > 250 && rows[0].line.win_ms < 800,
    `first window reports its real length (got ${rows[0].line.win_ms}ms)`,
  );
  for (let i = 1; i < rows.length; i++) {
    const observed = rows[i].at - rows[i - 1].at;
    assert.ok(
      Math.abs(rows[i].line.win_ms - observed) <= 30,
      `win_ms ${rows[i].line.win_ms} tracks the observed ${observed}ms`,
    );
  }
});

test("an edge line marks entering and leaving zero", async () => {
  const { state, server, sink } = await startServer();
  await sleep(1300); // at least one zero window closes first
  const c = await connectStream(server.port, server.token, "&binary=1");
  await c.nextJson();
  await sleep(30);
  const jpeg = Buffer.from("edge-frame").toString("base64");
  for (let i = 0; i < 3; i++) {
    state.session.emitFrame(jpeg);
    await sleep(10);
  }
  await sleep(2600); // then silence, so a zero window closes again
  c.close();
  server.close();

  const lines = sink.lines();
  assertContract(lines);
  const capture = sink.hop("daemon.capture");
  const leave = capture.filter((l) => l.edge === "leave_zero");
  const enter = capture.filter((l) => l.edge === "enter_zero");
  assert.equal(leave.length, 1, "one out-of-band line timestamps the resumption");
  assert.equal(leave[0].zero, false, "the leaving window carries the waking frame");
  assert.ok(enter.length >= 1, "the freeze boundary is marked on the way in");
  assert.equal(enter[0].zero, true, "the entering window is zero");
  // The stages are independent: nothing reached the encoder, so its row never
  // left zero and never claims an edge.
  assert.deepEqual(sink.hop("daemon.h264").filter((l) => l.edge), []);
  assertCumulative(lines, "daemon.capture");
});

// ── the drop paths, driven rather than assumed ───────────────────────────────

test("a stalled viewer's overwritten frames are counted as pending_overwrite", async () => {
  const { state, server, sink } = await startServer();
  // ack pacing with no acks IS a stalled viewer: one frame in flight, and the
  // single pending slot behind it takes every newer frame in its place.
  const c = await connectStream(server.port, server.token, "&binary=1&pacing=ack");
  await c.nextJson();
  await sleep(30);
  const jpeg = Buffer.from("overwrite-me").toString("base64");
  const frames = 8;
  for (let i = 0; i < frames; i++) {
    state.session.emitFrame(jpeg);
    await sleep(5);
  }
  await sleep(1400);
  c.close();
  server.close();

  const lines = sink.lines();
  assertContract(lines);
  const capture = sink.hop("daemon.capture");
  const total = (k) => capture.reduce((n, l) => n + (l.dr?.[k] ?? 0), 0);
  // One frame is sent, one occupies the slot, every later one displaces it.
  assert.equal(total("pending_overwrite"), frames - 2, "each displaced frame is counted");
  assert.equal(
    capture.reduce((n, l) => n + l.fi, 0),
    frames,
    "every screencast callback counted as input",
  );
  assert.equal(capture.reduce((n, l) => n + l.fo, 0), frames, "every delivery counted as output");
  assertCumulative(lines, "daemon.capture");
});

test("a saturated encoder drops a run, and the run is what is counted", async () => {
  const { dir, stub } = writeStub(FFMPEG_DEAF, "deaf");
  const big = Buffer.alloc(256 * 1024, 0x41).toString("base64");
  const { state, server, sink } = await startServer(
    { h264Config: { ffmpegPath: stub, encoder: "libx264" } },
    { screenshot: big },
  );
  const c = await connectStream(server.port, server.token, "&codec=h264");
  await c.nextJson();

  // The encoder spawns asynchronously; keep feeding until its stdin is
  // saturated and the refusals show up in a closed window.
  const deadline = Date.now() + 15000;
  let run = 0;
  while (Date.now() < deadline && run < 2) {
    for (let i = 0; i < 6; i++) {
      state.session.emitFrame(big);
      await sleep(5);
    }
    await sleep(1050);
    run = sink.hop("daemon.h264").reduce((n, l) => n + (l.dr?.encoder_input ?? 0), 0);
  }
  c.close();
  server.close();
  fs.rmSync(dir, { recursive: true, force: true });

  const lines = sink.lines();
  assertContract(lines);
  const encode = sink.hop("daemon.h264");
  assert.ok(run >= 2, `a saturated encoder refuses a RUN of frames (got ${run})`);
  const attempted = encode.reduce((n, l) => n + l.fi, 0);
  assert.ok(attempted > run, `every write attempt counted (${attempted} attempts, ${run} refused)`);
  // The stage that never handed anything on is the one that dropped it — the
  // whole point of splitting the daemon into two rows.
  assert.equal(encode.reduce((n, l) => n + l.fo, 0), 0, "the deaf encoder produced no units");
  assert.ok(sink.hop("daemon.capture").reduce((n, l) => n + l.fi, 0) > 0, "capture stayed healthy");
  assertCumulative(lines, "daemon.h264");
});

// Emits the shared corpus once, so the units reaching the counters are the
// same bytes the classification tests assert against.
const FFMPEG_CORPUS = `#!/usr/bin/env node
if (process.argv.includes("-encoders")) {
  process.stdout.write(" V....D libx264 stub\\n");
  process.exit(0);
}
let sent = false;
process.stdin.on("data", () => {
  if (sent) return;
  sent = true;
  process.stdout.write(Buffer.from("AAAAAQkQAAAAAWeqq6ytrq+wsbKztLUAAAABaKqrrK0AAAABZaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6OkAAAABCTAAAAABQaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NEAAAEJMAAAAUGqq6ytrq+wsbKztLW2t7i5uru8vb6/wMEAAAABCTAAAAFBqqusra6vsLGys7S1tre4ubq7vL2+v8DBAAAAAQkQAAAAAWeqq6ytrq+wsbKztLUAAAABaKqrrK0AAAABBqqrrK2ur7CxAAAAAWWqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2NkAAAABCTAAAAABQQAAAwAAAwHerQAAAAEJEAAAAAFlqqusra6vsLGys7S1tre4ubq7vL2+v8DBwsPExcbHyMkAAAABCRAAAAABZ6qrrK2ur7CxsrO0tQAAAAFoqqusrRESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8w", "base64"));
});
process.stdin.on("end", () => process.exit(0));
`;

test("the encode row reports what the framer found in each access unit", async () => {
  const { dir, stub } = writeStub(FFMPEG_CORPUS, "corpus");
  const jpeg = Buffer.from("corpus-frame").toString("base64");
  const { state, server, sink } = await startServer(
    { h264Config: { ffmpegPath: stub, encoder: "libx264" } },
    { screenshot: jpeg },
  );
  const c = await connectStream(server.port, server.token, "&codec=h264");
  await c.nextJson();
  await sleep(400); // the join restarts the encoder; feed only the survivor

  const units = expectedUnits();
  const deadline = Date.now() + 15000;
  let out = 0;
  while (Date.now() < deadline && out < units.length) {
    state.session.emitFrame(jpeg);
    await sleep(60);
    out = sink.hop("daemon.h264").reduce((n, l) => n + l.fo, 0);
  }
  await sleep(1200); // let the window carrying the last unit close
  c.close();
  server.close();
  fs.rmSync(dir, { recursive: true, force: true });

  const lines = sink.lines();
  assertContract(lines);
  const encode = sink.hop("daemon.h264");
  const sum = (k) => encode.reduce((n, l) => n + l[k], 0);
  assert.equal(sum("fo"), units.length, "one count per access unit handed on");
  assert.equal(sum("bo"), stream.length, "bytes out are the corpus, whole");
  assert.equal(sum("idr"), units.filter((u) => u.idr).length, "keyframes");
  assert.equal(sum("sps"), units.filter((u) => u.sps).length, "parameter sets");
  assert.equal(sum("pps"), units.filter((u) => u.pps).length);
  assert.equal(sum("perr"), 0, "every unit parsed");

  const withSeq = encode.filter((l) => l.seq);
  assert.equal(withSeq[0].seq.first, 1, "the stream is numbered from one");
  assert.equal(withSeq.at(-1).seq.last, units.length);
  assert.equal(withSeq.reduce((n, l) => n + l.seq.gaps, 0), 0, "no holes in the numbering");
  assertCumulative(lines, "daemon.h264");
});

// ── seq ──────────────────────────────────────────────────────────────────────

test("seq reports its range, its gaps, and a restart that replays from zero", () => {
  const c = createHopCounters("daemon.h264", { nal: true });
  const emitted = [];
  const close = (edge) => emitted.push(JSON.parse(JSON.stringify(c.close(c.since + 1000, edge))));

  for (const n of [10, 11, 12]) { c.out(100); c.note(n); }
  close();
  for (const n of [14, 15]) { c.out(100); c.note(n); }   // one gap at the boundary, one inside
  close();
  // The daemon restarted: seq replays from 0. A consumer that reads that as a
  // gap reports a 10^6-frame loss and sends everyone chasing a phantom.
  for (const n of [0, 1]) { c.out(100); c.note(n); }
  close();

  assertContract(emitted);
  assert.deepEqual(emitted[0].seq, { first: 10, last: 12, gaps: 0 });
  assert.equal(emitted[1].seq.first, 14);
  assert.equal(emitted[1].seq.last, 15);
  assert.equal(emitted[1].seq.gaps, 1, "the discontinuity across the window boundary is counted");
  assert.equal(emitted[2].seq.reset, true, "going backwards is a restart, not a gap");
  assert.equal(emitted[2].seq.gaps, 0);
  assert.equal(emitted[2].c.fo, 7, "the cumulative twin survives the reset");
});

test("the ticker aligns to the wall clock without a server attached", async () => {
  const rows = [createHopCounters("daemon.capture")];
  const seen = [];
  const ticker = startCounterTicker({ rows, emit: (l) => seen.push({ at: Date.now(), line: l }) });
  await sleep(2300);
  ticker.stop();
  const before = seen.length;
  await sleep(1200);
  assert.equal(seen.length, before, "stop() ends the tick");
  assert.ok(before >= 2, `ticked once a second (got ${before})`);
  for (const r of seen) assert.ok(r.at - (r.line.t + 1) * 1000 < 250, "aligned to the second");
});

// ── NAL classification against the shared corpus ─────────────────────────────

const stream = read("stream.h264");
const manifest = JSON.parse(read("manifest.json"));
const chunks = JSON.parse(read("chunks.json"));

/**
 * Access units the framer must produce from the whole corpus: every labelled
 * case begins an access unit except the one carrying no start code at all,
 * which belongs to the unit before it. Derived from the manifest so the
 * expectation cannot drift away from the labels.
 */
function expectedUnits() {
  const units = [];
  for (const c of manifest.cases) {
    if (c.expect.aud || units.length === 0) {
      units.push({ idr: false, sps: false, pps: false, sei: false, nals: [] });
    }
    const u = units[units.length - 1];
    u.idr ||= c.expect.idr;
    u.sps ||= c.expect.sps;
    u.pps ||= c.expect.pps;
    u.sei ||= c.expect.sei;
    u.nals.push(...c.expect.nals);
  }
  return units;
}

/** Feed `chunks` through a framer and collect every unit's descriptor. */
async function frameInfo(pieces) {
  const out = [];
  const framer = createAccessUnitFramer({
    onAccessUnit: (au, info) => out.push({ ...info, bytes: au.length }),
    flushMs: 5,
  });
  for (const piece of pieces) framer.push(piece);
  await sleep(40); // the last unit waits for the idle flush
  framer.close();
  return out;
}

test("every labelled case classifies exactly as the manifest says", async () => {
  for (const c of manifest.cases) {
    const got = await frameInfo([stream.subarray(c.offset, c.offset + c.length)]);
    assert.equal(got.length, 1, `${c.name}: one access unit`);
    const { bytes, ...info } = got[0];
    assert.equal(bytes, c.length, `${c.name}: the unit is delivered whole`);
    assert.deepEqual(
      { ...info, aud: info.nals.includes(9) },
      { idr: c.expect.idr, sps: c.expect.sps, pps: c.expect.pps, sei: c.expect.sei, nals: c.expect.nals, aud: c.expect.aud },
      c.name,
    );
  }
});

test("classification survives every hostile cut in the straddle corpus", async () => {
  const want = expectedUnits();
  const whole = (await frameInfo([stream])).map(({ bytes, ...i }) => i);
  assert.deepEqual(whole, want, "the whole buffer at once");

  // A start code and its NAL header byte can straddle two stdout chunks. A
  // stateless per-payload scan misses exactly the keyframe a resync waits for,
  // so every cut must classify identically to the whole buffer.
  for (const cut of chunks.cuts) {
    const got = await frameInfo([stream.subarray(0, cut.at), stream.subarray(cut.at)]);
    assert.deepEqual(
      got.map(({ bytes, ...i }) => i),
      want,
      `cut at ${cut.at} — ${cut.why}`,
    );
  }
  // One byte at a time is the same problem taken to its limit.
  const single = await frameInfo(Array.from(stream, (b) => Buffer.from([b])));
  assert.deepEqual(single.map(({ bytes, ...i }) => i), want, "one byte per push");
});

test("a payload with no start code is counted, not crashed on", async () => {
  const c = manifest.cases.find((x) => x.name === "no-nal-at-all");
  const got = await frameInfo([stream.subarray(c.offset, c.offset + c.length)]);
  assert.deepEqual(got[0].nals, [], "nothing to classify");
  assert.equal(got[0].idr, false);
  // A resync reports itself so the encode stage can count it as perr.
  const resyncs = [];
  const framer = createAccessUnitFramer({
    onAccessUnit: () => {},
    onResync: () => resyncs.push(1),
    maxPending: 4096,
  });
  for (let i = 0; i < 6; i++) framer.push(Buffer.alloc(2000, 0x11));
  framer.close();
  assert.ok(resyncs.length > 0, "the resync is reported, not only logged");
});
