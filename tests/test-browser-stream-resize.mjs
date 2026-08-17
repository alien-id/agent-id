#!/usr/bin/env node

// Tests for the stream protocol's `resize` message — the one extension beyond
// agent-browser's message shapes. A viewer (typically a phone) sends its own
// dimensions — and optionally a HiDPI capture `scale` — and the session
// reshapes the page viewport to match; without it there is no way to get a
// mobile-sized viewport through the stream. Driven end-to-end over real
// sockets against FAKE CDP sessions (no browser): the window resize is the
// injected callback, and every created CDP session records its traffic so the
// scale tests can pin the override lifecycle, the capture calls, and what
// actually got delivered. Delivered PIXEL dimensions against real Chrome are
// covered separately by test-browser-stream-scale-live.mjs.
//
// Run: node --test tests/test-browser-stream-resize.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import net from "node:net";
import { once } from "node:events";

import {
  startStreamServer,
  makeFrameParser,
  effectiveScale,
} from "../plugins/agent-id-browser/lib/stream-server.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// What the fake captureScreenshot returns vs what the fake screencast emits —
// distinct payloads, so a test can tell WHICH source a delivered frame came from.
const SHOT_B64 = Buffer.from("capture-screenshot-bytes").toString("base64");
const CAST_B64 = Buffer.from("raw-screencast-bytes").toString("base64");

// Poll until `fn` returns truthy (the resize pipeline is async behind the
// input chain).
async function until(fn, ms = 2000) {
  const deadline = Date.now() + ms;
  for (;;) {
    const v = fn();
    if (v || Date.now() > deadline) return v;
    await sleep(25);
  }
}

// ── fakes ────────────────────────────────────────────────────────────────────

function makeFakeSession(page) {
  const handlers = new Map();
  const session = {
    page,
    sent: [],
    detached: false,
    on: (event, fn) => handlers.set(event, fn),
    async send(method, params) {
      session.sent.push({ method, params });
      if (method === "Page.captureScreenshot") return { data: SHOT_B64 };
      return {};
    },
    async detach() { session.detached = true; },
    emitFrame(data = CAST_B64, metadata = { deviceWidth: 390, deviceHeight: 844, timestamp: Date.now() }) {
      handlers.get("Page.screencastFrame")?.({ data, metadata, sessionId: 1 });
    },
  };
  return session;
}

function makeFakePage(inner = { width: 390, height: 844 }) {
  return {
    inner,
    isClosed: () => false,
    viewportSize: () => ({ ...inner }),
    // measureViewport reads the page's own innerWidth/innerHeight.
    evaluate: async () => ({ ...inner }),
    mouse: { move: async () => {}, down: async () => {}, up: async () => {}, wheel: async () => {} },
    keyboard: { down: async () => {}, up: async () => {}, insertText: async () => {} },
  };
}

function makeFakeState(inner) {
  const sessions = [];
  return {
    current: makeFakePage(inner),
    invalidateRefs() {},
    sessions,
    sent: () => sessions.flatMap((s) => s.sent),
    liveCast: () =>
      [...sessions].reverse().find((s) => !s.detached && s.sent.some((x) => x.method === "Page.startScreencast")),
    ctx: {
      newCDPSession: async (page) => {
        const session = makeFakeSession(page);
        sessions.push(session);
        return session;
      },
    },
  };
}

// ── minimal WS client (client → server frames are masked, RFC 6455) ──────────

function maskedTextFrame(payload) {
  const data = Buffer.from(payload, "utf8");
  const mask = crypto.randomBytes(4);
  const masked = Buffer.from(data);
  for (let i = 0; i < masked.length; i++) masked[i] ^= mask[i & 3];
  let header;
  if (data.length < 126) header = Buffer.from([0x81, 0x80 | data.length]);
  else {
    header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 0x80 | 126;
    header.writeUInt16BE(data.length, 2);
  }
  return Buffer.concat([header, mask, masked]);
}

async function connectStream(port, token) {
  const sock = net.connect(port, "127.0.0.1");
  await once(sock, "connect");
  const key = crypto.randomBytes(16).toString("base64");
  sock.write(
    `GET /?token=${token} HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\n` +
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
    send: (obj) => sock.write(maskedTextFrame(JSON.stringify(obj))),
    async next(timeoutMs = 2000) {
      if (queue.length) return JSON.parse(queue.shift().payload.toString("utf8"));
      const frame = await new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error("timed out waiting for a frame")), timeoutMs);
        waiters.push((m) => { clearTimeout(t); resolve(m); });
      });
      return JSON.parse(frame.payload.toString("utf8"));
    },
    // Skip frames until the next `status` message (scaled sessions interleave
    // delivered frames with broadcasts).
    async nextStatus(timeoutMs = 2000) {
      for (;;) {
        const msg = await this.next(timeoutMs);
        if (msg.type === "status") return msg;
      }
    },
    close: () => sock.destroy(),
  };
}

// ── the classic resize contract ──────────────────────────────────────────────

test("resize: viewer dimensions reach the callback; the viewport is broadcast", async () => {
  const resizes = [];
  const stream = await startStreamServer(makeFakeState(), {
    // Fake session-side resize: the "window chrome" eats 87px of height.
    resize: async (w, h) => { resizes.push([w, h]); return { width: w, height: h - 87 }; },
  });
  const client = await connectStream(stream.port, stream.token);
  try {
    const hello = await client.next();
    assert.equal(hello.type, "status");
    client.send({ type: "resize", width: 390, height: 844 });
    const status = await client.nextStatus();
    assert.deepEqual(resizes, [[390, 844]]);
    assert.deepEqual(status.resized, { width: 390, height: 844, scale: 1 });
    assert.deepEqual(status.viewport, { width: 390, height: 757 });
  } finally {
    client.close();
    stream.close();
  }
});

test("resize with unknown extra fields is applied and the extras ignored", async () => {
  // Forward compatibility: a viewer from a newer protocol revision may attach
  // fields this daemon does not know. The handler reads only the known
  // fields, so the message must behave exactly like a plain resize —
  // applied, broadcast, extras neither acted on nor echoed.
  const resizes = [];
  const stream = await startStreamServer(makeFakeState(), {
    resize: async (w, h) => { resizes.push([w, h]); return { width: w, height: h - 87 }; },
  });
  const client = await connectStream(stream.port, stream.token);
  try {
    const hello = await client.next();
    assert.equal(hello.type, "status");
    client.send({ type: "resize", width: 390, height: 844, tint: "sepia", hdr: true });
    const status = await client.nextStatus();
    assert.deepEqual(resizes, [[390, 844]]);
    assert.deepEqual(status.resized, { width: 390, height: 844, scale: 1 });
    assert.deepEqual(status.viewport, { width: 390, height: 757 });
    assert.ok(!("tint" in status) && !("hdr" in status), "unknown fields are not echoed back");
  } finally {
    client.close();
    stream.close();
  }
});

test("resize: out-of-range dimensions clamp instead of failing the viewer", async () => {
  const resizes = [];
  const stream = await startStreamServer(makeFakeState(), {
    resize: async (w, h) => { resizes.push([w, h]); return { width: w, height: h }; },
  });
  const client = await connectStream(stream.port, stream.token);
  try {
    await client.next(); // greeting
    client.send({ type: "resize", width: 50, height: 99999 });
    await client.nextStatus();
    assert.deepEqual(resizes, [[200, 4096]]);
  } finally {
    client.close();
    stream.close();
  }
});

test("resize: garbage dimensions are ignored, not resized-to-minimum", async () => {
  const resizes = [];
  const stream = await startStreamServer(makeFakeState(), {
    resize: async (w, h) => { resizes.push([w, h]); return null; },
  });
  const client = await connectStream(stream.port, stream.token);
  try {
    await client.next(); // greeting
    client.send({ type: "resize" });
    client.send({ type: "resize", width: "wide", height: 700 });
    await sleep(150);
    assert.deepEqual(resizes, []);
  } finally {
    client.close();
    stream.close();
  }
});

test("resize: dropped while a credential fill has the stream suspended", async () => {
  const resizes = [];
  const stream = await startStreamServer(makeFakeState(), {
    resize: async (w, h) => { resizes.push([w, h]); return null; },
  });
  const client = await connectStream(stream.port, stream.token);
  try {
    await client.next(); // greeting
    stream.suspend();
    await client.next(); // suspended:true broadcast
    client.send({ type: "resize", width: 390, height: 844 });
    await sleep(150);
    assert.deepEqual(resizes, []);
    stream.resume();
  } finally {
    client.close();
    stream.close();
  }
});

// ── the HiDPI capture scale ──────────────────────────────────────────────────

test("scaled resize: override on the cast session, capture-delivered frames, remeasured viewport", async () => {
  const state = makeFakeState({ width: 390, height: 844 });
  const stream = await startStreamServer(state, {
    // The callback's measurement is deliberately STALE (what a window that
    // cannot shrink to the request reports): the broadcast must carry the
    // post-override remeasure instead.
    resize: async () => ({ width: 500, height: 844 }),
  });
  const client = await connectStream(stream.port, stream.token);
  try {
    await client.next(); // greeting
    client.send({ type: "resize", width: 390, height: 844, scale: 2 });
    const status = await client.nextStatus();
    assert.deepEqual(status.resized, { width: 390, height: 844, scale: 2 });
    // Remeasured after the override landed — NOT the callback's stale value.
    assert.deepEqual(status.viewport, { width: 390, height: 844 });

    // The override rides the live cast session, before the cast starts, with
    // exact params — and deliberately no mobile emulation.
    const live = state.liveCast();
    assert.ok(live, "a cast session is live after the scaled resize");
    const methods = live.sent.map((s) => s.method);
    const dsoAt = methods.indexOf("Emulation.setDeviceMetricsOverride");
    assert.ok(dsoAt >= 0, "the scaled cast session carries the override");
    assert.ok(dsoAt < methods.indexOf("Page.startScreencast"), "override applied before the cast starts");
    assert.deepEqual(live.sent[dsoAt].params, {
      width: 390,
      height: 844,
      deviceScaleFactor: 2,
      mobile: false,
    });
    // The cast stays a CSS-sized damage feed (integer caps, not multiplied):
    // delivered scaled frames come from captureScreenshot instead.
    const cast = live.sent.find((s) => s.method === "Page.startScreencast");
    assert.equal(cast.params.maxWidth, 390);
    assert.equal(cast.params.maxHeight, 844);

    // Motion: a screencast frame is a damage tick — the delivered frame is
    // the capture's payload, never the cast's CSS-pixel payload.
    live.emitFrame(CAST_B64);
    const frames = [];
    while (!frames.some((f) => f.refinement)) {
      const msg = await client.next(3000);
      if (msg.type === "frame") frames.push(msg);
    }
    assert.ok(frames.length >= 2, "a motion frame and a refinement frame arrived");
    for (const f of frames) {
      assert.equal(f.data, SHOT_B64, "every delivered frame comes from captureScreenshot");
    }
    assert.ok(frames.some((f) => !f.refinement), "the damage tick produced a motion frame");
    assert.equal(frames[0].metadata.deviceWidth, 390, "metadata stays CSS");

    // Both capture calls pin clip.scale=1 (the override already renders at
    // device pixels — a further multiply would deliver 4×): motion at the
    // stream quality, refinement at the refinement quality.
    const shots = live.sent.filter((s) => s.method === "Page.captureScreenshot");
    assert.ok(shots.length >= 2, "motion capture and refinement capture both fired");
    assert.equal(shots[0].params.quality, 80);
    assert.equal(shots[shots.length - 1].params.quality, 90);
    for (const s of shots) {
      assert.deepEqual(s.params.clip, { x: 0, y: 0, width: 390, height: 844, scale: 1 });
    }
  } finally {
    client.close();
    stream.close();
  }
});

test("effectiveScale: nearest-integer rounding, axis and pixel budgets", () => {
  // Rounding to nearest integer, clamped 1..3.
  assert.equal(effectiveScale(390, 844, 2), 2);
  assert.equal(effectiveScale(390, 844, 0.5), 1);
  assert.equal(effectiveScale(390, 844, 1.4), 1);
  assert.equal(effectiveScale(390, 844, 2.5), 3);
  assert.equal(effectiveScale(390, 844, 7), 3);
  // Axis budget: no scaled axis over 4096 device pixels.
  assert.equal(effectiveScale(2000, 1000, 3), 2);
  assert.equal(effectiveScale(2100, 2100, 2), 1);
  // Pixel budget: axes fit (4080 ≤ 4096) but 4080×4080 outgrows one 4K frame.
  assert.equal(effectiveScale(2040, 2040, 2), 1);
  assert.equal(effectiveScale(4096, 4096, 3), 1);
});

test("scale over budget is served at the largest scale that fits", async () => {
  const stream = await startStreamServer(makeFakeState({ width: 2000, height: 1000 }), {
    resize: async (w, h) => ({ width: w, height: h }),
  });
  const client = await connectStream(stream.port, stream.token);
  try {
    await client.next(); // greeting
    client.send({ type: "resize", width: 2000, height: 1000, scale: 3 });
    assert.equal((await client.nextStatus()).resized.scale, 2); // 3× would breach the 4096 axis
    client.send({ type: "resize", width: 2040, height: 2040, scale: 2 });
    assert.equal((await client.nextStatus()).resized.scale, 1); // 2× fits the axes, not the pixel budget
    client.send({ type: "resize", width: 390, height: 844, scale: "dense" });
    assert.equal((await client.nextStatus()).resized.scale, 1); // garbage means 1
  } finally {
    client.close();
    stream.close();
  }
});

test("a two-field resize never touches device metrics (pre-scale behavior)", async () => {
  // Back compatibility: clients that only ever send width/height must get
  // the exact pre-scale pipeline — the injected window resize and nothing
  // else. No Emulation call may appear anywhere in the CDP traffic, and the
  // cast must not restart.
  const state = makeFakeState({ width: 390, height: 844 });
  const stream = await startStreamServer(state, {
    resize: async (w, h) => ({ width: w, height: h }),
  });
  const client = await connectStream(stream.port, stream.token);
  try {
    await client.next(); // greeting
    await until(() => state.liveCast());
    const preCast = state.liveCast();
    client.send({ type: "resize", width: 390, height: 844 });
    const status = await client.nextStatus();
    assert.deepEqual(status.resized, { width: 390, height: 844, scale: 1 });
    await sleep(100); // any (wrong) trailing async CDP work gets to surface
    const emulation = state.sent().filter((s) => s.method.startsWith("Emulation."));
    assert.deepEqual(emulation, [], "no device-metrics traffic for a 1× resize");
    assert.equal(state.liveCast(), preCast, "a 1×→1× resize does not restart the cast");
  } finally {
    client.close();
    stream.close();
  }
});

test("the override follows the cast: retargets to the new tab, dies at 1×", async () => {
  const state = makeFakeState({ width: 390, height: 844 });
  const stream = await startStreamServer(state, {
    resize: async (w, h) => ({ width: w, height: h }),
  });
  const client = await connectStream(stream.port, stream.token);
  try {
    await client.next(); // greeting
    client.send({ type: "resize", width: 390, height: 844, scale: 2 });
    await client.nextStatus();
    const scaledSession = state.liveCast();
    assert.ok(scaledSession.sent.some((s) => s.method === "Emulation.setDeviceMetricsOverride"));

    // Tab switch: the retarget poll must attach to the NEW page and apply
    // the override THERE (overrides revert with their session, so the old
    // tab needs no explicit cleanup — its session detaches).
    const pageB = makeFakePage({ width: 390, height: 844 });
    state.current = pageB;
    await until(() => state.liveCast() !== scaledSession && state.liveCast()?.page === pageB);
    const retargeted = state.liveCast();
    assert.equal(retargeted.page, pageB, "the cast follows the current tab");
    assert.ok(scaledSession.detached, "the old tab's session (and its override) is gone");
    const methods = retargeted.sent.map((s) => s.method);
    const dsoAt = methods.indexOf("Emulation.setDeviceMetricsOverride");
    assert.ok(dsoAt >= 0 && dsoAt < methods.indexOf("Page.startScreencast"),
      "the new tab gets the override before its cast starts");
    assert.deepEqual(retargeted.sent[dsoAt].params, {
      width: 390, height: 844, deviceScaleFactor: 2, mobile: false,
    });

    // Back to 1×: the replacement cast session carries no override at all.
    client.send({ type: "resize", width: 390, height: 844 });
    const status = await client.nextStatus();
    assert.equal(status.resized.scale, 1);
    await until(() => state.liveCast() && state.liveCast() !== retargeted);
    const flat = state.liveCast();
    assert.ok(retargeted.detached, "the scaled session is replaced");
    assert.equal(
      flat.sent.filter((s) => s.method.startsWith("Emulation.")).length,
      0,
      "a 1× session never sees an Emulation call",
    );
  } finally {
    client.close();
    stream.close();
  }
});
