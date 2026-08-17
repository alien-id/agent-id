#!/usr/bin/env node

// Tests for the stream protocol's `resize` message — the one extension beyond
// agent-browser's message shapes. A viewer (typically a phone) sends its own
// dimensions — and optionally a HiDPI capture `scale` — and the session
// reshapes the page viewport to match; without it there is no way to get a
// mobile-sized viewport through the stream. Driven end-to-end over real
// sockets against a FAKE CDP session (no browser). Some tests inject the
// resize callback (wire contract: parse, clamp, suspend gating, broadcast);
// the scale tests wire the REAL resizeToViewport so the device-metrics
// override and the capture-cap plumbing are observable in the CDP traffic.
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
} from "../plugins/agent-id-browser/lib/stream-server.mjs";
import { resizeToViewport } from "../plugins/agent-id-browser/lib/session-server.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const FRAME_B64 = Buffer.from("motion-frame-bytes").toString("base64");

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

function makeFakeSession() {
  const handlers = new Map();
  const session = {
    sent: [],
    detached: false,
    on: (event, fn) => handlers.set(event, fn),
    async send(method, params) {
      session.sent.push({ method, params });
      if (method === "Page.captureScreenshot") return { data: FRAME_B64 };
      return {};
    },
    async detach() { session.detached = true; },
    emitFrame(data, metadata = { deviceWidth: 390, deviceHeight: 844, timestamp: Date.now() }) {
      handlers.get("Page.screencastFrame")?.({ data, metadata, sessionId: 1 });
    },
  };
  return session;
}

// A page + CDP-session pair complete enough for the REAL resizeToViewport:
// window-bounds changes land on a fake inner viewport whose height loses
// `chrome` px to window chrome (which is what the compensation pass measures
// and corrects for). Every created session records its CDP traffic; state.sent()
// is the union.
function makeFakeState({ chrome = 87, inner = { width: 1440, height: 813 } } = {}) {
  const sessions = [];
  const page = {
    isClosed: () => false,
    viewportSize: () => ({ ...inner }),
    // resizeWindow evaluates two shapes: the [innerWidth, innerHeight] probe
    // and the {width, height} result. Sniffed by source — the object shape
    // must stay a plain object (it is JSON-serialized into the broadcast).
    evaluate: async (fn) =>
      String(fn).includes("[window.innerWidth") ? [inner.width, inner.height] : { ...inner },
    waitForFunction: async () => {},
    mouse: { move: async () => {}, down: async () => {}, up: async () => {}, wheel: async () => {} },
    keyboard: { down: async () => {}, up: async () => {}, insertText: async () => {} },
  };
  return {
    current: page,
    invalidateRefs() {},
    sessions,
    sent: () => sessions.flatMap((s) => s.sent),
    ctx: {
      newCDPSession: async () => {
        const session = makeFakeSession();
        const send = session.send;
        session.send = async (method, params) => {
          if (method === "Browser.setWindowBounds" && params?.bounds?.width) {
            inner.width = params.bounds.width;
            inner.height = params.bounds.height - chrome;
          }
          return send(method, params);
        };
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
    close: () => sock.destroy(),
  };
}

// ── tests ────────────────────────────────────────────────────────────────────

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
    const status = await client.next();
    assert.deepEqual(resizes, [[390, 844]]);
    assert.equal(status.type, "status");
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
    const status = await client.next();
    assert.deepEqual(resizes, [[390, 844]]);
    assert.equal(status.type, "status");
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
    await client.next();
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

test("resize with scale: override applied, capture caps and refinement follow", async () => {
  const state = makeFakeState();
  const stream = await startStreamServer(state, {
    resize: (w, h, s) => resizeToViewport(state, w, h, s),
  });
  const client = await connectStream(stream.port, stream.token);
  try {
    await client.next(); // greeting
    client.send({ type: "resize", width: 390, height: 844, scale: 2 });
    const status = await client.next();
    assert.equal(status.type, "status");
    assert.deepEqual(status.resized, { width: 390, height: 844, scale: 2 });
    assert.deepEqual(status.viewport, { width: 390, height: 844 });

    // The device-metrics override carries the scale — and deliberately no
    // mobile emulation: the page's only new tell is devicePixelRatio.
    const dso = state.sent().find((s) => s.method === "Emulation.setDeviceMetricsOverride");
    assert.ok(dso, "a scaled resize applies a device-metrics override");
    assert.deepEqual(dso.params, {
      width: 390,
      height: 844,
      deviceScaleFactor: 2,
      mobile: false,
    });

    // The screencast restarts with pixel caps at viewport × scale, so the
    // device-pixel frames actually come through.
    const cast = await until(() =>
      state
        .sent()
        .filter((s) => s.method === "Page.startScreencast")
        .find((s) => s.params.maxWidth === 780),
    );
    assert.ok(cast, "screencast restarted with scaled caps");
    assert.equal(cast.params.maxHeight, 1688);

    // The refinement screenshot keeps the same pixel dimensions: CSS clip
    // geometry at clip.scale = the capture scale (the encoders choke on
    // dimension flips between the two frame sources).
    const live = [...state.sessions]
      .reverse()
      .find((s) => !s.detached && s.sent.some((x) => x.method === "Page.startScreencast"));
    live.emitFrame(FRAME_B64);
    const shot = await until(
      () => state.sent().find((s) => s.method === "Page.captureScreenshot"),
      3000,
    );
    assert.ok(shot, "refinement fired after the screencast went quiet");
    assert.deepEqual(shot.params.clip, { x: 0, y: 0, width: 390, height: 844, scale: 2 });
  } finally {
    client.close();
    stream.close();
  }
});

test("scale clamps to 1..3; garbage means 1", async () => {
  const scales = [];
  const stream = await startStreamServer(makeFakeState(), {
    resize: async (w, h, s) => { scales.push(s); return { width: w, height: h }; },
  });
  const client = await connectStream(stream.port, stream.token);
  try {
    await client.next(); // greeting
    client.send({ type: "resize", width: 390, height: 844, scale: 0.5 });
    assert.equal((await client.next()).resized.scale, 1);
    client.send({ type: "resize", width: 390, height: 844, scale: 7 });
    assert.equal((await client.next()).resized.scale, 3);
    client.send({ type: "resize", width: 390, height: 844, scale: "dense" });
    assert.equal((await client.next()).resized.scale, 1);
    assert.deepEqual(scales, [1, 3, 1]);
  } finally {
    client.close();
    stream.close();
  }
});

test("a two-field resize never touches device metrics (pre-scale behavior)", async () => {
  // Back compatibility: clients that only ever send width/height must get
  // the exact pre-scale pipeline — window resize + chrome compensation and
  // nothing else. No Emulation call may appear anywhere in the CDP traffic.
  const state = makeFakeState();
  const stream = await startStreamServer(state, {
    resize: (w, h, s) => resizeToViewport(state, w, h, s),
  });
  const client = await connectStream(stream.port, stream.token);
  try {
    await client.next(); // greeting
    client.send({ type: "resize", width: 390, height: 844 });
    const status = await client.next();
    assert.deepEqual(status.resized, { width: 390, height: 844, scale: 1 });
    assert.deepEqual(status.viewport, { width: 390, height: 844 });
    await sleep(100); // any (wrong) trailing async CDP work gets to surface
    const emulation = state.sent().filter((s) => s.method.startsWith("Emulation."));
    assert.deepEqual(emulation, [], "no device-metrics traffic for a 1× resize");
  } finally {
    client.close();
    stream.close();
  }
});

test("re-scaling lifts the stale override before measuring; 1× clears it", async () => {
  const state = makeFakeState();
  const stream = await startStreamServer(state, {
    resize: (w, h, s) => resizeToViewport(state, w, h, s),
  });
  const client = await connectStream(stream.port, stream.token);
  try {
    await client.next(); // greeting
    client.send({ type: "resize", width: 390, height: 844, scale: 2 });
    await client.next();
    // A scaled session pins its viewport to the override, which would blind
    // the chrome-compensation measurement of the NEXT resize — the override
    // must be lifted first, then re-applied at the new geometry (the rotated
    // phone case).
    client.send({ type: "resize", width: 844, height: 390, scale: 2 });
    const rotated = await client.next();
    assert.deepEqual(rotated.resized, { width: 844, height: 390, scale: 2 });
    assert.deepEqual(rotated.viewport, { width: 844, height: 390 });
    // Dropping back to 1× clears the override for good.
    client.send({ type: "resize", width: 844, height: 390 });
    const flat = await client.next();
    assert.deepEqual(flat.resized, { width: 844, height: 390, scale: 1 });
    const emulation = state
      .sent()
      .filter((s) => s.method.startsWith("Emulation."))
      .map((s) => (s.method === "Emulation.setDeviceMetricsOverride" ? `set@${s.params.width}x${s.params.height}` : "clear"));
    assert.deepEqual(emulation, ["set@390x844", "clear", "set@844x390", "clear"]);
  } finally {
    client.close();
    stream.close();
  }
});
