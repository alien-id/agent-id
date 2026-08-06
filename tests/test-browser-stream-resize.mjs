#!/usr/bin/env node

// Tests for the stream protocol's `resize` message — the one extension beyond
// agent-browser's message shapes. A viewer (typically a phone) sends its own
// dimensions and the session reshapes the page viewport to match; without it
// there is no way to get a mobile-sized viewport through the stream. Driven
// end-to-end over real sockets against a FAKE CDP session (no browser): the
// resize itself is the injected callback, so what's under test is the wire
// contract — parse, clamp, suspend gating, and the status broadcast.
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

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── fakes ────────────────────────────────────────────────────────────────────

function makeFakeSession() {
  const handlers = new Map();
  return {
    on: (event, fn) => handlers.set(event, fn),
    async send() { return {}; },
    async detach() {},
  };
}

function makeFakeState() {
  const page = {
    isClosed: () => false,
    mouse: { move: async () => {}, down: async () => {}, up: async () => {}, wheel: async () => {} },
    keyboard: { down: async () => {}, up: async () => {}, insertText: async () => {} },
  };
  return {
    current: page,
    invalidateRefs() {},
    ctx: { newCDPSession: async () => makeFakeSession() },
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
    assert.deepEqual(status.resized, { width: 390, height: 844 });
    assert.deepEqual(status.viewport, { width: 390, height: 757 });
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
