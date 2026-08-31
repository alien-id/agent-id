#!/usr/bin/env node

// Wire contract of the `input_focus` status messages — the page-truth focus
// signal viewers use to open/close their keyboard. Driven over real sockets
// against a FAKE CDP session (no browser), like the resize tests: what is
// under test is the stream side — dedup, suspend gating, broadcast shape, and
// the join snapshot. The page side (init script → binding) is covered by the
// local-only integration test in tests/integration/browser-focus-e2e.mjs.
//
// Run: node --test tests/test-browser-stream-focus.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import net from "node:net";
import { once } from "node:events";

import {
  startStreamServer,
  makeFrameParser,
} from "../plugins/agent-id-browser/lib/stream-server.mjs";

// ── fakes (the resize tests' shapes) ─────────────────────────────────────────

function makeFakeSession() {
  const handlers = new Map();
  return {
    on: (event, fn) => handlers.set(event, fn),
    async send() {
      return {};
    },
    async detach() {},
  };
}

function makeFakeState() {
  const page = {
    isClosed: () => false,
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
    ctx: { newCDPSession: async () => makeFakeSession() },
  };
}

// ── minimal WS client ────────────────────────────────────────────────────────

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
    send: (obj) => sock.write(maskedTextFrame(JSON.stringify(obj))),
    async next(timeoutMs = 2000) {
      if (queue.length)
        return JSON.parse(queue.shift().payload.toString("utf8"));
      const frame = await new Promise((resolve, reject) => {
        const t = setTimeout(
          () => reject(new Error("timed out waiting for a frame")),
          timeoutMs
        );
        waiters.push((m) => {
          clearTimeout(t);
          resolve(m);
        });
      });
      return JSON.parse(frame.payload.toString("utf8"));
    },
    close: () => sock.destroy(),
  };
}

async function nextInputFocus(client) {
  for (let i = 0; i < 10; i++) {
    const msg = await client.next();
    if (msg.input_focus !== undefined) return msg.input_focus;
  }
  throw new Error("no input_focus status arrived");
}

// ── tests ────────────────────────────────────────────────────────────────────

test("a focus report reaches the viewer as an input_focus status", async () => {
  const stream = await startStreamServer(makeFakeState(), { log: () => {} });
  const client = await connectStream(stream.port, stream.token);
  await client.next(); // join status
  stream.inputFocus({ editable: true, type: "password" });
  const focus = await nextInputFocus(client);
  assert.deepEqual(focus, { editable: true, type: "password" });
  client.close();
  await stream.close();
});

test("identical consecutive reports are deduplicated", async () => {
  const stream = await startStreamServer(makeFakeState(), { log: () => {} });
  const client = await connectStream(stream.port, stream.token);
  await client.next(); // join status
  stream.inputFocus({ editable: true, type: "text" });
  await nextInputFocus(client);
  stream.inputFocus({ editable: true, type: "text" });
  stream.inputFocus({ editable: false });
  const focus = await nextInputFocus(client);
  assert.deepEqual(
    focus,
    { editable: false },
    "the duplicate must be swallowed, so the NEXT message is the blur"
  );
  client.close();
  await stream.close();
});

test("focus reports are suppressed while a credential fill suspends the feed", async () => {
  const state = makeFakeState();
  const stream = await startStreamServer(state, { log: () => {} });
  const client = await connectStream(stream.port, stream.token);
  await client.next(); // join status
  stream.suspend();
  stream.inputFocus({ editable: true, type: "password" });
  stream.resume();
  stream.inputFocus({ editable: true, type: "email" });
  const focus = await nextInputFocus(client);
  assert.deepEqual(
    focus,
    { editable: true, type: "email" },
    "the suspended-era report must never surface; the first visible one is post-resume"
  );
  client.close();
  await stream.close();
});

test("a viewer joining with a field already focused learns it from the join status", async () => {
  const stream = await startStreamServer(makeFakeState(), { log: () => {} });
  const early = await connectStream(stream.port, stream.token);
  await early.next(); // join status
  stream.inputFocus({ editable: true, type: "email", inputmode: "email" });
  await nextInputFocus(early);
  const late = await connectStream(stream.port, stream.token);
  const join = await late.next();
  assert.deepEqual(join.input_focus, {
    editable: true,
    type: "email",
    inputmode: "email",
  });
  early.close();
  late.close();
  await stream.close();
});
