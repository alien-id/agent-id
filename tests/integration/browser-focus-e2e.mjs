#!/usr/bin/env node

// LOCAL-ONLY end-to-end for the input-focus events: a REAL Chromium (via the
// plugin's own patchright loader, driving installed Chrome) renders a fixture
// page with fields at fixed coordinates, viewer taps arrive as real
// mousePressed/mouseReleased over the stream WebSocket, and the test asserts
// the `input_focus` status messages the viewer-gated focus poller produces —
// text, password, inputmode, a non-editable button, and a field INSIDE an
// iframe (the poller walks frames; document.hasFocus() picks the right one).
//
// Deliberately not part of `npm test` (the CI glob only picks tests/test-*.mjs):
// it needs a local Chrome. Run it by hand when touching the stream or the
// focus-reporting script:
//
//   node --test tests/integration/browser-focus-e2e.mjs
//
// Skips cleanly when patchright/Chrome is unavailable.

import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import net from "node:net";
import { once } from "node:events";

import {
  startStreamServer,
  makeFrameParser,
} from "../../plugins/agent-id-browser/lib/stream-server.mjs";
import { loadChromium } from "../../plugins/agent-id-browser/lib/launch.mjs";

const FIXTURE = `data:text/html,${encodeURIComponent(`
<!doctype html><meta name="viewport" content="width=device-width">
<style>
  body { margin: 0; }
  input, button, iframe { position: absolute; width: 200px; height: 40px; left: 100px; }
</style>
<input id="text"    type="text"                        style="top: 50px">
<input id="pass"    type="password"                    style="top: 150px">
<input id="num"     type="text" inputmode="numeric"    style="top: 250px">
<button id="button" style="top: 350px">not editable</button>
<iframe style="top: 430px; height: 100px" srcdoc="
  <style>input { position: absolute; left: 20px; top: 20px; width: 150px; height: 30px }</style>
  <input id='framed' type='email'>"></iframe>
`)}`;

// Field centers in CSS px (the fixture pins everything absolutely).
const AT = {
  text: { x: 200, y: 70 },
  pass: { x: 200, y: 170 },
  num: { x: 200, y: 270 },
  button: { x: 200, y: 370 },
  framed: { x: 100 + 20 + 75, y: 430 + 20 + 15 },
};

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
    send: (obj) => sock.write(maskedTextFrame(JSON.stringify(obj))),
    async nextInputFocus(timeoutMs = 5000) {
      const deadline = Date.now() + timeoutMs;
      for (;;) {
        let msg;
        if (queue.length) msg = queue.shift();
        else {
          msg = await new Promise((resolve, reject) => {
            const t = setTimeout(
              () => reject(new Error("timed out waiting for input_focus")),
              Math.max(1, deadline - Date.now()),
            );
            waiters.push((m) => { clearTimeout(t); resolve(m); });
          });
        }
        let parsed;
        try {
          parsed = JSON.parse(msg.payload.toString("utf8"));
        } catch {
          continue; // a binary/odd frame — screencast traffic, not ours
        }
        // Frames and other statuses flow constantly; only focus reports matter.
        if (parsed && parsed.type === "status" && parsed.input_focus !== undefined) {
          return parsed.input_focus;
        }
      }
    },
    close: () => sock.destroy(),
  };
}

async function tap(client, { x, y }) {
  client.send({ type: "input_mouse", eventType: "mousePressed", x, y, button: "left" });
  client.send({ type: "input_mouse", eventType: "mouseReleased", x, y, button: "left" });
}

let chromium = null;
try {
  chromium = await loadChromium();
} catch {
  chromium = null;
}

test("taps on the fixture report page-truth focus over the stream", { skip: !chromium && "patchright/Chrome unavailable" }, async () => {
  const browser = await chromium.launch({ channel: "chrome", headless: true });
  try {
    const ctx = await browser.newContext({ viewport: { width: 800, height: 600 } });
    const state = { current: null, ctx, invalidateRefs() {} };
    const page = await ctx.newPage();
    state.current = page;
    await page.goto(FIXTURE);

    const stream = await startStreamServer(state, { log: () => {} });
    const client = await connectStream(stream.port, stream.token);
    try {
      await tap(client, AT.text);
      assert.deepEqual(await client.nextInputFocus(), { editable: true, type: "text" });

      await tap(client, AT.pass);
      assert.deepEqual(await client.nextInputFocus(), { editable: true, type: "password" });

      await tap(client, AT.num);
      assert.deepEqual(await client.nextInputFocus(), {
        editable: true,
        type: "text",
        inputmode: "numeric",
      });

      await tap(client, AT.button);
      assert.deepEqual(
        await client.nextInputFocus(),
        { editable: false },
        "a button steals focus from the field but must read as not-editable",
      );

      await tap(client, AT.framed);
      assert.deepEqual(
        await client.nextInputFocus(),
        { editable: true, type: "email" },
        "a field inside an iframe must report through the same channel",
      );
    } finally {
      client.close();
      await stream.close();
    }
  } finally {
    await browser.close();
  }
});
