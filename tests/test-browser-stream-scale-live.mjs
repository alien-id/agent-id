#!/usr/bin/env node

// LIVE test for the stream's HiDPI capture scale — real Chrome, real pixels.
//
// The fake-CDP suites pin the protocol and the CDP call shapes; this one pins
// what actually matters and cannot be faked: the PIXEL DIMENSIONS of the
// frames a viewer receives. Chrome's screencast delivers CSS-pixel frames no
// matter what devicePixelRatio says, and captureScreenshot renders at device
// pixels — so the invariant under test is that at any scale, every delivered
// frame (motion and refinement alike) has identical viewport×scale
// dimensions, that the device-metrics override really lands (and follows a
// tab switch), and that the broadcast viewport is the page's post-override
// truth rather than the stale pre-override measurement.
//
// Skips automatically when patchright / Chrome are not installed.
//
// Run: node --test tests/test-browser-stream-scale-live.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";
import { once } from "node:events";

import { resolvePatchright, launchContext } from "../plugins/agent-id-browser/lib/launch.mjs";
import { startStreamServer, makeFrameParser } from "../plugins/agent-id-browser/lib/stream-server.mjs";
import { chromeCompensatedBounds } from "../plugins/agent-id-browser/lib/session-server.mjs";

const patchrightAvailable = !!resolvePatchright();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// A page that repaints continuously (screencast damage); refinement needs a
// QUIET page, so tests navigate to the static page when they want it.
const ANIMATED = "data:text/html," + encodeURIComponent(`<!doctype html>
<title>scale probe</title><body style="margin:0">
<div id="t" style="font:20px monospace">tick</div>
<script>
  setInterval(() => { t.textContent = Date.now() + " " + Math.random(); }, 30);
</script>`);
const STATIC = "data:text/html," + encodeURIComponent(`<!doctype html>
<title>quiet probe</title><body style="margin:0"><p style="font:20px monospace">still</p>`);

// ── jpeg dimensions (SOF scan) ───────────────────────────────────────────────

function jpegDims(b64) {
  const buf = Buffer.from(b64, "base64");
  let i = 2;
  while (i < buf.length - 9) {
    if (buf[i] !== 0xff) { i++; continue; }
    const marker = buf[i + 1];
    if (marker >= 0xc0 && marker <= 0xcf && ![0xc4, 0xc8, 0xcc].includes(marker)) {
      return { height: buf.readUInt16BE(i + 5), width: buf.readUInt16BE(i + 7) };
    }
    i += 2 + buf.readUInt16BE(i + 2);
  }
  return null;
}

// ── the session-side resize (window bounds + chrome compensation) ────────────

async function resizeWindowOnce(ctx, page, width, height) {
  const cdp = await ctx.newCDPSession(page);
  try {
    const { windowId } = await cdp.send("Browser.getWindowForTarget");
    await cdp.send("Browser.setWindowBounds", { windowId, bounds: { windowState: "normal" } }).catch(() => {});
    await cdp.send("Browser.setWindowBounds", { windowId, bounds: { width, height } });
  } finally {
    await cdp.detach().catch(() => {});
  }
  await sleep(250);
  return page.evaluate(() => ({ width: window.innerWidth, height: window.innerHeight })).catch(() => null);
}

async function resizeToViewport(ctx, state, width, height) {
  const page = state.current;
  if (!page || page.isClosed?.()) return null;
  const first = await resizeWindowOnce(ctx, page, width, height);
  const second = chromeCompensatedBounds({ width, height }, first);
  if (!second) return first;
  return (await resizeWindowOnce(ctx, page, second.width, second.height)) ?? first;
}

// ── minimal WS client (masked frames, RFC 6455) ──────────────────────────────

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
    async next(timeoutMs = 5000) {
      if (queue.length) return JSON.parse(queue.shift().payload.toString("utf8"));
      const frame = await new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error("timed out waiting for a ws message")), timeoutMs);
        waiters.push((m) => { clearTimeout(t); resolve(m); });
      });
      return JSON.parse(frame.payload.toString("utf8"));
    },
    async nextStatus(timeoutMs = 10000) {
      const deadline = Date.now() + timeoutMs;
      for (;;) {
        const msg = await this.next(Math.max(100, deadline - Date.now()));
        if (msg.type === "status") return msg;
      }
    },
    close: () => sock.destroy(),
  };
}

// Collect delivered frames until `want` of them match the expected dims (or
// timeout). Returns every frame seen, tagged with its decoded dimensions.
async function collectFrames(client, { want, dims, timeoutMs = 15000 }) {
  const frames = [];
  const matches = () => frames.filter((f) => f.dims && f.dims.width === dims.width && f.dims.height === dims.height);
  const deadline = Date.now() + timeoutMs;
  while (matches().length < want && Date.now() < deadline) {
    let msg;
    try {
      msg = await client.next(Math.max(100, deadline - Date.now()));
    } catch {
      break;
    }
    if (msg.type !== "frame") continue;
    frames.push({ refinement: !!msg.refinement, metadata: msg.metadata, dims: jpegDims(msg.data) });
  }
  return frames;
}

// Frames may straddle a mode switch (a staged pre-switch frame can flush
// late). The invariant is: once the first frame at the NEW dimensions
// arrives, every later frame has exactly those dimensions.
function assertStableAfterSwitch(frames, dims, label) {
  const at = frames.findIndex((f) => f.dims && f.dims.width === dims.width && f.dims.height === dims.height);
  const seen = frames.map((f) => (f.dims ? `${f.dims.width}x${f.dims.height}` : "?")).join(",");
  assert.ok(at >= 0, `${label}: at least one ${dims.width}×${dims.height} frame arrived (saw: ${seen || "none"})`);
  for (const f of frames.slice(at)) {
    assert.deepEqual(
      { width: f.dims.width, height: f.dims.height },
      dims,
      `${label}: no dimension flips after the switch (motion and refinement identical)`,
    );
  }
}

test(
  "scaled stream against real Chrome: delivered pixels, override lifecycle, remeasured viewport",
  { skip: patchrightAvailable ? false : "patchright/Chrome not installed" },
  async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "stream-scale-live-"));
    let ctx = null;
    let stream = null;
    let client = null;
    try {
      ctx = await launchContext({ profileDir: dir, headless: true });
      const pageA = ctx.pages()[0] || (await ctx.newPage());
      await pageA.goto(ANIMATED);
      const state = { current: pageA, ctx, invalidateRefs() {} };
      stream = await startStreamServer(state, {
        log: () => {},
        resize: (w, h) => resizeToViewport(ctx, state, w, h),
      });
      client = await connectStream(stream.port, stream.token);
      await client.next(); // greeting

      // ── scale 2: the delivered stream is viewport × 2, with no flips ──────
      client.send({ type: "resize", width: 390, height: 844, scale: 2 });
      let status;
      for (;;) {
        status = await client.nextStatus();
        if (status.resized) break;
      }
      assert.deepEqual(status.resized, { width: 390, height: 844, scale: 2 });
      // The broadcast is the page's POST-override truth. The window cannot
      // shrink to 390 css px (Chrome's minimum window width is wider), so a
      // pre-override measurement would report ~500×844 — only the override
      // pins the viewport to the request. This assert fails without the
      // remeasure.
      assert.deepEqual(status.viewport, { width: 390, height: 844 });
      assert.equal(await pageA.evaluate(() => devicePixelRatio), 2, "the override is live on the page");

      const scaled = { width: 780, height: 1688 };
      const motion = await collectFrames(client, { want: 4, dims: scaled });
      assertStableAfterSwitch(motion, scaled, "scale-2 motion");
      const anyScaled = motion.find((f) => f.dims && f.dims.width === scaled.width);
      assert.equal(anyScaled.metadata.deviceWidth, 390, "metadata stays CSS px");
      assert.equal(anyScaled.metadata.deviceHeight, 844, "metadata stays CSS px");

      // Quiet page → the refinement path must produce the SAME dimensions.
      await pageA.goto(STATIC);
      const refined = await collectFrames(client, { want: 1, dims: scaled, timeoutMs: 10000 }).then(
        async (frames) => {
          // keep collecting until a refinement-flagged frame shows up
          const deadline = Date.now() + 10000;
          while (!frames.some((f) => f.refinement) && Date.now() < deadline) {
            frames.push(...(await collectFrames(client, { want: 1, dims: scaled, timeoutMs: 2000 })));
          }
          return frames;
        },
      );
      const refinement = refined.find((f) => f.refinement);
      assert.ok(refinement, "a refinement frame arrived on the quiet page");
      assert.deepEqual(refinement.dims, scaled, "refinement pixels match motion pixels exactly");

      // ── tab switch: the override follows the cast to the new tab ─────────
      const pageB = await ctx.newPage();
      await pageB.goto(ANIMATED);
      state.current = pageB;
      // The retarget poll flips the cast on its own clock (~500ms) — wait for
      // the override to land on the new tab before asserting around it.
      let dprB = 1;
      const retargetDeadline = Date.now() + 5000;
      while (dprB !== 2 && Date.now() < retargetDeadline) {
        await sleep(100);
        dprB = await pageB.evaluate(() => devicePixelRatio);
      }
      assert.equal(dprB, 2, "the new tab gets the override");
      assert.equal(await pageA.evaluate(() => devicePixelRatio), 1, "the old tab reverts (override died with its session)");
      const afterSwitch = await collectFrames(client, { want: 3, dims: scaled });
      assertStableAfterSwitch(afterSwitch, scaled, "post-retarget");

      // ── back to 1×: override gone, delivered pixels match the viewport ───
      client.send({ type: "resize", width: 390, height: 844 });
      for (;;) {
        status = await client.nextStatus();
        if (status.resized) break;
      }
      assert.equal(status.resized.scale, 1);
      assert.ok(status.viewport, "the 1× resize still reports a viewport");
      assert.equal(await pageB.evaluate(() => devicePixelRatio), 1, "1× drops the override");
      const flat = { width: status.viewport.width, height: status.viewport.height };
      assert.notDeepEqual(flat, scaled, "the 1× viewport is not the scaled pixel size");
      const flatFrames = await collectFrames(client, { want: 2, dims: flat });
      assertStableAfterSwitch(flatFrames, flat, "back-to-1x");
    } finally {
      client?.close();
      stream?.close();
      if (ctx) await ctx.close().catch(() => {});
      await fs.rm(dir, { recursive: true, force: true }).catch(() => {});
    }
  },
);
