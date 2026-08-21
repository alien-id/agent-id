#!/usr/bin/env node

// Tests for viewer navigation on the viewport stream server: `applyNav`'s CDP
// execution, and the `{"type":"nav",...}` command's wire contract (unknown
// actions, suspend-gating). Modeled on tests/test-browser-stream.mjs — same
// fake/state/WS-client shape, extended locally with a `context()` seam
// `applyNav` needs that the base fake page does not have.
//
// Run: node --test tests/test-browser-stream-nav.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import net from "node:net";
import { once } from "node:events";

import {
  startStreamServer,
  makeFrameParser,
  applyNav,
} from "../plugins/agent-id-browser/lib/stream-server.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── fakes (local copies — see header note) ─────────────────────────────────

// A fresh short-lived CDP session, the kind `applyNav`/`page.context()`
// hands out — distinct from the long-lived cast session.
function makeFakeCdpSession(history = { currentIndex: 0, entries: [] }) {
  const session = {
    sent: [],
    detached: false,
    async send(method, params) {
      session.sent.push({ method, params });
      if (method === "Page.getNavigationHistory") return history;
      return {};
    },
    async detach() { session.detached = true; },
  };
  return session;
}

function makeFakeSession(screenshotData = "sharp") {
  const handlers = new Map();
  // The long-lived cast session also answers the focus poller's
  // Page.getNavigationHistory reads; navHistory is settable so a test can
  // change what the "next" read would report before triggering it.
  let navHistory = { currentIndex: 0, entries: [{ id: "e1" }] };
  const session = {
    sent: [],
    detached: false,
    on: (event, fn) => handlers.set(event, fn),
    async send(method, params) {
      session.sent.push({ method, params });
      if (method === "Page.captureScreenshot") return { data: screenshotData };
      if (method === "Page.getNavigationHistory") return navHistory;
      return {};
    },
    async detach() { session.detached = true; },
    emitFrame(data, metadata = { deviceWidth: 640, deviceHeight: 480, timestamp: Date.now() }) {
      handlers.get("Page.screencastFrame")?.({ data, metadata, sessionId: 1 });
    },
    setNavHistory(next) { navHistory = next; },
  };
  return session;
}

// `castGate` (resolved by default) lets a test hold back the moment the
// long-lived screencast CDP session becomes available, to drive the
// late-attaching-session case without a second timer.
function makeFakeState() {
  let session = makeFakeSession();
  const navSessions = [];
  let castGate = Promise.resolve();
  let urlValue = "https://example.test/";
  const page = {
    isClosed: () => false,
    url: () => urlValue,
    viewportSize: () => ({ width: 640, height: 480 }),
    mouse: { move: async () => {}, down: async () => {}, up: async () => {}, wheel: async () => {} },
    keyboard: { down: async () => {}, up: async () => {}, insertText: async () => {} },
    context: () => ({
      newCDPSession: async () => {
        const navSession = makeFakeCdpSession();
        navSessions.push(navSession);
        return navSession;
      },
    }),
  };
  return {
    current: page,
    invalidated: [],
    invalidateRefs(reason) { this.invalidated.push(reason); },
    navSessions,
    ctx: {
      newCDPSession: async () => {
        await castGate;
        if (session.detached) session = makeFakeSession();
        return session;
      },
    },
    get session() { return session; },
    setUrl(next) { urlValue = next; },
    /** Delay the next newCDPSession resolution until the returned fn is called. */
    holdCast() {
      let release;
      castGate = new Promise((resolve) => { release = resolve; });
      return () => release();
    },
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

async function startServer(opts = {}) {
  const state = makeFakeState();
  const server = await startStreamServer(state, { log: () => {}, ...opts });
  return { state, server };
}

// ── applyNav: direct CDP execution ──────────────────────────────────────────

test("applyNav back sends getNavigationHistory then navigateToHistoryEntry for the entry before currentIndex", async () => {
  const entries = [{ id: "e1" }, { id: "e2" }, { id: "e3" }];
  const session = makeFakeCdpSession({ currentIndex: 1, entries });
  const page = { context: () => ({ newCDPSession: async () => session }) };
  await applyNav(page, "back");
  assert.deepEqual(session.sent.map((s) => s.method), [
    "Page.getNavigationHistory",
    "Page.navigateToHistoryEntry",
  ]);
  assert.equal(session.sent[1].params.entryId, "e1");
});

test("applyNav forward sends getNavigationHistory then navigateToHistoryEntry for the entry after currentIndex", async () => {
  const entries = [{ id: "e1" }, { id: "e2" }, { id: "e3" }];
  const session = makeFakeCdpSession({ currentIndex: 1, entries });
  const page = { context: () => ({ newCDPSession: async () => session }) };
  await applyNav(page, "forward");
  assert.deepEqual(session.sent.map((s) => s.method), [
    "Page.getNavigationHistory",
    "Page.navigateToHistoryEntry",
  ]);
  assert.equal(session.sent[1].params.entryId, "e3");
});

test("applyNav reload sends Page.reload and no history call", async () => {
  const session = makeFakeCdpSession({ currentIndex: 0, entries: [{ id: "e1" }] });
  const page = { context: () => ({ newCDPSession: async () => session }) };
  await applyNav(page, "reload");
  assert.deepEqual(session.sent.map((s) => s.method), ["Page.reload"]);
});

test("applyNav back at the start of history sends no navigateToHistoryEntry", async () => {
  const entries = [{ id: "e1" }, { id: "e2" }];
  const session = makeFakeCdpSession({ currentIndex: 0, entries });
  const page = { context: () => ({ newCDPSession: async () => session }) };
  await applyNav(page, "back");
  assert.deepEqual(session.sent.map((s) => s.method), ["Page.getNavigationHistory"]);
});

test("applyNav forward at the end of history sends no navigateToHistoryEntry", async () => {
  const entries = [{ id: "e1" }, { id: "e2" }];
  const session = makeFakeCdpSession({ currentIndex: 1, entries });
  const page = { context: () => ({ newCDPSession: async () => session }) };
  await applyNav(page, "forward");
  assert.deepEqual(session.sent.map((s) => s.method), ["Page.getNavigationHistory"]);
});

test("applyNav always detaches the session it opened", async () => {
  for (const action of ["back", "forward", "reload"]) {
    const session = makeFakeCdpSession({ currentIndex: 0, entries: [{ id: "e1" }, { id: "e2" }] });
    const page = { context: () => ({ newCDPSession: async () => session }) };
    await applyNav(page, action);
    assert.equal(session.detached, true, `detached after ${action}`);
  }
});

// ── over the wire ────────────────────────────────────────────────────────────

test("an unknown nav action reaches the server and produces no CDP navigation call", async () => {
  const { state, server } = await startServer();
  const c = await connectStream(server.port, server.token);
  await c.nextJson(); // status
  await sleep(20);
  c.sendJson({ type: "nav", action: "sideways" });
  await sleep(50);
  assert.equal(state.navSessions.length, 0, "no nav CDP session was opened");
  assert.equal(state.invalidated.length, 0, "no refs invalidated for a rejected action");
  c.close();
  server.close();
});

test("a nav command sent while suspended performs no navigation", async () => {
  const { state, server } = await startServer();
  const c = await connectStream(server.port, server.token);
  await c.nextJson(); // status
  await sleep(20);
  server.suspend();
  await c.nextJson(); // suspended: true
  c.sendJson({ type: "nav", action: "back" });
  await sleep(50);
  assert.equal(state.navSessions.length, 0, "no nav CDP session was opened while suspended");
  assert.equal(state.invalidated.length, 0, "no refs invalidated while suspended");
  server.resume();
  c.close();
  server.close();
});

// ── nav-poll cost: Page.getNavigationHistory is gated on the cheap url read ──

function historyCallCount(state) {
  return state.session.sent.filter((s) => s.method === "Page.getNavigationHistory").length;
}

test("steady state: an unchanging url gets Page.getNavigationHistory once, not once per poll tick", async () => {
  const { state, server } = await startServer();
  const c = await connectStream(server.port, server.token);
  await c.nextJson(); // initial status, no nav yet
  await sleep(700); // several FOCUS_POLL_MS(250ms) ticks over an unmoving url
  assert.equal(historyCallCount(state), 1, "the history flags are measured once, then reused");
  c.close();
  server.close();
});

test("after a navigation, the next tick re-measures and the broadcast nav carries the new flags", async () => {
  const { state, server } = await startServer();
  const c = await connectStream(server.port, server.token);
  await c.nextJson(); // initial status, no nav yet
  const first = await c.nextJson(); // first poll tick
  assert.deepEqual(first.nav, { url: "https://example.test/", canGoBack: false, canGoForward: false });
  assert.equal(historyCallCount(state), 1);

  state.setUrl("https://example.test/next");
  state.session.setNavHistory({ currentIndex: 1, entries: [{ id: "e1" }, { id: "e2" }] });

  const second = await c.nextJson(); // next tick, after the url moved
  assert.deepEqual(second.nav, { url: "https://example.test/next", canGoBack: true, canGoForward: false });
  assert.equal(historyCallCount(state), 2, "a url change re-measures the history flags");

  c.close();
  server.close();
});

test("a late-attaching cast session is measured on the next tick even though the url never changed", async () => {
  const { state, server } = await startServer();
  const release = state.holdCast(); // hold back the screencast CDP session
  const c = await connectStream(server.port, server.token);
  await c.nextJson(); // initial status, no nav yet

  const first = await c.nextJson(); // first poll tick: no cast session exists yet
  assert.deepEqual(first.nav, { url: "https://example.test/", canGoBack: false, canGoForward: false });
  assert.equal(historyCallCount(state), 0, "no CDP call is made while there is no cast session");

  state.session.setNavHistory({ currentIndex: 1, entries: [{ id: "e1" }, { id: "e2" }] });
  release(); // the cast session now attaches

  const second = await c.nextJson(); // next tick: same url, session now present
  assert.deepEqual(second.nav, { url: "https://example.test/", canGoBack: true, canGoForward: false });
  assert.equal(
    historyCallCount(state),
    1,
    "the newly attached session is measured even though the url didn't change",
  );

  c.close();
  server.close();
});
