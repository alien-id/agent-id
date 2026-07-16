// Live viewport stream for an open session — the "watch Lethe browse" feed.
//
// A minimal WebSocket server (hand-rolled, no dependency — same ethos as the
// line-JSON TCP protocol in session-server.mjs) on 127.0.0.1, gated by a
// per-session random token (`?token=` on the upgrade URL). It pushes CDP
// screencast frames of the CURRENT tab as JSON text frames and accepts input
// events back, using the same message shapes as agent-browser's stream so one
// viewer client works against both browser stacks:
//
//   server → client   {"type":"frame","data":"<base64 jpeg>","metadata":{...}}
//                     {"type":"status", ...}
//   client → server   {"type":"input_mouse","eventType":"mousePressed",...}
//                     {"type":"input_keyboard","eventType":"keyDown",...}
//
// SEAL PRESERVED: this never opens a CDP debug port — frames come from a
// patchright CDPSession over the existing pipe, input goes through
// page.mouse/page.keyboard. fill-secret / fill-otp SUSPEND the feed while a
// credential value is being injected (session-server calls suspend/resume),
// so a watcher never sees more than the existing `screenshot` verb could show
// outside those windows.

import crypto from "node:crypto";
import http from "node:http";

const WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const RETARGET_POLL_MS = 500;
const JPEG_QUALITY = 70;

// ── WS wire helpers (server side: outgoing unmasked, incoming masked) ────────

function encodeTextFrame(payload) {
  const data = Buffer.from(payload, "utf8");
  let header;
  if (data.length < 126) {
    header = Buffer.from([0x81, data.length]);
  } else if (data.length < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 126;
    header.writeUInt16BE(data.length, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x81;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(data.length), 2);
  }
  return Buffer.concat([header, data]);
}

function encodeControlFrame(opcode, payload = Buffer.alloc(0)) {
  return Buffer.concat([Buffer.from([0x80 | opcode, payload.length]), payload]);
}

// Incremental parser for client frames. Client→server frames are always
// masked (RFC 6455 §5.1). Yields {opcode, payload} per complete frame;
// fragmented text is reassembled.
function makeFrameParser(onFrame) {
  let buf = Buffer.alloc(0);
  let fragments = null;
  return (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    for (;;) {
      if (buf.length < 2) return;
      const fin = (buf[0] & 0x80) !== 0;
      const opcode = buf[0] & 0x0f;
      const masked = (buf[1] & 0x80) !== 0;
      let len = buf[1] & 0x7f;
      let off = 2;
      if (len === 126) {
        if (buf.length < 4) return;
        len = buf.readUInt16BE(2);
        off = 4;
      } else if (len === 127) {
        if (buf.length < 10) return;
        len = Number(buf.readBigUInt64BE(2));
        off = 10;
      }
      const maskOff = off;
      if (masked) off += 4;
      if (buf.length < off + len) return;
      let payload = buf.subarray(off, off + len);
      if (masked) {
        const mask = buf.subarray(maskOff, maskOff + 4);
        const un = Buffer.alloc(len);
        for (let i = 0; i < len; i++) un[i] = payload[i] ^ mask[i & 3];
        payload = un;
      }
      buf = buf.subarray(off + len);
      if (opcode === 0x0 && fragments) {
        fragments.push(payload);
        if (fin) {
          onFrame({ opcode: 0x1, payload: Buffer.concat(fragments) });
          fragments = null;
        }
      } else if (!fin) {
        fragments = [payload];
      } else {
        onFrame({ opcode, payload });
      }
    }
  };
}

// ── Input mapping (viewer events → playwright page APIs) ─────────────────────

const KEY_ALIASES = { " ": "Space" };

async function applyInput(page, msg) {
  if (msg.type === "input_mouse") {
    const x = Number(msg.x) || 0;
    const y = Number(msg.y) || 0;
    const button = ["left", "middle", "right"].includes(msg.button) ? msg.button : "left";
    const clickCount = Number(msg.clickCount) || 1;
    switch (msg.eventType) {
      case "mouseMoved":
        return page.mouse.move(x, y);
      case "mousePressed":
        await page.mouse.move(x, y);
        return page.mouse.down({ button, clickCount });
      case "mouseReleased":
        return page.mouse.up({ button, clickCount });
      case "mouseWheel":
        return page.mouse.wheel(Number(msg.deltaX) || 0, Number(msg.deltaY) || 0);
      default:
        return;
    }
  }
  if (msg.type === "input_keyboard") {
    const key = KEY_ALIASES[msg.key] ?? msg.key;
    if (!key || typeof key !== "string") return;
    switch (msg.eventType) {
      case "keyDown":
        return page.keyboard.down(key);
      case "keyUp":
        return page.keyboard.up(key);
      case "char":
        return page.keyboard.insertText(String(msg.text ?? key));
      default:
        return;
    }
  }
}

// Pointer movement alone does not change page state. Clicks, wheel events, and
// keyboard input can navigate or mutate a form, so refs observed by the agent
// must be invalidated before viewer control is applied.
function mutatesPage(msg) {
  return (
    (msg.type === "input_mouse" && ["mousePressed", "mouseWheel"].includes(msg.eventType)) ||
    (msg.type === "input_keyboard" && ["keyDown", "char"].includes(msg.eventType))
  );
}

// ── Stream server ─────────────────────────────────────────────────────────────

/**
 * Start the viewport stream for a session. `state` is session-server's live
 * state ({ctx, current, ...}) — the feed follows `state.current` (poll-based,
 * so tab-new / tab-switch / tab-close all retarget without hooks).
 * Returns { port, token, suspend, resume, close }.
 */
export async function startStreamServer(state, { log = () => {} } = {}) {
  const token = crypto.randomBytes(24).toString("hex");
  const clients = new Set();
  let cdp = null; // active CDPSession for the screencast
  let cdpPage = null;
  let suspended = 0; // depth-counted: nested fills keep it suspended
  let closed = false;

  function broadcast(obj) {
    if (clients.size === 0) return;
    const frame = encodeTextFrame(JSON.stringify(obj));
    for (const sock of clients) sock.write(frame);
  }

  async function stopScreencast() {
    const session = cdp;
    cdp = null;
    cdpPage = null;
    if (!session) return;
    try { await session.send("Page.stopScreencast"); } catch { /* page gone */ }
    try { await session.detach(); } catch { /* already detached */ }
  }

  async function startScreencast() {
    if (closed || clients.size === 0) return;
    const page = state.current;
    if (!page || page.isClosed?.() || (cdp && cdpPage === page)) return;
    await stopScreencast();
    let session;
    try {
      session = await state.ctx.newCDPSession(page);
    } catch (err) {
      log(`stream: cdp attach failed: ${err.message || err}`);
      return;
    }
    cdp = session;
    cdpPage = page;
    session.on("Page.screencastFrame", (ev) => {
      // Ack ALWAYS (even suspended/stale) or Chrome stops sending frames.
      session.send("Page.screencastFrameAck", { sessionId: ev.sessionId }).catch(() => {});
      if (suspended > 0 || session !== cdp) return;
      broadcast({ type: "frame", data: ev.data, metadata: ev.metadata });
    });
    try {
      await session.send("Page.startScreencast", {
        format: "jpeg",
        quality: JPEG_QUALITY,
        maxWidth: 1600,
        maxHeight: 1200,
      });
    } catch (err) {
      log(`stream: screencast start failed: ${err.message || err}`);
      await stopScreencast();
    }
  }

  // Follow the current tab; also (re)starts after a resume-forced restart.
  const retarget = setInterval(() => {
    if (closed || clients.size === 0 || suspended > 0) return;
    if (state.current !== cdpPage) void startScreencast();
  }, RETARGET_POLL_MS);
  retarget.unref?.();

  const server = http.createServer((req, res) => {
    res.writeHead(426).end(); // this port only speaks WebSocket
  });

  server.on("upgrade", (req, socket) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const key = req.headers["sec-websocket-key"];
    if (url.searchParams.get("token") !== token || !key) {
      socket.end("HTTP/1.1 403 Forbidden\r\n\r\n");
      return;
    }
    const accept = crypto.createHash("sha1").update(key + WS_MAGIC).digest("base64");
    socket.write(
      "HTTP/1.1 101 Switching Protocols\r\n" +
        "Upgrade: websocket\r\nConnection: Upgrade\r\n" +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
    );
    clients.add(socket);
    socket.write(encodeTextFrame(JSON.stringify({ type: "status", source: "alien", screencasting: true })));

    const parse = makeFrameParser(({ opcode, payload }) => {
      if (opcode === 0x8) {
        socket.write(encodeControlFrame(0x8));
        socket.end();
        return;
      }
      if (opcode === 0x9) {
        socket.write(encodeControlFrame(0xa, payload));
        return;
      }
      if (opcode !== 0x1) return;
      let msg;
      try { msg = JSON.parse(payload.toString("utf8")); } catch { return; }
      // Input is disabled while a credential fill is in flight — the viewer
      // must not be able to interact with a form mid-injection.
      if (suspended > 0) return;
      const page = state.current;
      if (!page || page.isClosed?.()) return;
      if (mutatesPage(msg)) state.invalidateRefs?.("owner used live browser control");
      applyInput(page, msg).catch(() => {});
    });
    socket.on("data", parse);

    const drop = () => {
      clients.delete(socket);
      if (clients.size === 0) void stopScreencast(); // save CPU when unwatched
    };
    socket.on("close", drop);
    socket.on("error", drop);

    void startScreencast(); // first watcher starts the feed
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));

  return {
    port: server.address().port,
    token,
    /** Hide the feed while a secret is typed into the page. Depth-counted. */
    suspend() {
      suspended++;
      broadcast({ type: "status", source: "alien", suspended: true });
    },
    resume() {
      suspended = Math.max(0, suspended - 1);
      if (suspended === 0) {
        broadcast({ type: "status", source: "alien", suspended: false });
        // Restart to force a fresh keyframe — otherwise a static page after the
        // fill would leave the viewer on the pre-fill frame indefinitely.
        void stopScreencast().then(() => startScreencast());
      }
    },
    close() {
      closed = true;
      clearInterval(retarget);
      void stopScreencast();
      for (const sock of clients) sock.destroy();
      clients.clear();
      server.close();
    },
  };
}
