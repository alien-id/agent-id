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
//                     {"type":"resize","width":W,"height":H}
//
// `resize` is our one extension beyond agent-browser's shapes (harmless there —
// unknown types are ignored). width/height are the VIEWER's dimensions — the
// desired page viewport — so a phone-sized viewer gets the page's mobile
// layout, not a shrunken desktop one. The resulting viewport is broadcast to
// every watcher as {"type":"status","resized":{...},"viewport":{...}}.
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
// fragmented text is reassembled. Exported for tests.
export function makeFrameParser(onFrame) {
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
// Viewer resize requests are clamped to sane page dimensions: below 200 the
// page is unusable, above 4096 a typo'd request could balloon the framebuffer.
const RESIZE_MIN = 200;
const RESIZE_MAX = 4096;

export async function startStreamServer(state, { log = () => {}, resize = null } = {}) {
  const token = crypto.randomBytes(24).toString("hex");
  const clients = new Set();
  let cdp = null; // active CDPSession for the screencast
  let cdpPage = null;
  let suspended = 0; // depth-counted: nested fills keep it suspended
  let closed = false;
  // Input events apply strictly in arrival order. page.mouse/keyboard calls are
  // async; firing them unawaited lets a press overtake the move before it (or a
  // release overtake the press), which drops clicks sent in a burst.
  let inputChain = Promise.resolve();

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
    // Tell a joining client the CURRENT state, not just "screencasting". A
    // blacked-out feed (credential fill in flight) looks exactly like a broken
    // one from the outside — the viewer needs to know which it is.
    socket.write(
      encodeTextFrame(
        JSON.stringify({
          type: "status",
          source: "alien",
          screencasting: true,
          suspended: suspended > 0,
        }),
      ),
    );

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
      if (msg.type === "resize") {
        // Reshape the page viewport to the viewer's screen (mobile-sized
        // viewports for phone watchers). Serialized behind pending input and
        // suspend-checked at apply time like every other viewer event; the
        // achieved viewport is broadcast so ALL watchers learn the new shape.
        const width = Math.round(Number(msg.width));
        const height = Math.round(Number(msg.height));
        if (!resize || ![width, height].every(Number.isFinite)) return;
        const clamp = (n) => Math.min(Math.max(n, RESIZE_MIN), RESIZE_MAX);
        inputChain = inputChain
          .then(async () => {
            if (suspended > 0) return;
            const viewport = await resize(clamp(width), clamp(height));
            broadcast({
              type: "status",
              source: "alien",
              resized: { width: clamp(width), height: clamp(height) },
              ...(viewport ? { viewport } : {}),
            });
          })
          .catch(() => {});
        return;
      }
      if (mutatesPage(msg)) state.invalidateRefs?.("owner used live browser control");
      // Queue, don't fire-and-forget: the suspend/page checks re-run at apply
      // time so a fill starting mid-queue still blacks out the queued tail.
      inputChain = inputChain
        .then(() => {
          if (suspended > 0) return;
          const page = state.current;
          if (!page || page.isClosed?.()) return;
          return applyInput(page, msg);
        })
        .catch(() => {});
    });
    socket.on("data", parse);

    const drop = () => {
      clients.delete(socket);
      if (clients.size === 0) void stopScreencast(); // save CPU when unwatched
    };
    socket.on("close", drop);
    socket.on("error", drop);

    // Frames are CHANGE-driven, so a client that joins an already-running cast
    // gets nothing at all until the page happens to move — on a sign-in form
    // that is forever, and a blank canvas reads as "the browser view is
    // broken". Restart the cast so Chrome emits a fresh first frame for it
    // (the same trick `resume` uses); otherwise this is the first watcher and
    // starting the feed produces that frame anyway.
    if (cdp) void stopScreencast().then(() => startScreencast());
    else void startScreencast();
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
