// Live viewport stream for an open session — the pair-browsing feed.
//
// A minimal WebSocket server (hand-rolled, no dependency — same ethos as the
// line-JSON TCP protocol in session-server.mjs) on 127.0.0.1, gated by a
// per-session random token (`?token=` on the upgrade URL). It pushes CDP
// screencast frames of the CURRENT tab and accepts input events back, using
// agent-browser's message shapes (frame/status/ack/config/input_*) so one
// viewer client works against both browser stacks.
//
// Wire protocol v2, negotiated per client via upgrade-URL query params. Every
// mode degrades to the v1 default, so an agent-browser viewer that knows none
// of them keeps working:
//
//   ?token=<hex>      required, per-session gate
//   ?binary=1         type:"frame" messages arrive as WS binary messages:
//                     [u32 LE header length][JSON header][payload bytes]
//                     (everything else stays a JSON text frame)
//   ?codec=h264       payload is ONE complete H.264 Annex-B access unit from
//                     an ffmpeg subprocess (implies binary=1; falls back to
//                     jpeg with a status notice when no usable ffmpeg/encoder
//                     exists)
//   ?pacing=ack|push  ack: at most one frame in flight — the client releases
//                     the next with {"type":"ack","seq":N}
//   ?maxFps=<0-120>   per-client delivery cap (0 = uncapped)
//
//   server → client   {"type":"frame","seq":N,"data":"<base64 jpeg>","metadata":{...}}
//                     {"type":"status", ...}      (negotiated caps on join)
//   client → server   {"type":"input_mouse"|"input_keyboard", ...}
//                     {"type":"ack","seq":N}
//                     {"type":"config","maxFps":N,"pacing":"ack"|"push"}
//                     {"type":"status_request"}
//                     {"type":"resize","width":W,"height":H[,"scale":S]}
//                     {"type":"webrtc_offer"|"webrtc_ice", ...}  (experimental)
//
// `seq` counts per codec, so each viewer sees its own stream contiguous.
//
// Delivery is latest-frame-wins: each JPEG client has ONE pending slot that
// newer frames overwrite whenever the client is slower than the feed (socket
// backpressure, outstanding ack, fps cap), so a viewer always resumes at live
// and the server never queues stale frames. H.264 is a temporally-dependent
// byte stream, so access units can't be dropped mid-GOP — a client whose
// socket buffer exceeds a bound is disconnected instead (it reconnects at a
// fresh keyframe). After ~600ms without a screencast frame the page has
// settled and one high-quality Page.captureScreenshot "refinement" frame is
// pushed, so text is sharp at rest while motion runs at aggressive JPEG
// quality.
//
// `resize` is our one extension beyond agent-browser's shapes (harmless there —
// unknown types are ignored). width/height are the VIEWER's dimensions — the
// desired page viewport — so a phone-sized viewer gets the page's mobile
// layout, not a shrunken desktop one. An optional integer `scale` (1–3,
// default 1) asks for the capture at scale× device pixels so a retina-density
// viewer gets text crisp at native density; the page keeps its CSS geometry
// and desktop UA — the only page-visible change is devicePixelRatio. The
// resulting viewport is broadcast to every watcher as
// {"type":"status","resized":{...},"viewport":{...}}.
//
// HOW scaled capture works (all of it measured against real Chrome, not
// assumed): the screencast delivers CSS-pixel frames no matter what
// devicePixelRatio is — a device-metrics override does not change the cast's
// delivered size — while Page.captureScreenshot DOES render at device pixels
// (clip.scale=1 under a scale-2 override delivers exactly viewport×2). So a
// scaled session applies Emulation.setDeviceMetricsOverride on the SAME
// long-lived CDP session that runs the screencast — the override lives
// exactly as long as the cast (retargeting to another tab moves it there),
// and stopping the cast clears it EXPLICITLY before detaching (detach alone
// leaves a dormant registration that re-pins the viewport on later
// navigations — measured). The screencast keeps running purely as a damage
// detector, and delivery is coalesced captureScreenshot frames instead of
// the 1× cast payloads, with metadata normalized to the session's CSS
// geometry. Refinement uses the same capture call, so motion and refinement
// frames are identical in pixel dimensions — the invariant the encoders
// depend on.
//
// SEAL PRESERVED: this never opens a CDP debug port — frames come from a
// patchright CDPSession over the existing pipe, input goes through
// page.mouse/page.keyboard. fill-secret / fill-otp SUSPEND the feed while a
// credential value is being injected (session-server calls suspend/resume).
// Suspend drops every pending frame, gates encoder input and the refinement
// capture, and re-checks after each await, so a watcher never sees more than
// the existing `screenshot` verb could show outside those windows.

import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";

import { createH264Encoder } from "./stream-encoder.mjs";
import { createHopCounters, startCounterTicker } from "./stream-counters.mjs";

const WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const RETARGET_POLL_MS = 500;
const REFINE_AFTER_MS = 600;
const REFINE_POLL_MS = 250;
const H264_MAX_BUFFERED = 4 * 1024 * 1024;

// Keyboard-open latency budget: the viewer's IME pops within a quarter second
// of the page focusing a field — imperceptible next to the tap round-trip.
const FOCUS_POLL_MS = 250;

function envInt(name, fallback, min, max) {
  const n = Number(process.env[name]);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(n)));
}

// Motion frames at 80: at >=80 the JPEG artifacts sit below what the H.264
// stage preserves anyway, so the double compression stops being visible — 55
// produced ringing around text that the encoder then spent bits reproducing.
// The idle refinement frame still carries the top visual quality (0 disables
// refinement). Bind is overridable ONLY for LAN viewer testing.
const STREAM_QUALITY = envInt("AGENT_ID_STREAM_QUALITY", 80, 1, 100);
const REFINE_QUALITY = envInt("AGENT_ID_STREAM_REFINE_QUALITY", 90, 0, 100);
// Watchdog: with a viewer attached and nothing arriving for this long, restart
// the screencast (0 disables). Refinement is NOT a substitute — it is armed by
// a screencast frame (`refined` starts true and `lastMetadata` starts null), so
// a cast that dies before or between frames never triggers it, and the retarget
// poll only fires when `state.current` CHANGES, which a silently-detached CDP
// session does not do. On a genuinely static page this restarts every interval:
// two CDP calls and one keyframe, which also proves the pipe is alive and is
// far cheaper than a viewer staring at a frozen picture.
const WATCHDOG_MS = envInt("AGENT_ID_STREAM_WATCHDOG_MS", 15000, 0, 600000);
const BIND_HOST = process.env.AGENT_ID_STREAM_BIND || "127.0.0.1";
// Per-second counter rows (stream-counters.mjs). On by default — a freeze is
// diagnosed from the rows it produces, and a host that cannot carry two lines
// per second per session turns them off rather than losing the diagnostic by
// default everywhere.
const COUNTERS = process.env.AGENT_ID_STREAM_COUNTERS !== "0";

// Decoded size of a base64 payload without decoding it: the counters want the
// byte count of every frame and a Buffer.from per frame would cost more than
// the measurement is worth.
function b64Bytes(s) {
  const n = typeof s === "string" ? s.length : 0;
  if (n === 0) return 0;
  let pad = 0;
  if (s.charCodeAt(n - 1) === 61) pad++;
  if (s.charCodeAt(n - 2) === 61) pad++;
  return Math.floor((n * 3) / 4) - pad;
}

// ── WS wire helpers (server side: outgoing unmasked, incoming masked) ────────

function wsFrame(opcode, data) {
  let header;
  if (data.length < 126) {
    header = Buffer.from([0x80 | opcode, data.length]);
  } else if (data.length < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x80 | opcode;
    header[1] = 126;
    header.writeUInt16BE(data.length, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | opcode;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(data.length), 2);
  }
  return Buffer.concat([header, data]);
}

const encodeTextFrame = (payload) => wsFrame(0x1, Buffer.from(payload, "utf8"));

function encodeControlFrame(opcode, payload = Buffer.alloc(0)) {
  return Buffer.concat([Buffer.from([0x80 | opcode, payload.length]), payload]);
}

// Application close code (4000-4999 is the private-use range) for "you asked
// for a codec I cannot serve". Typed so a strict client can distinguish it
// from a network drop and stop retrying, instead of reconnecting forever.
export const CLOSE_CODEC_UNAVAILABLE = 4002;

/** Binary frame-message body: [u32 LE header length][JSON header][payload]. */
export function encodeFrameBinary(header, payload) {
  const headerBuf = Buffer.from(JSON.stringify(header), "utf8");
  const len = Buffer.alloc(4);
  len.writeUInt32LE(headerBuf.length, 0);
  return Buffer.concat([len, headerBuf, payload]);
}

export function decodeFrameBinary(buf) {
  const headerLen = buf.readUInt32LE(0);
  return {
    header: JSON.parse(buf.subarray(4, 4 + headerLen).toString("utf8")),
    payload: buf.subarray(4 + headerLen),
  };
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

// ── Per-client negotiation ───────────────────────────────────────────────────

export function parseStreamParams(url) {
  const raw = url.searchParams.get("codec");
  // "auto" = h264 when the host provisioned codecs (install-codecs), else
  // jpeg — resolved at join time. v1 clients that send nothing get jpeg.
  const codec = raw === "h264" || raw === "auto" ? raw : "jpeg";
  const rawFps = Number(url.searchParams.get("maxFps"));
  return {
    // `strict=1` turns the codec request into a requirement. A silent fall
    // back to jpeg hides broken provisioning and quietly costs ~10x the
    // traffic, so a client that cannot use jpeg wants the refusal instead —
    // immediately, and typed, rather than as a surprise in the bandwidth bill.
    // Only meaningful with an explicit codec: `auto` ASKS for the best
    // available and jpeg is a valid answer.
    strict: url.searchParams.get("strict") === "1" && raw === "h264",
    // h264/auto payloads are raw bytes — the codec choice implies binary framing.
    binary: url.searchParams.get("binary") === "1" || codec !== "jpeg",
    codec,
    pacing: url.searchParams.get("pacing") === "ack" ? "ack" : "push",
    maxFps: Number.isFinite(rawFps) ? Math.min(120, Math.max(0, Math.floor(rawFps))) : 0,
  };
}

// ── Input mapping (viewer events → playwright page APIs) ─────────────────────

const KEY_ALIASES = { " ": "Space" };

// Exported for tests: the input contract is only observable here.
export async function applyInput(page, msg) {
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
    // `char` is the text-insertion event: what it needs is `text`, and `key`
    // is only ever a fallback for it. Requiring `key` here dropped a
    // perfectly well-formed {eventType:"char", text:"…"} on the floor without
    // a word — silently losing the character. keyDown/keyUp genuinely need a
    // key, since there is no such thing as pressing "nothing".
    if (msg.eventType === "char") {
      const text = typeof msg.text === "string" && msg.text !== "" ? msg.text : key;
      if (typeof text !== "string" || text === "") {
        throw new Error("input_keyboard char needs `text` (or a `key` to fall back to)");
      }
      return page.keyboard.insertText(text);
    }
    if (!key || typeof key !== "string") {
      throw new Error(`input_keyboard ${msg.eventType || "?"} needs \`key\``);
    }
    switch (msg.eventType) {
      case "keyDown":
        return page.keyboard.down(key);
      case "keyUp":
        return page.keyboard.up(key);
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
// The optional capture scale: integers only (Chrome hard-rejects fractional
// pixel dimensions in CDP — a fractional maxWidth kills the screencast — and
// a fractional factor would let the capture paths disagree by a rounding
// step), rounded to nearest, 1..3: 1 is the classic capture, 3 covers the
// densest phone screens — beyond that the quadratic pixel cost buys nothing
// a display can show. Anything unparseable means 1, so the pre-`scale`
// message shape keeps its exact behavior. On top of the per-axis clamp the
// scaled request must fit a total budget: no axis over RESIZE_MAX device
// pixels and no more pixels than one 4K frame — otherwise 4096-per-axis and
// scale 3 could combine into a 12288×12288 capture.
const SCALE_MIN = 1;
const SCALE_MAX = 3;
const SCALE_MAX_PIXELS = 3840 * 2160;

// The largest integer scale (1..requested) whose scaled capture fits the
// axis budget and comes closest to the pixel budget. Exported for tests.
export function effectiveScale(width, height, requested) {
  let scale = Math.min(Math.max(Math.round(requested), SCALE_MIN), SCALE_MAX);
  while (
    scale > 1 &&
    (width * scale > RESIZE_MAX ||
      height * scale > RESIZE_MAX ||
      width * height * scale * scale > SCALE_MAX_PIXELS)
  ) {
    scale--;
  }
  return scale;
}

// The applied-geometry policy for a resize request, in order:
//   1. each axis clamps to RESIZE_MIN..RESIZE_MAX (as always);
//   2. the scale drops until the SCALED capture fits the axis and pixel
//      budgets — layout beats density, so density gives way first;
//   3. if the base viewport ALONE still exceeds the pixel budget (possible:
//      RESIZE_MAX² is ~2× the budget), it shrinks proportionally to fit —
//      scale reduction cannot fix what the base already breaks.
// Everything returned is what will actually be applied and broadcast — the
// `resized` status mirrors the ACHIEVED geometry, not the request.
// Exported for tests.
export function budgetedResize(width, height, requested) {
  const clamp = (n) => Math.min(Math.max(n, RESIZE_MIN), RESIZE_MAX);
  let w = clamp(width);
  let h = clamp(height);
  const scale = effectiveScale(w, h, requested);
  if (w * h * scale * scale > SCALE_MAX_PIXELS) {
    const f = Math.sqrt(SCALE_MAX_PIXELS / (w * h * scale * scale));
    w = Math.max(RESIZE_MIN, Math.floor(w * f));
    h = Math.max(RESIZE_MIN, Math.floor(h * f));
  }
  return { width: w, height: h, scale };
}

export async function startStreamServer(
  state,
  { log = () => {}, h264Config = null, resize = null, onActivity = () => {} } = {},
) {
  const token = crypto.randomBytes(24).toString("hex");
  const clients = new Set();
  // TWO rows, because the two stages fail differently and the split is the
  // whole diagnostic: capture healthy with encode at zero means the encoder is
  // holding the picture, both at zero means the page stopped painting. One
  // merged row cannot express that.
  // x.refine: how many idle refinement passes actually fired. The encoder's
  // demuxer only delimits a frame when the next one arrives, so this pass is
  // what flushes the last frame of a burst — and four runtime gates can
  // suppress it while the configuration looks correct. Nothing static answers
  // whether it runs; this counter does.
  const cap = createHopCounters("daemon.capture", { local: ["refine"] });
  const enc = createHopCounters("daemon.h264", { nal: true });
  // The `stream: ` prefix is load-bearing — the relay that mirrors these lines
  // drops anything without it.
  const counters = COUNTERS
    ? startCounterTicker({
        rows: [cap, enc],
        emit: (line) => log(`stream: counters ${JSON.stringify(line)}`),
      })
    : null;
  let cdp = null; // active CDPSession for the screencast
  let cdpPage = null;
  let suspended = 0; // depth-counted: nested fills keep it suspended
  let closed = false;
  // Per-codec sequences: a client consumes exactly one codec, and each
  // codec's subscribers must see their own stream contiguous. A shared
  // counter made every jpeg delivery punch a hole in the h264 sequence,
  // which viewers read as frame loss.
  let frameSeq = 0;
  let h264Seq = 0;
  let lastFrameAt = 0;
  let lastMetadata = null;
  let refined = true; // no refinement until at least one screencast frame
  // The session's current capture scale and CSS geometry (viewer-set via
  // `resize`). At scale 1 everything below is byte-identical to the classic
  // pipeline. At scale > 1 the screencast is demoted to a damage detector
  // and both frame sources are captureScreenshot calls — identical pixel
  // dimensions by construction (the encoders choke on dimension flips).
  // streamView is the last MEASURED viewport (what the page actually became,
  // vs streamDims = what was asked): the cast caps follow it so cast frames
  // are never silently downscaled out of agreement with the refinement pass.
  let streamScale = 1;
  let streamDims = null;
  let streamView = null;
  let castCaps = null;
  // Input events apply strictly in arrival order. page.mouse/keyboard calls are
  // async; firing them unawaited lets a press overtake the move before it (or a
  // release overtake the press), which drops clicks sent in a burst.
  let inputChain = Promise.resolve();

  // Encoder sinks eat the decoded JPEG of every live screencast frame: the
  // shared Annex-B encoder for WS h264 clients, plus one RTP encoder per
  // WebRTC peer (stream-webrtc.mjs registers those).
  const encoderSinks = new Set();
  let annexB = null;
  let webrtc = null;

  function sendText(client, obj) {
    client.sock.write(encodeTextFrame(JSON.stringify(obj)));
  }

  // Refuse a client with a close code it can act on. The status frame goes
  // first so a viewer that logs text has the reason in words, not just a
  // number; then a proper WS close (2-byte big-endian code + UTF-8 reason).
  function closeClient(client, code, reason) {
    try {
      sendText(client, { type: "status", source: "alien", error: reason, code });
      const body = Buffer.from(reason, "utf8").subarray(0, 123);
      const payload = Buffer.alloc(2 + body.length);
      payload.writeUInt16BE(code, 0);
      body.copy(payload, 2);
      client.sock.write(encodeControlFrame(0x8, payload));
    } catch { /* socket already gone */ }
    clients.delete(client);
    try { client.sock.end(); } catch { /* already closed */ }
  }

  function broadcastStatus(obj) {
    if (clients.size === 0) return;
    const frame = encodeTextFrame(JSON.stringify(obj));
    for (const c of clients) c.sock.write(frame);
  }

  // The page's focus truth, pushed by the session's init script. Deduped so a
  // page that re-reports the same element (focus bouncing inside an editor)
  // doesn't spam viewers, remembered so statusFor can hand the current state
  // to a viewer that joins with a field already focused, and suppressed during
  // a credential fill — the owner's keyboard must not pop over a blackout.
  let lastInputFocus = null;

  function inputFocus(payload) {
    if (suspended > 0) return;
    const next = payload && typeof payload === "object" ? payload : { editable: false };
    if (lastInputFocus && JSON.stringify(lastInputFocus) === JSON.stringify(next)) return;
    lastInputFocus = next;
    broadcastStatus({ type: "status", source: "alien", input_focus: next });
  }

  // Focus is POLLED, not event-driven: the stealth patching deliberately keeps
  // the CDP Runtime domain off, which is exactly what exposeBinding/initScript
  // reporting rides on — and a page-side beacon would die on strict CSPs. An
  // isolated-world evaluate sees the DOM without touching either. Frames are
  // walked because a field inside an iframe focuses ITS document, not the
  // main one; document.hasFocus() is true for the whole ancestor chain, but
  // only the actually-focused document holds an editable activeElement, so at
  // most one frame answers. Runs only while someone is watching, like the
  // screencast itself.
  let focusPoller = null;

  async function readInputFocus() {
    const page = state.current;
    if (!page || page.isClosed?.() || typeof page.frames !== "function") return null;
    for (const frame of page.frames()) {
      try {
        const found = await frame.evaluate(() => {
          if (!document.hasFocus()) return null;
          const NON_TEXT = new Set([
            "button", "submit", "reset", "image", "checkbox", "radio",
            "range", "color", "file", "hidden",
          ]);
          let el = document.activeElement;
          while (el && el.shadowRoot && el.shadowRoot.activeElement) el = el.shadowRoot.activeElement;
          if (!el || el === document.body || el === document.documentElement) return null;
          const tag = (el.tagName || "").toLowerCase();
          const type = tag === "input" ? (el.getAttribute("type") || "text").toLowerCase() : null;
          const editable =
            tag === "textarea" ||
            el.isContentEditable === true ||
            (tag === "input" && !NON_TEXT.has(type));
          if (!editable) return null;
          const inputmode = (el.getAttribute && el.getAttribute("inputmode")) || null;
          return {
            editable: true,
            ...(type ? { type } : {}),
            ...(inputmode ? { inputmode } : {}),
          };
        });
        if (found) return found;
      } catch {
        /* frame detached mid-poll */
      }
    }
    return { editable: false };
  }

  function ensureFocusPoller() {
    if (focusPoller) return;
    let inFlight = false;
    focusPoller = setInterval(async () => {
      if (inFlight || suspended > 0 || clients.size === 0) return;
      inFlight = true;
      try {
        const focus = await readInputFocus();
        if (focus) inputFocus(focus);
      } finally {
        inFlight = false;
      }
    }, FOCUS_POLL_MS);
    if (typeof focusPoller.unref === "function") focusPoller.unref();
  }

  function stopFocusPoller() {
    if (!focusPoller) return;
    clearInterval(focusPoller);
    focusPoller = null;
    lastInputFocus = null;
  }

  function statusFor(client) {
    const vp = state.current?.viewportSize?.() ?? null;
    return {
      type: "status",
      source: "alien",
      screencasting: true, // v1 shape: the join itself starts the feed
      suspended: suspended > 0,
      binary: client.binary,
      codec: client.codec,
      h264Available: Boolean(h264Config),
      pacing: client.pacing,
      maxFps: client.maxFps,
      ...(vp ? { viewportWidth: vp.width, viewportHeight: vp.height } : {}),
      ...(lastInputFocus ? { input_focus: lastInputFocus } : {}),
    };
  }

  // Lazily-cached per-frame encodings, shared across clients.
  function frameText(f) {
    f._text ??= encodeTextFrame(
      JSON.stringify({
        type: "frame",
        seq: f.seq,
        data: f.data,
        metadata: f.metadata,
        ...(f.refinement ? { refinement: true } : {}),
      }),
    );
    return f._text;
  }

  function frameBinary(f) {
    f._bin ??= wsFrame(
      0x2,
      encodeFrameBinary(
        {
          type: "frame",
          seq: f.seq,
          codec: "jpeg",
          metadata: f.metadata,
          ...(f.refinement ? { refinement: true } : {}),
        },
        Buffer.from(f.data, "base64"),
      ),
    );
    return f._bin;
  }

  // The one send gate. A frame leaves only when the client has a pending
  // frame AND isn't congested, awaiting an ack, or inside its fps interval.
  // Everything that unblocks a client (drain, ack, config, timer) re-enters
  // here; the pending slot was possibly overwritten in the meantime — that IS
  // the latest-frame-wins behavior.
  function pump(client) {
    if (closed || !client.pending || client.congested) return;
    if (client.pacing === "ack" && client.awaitingAck !== null) return;
    if (client.maxFps > 0) {
      const wait = client.lastSentAt + 1000 / client.maxFps - Date.now();
      if (wait > 0) {
        client.timer ??= setTimeout(() => {
          client.timer = null;
          pump(client);
        }, wait);
        return;
      }
    }
    const frame = client.pending;
    client.pending = null;
    const ok = client.sock.write(client.binary ? frameBinary(frame) : frameText(frame));
    client.lastSentAt = Date.now();
    if (client.pacing === "ack") client.awaitingAck = frame.seq;
    if (!ok) client.congested = true; // drain listener clears and re-pumps
  }

  function deliverFrame({ data, metadata, refinement = false }) {
    const frame = { seq: ++frameSeq, data, metadata, refinement };
    cap.out(b64Bytes(data));
    for (const client of clients) {
      if (client.codec !== "jpeg") continue;
      // Replacing an undelivered frame is the latest-wins behaviour working as
      // designed, but it is still a frame that viewer never saw — and until
      // now it vanished without a number anywhere.
      if (client.pending) cap.lost("pending_overwrite");
      client.pending = frame;
      pump(client);
    }
  }

  // The one place encoder input is offered, so every attempt is counted once.
  // Only the shared Annex-B encoder counts: the RTP sinks are a separate path
  // and would double this stage's input. `copies` is the refinement's flush
  // trick (see the refine timer) — two genuine writes, so two attempts.
  function feedEncoders(jpeg, copies = 1) {
    for (const sink of encoderSinks) {
      for (let i = 0; i < copies; i++) {
        const ok = sink.write(jpeg);
        if (sink !== annexB) continue;
        enc.in(jpeg.length);
        if (!ok) enc.lost("encoder_input");
      }
    }
  }

  // One message per ACCESS UNIT, never per stdout chunk: the encoder's pipe
  // splits a unit larger than 64 KiB across chunks, and the tail carries no
  // start code, so a viewer parsing one unit per message would discard it
  // (h264-framer.mjs does the framing).
  function sendAccessUnit(au, info) {
    let msg = null;
    for (const client of clients) {
      if (client.codec !== "h264") continue;
      if (!msg) {
        const seq = ++h264Seq;
        // Counted here rather than per client: one unit numbered once is what
        // the next stage receives, so this is the number its own `fi` is
        // compared against.
        enc.out(au.length);
        enc.note(seq);
        if (info?.idr) enc.idr++;
        if (info?.sps) enc.sps++;
        if (info?.pps) enc.pps++;
        // A unit carrying no NAL at all is a payload this stage could not
        // parse — the framer flushed a buffer that never held a start code.
        if (info && info.nals.length === 0) enc.perr++;
        // Same metadata rule as deliverFrame: EVERY envelope builder must ship
        // CSS geometry at scale — this one stamped raw cast metadata (device
        // pixels while scaled), doubling h264 viewers' tap coordinates.
        msg = wsFrame(
          0x2,
          encodeFrameBinary(
            {
              type: "frame",
              seq,
              codec: "h264",
              metadata: streamScale > 1 ? scaledMetadata() : lastMetadata,
            },
            au,
          ),
        );
      }
      client.sock.write(msg);
      // A temporally-dependent stream can't drop access units; a viewer that
      // can't keep up is cut instead of buffering without bound. It reconnects
      // and the encoder restart gives it a fresh keyframe. Whole units are
      // larger writes than the old per-chunk ones, but the bound still holds
      // several of even the biggest measured unit (~440 KiB against 4 MiB),
      // so only a genuinely stalled socket trips it.
      if (client.sock.writableLength > H264_MAX_BUFFERED) {
        log("stream: h264 viewer too slow — disconnecting");
        enc.lost("viewer_slow");
        client.sock.destroy();
      }
    }
  }

  // Serialized: join/leave/restart events can interleave, and two concurrent
  // ensures must not double-spawn ffmpeg.
  let annexBChain = Promise.resolve();
  function ensureAnnexBEncoder(opts) {
    annexBChain = annexBChain.then(() => ensureAnnexBEncoderNow(opts)).catch(() => {});
    return annexBChain;
  }

  async function ensureAnnexBEncoderNow({ restart = false } = {}) {
    const wanted = !closed && [...clients].some((c) => c.codec === "h264");
    if (!wanted || restart) {
      if (annexB) {
        encoderSinks.delete(annexB);
        annexB.close();
        annexB = null;
      }
      if (!wanted) return;
    }
    if (annexB) return;
    try {
      const encoder = await createH264Encoder({
        onChunk: sendAccessUnit,
        onResync: () => enc.perr++,
        log,
        ffmpegPath: h264Config?.ffmpegPath ?? null,
        onExit: () => {
          if (annexB !== encoder) return; // already replaced/closed deliberately
          encoderSinks.delete(encoder);
          annexB = null;
          // Died mid-stream (e.g. a viewport resize changed the input frame
          // size). Rate-limited restart resumes the feed for h264 viewers.
          setTimeout(() => {
            if (!closed) void ensureAnnexBEncoder();
          }, 500).unref?.();
        },
      });
      annexB = encoder;
      encoderSinks.add(encoder);
      // Prime a fresh encoder on a static page: the screencast is damage-
      // driven, so without this an h264 viewer joining a quiet page decodes
      // nothing (black) until the next repaint. Arming the refinement pass
      // feeds one captureScreenshot within ~250ms.
      if (lastMetadata) {
        refined = false;
        lastFrameAt = 0;
      }
    } catch (err) {
      const why = err.message || String(err);
      log(`stream: h264 unavailable (${why})`);
      for (const client of clients) {
        if (client.codec !== "h264") continue;
        if (client.strict) {
          // Asked for h264 and nothing else: say so and close, rather than
          // serve a format the client did not agree to.
          closeClient(client, CLOSE_CODEC_UNAVAILABLE, `h264 unavailable: ${why}`);
          continue;
        }
        client.codec = "jpeg";
        sendText(client, statusFor(client));
      }
    }
  }

  // One viewport screenshot at the page's device pixels. clip.scale stays 1
  // in every mode: under a device-metrics override Chrome already renders
  // the capture at devicePixelRatio (a 390×844 clip delivers 780×1688 at
  // scale 2 — measured), so multiplying by the scale again would deliver 4×.
  // No viewport to clip to (viewport:null launches) means "whole visible
  // viewport" — the same delivered dimensions.
  function captureShot(session, quality) {
    const vp = state.current?.viewportSize?.() ?? null;
    return session.send("Page.captureScreenshot", {
      format: "jpeg",
      quality,
      ...(vp
        ? { clip: { x: 0, y: 0, width: Math.round(vp.width), height: Math.round(vp.height), scale: 1 } }
        : {}),
    });
  }

  // Scaled motion path: coalesced device-pixel captures — at most one in
  // flight, latest damage wins. A 2× phone-viewport capture costs ~20ms
  // (measured), so scaled motion tops out around 30–50fps, and idle costs
  // nothing extra: captures happen only when the damage-driven cast reports
  // a change, exactly like classic frame delivery.
  let scaledDirty = false;
  let scaledBusy = false;

  // While a scaled resize is reshaping the window and override, nothing else
  // may (re)start the cast: a cast started mid-resize re-applies the OLD
  // override after the new geometry was already measured — and in headless
  // an override also sizes the platform window in a way its later removal
  // does not undo (measured), so one stale mid-resize override permanently
  // poisons the window size. The in-flight resize ends with its own restart,
  // which serves any viewer that joined meanwhile.
  let reshaping = false;

  // Frame metadata is the client's coordinate space and must be CSS px in
  // every frame. Chrome's cast metadata is CSS in steady state, but frames
  // emitted while an override is being applied or lifted can carry the
  // transitional surface size (measured: 780×1688 interleaved with 390×844
  // on the same scaled session) — so scaled delivery normalizes every
  // frame's metadata to the session's own CSS geometry, which the override
  // pins authoritatively.
  function scaledMetadata() {
    return {
      ...(lastMetadata ?? {}),
      ...(streamDims ? { deviceWidth: streamDims.width, deviceHeight: streamDims.height } : {}),
    };
  }

  async function pumpScaledCapture(session) {
    if (scaledBusy) return;
    scaledBusy = true;
    try {
      while (scaledDirty && !closed && session === cdp && suspended === 0) {
        scaledDirty = false;
        const shot = await captureShot(session, STREAM_QUALITY);
        if (closed || suspended > 0 || session !== cdp) return;
        deliverFrame({ data: shot.data, metadata: scaledMetadata() });
        if (encoderSinks.size > 0) feedEncoders(Buffer.from(shot.data, "base64"));
      }
    } catch {
      /* navigating/detached — the next damage tick retries */
    } finally {
      scaledBusy = false;
      // A capture that straddled a cast switch exits with the dirty flag
      // still set (its session lost the cast mid-flight) — re-dispatch for
      // the live session, or the new tab's first damage tick would sit
      // stranded behind the stale busy flag until the next tick.
      if (scaledDirty && !closed && cdp && cdp !== session) void pumpScaledCapture(cdp);
    }
  }

  // The truth about the viewport, read from the page itself. A scaled resize
  // needs it AFTER the override lands: the override pins the viewport to the
  // requested CSS size, so anything measured before it is stale (measured:
  // 500×844 before the override vs 390×844 after, when the window cannot
  // shrink to the request). Polls briefly for the expected size — the
  // renderer applies the override a beat after the CDP ack.
  async function measureViewport(expected) {
    let got = null;
    for (let attempt = 0; attempt < 20; attempt++) {
      const page = state.current;
      if (!page || page.isClosed?.() || typeof page.evaluate !== "function") return got;
      let next = null;
      try {
        next = await page.evaluate(() => ({ width: window.innerWidth, height: window.innerHeight }));
      } catch {
        return got;
      }
      if (!next) return got;
      got = next;
      if (!expected || (got.width === expected.width && got.height === expected.height)) return got;
      await new Promise((r) => setTimeout(r, 50));
    }
    return got;
  }

  // Cast start/stop are SERIALIZED behind one promise chain: concurrent
  // joins used to race startScreencast's idempotence guard — a real-Chrome
  // probe with delayed attaches left THREE live CDP sessions, each keeping
  // its override and captures alive. An epoch stamps every state change; a
  // session whose attach outlives its epoch (close, retarget, another
  // start) is detached and never installed.
  let castChain = Promise.resolve();
  let castEpoch = 0;
  let castOverride = false; // the CURRENT cast session applied a device-metrics override

  function stopScreencast() {
    castChain = castChain.then(stopScreencastNow).catch(() => {});
    return castChain;
  }

  function startScreencast() {
    castChain = castChain.then(startScreencastNow).catch(() => {});
    return castChain;
  }

  async function stopScreencastNow() {
    castEpoch++;
    const session = cdp;
    const hadOverride = castOverride;
    cdp = null;
    cdpPage = null;
    castOverride = false;
    if (!session) return;
    // An applied override must be cleared EXPLICITLY before its session goes
    // away: detach alone reverts the live values but leaves a dormant
    // registration that re-pins the viewport to the stale size on every
    // later NAVIGATION (measured: a 2040×2040 window snapped back to the old
    // 390×844 on goto until a clear was sent). Sent only when this session
    // applied one, so never-scaled sessions still see zero Emulation traffic.
    if (hadOverride) {
      try { await session.send("Emulation.clearDeviceMetricsOverride"); } catch { /* page gone */ }
    }
    try { await session.send("Page.stopScreencast"); } catch { /* page gone */ }
    try { await session.detach(); } catch { /* already detached */ }
  }

  async function startScreencastNow() {
    if (closed || clients.size === 0) return;
    const page = state.current;
    if (!page || page.isClosed?.() || (cdp && cdpPage === page)) return;
    await stopScreencastNow();
    const epoch = ++castEpoch;
    let session;
    try {
      session = await state.ctx.newCDPSession(page);
    } catch (err) {
      log(`stream: cdp attach failed: ${err.message || err}`);
      return;
    }
    // The world may have moved during the attach (close, retarget to another
    // tab, a newer start/stop): discard the session — detach, never install.
    if (closed || epoch !== castEpoch || state.current !== page) {
      try { await session.detach(); } catch { /* already gone */ }
      return;
    }
    cdp = session;
    cdpPage = page;
    session.on("Page.screencastFrame", (ev) => {
      // Ack ALWAYS (even suspended/stale) or Chrome stops sending frames.
      session.send("Page.screencastFrameAck", { sessionId: ev.sessionId }).catch(() => {});
      cap.in(b64Bytes(ev.data));
      if (suspended > 0 || session !== cdp) return;
      lastFrameAt = Date.now();
      lastMetadata = ev.metadata;
      refined = false;
      if (streamScale > 1) {
        // Scaled session: the cast's CSS-pixel payload is never delivered
        // (wrong dimensions for this stream) — the frame is the damage tick
        // that drives the device-pixel capture.
        scaledDirty = true;
        void pumpScaledCapture(session);
        return;
      }
      deliverFrame({ data: ev.data, metadata: ev.metadata });
      if (encoderSinks.size > 0) feedEncoders(Buffer.from(ev.data, "base64"));
    });
    // A scaled session's device-metrics override lives on THIS session, so
    // it spans exactly the life of the capture: a retarget applies it to the
    // new tab and the old tab reverts when its session detaches (overrides
    // do not survive their session — measured). mobile:false on purpose —
    // no touch capability, no mobile emulation; the page's only new surface
    // is devicePixelRatio. If Chrome refuses the override, fall back to the
    // classic 1× pipeline rather than stream mismatched dimensions.
    if (streamScale > 1 && streamDims) {
      try {
        await session.send("Emulation.setDeviceMetricsOverride", {
          width: Math.round(streamDims.width),
          height: Math.round(streamDims.height),
          deviceScaleFactor: streamScale,
          mobile: false,
        });
        castOverride = true;
      } catch (err) {
        log(`stream: device-scale override failed, continuing at 1x: ${err.message || err}`);
        streamScale = 1;
      }
    }
    // Capture is clamped to the CSS viewport so HiDPI doesn't ship 2× pixels
    // that the viewer scales straight back down (input mapping is 1:1 too).
    // That clamp is also right for scaled sessions: their cast frames are
    // damage ticks, never delivered, so CSS size keeps them cheap — the
    // delivered device-pixel frames come from captureScreenshot instead
    // (the cast cannot deliver above 1× whatever the override says — measured).
    // With no explicit context viewport the caps follow the MEASURED viewport
    // (floored at the legacy defaults): fixed fallback caps silently
    // downscaled big viewports' cast frames out of agreement with the
    // refinement pass (measured: 1253×1200 cast vs 2040×1953 refinement).
    const vp = page.viewportSize?.() ?? null;
    castCaps = vp
      ? { width: Math.round(vp.width), height: Math.round(vp.height) }
      : {
          width: Math.max(Math.round(streamView?.width ?? 0), 1600),
          height: Math.max(Math.round(streamView?.height ?? 0), 1200),
        };
    try {
      await session.send("Page.startScreencast", {
        format: "jpeg",
        quality: STREAM_QUALITY,
        maxWidth: castCaps.width,
        maxHeight: castCaps.height,
      });
    } catch (err) {
      log(`stream: screencast start failed: ${err.message || err}`);
      await stopScreencastNow();
      return;
    }
    // New capture epoch (join/tab-switch/resume): restart the shared encoder
    // so h264 viewers get fresh SPS/PPS + IDR and any dimension change lands.
    void ensureAnnexBEncoder({ restart: true });
  }

  // Follow the current tab; also (re)starts after a resume-forced restart.
  const retarget = setInterval(() => {
    if (closed || clients.size === 0 || suspended > 0 || reshaping) return;
    if (state.current !== cdpPage) void startScreencast();
  }, RETARGET_POLL_MS);
  retarget.unref?.();

  // Idle refinement: once the screencast has gone quiet the page has settled —
  // push ONE sharp captureScreenshot so static text isn't stuck at motion
  // quality. Rearmed by the next screencast frame. Never fires suspended, and
  // re-checks after the await in case a fill started mid-capture.
  const refine = setInterval(async () => {
    if (closed || suspended > 0 || refined || REFINE_QUALITY <= 0) return;
    const session = cdp;
    if (!session || !lastMetadata || clients.size === 0) return;
    if (Date.now() - lastFrameAt < REFINE_AFTER_MS) return;
    refined = true;
    // Counted where the pass commits, before the capture: a capture that dies
    // on a navigation still fired, and the gap against the `fi` it would have
    // added is itself the reading.
    cap.x.refine++;
    try {
      // Same capture call as the scaled motion path (captureShot pins
      // clip.scale to 1), so the refinement's pixel dimensions match the
      // motion frames in every mode — the encoders choke on dimension flips.
      const shot = await captureShot(session, REFINE_QUALITY);
      if (closed || suspended > 0 || session !== cdp) return;
      // The capture stage's SECOND frame source. Counted as input like a cast
      // frame or `fo` would exceed `fi` every time the page went quiet.
      cap.in(b64Bytes(shot.data));
      deliverFrame({
        data: shot.data,
        metadata: streamScale > 1 ? scaledMetadata() : lastMetadata,
        refinement: true,
      });
      // The encoder gets refinements too — on a damage-driven screencast this
      // is what keeps an h264 viewer's picture alive across idle stretches.
      // Written TWICE: raw MJPEG only delimits frame N when frame N+1's SOI
      // arrives, so a single write would sit in ffmpeg's parser until the
      // next repaint. Copy #1 flushes whatever was stuck AND gets encoded
      // (flushed by copy #2); the stuck copy #2 is identical, so no loss.
      if (encoderSinks.size > 0) feedEncoders(Buffer.from(shot.data, "base64"), 2);
    } catch { /* navigating/closed — the next screencast frame rearms */ }
  }, REFINE_POLL_MS);
  refine.unref?.();

  // "A viewer is watching and no frames are coming" — the one condition that
  // always means the picture is wrong, whatever the cause (dead CDP session,
  // a screencast Chrome stopped feeding, an encoder that never started).
  const watchdog = setInterval(() => {
    if (closed || WATCHDOG_MS <= 0 || suspended > 0 || clients.size === 0 || reshaping) return;
    const page = state.current;
    if (!page || page.isClosed?.()) return;
    if (cdp && Date.now() - lastFrameAt < WATCHDOG_MS) return;
    if (!cdp) {
      void startScreencast();
      return;
    }
    log(`stream: no frames for ${WATCHDOG_MS}ms with ${clients.size} viewer(s) — restarting screencast`);
    void stopScreencast().then(() => startScreencast());
  }, Math.max(1000, Math.floor(WATCHDOG_MS / 3)));
  watchdog.unref?.();

  async function handleWebRtcSignal(client, msg) {
    try {
      if (!webrtc) {
        const { createWebRtcStreamer } = await import("./stream-webrtc.mjs");
        webrtc = await createWebRtcStreamer({
          addSink: (s) => encoderSinks.add(s),
          removeSink: (s) => encoderSinks.delete(s),
          send: (c, obj) => sendText(c, obj),
          log,
          ffmpegPath: h264Config?.ffmpegPath ?? null,
        });
      }
      await webrtc.signal(client, msg);
    } catch (err) {
      sendText(client, { type: "webrtc_error", error: String(err?.message || err) });
    }
  }

  let viewerHtml = null;
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (req.method === "GET" && url.pathname === "/viewer") {
      if (url.searchParams.get("token") !== token) {
        res.writeHead(403).end();
        return;
      }
      try {
        viewerHtml ??= await fs.readFile(new URL("./stream-viewer.html", import.meta.url));
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end(viewerHtml);
      } catch {
        res.writeHead(404).end();
      }
      return;
    }
    res.writeHead(426).end(); // otherwise this port only speaks WebSocket
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

    const client = {
      sock: socket,
      ...parseStreamParams(url),
      pending: null, // the ONE latest-frame-wins slot
      awaitingAck: null,
      lastSentAt: 0,
      timer: null,
      congested: false,
    };
    // auto resolves against provisioning: h264 only on an install-codecs'd
    // host. The join status tells the viewer which one it got.
    if (client.codec === "auto") client.codec = h264Config ? "h264" : "jpeg";
    // Strict + unprovisioned host: refuse now. Waiting for the encoder to
    // fail would answer a handshake question minutes later, and only after
    // the viewer had already been served jpeg it never agreed to.
    if (client.strict && !h264Config) {
      clients.add(client);
      closeClient(
        client,
        CLOSE_CODEC_UNAVAILABLE,
        "h264 requested with strict=1 but this host has no encoder — run `agent-id-browser install-codecs`",
      );
      return;
    }
    clients.add(client);
    sendText(client, statusFor(client));
    if (client.codec === "h264") void ensureAnnexBEncoder();

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
      // Flow-control messages stay live even during a suspend blackout — an
      // ack for a pre-suspend frame must still release the pipeline.
      if (msg.type === "ack") {
        if (client.awaitingAck !== null && Number(msg.seq) >= client.awaitingAck) {
          client.awaitingAck = null;
          pump(client);
        }
        return;
      }
      if (msg.type === "config") {
        if (msg.pacing === "ack" || msg.pacing === "push") {
          client.pacing = msg.pacing;
          if (msg.pacing === "push") client.awaitingAck = null;
        }
        if (msg.maxFps !== undefined) {
          const n = Number(msg.maxFps);
          if (Number.isFinite(n)) client.maxFps = Math.min(120, Math.max(0, Math.floor(n)));
        }
        pump(client);
        return;
      }
      if (msg.type === "status_request") {
        sendText(client, statusFor(client));
        return;
      }
      if (msg.type === "webrtc_offer" || msg.type === "webrtc_ice") {
        void handleWebRtcSignal(client, msg);
        return;
      }
      // Input is disabled while a credential fill is in flight — the viewer
      // must not be able to interact with a form mid-injection.
      if (suspended > 0) return;
      onActivity();
      if (msg.type === "resize") {
        // Reshape the page viewport to the viewer's screen (mobile-sized
        // viewports for phone watchers). Serialized behind pending input and
        // suspend-checked at apply time like every other viewer event; the
        // achieved viewport is broadcast so ALL watchers learn the new shape.
        const width = Math.round(Number(msg.width));
        const height = Math.round(Number(msg.height));
        if (!resize || ![width, height].every(Number.isFinite)) return;
        // Optional HiDPI knob: a retina-density viewer asks for the capture
        // at scale× device pixels. Absent/garbage → 1, so clients that only
        // ever send width/height keep their exact pre-`scale` behavior. The
        // request then passes the geometry policy (axis clamps, integer
        // scale, axis + pixel budgets — see budgetedResize).
        const requestedScale = Number(msg.scale);
        const { width: w, height: h, scale } = budgetedResize(
          width,
          height,
          Number.isFinite(requestedScale) ? requestedScale : SCALE_MIN,
        );
        inputChain = inputChain
          .then(async () => {
            if (suspended > 0) return;
            // An active override pins the viewport (blinding the window
            // resize's chrome measurement) and lives on the cast session —
            // drop the cast first, and hold the `reshaping` gate so no other
            // path casts (and re-applies a stale override) mid-resize. The
            // closing restart applies the override at the new geometry and
            // replaces the shared encoder, so h264 viewers get fresh SPS/PPS
            // + an IDR at the new pixel dimensions instead of a decoder
            // stall. A 1×→1× resize skips all of this and keeps the classic
            // behavior.
            const scaling = scale > 1 || streamScale > 1;
            let viewport;
            if (scaling) {
              reshaping = true;
              try {
                await stopScreencast();
                viewport = await resize(w, h);
                streamScale = scale;
                streamDims = { width: w, height: h };
                streamView = viewport ?? streamDims;
                await stopScreencast(); // belt: kill anything that slipped in
                await startScreencast();
                // The override pins the viewport AFTER the measurement inside
                // resize() — remeasure so the broadcast reports what the page
                // actually became. (startScreencast may have downgraded
                // streamScale to 1 if Chrome refused the override.)
                if (streamScale > 1) {
                  viewport = (await measureViewport(streamDims)) ?? viewport;
                  streamView = viewport ?? streamDims;
                }
              } finally {
                reshaping = false;
              }
            } else {
              viewport = await resize(w, h);
              streamScale = scale;
              streamDims = { width: w, height: h };
              streamView = viewport ?? streamDims;
              // Frames larger than the running cast's caps would be silently
              // downscaled out of agreement with the refinement pass — grow
              // into fresh caps. Resizes within the caps keep the classic
              // no-restart behavior.
              if (cdp && castCaps && (streamView.width > castCaps.width || streamView.height > castCaps.height)) {
                await stopScreencast();
                await startScreencast();
              }
            }
            broadcastStatus({
              type: "status",
              source: "alien",
              resized: { width: w, height: h, scale: streamScale },
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
        // Malformed input used to disappear here: the viewer sent something
        // the server could not act on and heard nothing back, so a client bug
        // looked like a dead feed. Report it to the sender (only — it is their
        // message) and keep the queue running.
        .catch((err) => {
          sendText(client, {
            type: "status",
            source: "alien",
            error: err?.message || String(err),
            for: msg.type,
          });
        });
    });
    socket.on("data", parse);
    socket.on("drain", () => {
      client.congested = false;
      pump(client);
    });

    const drop = () => {
      clients.delete(client);
      if (client.timer) clearTimeout(client.timer);
      webrtc?.drop(client);
      void ensureAnnexBEncoder(); // tears down when the last h264 viewer left
      if (clients.size === 0) {
        void stopScreencast(); // save CPU when unwatched
        stopFocusPoller();
      }
    };
    socket.on("close", drop);
    socket.on("error", drop);

    // Frames are CHANGE-driven, so a client that joins an already-running cast
    // gets nothing at all until the page happens to move — on a sign-in form
    // that is forever, and a blank canvas reads as "the browser view is
    // broken". Restart the cast so Chrome emits a fresh first frame for it
    // (the same trick `resume` uses); otherwise this is the first watcher and
    // starting the feed produces that frame anyway. A join mid-(scaled-)resize
    // must not start its own cast — the resize's closing restart serves it.
    if (!reshaping) {
      if (cdp) void stopScreencast().then(() => startScreencast());
      else void startScreencast();
    }
    ensureFocusPoller();
  });

  await new Promise((resolve) => server.listen(0, BIND_HOST, resolve));

  return {
    port: server.address().port,
    token,
    /** How many viewers are attached — a watched session is never idle. */
    viewers: () => clients.size,
    /** Report the page's input-focus state (see the session init script). */
    inputFocus,
    /** Hide the feed while a secret is typed into the page. Depth-counted. */
    suspend() {
      suspended++;
      // Drop staged frames: nothing captured before the blackout may deliver
      // during it (a drain/ack arriving mid-fill would otherwise flush one).
      for (const client of clients) client.pending = null;
      broadcastStatus({ type: "status", source: "alien", suspended: true });
    },
    resume() {
      suspended = Math.max(0, suspended - 1);
      if (suspended === 0) {
        broadcastStatus({ type: "status", source: "alien", suspended: false });
        // Restart to force a fresh keyframe — otherwise a static page after the
        // fill would leave the viewer on the pre-fill frame indefinitely.
        void stopScreencast().then(() => startScreencast());
      }
    },
    close() {
      stopFocusPoller();
      counters?.stop();
      closed = true;
      clearInterval(retarget);
      clearInterval(watchdog);
      clearInterval(refine);
      void stopScreencast();
      if (annexB) {
        encoderSinks.delete(annexB);
        annexB.close();
        annexB = null;
      }
      webrtc?.close();
      for (const client of clients) {
        if (client.timer) clearTimeout(client.timer);
        client.sock.destroy();
      }
      clients.clear();
      server.close();
    },
  };
}
