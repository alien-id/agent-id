// H.264 encoding for the viewport stream — an ffmpeg subprocess per encoder.
//
// Input is the CDP screencast's JPEG frames written to stdin as an MJPEG
// stream (wallclock timestamps: the screencast is damage-driven, so input is
// variable-rate and a static page costs nothing). Output is either raw
// Annex-B on stdout (WS `codec=h264` clients, WebCodecs/MSE decodable) or an
// RTP stream to a loopback UDP port (the WebRTC path repacketizes nothing —
// ffmpeg already speaks RTP).
//
// Encoder selection: libx264 when the ffmpeg build has it (typical container
// images), else libopenh264 (Cisco's BSD encoder — what Fedora ships). Both
// are Constrained Baseline, GOP ~30, no B-frames: every browser decodes it
// and a joining viewer waits at most one GOP for an IDR (in practice zero —
// the server restarts the encoder on join, forcing SPS/PPS + IDR up front).
//
// Backpressure: write() drops the frame when ffmpeg's stdin is saturated.
// Dropping INPUT frames is safe (the encoder just sees a lower fps) — it is
// the output that must never gap mid-GOP.

import { spawn, execFile } from "node:child_process";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFileP = promisify(execFile);

const FFMPEG = () => process.env.AGENT_ID_FFMPEG || "ffmpeg";
const GOP = 30;

// ── codec provisioning ───────────────────────────────────────────────────────
// H.264 is the DEFAULT stream codec only after the owner explicitly
// provisioned it (`agent-id-browser install-codecs`) — the record below is
// what flips `codec=auto` clients from jpeg to h264. An un-provisioned host
// never spawns ffmpeg implicitly; explicit `?codec=h264` still probes PATH.

export const codecConfigPath = (stateDir) => path.join(stateDir, "browser-codecs.json");

/**
 * The codec provisioning for this host: the `install-codecs` record from
 * stateDir, re-verified against the binary — or, when no record exists, the
 * host-level `AGENT_ID_FFMPEG` override, probed live. Null only when neither
 * provisions the host.
 *
 * The env fallback is what makes an immutable-image host provisionable at
 * all: `install-codecs` writes into a per-tenant stateDir, but a container
 * image is shared across every tenant and cannot pre-write per-tenant files —
 * the one host-level channel an image has is an env var. Setting
 * AGENT_ID_FFMPEG is the same explicit operator opt-in the record represents
 * (nothing is probed on a host that set neither), and the probe re-verifies
 * the binary the same way a record is re-verified, so a stale override
 * degrades to unprovisioned rather than to a broken encoder. Deliberately
 * NOT persisted back into stateDir: the env is authoritative per-process,
 * and a written record would outlive an image whose ffmpeg moved.
 */
export async function loadCodecConfig(stateDir) {
  try {
    const cfg = JSON.parse(await fsp.readFile(codecConfigPath(stateDir), "utf8"));
    if (cfg?.ffmpegPath && (await detectH264Encoder(cfg.ffmpegPath))) return cfg;
  } catch { /* absent or stale */ }
  const envPath = process.env.AGENT_ID_FFMPEG;
  if (envPath) {
    const encoder = await detectH264Encoder(envPath);
    if (encoder) return { ffmpegPath: envPath, encoder, source: "env" };
  }
  return null;
}

/**
 * Probe for a usable ffmpeg (env override → PATH → previously downloaded),
 * downloading a static build into <stateDir>/tools as a last resort (Linux
 * only — BtbN's gpl build, the ffmpeg-project-recommended static binaries,
 * which include libx264). Records the result in browser-codecs.json.
 */
export async function installCodecs({ stateDir, allowDownload = true, log = () => {} }) {
  const candidates = [
    process.env.AGENT_ID_FFMPEG,
    "ffmpeg",
    path.join(stateDir, "tools", "ffmpeg"),
  ].filter(Boolean);
  for (const cand of candidates) {
    const encoder = await detectH264Encoder(cand);
    if (encoder) return record(stateDir, cand, encoder, "probed");
  }
  if (!allowDownload) {
    throw new Error("no usable ffmpeg found (install one: dnf/apt/brew install ffmpeg) — or rerun without --no-download");
  }
  if (process.platform !== "linux" || !["x64", "arm64"].includes(process.arch)) {
    throw new Error(`no usable ffmpeg found and static download is Linux-only — install ffmpeg with your package manager (${process.platform}/${process.arch})`);
  }
  const flavor = process.arch === "arm64" ? "linuxarm64" : "linux64";
  const url = `https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-${flavor}-gpl.tar.xz`;
  log(`downloading static ffmpeg: ${url}`);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`ffmpeg download failed: HTTP ${res.status}`);
  const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), "aid-ffmpeg-"));
  const archive = path.join(tmp, "ffmpeg.tar.xz");
  await fsp.writeFile(archive, Buffer.from(await res.arrayBuffer()));
  await execFileP("tar", ["-xJf", archive, "-C", tmp]);
  const [root] = (await fsp.readdir(tmp)).filter((f) => f.startsWith("ffmpeg-"));
  const extracted = path.join(tmp, root, "bin", "ffmpeg");
  const dest = path.join(stateDir, "tools", "ffmpeg");
  await fsp.mkdir(path.dirname(dest), { recursive: true, mode: 0o700 });
  await fsp.copyFile(extracted, dest);
  await fsp.chmod(dest, 0o755);
  await fsp.rm(tmp, { recursive: true, force: true });
  const encoder = await detectH264Encoder(dest);
  if (!encoder) throw new Error("downloaded ffmpeg has no usable h264 encoder (unexpected)");
  return record(stateDir, dest, encoder, "downloaded");
}

async function record(stateDir, ffmpegPath, encoder, source) {
  const cfg = { ffmpegPath, encoder, source, installedAt: new Date().toISOString() };
  await fsp.mkdir(stateDir, { recursive: true, mode: 0o700 });
  await fsp.writeFile(codecConfigPath(stateDir), JSON.stringify(cfg, null, 2) + "\n", { mode: 0o600 });
  return cfg;
}

const detected = new Map(); // ffmpeg path → cached probe promise

/** Resolve the usable H.264 encoder in this ffmpeg build, or null. */
export function detectH264Encoder(ffmpegPath) {
  const path = ffmpegPath || FFMPEG();
  if (!detected.has(path)) {
    detected.set(path, new Promise((resolve) => {
      const forced = process.env.AGENT_ID_STREAM_H264_ENCODER;
      if (forced) return resolve(forced);
      const probe = spawn(path, ["-hide_banner", "-encoders"], {
        stdio: ["ignore", "pipe", "ignore"],
      });
      let out = "";
      probe.stdout.on("data", (d) => (out += d));
      probe.on("error", () => resolve(null));
      probe.on("close", () => {
        if (/\blibx264\b/.test(out)) return resolve("libx264");
        if (/\blibopenh264\b/.test(out)) return resolve("libopenh264");
        resolve(null);
      });
    }));
  }
  return detected.get(path);
}

function codecArgs(encoder) {
  // yuv420p needs even dimensions; screencast frames can be odd-sized.
  const scale = ["-vf", "scale=trunc(iw/2)*2:trunc(ih/2)*2"];
  if (encoder === "libx264") {
    // veryfast/CRF over ultrafast/defaults: roughly 2x the quality per bit,
    // still comfortably realtime for a viewport-sized feed. zerolatency keeps
    // lookahead off so latency is unchanged; CRF spends bits only when the
    // picture moves and the maxrate cap bounds worst-case bursts. The profile
    // stays constrained-baseline on purpose — the WebCodecs viewer and the
    // WebRTC path both pin avc1.42E01F, and that contract is what guarantees
    // every consumer decodes the feed.
    return [
      ...scale,
      "-c:v", "libx264",
      "-preset", "veryfast",
      "-tune", "zerolatency",
      "-profile:v", "baseline",
      "-crf", "20",
      "-maxrate", "4M",
      "-bufsize", "8M",
      "-pix_fmt", "yuv420p",
      "-g", String(GOP),
      "-bf", "0",
    ];
  }
  // openh264 has no preset/tune/crf — it is rate-controlled. Built for
  // real-time (WebRTC) use, so it is already zero-latency shaped.
  return [
    ...scale,
    "-c:v", "libopenh264",
    "-profile:v", "constrained_baseline",
    "-pix_fmt", "yuv420p",
    "-g", String(GOP),
    "-b:v", "4000k",
    "-maxrate", "6000k",
  ];
}

/**
 * Spawn an encoder. `onChunk(Buffer)` receives Annex-B output; pass `rtp:
 * {port, payloadType, ssrc}` instead to emit RTP to loopback UDP (onChunk
 * unused). Returns { write(jpegBuffer) → bool, close() }; calls `onExit()`
 * once when the process dies for any reason. Throws when ffmpeg or an H.264
 * encoder is unavailable.
 */
export async function createH264Encoder({ onChunk, onExit, log = () => {}, rtp = null, ffmpegPath = null }) {
  const ffmpeg = ffmpegPath || FFMPEG();
  const encoder = await detectH264Encoder(ffmpeg);
  if (!encoder) throw new Error("ffmpeg with libx264/libopenh264 not found");

  // Annex-B gets AUD NALs inserted so WebCodecs viewers can split the byte
  // stream into access units without parsing slice headers.
  const output = rtp
    ? ["-f", "rtp", "-payload_type", String(rtp.payloadType ?? 96),
       ...(rtp.ssrc ? ["-ssrc", String(rtp.ssrc)] : []),
       `rtp://127.0.0.1:${rtp.port}?pkt_size=1200`]
    : ["-bsf:v", "h264_metadata=aud=insert", "-f", "h264", "pipe:1"];

  const proc = spawn(
    ffmpeg,
    [
      "-hide_banner", "-loglevel", "error", "-fflags", "nobuffer",
      // Without these, find_stream_info sits on the default 5MB probe window
      // and the first frames never reach the encoder (measured: 3 frames in,
      // 0 bytes out). Dimensions come from the first JPEG's SOF either way.
      "-analyzeduration", "0", "-probesize", "32",
      "-f", "mjpeg", "-use_wallclock_as_timestamps", "1", "-i", "pipe:0",
      "-an", ...codecArgs(encoder), ...output,
    ],
    { stdio: ["pipe", rtp ? "ignore" : "pipe", "pipe"] },
  );

  await new Promise((resolve, reject) => {
    proc.once("spawn", resolve);
    proc.once("error", reject);
  });

  let stderrTail = "";
  proc.stderr.on("data", (d) => {
    stderrTail = (stderrTail + d.toString()).slice(-2048);
  });
  const onStdout = rtp ? null : (chunk) => onChunk?.(chunk);
  if (onStdout) proc.stdout.on("data", onStdout);

  let writable = true;
  let alive = true;
  let closed = false;
  proc.stdin.on("drain", () => (writable = true));
  proc.stdin.on("error", () => {}); // EPIPE on teardown races
  proc.once("close", (code) => {
    alive = false;
    if (code) log(`stream: h264 encoder (${encoder}) exited ${code}: ${stderrTail.trim()}`);
    onExit?.();
  });

  return {
    encoder,
    write(jpeg) {
      if (!alive || !writable) return false; // drop the frame — input-side only
      writable = proc.stdin.write(jpeg);
      return true;
    },
    close() {
      if (closed) return;
      closed = true;
      alive = false;
      // Detach before the kill: whatever is already in the pipe is still
      // delivered after it, and a replaced encoder's tail must never reach the
      // sink its replacement writes to (it references the old parameter sets).
      if (onStdout) proc.stdout.off("data", onStdout);
      try { proc.stdin.destroy(); } catch { /* already gone */ }
      try { proc.kill("SIGKILL"); } catch { /* already dead */ }
    },
  };
}
