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

import { spawn } from "node:child_process";

const FFMPEG = () => process.env.AGENT_ID_FFMPEG || "ffmpeg";
const GOP = 30;

const detected = new Map(); // ffmpeg path → cached probe promise

/** Resolve the usable H.264 encoder in this ffmpeg build, or null. */
export function detectH264Encoder() {
  const path = FFMPEG();
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
    return [
      ...scale,
      "-c:v", "libx264",
      "-preset", "ultrafast",
      "-tune", "zerolatency",
      "-profile:v", "baseline",
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
    "-b:v", "1500k",
    "-maxrate", "2500k",
  ];
}

/**
 * Spawn an encoder. `onChunk(Buffer)` receives Annex-B output; pass `rtp:
 * {port, payloadType, ssrc}` instead to emit RTP to loopback UDP (onChunk
 * unused). Returns { write(jpegBuffer) → bool, close() }; calls `onExit()`
 * once when the process dies for any reason. Throws when ffmpeg or an H.264
 * encoder is unavailable.
 */
export async function createH264Encoder({ onChunk, onExit, log = () => {}, rtp = null }) {
  const encoder = await detectH264Encoder();
  if (!encoder) throw new Error("ffmpeg with libx264/libopenh264 not found");

  // Annex-B gets AUD NALs inserted so WebCodecs viewers can split the byte
  // stream into access units without parsing slice headers.
  const output = rtp
    ? ["-f", "rtp", "-payload_type", String(rtp.payloadType ?? 96),
       ...(rtp.ssrc ? ["-ssrc", String(rtp.ssrc)] : []),
       `rtp://127.0.0.1:${rtp.port}?pkt_size=1200`]
    : ["-bsf:v", "h264_metadata=aud=insert", "-f", "h264", "pipe:1"];

  const proc = spawn(
    FFMPEG(),
    [
      "-hide_banner", "-loglevel", "error", "-fflags", "nobuffer",
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
  if (!rtp) proc.stdout.on("data", (chunk) => onChunk?.(chunk));

  let writable = true;
  let alive = true;
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
      alive = false;
      try { proc.stdin.destroy(); } catch { /* already gone */ }
      try { proc.kill("SIGKILL"); } catch { /* already dead */ }
    },
  };
}
