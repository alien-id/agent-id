// EXPERIMENTAL WebRTC delivery for the viewport stream.
//
// Signaling rides the existing stream WebSocket (webrtc_offer / webrtc_answer
// / webrtc_ice messages, trickle ICE both ways), so the token gate and the
// session lifecycle stay exactly as they are — WebRTC replaces only the frame
// transport. Media is H.264 (the one codec every browser's WebRTC stack
// decodes, mobile included): a per-peer ffmpeg encoder emits RTP to a
// loopback UDP port and werift forwards the packets into the negotiated
// track. werift is a pure-JS WebRTC implementation and an OPTIONAL dependency
// — when it isn't installed the caller reports webrtc_error and the viewer
// falls back to a WS mode.
//
// Known experiment limits: no RTCP feedback loop (a PLI can't force an ffmpeg
// keyframe — recovery is the periodic GOP), and candidates are host-only (no
// STUN/TURN): fine for localhost and LAN viewer testing, not for internet
// relay.

import dgram from "node:dgram";

import { createH264Encoder } from "./stream-encoder.mjs";

const H264_FMTP =
  "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f";

export async function createWebRtcStreamer({
  addSink,
  removeSink,
  send,
  log = () => {},
  ffmpegPath = null,
}) {
  const werift = await import("werift");
  const peers = new Map(); // client → {pc, udp, enc}

  async function teardown(peer) {
    if (!peer) return;
    if (peer.enc) removeSink(peer.enc);
    try {
      peer.enc?.close();
    } catch {
      /* already dead */
    }
    try {
      peer.udp.close();
    } catch {
      /* already closed */
    }
    try {
      await peer.pc.close();
    } catch {
      /* already closed */
    }
  }

  async function startPeer(client, offerSdp) {
    const udp = dgram.createSocket("udp4");
    await new Promise((resolve, reject) => {
      udp.once("error", reject);
      udp.bind(0, "127.0.0.1", resolve);
    });

    const pc = new werift.RTCPeerConnection({
      codecs: {
        video: [
          new werift.RTCRtpCodecParameters({
            mimeType: "video/H264",
            clockRate: 90000,
            payloadType: 96,
            parameters: H264_FMTP,
          }),
        ],
      },
    });
    const track = new werift.MediaStreamTrack({ kind: "video" });
    pc.addTransceiver(track, { direction: "sendonly" });
    pc.onIceCandidate.subscribe((candidate) => {
      send(client, { type: "webrtc_ice", candidate: candidate.toJSON() });
    });
    udp.on("message", (rtp) => {
      try {
        track.writeRtp(rtp);
      } catch {
        /* peer torn down mid-packet */
      }
    });

    await pc.setRemoteDescription({ type: "offer", sdp: offerSdp });
    await pc.setLocalDescription(await pc.createAnswer());
    send(client, { type: "webrtc_answer", sdp: pc.localDescription.sdp });

    const peer = { pc, udp, enc: null };
    peers.set(client, peer);
    peer.enc = await createH264Encoder({
      log,
      ffmpegPath,
      rtp: { port: udp.address().port, payloadType: 96 },
      onExit: () => {
        if (peers.get(client) !== peer || !peer.enc) return;
        removeSink(peer.enc);
        peer.enc = null; // resize/crash: a re-offer builds a fresh peer
        send(client, { type: "webrtc_error", error: "encoder exited" });
      },
    });
    addSink(peer.enc);
  }

  return {
    async signal(client, msg) {
      if (msg.type === "webrtc_offer") {
        await teardown(peers.get(client)); // re-offer = fresh peer
        peers.delete(client);
        await startPeer(client, String(msg.sdp ?? ""));
        return;
      }
      if (msg.type === "webrtc_ice") {
        const peer = peers.get(client);
        if (peer && msg.candidate) await peer.pc.addIceCandidate(msg.candidate);
      }
    },
    drop(client) {
      const peer = peers.get(client);
      peers.delete(client);
      void teardown(peer);
    },
    close() {
      for (const peer of peers.values()) void teardown(peer);
      peers.clear();
    },
  };
}
