---
"@alien-id/agent-id-browser": patch
---

Viewport stream quality: screencast motion frames go out at JPEG quality 80
(was 55 — visible ringing around text that the H.264 stage then spent bits
reproducing), and the libx264 path encodes at veryfast/CRF 20 with a 4M/8M
rate cap instead of ultrafast with defaults (~2x quality per bit, latency
unchanged). The openh264 fallback's bitrate rises to 4000k/6000k for parity.
Profile stays constrained-baseline — the WebCodecs viewer and the WebRTC path
pin avc1.42E01F. Traffic is roughly unchanged: the pipeline is change-driven,
and CRF only spends bits while the picture moves.
