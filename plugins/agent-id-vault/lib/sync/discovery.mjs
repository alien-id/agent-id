// Alien Agent ID — sync peer discovery.
//
// A deliberately tiny UDP multicast beacon (NOT full mDNS/DNS-SD — phase 2).
// Beacons are unsigned and carry no secrets: a beacon is only an invitation
// to open a TLS connection, where the real mutual authentication happens
// (trust.mjs). The worst a forged beacon can cause is a failed handshake.

import dgram from "node:dgram";

export const BEACON_GROUP = "239.83.7.71";
export const BEACON_PORT = 48338;
const BEACON_MAGIC = "agent-id-vault-sync";

export function announceBeacon({
  deviceJkt,
  tcpPort,
  intervalMs = 2000,
  port = BEACON_PORT,
}) {
  const socket = dgram.createSocket({ type: "udp4", reuseAddr: true });
  const message = Buffer.from(JSON.stringify({ magic: BEACON_MAGIC, v: 1, deviceJkt, tcpPort }));
  let timer = null;
  socket.on("error", () => { /* discovery is best-effort */ });
  socket.bind(() => {
    try { socket.setMulticastTTL(1); } catch { /* not fatal */ }
    const send = () => socket.send(message, port, BEACON_GROUP);
    send();
    timer = setInterval(send, intervalMs);
    timer.unref?.();
  });
  return {
    stop() {
      if (timer) clearInterval(timer);
      try { socket.close(); } catch { /* already closed */ }
    },
  };
}

export function listenForBeacons({
  timeoutMs = 2500,
  ownJkt = null,
  port = BEACON_PORT,
} = {}) {
  return new Promise((resolve) => {
    const socket = dgram.createSocket({ type: "udp4", reuseAddr: true });
    const peers = new Map();
    const finish = () => {
      try { socket.close(); } catch { /* already closed */ }
      resolve([...peers.values()]);
    };
    socket.on("error", finish);
    socket.on("message", (buf, rinfo) => {
      try {
        const msg = JSON.parse(buf.toString("utf8"));
        if (msg.magic !== BEACON_MAGIC || !Number.isInteger(msg.tcpPort)) return;
        if (ownJkt && msg.deviceJkt === ownJkt) return;
        peers.set(`${rinfo.address}:${msg.tcpPort}`, {
          host: rinfo.address,
          port: msg.tcpPort,
          deviceJkt: msg.deviceJkt || null,
        });
      } catch { /* ignore malformed beacons */ }
    });
    socket.bind(port, () => {
      try { socket.addMembership(BEACON_GROUP); } catch { /* no multicast here */ }
      setTimeout(finish, timeoutMs).unref?.();
    });
  });
}
