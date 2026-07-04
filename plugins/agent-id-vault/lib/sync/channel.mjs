// Alien Agent ID — Vault sync transport.
//
// TLS 1.3 with ephemeral self-signed P-256 certs on BOTH ends. The certs are
// pure key carriers: CA/hostname validation is disabled and nothing is pinned
// — identity lives entirely in the Ed25519 signature over the RFC 5705
// exported keying material (see trust.mjs), so cert rotation is a non-event
// and an active MITM is structurally excluded.
//
// Framing: one JSON object per LF-terminated line.

import tls from "node:tls";

import { generateControlCert } from "@alien-id/agent-id-core/lib/tls-cert.mjs";
import { SYNC_EKM_LABEL } from "./trust.mjs";

const EKM_BYTES = 32;
const MAX_BUFFERED = 16 * 1024 * 1024; // ops carry full credential records

export function makeLineIO(socket) {
  let buffered = "";
  const queue = [];
  const waiters = [];
  let finished = null;

  const fail = (err) => {
    if (finished) return;
    finished = err || new Error("sync connection closed");
    for (const w of waiters.splice(0)) w.reject(finished);
  };

  socket.setEncoding("utf8");
  socket.on("data", (chunk) => {
    buffered += chunk;
    if (buffered.length > MAX_BUFFERED) {
      socket.destroy(new Error("sync frame too large"));
      return;
    }
    let idx;
    while ((idx = buffered.indexOf("\n")) >= 0) {
      const line = buffered.slice(0, idx);
      buffered = buffered.slice(idx + 1);
      if (!line.trim()) continue;
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        socket.destroy(new Error("malformed sync frame"));
        return;
      }
      const waiter = waiters.shift();
      if (waiter) waiter.resolve(msg);
      else queue.push(msg);
    }
  });
  socket.on("error", fail);
  socket.on("close", () => fail());

  return {
    write(msg) {
      socket.write(JSON.stringify(msg) + "\n");
    },
    read() {
      if (queue.length) return Promise.resolve(queue.shift());
      if (finished) return Promise.reject(finished);
      return new Promise((resolve, reject) => waiters.push({ resolve, reject }));
    },
    async expect(type) {
      const msg = await this.read();
      if (msg.t === "error") {
        const err = new Error(`peer refused: ${msg.code || "unknown"}`);
        err.code = msg.code || "peer-error";
        throw err;
      }
      if (msg.t !== type) {
        throw new Error(`sync protocol error: expected "${type}", got "${String(msg.t)}"`);
      }
      return msg;
    },
  };
}

export async function startSyncServer({ host = "0.0.0.0", port = 0, onSession }) {
  const { certPem, keyPem } = generateControlCert({ cn: "agent-id-vault-sync" });
  const server = tls.createServer(
    {
      cert: certPem,
      key: keyPem,
      minVersion: "TLSv1.3",
      requestCert: true,
      rejectUnauthorized: false, // peer cert is a key carrier, not an identity
    },
    (socket) => {
      const ekm = socket.exportKeyingMaterial(EKM_BYTES, SYNC_EKM_LABEL);
      onSession({ socket, ekm, io: makeLineIO(socket), role: "listener" });
    },
  );
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, resolve);
  });
  return {
    server,
    port: server.address().port,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

export async function connectToPeer({ host, port, timeoutMs = 10_000 }) {
  const { certPem, keyPem } = generateControlCert({ cn: "agent-id-vault-sync" });
  const socket = tls.connect({
    host,
    port,
    cert: certPem,
    key: keyPem,
    minVersion: "TLSv1.3",
    rejectUnauthorized: false,
  });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`sync connect timeout to ${host}:${port}`));
    }, timeoutMs);
    socket.once("secureConnect", () => { clearTimeout(timer); resolve(); });
    socket.once("error", (err) => { clearTimeout(timer); reject(err); });
  });
  const ekm = socket.exportKeyingMaterial(EKM_BYTES, SYNC_EKM_LABEL);
  return { socket, ekm, io: makeLineIO(socket), role: "initiator" };
}
