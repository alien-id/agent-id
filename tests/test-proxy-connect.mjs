#!/usr/bin/env node

// The CONNECT tunnel is a second data-plane entrance, and it must enforce the
// same rules as the request handler: the opt-in shared secret, the SSRF guard
// (a tunnel to 169.254.169.254 is the same cloud-metadata reach a plain request
// is refused), and the self-reopen an idle-locked vault gets.
//
// Run: node --test tests/test-proxy-connect.mjs

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";

import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import {
  createProxy,
  PROXY_AUTH_HEADER,
} from "../plugins/agent-id-proxy/lib/proxy.mjs";

const TOKEN = "s3cret-proxy-token";

// A plain TCP echo upstream: the tunnel target, and a connection counter that
// proves a refusal never opened a socket.
function startTcpUpstream() {
  return new Promise((resolve) => {
    const state = { connections: 0 };
    const server = net.createServer((sock) => {
      state.connections += 1;
      sock.on("data", (d) => sock.write(d));
      sock.on("error", () => {});
    });
    server.listen(0, "127.0.0.1", () => {
      const a = server.address();
      resolve({ server, state, host: a.address, port: a.port });
    });
  });
}

// Every client socket this file opens, so a failed assertion can't leave an
// established tunnel holding the proxy's close() open.
const openSockets = new Set();
function destroyOpenSockets() {
  for (const s of openSockets) s.destroy();
  openSockets.clear();
}

// A raw CONNECT, spoken by hand: the node http client hides the failure status
// line behind its own upgrade handling, and the status line is exactly what
// these tests assert on.
function rawConnect({ port, target, headers = {}, timeoutMs = 4000 }) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, "127.0.0.1", () => {
      let raw = `CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n`;
      for (const [k, v] of Object.entries(headers)) raw += `${k}: ${v}\r\n`;
      socket.write(`${raw}\r\n`);
    });
    openSockets.add(socket);
    let buf = "";
    let closed = false;
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(
        new Error(
          `timeout waiting for a CONNECT response (got: ${JSON.stringify(buf)})`
        )
      );
    }, timeoutMs);
    const settle = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const head = buf.split("\r\n\r\n")[0];
      resolve({
        statusLine: head.split("\r\n")[0] || "",
        head,
        socket,
        // Whether the proxy destroyed the connection after answering.
        closedSoon: () =>
          new Promise((r) => {
            if (closed) return r(true);
            const t = setTimeout(() => r(closed), 500);
            socket.on("close", () => {
              clearTimeout(t);
              r(true);
            });
          }),
      });
    };
    socket.on("data", (d) => {
      buf += d.toString("latin1");
      if (buf.includes("\r\n\r\n")) settle();
    });
    socket.on("close", () => {
      closed = true;
      openSockets.delete(socket);
      settle();
    });
    socket.on("error", (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });
  });
}

async function makeVault(stateDir) {
  await initVault({ stateDir, passphrase: "p" });
  return openVault({ stateDir, passphrase: "p" });
}

function closeServer(server) {
  return new Promise((resolve) =>
    server ? server.close(() => resolve()) : resolve()
  );
}

async function readAccessLog(logFile) {
  let raw = "";
  try {
    raw = await fs.readFile(logFile, "utf8");
  } catch {
    return [];
  }
  return raw
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

describe("CONNECT: data-plane auth", () => {
  let stateDir;
  let upstream;
  let proxy;
  let proxyPort;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-connect-auth-"));
    upstream = await startTcpUpstream();
    proxy = createProxy({
      vault: await makeVault(stateDir),
      logPath: path.join(stateDir, "proxy.log"),
      authToken: TOKEN,
    });
    proxyPort = (await proxy.listen()).port;
  });

  after(async () => {
    destroyOpenSockets();
    await proxy?.close();
    await closeServer(upstream?.server);
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("refuses a tokenless CONNECT with 401 and opens no upstream socket", async () => {
    const before = upstream.state.connections;
    const r = await rawConnect({
      port: proxyPort,
      target: `${upstream.host}:${upstream.port}`,
    });
    assert.equal(r.statusLine, "HTTP/1.1 401 Unauthorized");
    assert.match(r.head, /X-AgentVault-Proxy-Error: unauthorized/i);
    assert.equal(await r.closedSoon(), true);
    assert.equal(upstream.state.connections, before);
  });

  it("refuses a wrong token", async () => {
    const before = upstream.state.connections;
    const r = await rawConnect({
      port: proxyPort,
      target: `${upstream.host}:${upstream.port}`,
      headers: { [PROXY_AUTH_HEADER]: `${TOKEN}x` },
    });
    assert.equal(r.statusLine, "HTTP/1.1 401 Unauthorized");
    assert.equal(upstream.state.connections, before);
  });

  it("establishes the tunnel on a correct token", async () => {
    const before = upstream.state.connections;
    const r = await rawConnect({
      port: proxyPort,
      target: `${upstream.host}:${upstream.port}`,
      headers: { [PROXY_AUTH_HEADER]: TOKEN },
    });
    assert.equal(r.statusLine, "HTTP/1.1 200 Connection Established");
    assert.equal(upstream.state.connections, before + 1);
    const echoed = await new Promise((resolve, reject) => {
      r.socket.once("data", (d) => resolve(d.toString("utf8")));
      r.socket.on("error", reject);
      r.socket.write("ping");
    });
    assert.equal(echoed, "ping");
    r.socket.destroy();
  });
});

describe("CONNECT: SSRF guard", () => {
  let stateDir;
  let upstream;
  let openProxy;
  let openPort;
  let strictProxy;
  let strictPort;

  before(async () => {
    stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-connect-ssrf-"));
    upstream = await startTcpUpstream();
    openProxy = createProxy({
      vault: await makeVault(stateDir),
      logPath: path.join(stateDir, "proxy.log"),
    });
    openPort = (await openProxy.listen()).port;
    strictProxy = createProxy({
      vault: await openVault({ stateDir, passphrase: "p" }),
      logPath: path.join(stateDir, "proxy-strict.log"),
      blockPrivateHosts: true,
    });
    strictPort = (await strictProxy.listen()).port;
  });

  // Ordered so nothing is still writing when the state dir goes: close() is the
  // quiesce point for the access log (it awaits the fire-and-forget writes), and
  // the upstream close is awaited rather than assumed done.
  after(async () => {
    destroyOpenSockets();
    await openProxy?.close();
    await strictProxy?.close();
    await closeServer(upstream?.server);
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("refuses a link-local literal (cloud metadata) even with private hosts allowed", async () => {
    const r = await rawConnect({
      port: openPort,
      target: "169.254.169.254:80",
    });
    assert.equal(r.statusLine, "HTTP/1.1 403 Forbidden");
    assert.match(r.head, /X-AgentVault-Proxy-Error: upstream_blocked/i);
    assert.equal(await r.closedSoon(), true);
  });

  it("still tunnels to an allowed target", async () => {
    const before = upstream.state.connections;
    const r = await rawConnect({
      port: openPort,
      target: `${upstream.host}:${upstream.port}`,
    });
    assert.equal(r.statusLine, "HTTP/1.1 200 Connection Established");
    assert.equal(upstream.state.connections, before + 1);
    r.socket.destroy();
  });

  it("refuses a loopback literal under --block-private-hosts, opening no socket", async () => {
    const before = upstream.state.connections;
    const r = await rawConnect({
      port: strictPort,
      target: `${upstream.host}:${upstream.port}`,
    });
    assert.equal(r.statusLine, "HTTP/1.1 403 Forbidden");
    assert.match(r.head, /X-AgentVault-Proxy-Error: upstream_blocked/i);
    assert.equal(upstream.state.connections, before);
  });

  it("refuses a hostname that RESOLVES into a blocked range", async () => {
    const before = upstream.state.connections;
    const r = await rawConnect({
      port: strictPort,
      target: `localhost:${upstream.port}`,
    });
    assert.equal(r.statusLine, "HTTP/1.1 403 Forbidden");
    assert.match(r.head, /X-AgentVault-Proxy-Error: upstream_blocked/i);
    assert.equal(upstream.state.connections, before);
  });
});

describe("CONNECT: self-reopen after an idle lock", () => {
  let stateDir;
  let upstream;
  let proxy;
  let proxyPort;
  let reopenCalls;

  before(async () => {
    stateDir = await fs.mkdtemp(
      path.join(os.tmpdir(), "proxy-connect-reopen-")
    );
    upstream = await startTcpUpstream();
    reopenCalls = 0;
    proxy = createProxy({
      vault: await makeVault(stateDir),
      logPath: path.join(stateDir, "proxy.log"),
      authToken: TOKEN,
      reopenVault: async () => {
        reopenCalls += 1;
        return openVault({ stateDir, passphrase: "p" });
      },
    });
    proxyPort = (await proxy.listen()).port;
    proxy.forceLock("test");
  });

  after(async () => {
    destroyOpenSockets();
    await proxy?.close();
    await closeServer(upstream?.server);
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("reopens the vault instead of refusing an authenticated CONNECT", async () => {
    const r = await rawConnect({
      port: proxyPort,
      target: `${upstream.host}:${upstream.port}`,
      headers: { [PROXY_AUTH_HEADER]: TOKEN },
    });
    assert.equal(r.statusLine, "HTTP/1.1 200 Connection Established");
    assert.equal(reopenCalls, 1);
    r.socket.destroy();
  });
});

// Self-reopen is a self-heal for the unattended setup, never a way around an
// owner. With the control plane on, an unlock is the owner's decision — the
// tunnel must refuse exactly as it did before self-reopen existed, the same
// gate the request path applies.
describe("CONNECT: self-reopen never bypasses the control plane", () => {
  let stateDir;
  let upstream;
  let proxy;
  let proxyPort;
  let reopenCalls;

  before(async () => {
    stateDir = await fs.mkdtemp(
      path.join(os.tmpdir(), "proxy-connect-consent-")
    );
    upstream = await startTcpUpstream();
    reopenCalls = 0;
    proxy = createProxy({
      vault: await makeVault(stateDir),
      stateDir,
      logPath: path.join(stateDir, "proxy.log"),
      authToken: TOKEN,
      control: {
        listen: { port: 0, host: "127.0.0.1" },
        approvalTimeoutMs: 1000,
      },
      reopenVault: async () => {
        reopenCalls += 1;
        return openVault({ stateDir, passphrase: "p" });
      },
    });
    proxyPort = (await proxy.listen()).port;
    proxy.forceLock("test");
  });

  after(async () => {
    destroyOpenSockets();
    await proxy?.close();
    await closeServer(upstream?.server);
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  it("refuses an authenticated CONNECT instead of re-unlocking behind the owner", async () => {
    const before = upstream.state.connections;
    const r = await rawConnect({
      port: proxyPort,
      target: `${upstream.host}:${upstream.port}`,
      headers: { [PROXY_AUTH_HEADER]: TOKEN },
    });
    assert.equal(r.statusLine, "HTTP/1.1 401 Vault Locked");
    assert.match(r.head, /X-AgentVault-Proxy-Error: vault_locked/i);
    assert.equal(
      reopenCalls,
      0,
      "the control plane owns the unlock — no self-reopen"
    );
    assert.equal(proxy.locked, true);
    assert.equal(upstream.state.connections, before);
  });
});

// A CONNECT target is attacker-shaped input: it arrives before any credential
// is involved, so a malformed one must be refused, not thrown — an escaping
// throw takes the whole proxy process down with it.
describe("CONNECT: a malformed target is refused, not fatal", () => {
  let stateDir;
  let upstream;
  let proxy;
  let proxyPort;

  before(async () => {
    stateDir = await fs.mkdtemp(
      path.join(os.tmpdir(), "proxy-connect-malformed-")
    );
    upstream = await startTcpUpstream();
    proxy = createProxy({
      vault: await makeVault(stateDir),
      logPath: path.join(stateDir, "proxy.log"),
    });
    proxyPort = (await proxy.listen()).port;
  });

  after(async () => {
    destroyOpenSockets();
    await proxy?.close();
    await closeServer(upstream?.server);
    if (stateDir) await fs.rm(stateDir, { recursive: true, force: true });
  });

  for (const target of [
    "bad-target",
    "example.com:not-a-port",
    "example.com:0",
    ":443",
    "",
  ]) {
    it(`refuses ${JSON.stringify(target)} and keeps serving`, async () => {
      const before = upstream.state.connections;
      const r = await rawConnect({ port: proxyPort, target });
      assert.equal(r.statusLine, "HTTP/1.1 400 Bad Request");
      assert.match(r.head, /X-AgentVault-Proxy-Error: bad_request/i);
      assert.equal(upstream.state.connections, before);

      // The proxy survived the malformed request and still tunnels.
      const ok = await rawConnect({
        port: proxyPort,
        target: `${upstream.host}:${upstream.port}`,
      });
      assert.equal(ok.statusLine, "HTTP/1.1 200 Connection Established");
      ok.socket.destroy();
    });
  }
});

// The access log is written fire-and-forget from the request path, so "the
// response arrived" says nothing about the log. close() is the quiesce point
// every teardown (and every operator reading the log after a stop) relies on.
describe("close() settles the access log", () => {
  it("has the refusal on disk by the time close() resolves", async () => {
    const stateDir = await fs.mkdtemp(
      path.join(os.tmpdir(), "proxy-connect-quiesce-")
    );
    const logFile = path.join(stateDir, "proxy.log");
    const proxy = createProxy({
      vault: await makeVault(stateDir),
      logPath: logFile,
    });
    const proxyPort = (await proxy.listen()).port;
    try {
      const r = await rawConnect({
        port: proxyPort,
        target: "169.254.169.254:80",
      });
      assert.equal(r.statusLine, "HTTP/1.1 403 Forbidden");
      await proxy.close();
      const blocked = (await readAccessLog(logFile)).filter(
        (e) => e.error === "upstream_blocked" && e.method === "CONNECT"
      );
      assert.equal(
        blocked.length,
        1,
        "close() must not leave an access-log write in flight"
      );
    } finally {
      destroyOpenSockets();
      await proxy.close();
      await fs.rm(stateDir, { recursive: true, force: true });
    }
  });
});
