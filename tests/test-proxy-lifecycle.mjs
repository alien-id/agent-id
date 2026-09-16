#!/usr/bin/env node

// Lifecycle safety for a supervisor that restarts the proxy back to back:
// `stop` must wait for the old daemon to actually exit (force-killing one
// that ignores SIGTERM) instead of returning the moment the signal is sent,
// `start` must see through a stale or foreign pidfile instead of refusing to
// boot, and `close()` must not hang on a slow upstream or an idle client
// connection.
//
// Run: node --test tests/test-proxy-lifecycle.mjs

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";

import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { writeJsonFile, statePaths } from "../plugins/agent-id-core/lib/state.mjs";
import { fingerprintPublicKeyPem } from "../plugins/agent-id-core/lib/crypto.mjs";
import { createProxy } from "../plugins/agent-id-proxy/lib/proxy.mjs";

const CLI = new URL("../plugins/agent-id-proxy/bin/cli.mjs", import.meta.url).pathname;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

function pidAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function pathExists(p) {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

async function waitForSpawn(child) {
  await new Promise((resolve, reject) => {
    child.once("spawn", resolve);
    child.once("error", reject);
  });
}

// An agent-key vault: the one unlock path a spawned proxy can walk with no
// human, so the CLI reaches "listening" unattended.
async function makeAgentKeyVault(stateDir) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
  const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  await writeJsonFile(statePaths(stateDir).mainKey, {
    version: 1,
    agentId: "main",
    keyNonce: 0,
    createdAt: 1,
    publicKeyPem,
    privateKeyPem,
    fingerprint: fingerprintPublicKeyPem(publicKeyPem),
  });
  await initVault({ stateDir, privateKeyPem, agentId: "main" });
  const v = await openVault({ stateDir, privateKeyPem });
  await v.save();
  v.lock();
}

function spawnCli(args) {
  const child = spawn("node", [CLI, ...args], {
    env: { ...process.env, AGENT_ID_NO_BROWSER: "1" },
  });
  const out = { stdout: "", stderr: "" };
  child.stdout.on("data", (d) => (out.stdout += d));
  child.stderr.on("data", (d) => (out.stderr += d));
  return { child, out };
}

function waitForStderr({ child, out }, re, ms) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`timeout waiting for ${re}\n${out.stderr}\n${out.stdout}`)),
      ms,
    );
    const check = () => {
      const m = out.stderr.match(re);
      if (m) {
        clearTimeout(timer);
        resolve(m[0]);
      }
    };
    child.stderr.on("data", check);
    child.on("exit", () => {
      clearTimeout(timer);
      reject(new Error(`proxy exited early\n${out.stderr}\n${out.stdout}`));
    });
    check();
  });
}

// A CLI invocation that never returns is the bug under test in more than one
// of these cases, so every wait is bounded rather than hanging the suite.
function waitForExit({ child, out }, ms = 15000) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      resolve({ code: "still-running", ...out });
    }, ms);
    child.on("exit", (code) => {
      clearTimeout(timer);
      resolve({ code, ...out });
    });
  });
}

describe("stop waits for the daemon to exit", () => {
  let dir;
  let port;
  let proc;

  before(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-lifecycle-a-"));
    await makeAgentKeyVault(dir);
    port = await freePort();
    proc = spawnCli([
      "start",
      "--no-control",
      "--idle-timeout",
      "never",
      "--port",
      String(port),
      "--state-dir",
      dir,
    ]);
    await waitForStderr(proc, /agent-id-proxy listening on/, 15000);
  });

  after(async () => {
    if (proc?.child.exitCode === null) proc.child.kill("SIGKILL");
    if (dir) await fs.rm(dir, { recursive: true, force: true });
  });

  it("stop waits for the daemon to exit and clears proxy.json", async () => {
    const pid = proc.child.pid;
    const stopProc = spawnCli(["stop", "--state-dir", dir]);
    const result = await waitForExit(stopProc, 10000);
    assert.notEqual(result.code, "still-running", `stop hung: ${result.stderr}`);

    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.ok, true);
    assert.equal(parsed.exited, true);
    assert.equal(parsed.pid, pid);

    assert.equal(pidAlive(pid), false, "the daemon pid must be gone once stop returns");
    assert.equal(
      await pathExists(statePaths(dir).proxyState),
      false,
      "proxy.json must be cleared once stop returns",
    );
  });
});

describe("stop force-kills a daemon that ignores SIGTERM", () => {
  let dir;
  let fake;

  before(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-lifecycle-b-"));
    fake = spawn("bash", ["-c", 'trap "" TERM; sleep 60']);
    await waitForSpawn(fake);
    await writeJsonFile(statePaths(dir).proxyState, {
      pid: fake.pid,
      host: "127.0.0.1",
      port: 0,
      startedAt: Date.now(),
    });
  });

  after(async () => {
    if (fake && pidAlive(fake.pid)) fake.kill("SIGKILL");
    if (dir) await fs.rm(dir, { recursive: true, force: true });
  });

  it("stop force-kills a daemon that ignores SIGTERM", async () => {
    const stopProc = spawnCli(["stop", "--timeout", "500", "--state-dir", dir]);
    const result = await waitForExit(stopProc, 10000);
    assert.notEqual(result.code, "still-running", `stop hung: ${result.stderr}`);

    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.ok, true);
    assert.equal(parsed.exited, true);
    assert.equal(parsed.forced, true);

    assert.equal(pidAlive(fake.pid), false, "SIGKILL must have reached the ignoring daemon");
    assert.equal(await pathExists(statePaths(dir).proxyState), false);
  });
});

describe("start ignores a proxy.json naming a foreign pid", () => {
  it(
    "start ignores a proxy.json naming a foreign pid",
    { skip: process.platform !== "linux" ? "Linux-only /proc identity check" : false },
    async () => {
      const dir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-lifecycle-c-"));
      let foreign;
      let proc;
      try {
        await makeAgentKeyVault(dir);
        foreign = spawn("sleep", ["30"]);
        await waitForSpawn(foreign);
        await writeJsonFile(statePaths(dir).proxyState, {
          pid: foreign.pid,
          host: "127.0.0.1",
          port: 0,
          startedAt: Date.now(),
        });

        const port = await freePort();
        proc = spawnCli([
          "start",
          "--no-control",
          "--idle-timeout",
          "never",
          "--port",
          String(port),
          "--state-dir",
          dir,
        ]);
        await waitForStderr(proc, /agent-id-proxy listening on/, 15000);

        assert.equal(
          pidAlive(foreign.pid),
          true,
          "start must not signal a foreign pid it decided was stale",
        );
      } finally {
        if (proc?.child.exitCode === null) proc.child.kill("SIGKILL");
        if (foreign && pidAlive(foreign.pid)) foreign.kill("SIGKILL");
        await fs.rm(dir, { recursive: true, force: true });
      }
    },
  );
});

describe("close() bounds shutdown against slow or idle connections", () => {
  it("close resolves while an upstream request is still hanging", async () => {
    const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-lifecycle-d-"));
    const hangingServer = http.createServer(() => {
      // Deliberately never responds — a slow upstream that outlives the proxy.
    });
    await new Promise((resolve) => hangingServer.listen(0, "127.0.0.1", resolve));
    const { address, port: upstreamPort } = hangingServer.address();
    const upstreamHost = `${address}:${upstreamPort}`;

    let proxy;
    let vault;
    try {
      await initVault({ stateDir, passphrase: "test-pass-1234" });
      vault = await openVault({ stateDir, passphrase: "test-pass-1234" });
      vault.add({
        name: "hang-cred",
        type: "bearer",
        domains: [address],
        value: "secret",
        upstreamScheme: "http",
      });
      await vault.save();

      proxy = createProxy({
        vault,
        logPath: path.join(stateDir, "proxy.log"),
        closeGraceMs: 300,
      });
      const addr = await proxy.listen();

      const pending = new Promise((resolve) => {
        const req = http.request(
          {
            host: "127.0.0.1",
            port: addr.port,
            method: "GET",
            path: `/hang-cred/${upstreamHost}/a`,
          },
          () => resolve("responded"),
        );
        req.on("error", () => resolve("errored"));
        req.end();
      });

      // Give the proxy a moment to actually open the upstream connection
      // before closing — otherwise the race is against a request that never
      // started, which would pass for the wrong reason.
      await sleep(150);

      const start = Date.now();
      await proxy.close();
      const elapsed = Date.now() - start;
      assert.ok(elapsed < 3000, `close() took ${elapsed}ms`);

      const outcome = await Promise.race([pending, sleep(1000).then(() => "timed-out")]);
      assert.equal(outcome, "errored", "the hanging client request must be torn down, not left dangling");
    } finally {
      vault?.lock();
      hangingServer.close();
      await fs.rm(stateDir, { recursive: true, force: true });
    }
  });

  it("close resolves with an idle keep-alive client socket open", async () => {
    const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-lifecycle-e-"));
    let proxy;
    let vault;
    let idle;
    try {
      await initVault({ stateDir, passphrase: "test-pass-1234" });
      vault = await openVault({ stateDir, passphrase: "test-pass-1234" });

      proxy = createProxy({
        vault,
        logPath: path.join(stateDir, "proxy.log"),
        closeGraceMs: 300,
      });
      const addr = await proxy.listen();

      idle = net.connect({ host: "127.0.0.1", port: addr.port });
      await new Promise((resolve, reject) => {
        idle.once("connect", resolve);
        idle.once("error", reject);
      });

      const start = Date.now();
      await proxy.close();
      const elapsed = Date.now() - start;
      assert.ok(elapsed < 3000, `close() took ${elapsed}ms`);
    } finally {
      idle?.destroy();
      vault?.lock();
      await fs.rm(stateDir, { recursive: true, force: true });
    }
  });
});
