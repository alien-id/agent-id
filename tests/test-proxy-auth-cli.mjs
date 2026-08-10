#!/usr/bin/env node

// `agent-id-proxy start --auth-token-file` end to end, through the REAL CLI.
// The plumbing from the flag to the running proxy has to be exercised as a
// whole: a typo in the option name, or a refactor that drops the field, would
// otherwise start a fully UNAUTHENTICATED proxy while the operator believes
// auth is on — a failure that is invisible until someone reaches the port.
// The token file itself is held to the same 0600 bar as the other secret files
// the proxy reads, and to a charset the wire can actually carry.
//
// Run: node --test tests/test-proxy-auth-cli.mjs

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
import { PROXY_AUTH_HEADER } from "../plugins/agent-id-proxy/lib/proxy.mjs";

const CLI = new URL("../plugins/agent-id-proxy/bin/cli.mjs", import.meta.url).pathname;
const TOKEN = "cli-plumbing-token";

function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

function startUpstream() {
  return new Promise((resolve) => {
    const requests = [];
    const server = http.createServer((req, res) => {
      requests.push({ url: req.url, authorization: req.headers.authorization || null });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"ok":true}');
    });
    server.listen(0, "127.0.0.1", () => {
      const a = server.address();
      resolve({ server, requests, host: `${a.address}:${a.port}`, hostname: a.address });
    });
  });
}

// An agent-key vault: the one unlock path a spawned proxy can walk with no
// human, so the CLI reaches "listening" unattended.
async function makeAgentKeyVault(stateDir, upstreamHostname) {
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
  v.add({
    name: "tok",
    type: "bearer",
    domains: [upstreamHostname],
    value: "SECRET-VALUE",
    upstreamScheme: "http",
  });
  await v.save();
  v.lock();
}

function spawnStart(args) {
  const child = spawn("node", [CLI, "start", ...args], {
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

// A CLI that refuses the token file must EXIT; a run that keeps going is the
// bug under test, so the wait is bounded rather than hanging the suite.
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

function proxyRequest({ port, target, headers = {} }) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, method: "GET", path: target, headers },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString("utf8") }),
        );
      },
    );
    req.on("error", reject);
    req.end();
  });
}

describe("CLI --auth-token-file reaches the running data plane", () => {
  let dir;
  let upstream;
  let proc;
  let port;

  before(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-auth-cli-"));
    upstream = await startUpstream();
    await makeAgentKeyVault(dir, upstream.hostname);
    const tokenFile = path.join(dir, "token");
    await fs.writeFile(tokenFile, `${TOKEN}\n`, { mode: 0o600 });
    port = await freePort();
    proc = spawnStart([
      "--auth-token-file", tokenFile,
      "--no-control",
      "--idle-timeout", "never",
      "--port", String(port),
      "--state-dir", dir,
    ]);
    await waitForStderr(proc, /agent-id-proxy listening on/, 15000);
  });

  after(async () => {
    proc?.child.kill("SIGKILL");
    upstream?.server.close();
    if (dir) await fs.rm(dir, { recursive: true, force: true });
  });

  it("refuses a tokenless data-plane request", async () => {
    const before = upstream.requests.length;
    const r = await proxyRequest({ port, target: `/tok/${upstream.host}/a` });
    assert.equal(r.status, 401);
    assert.equal(JSON.parse(r.body).error, "unauthorized");
    assert.equal(upstream.requests.length, before);
  });

  it("serves the same request when the token from the file is presented", async () => {
    const r = await proxyRequest({
      port,
      target: `/tok/${upstream.host}/a`,
      headers: { [PROXY_AUTH_HEADER]: TOKEN },
    });
    assert.equal(r.status, 200);
    assert.equal(upstream.requests.at(-1).authorization, "Bearer SECRET-VALUE");
  });

  it("never leaks the token to the agent-visible streams", () => {
    assert.ok(!proc.out.stdout.includes(TOKEN), "stdout leaked the token");
    assert.ok(!proc.out.stderr.includes(TOKEN), "stderr leaked the token");
  });
});

describe("CLI --auth-token-file validation", () => {
  let dir;
  let port;

  before(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "proxy-auth-cli-bad-"));
    await makeAgentKeyVault(dir, "127.0.0.1");
    port = await freePort();
  });

  after(async () => {
    if (dir) await fs.rm(dir, { recursive: true, force: true });
  });

  async function startWithTokenFile(name, contents, mode) {
    const tokenFile = path.join(dir, name);
    await fs.writeFile(tokenFile, contents, { mode });
    await fs.chmod(tokenFile, mode);
    const proc = spawnStart([
      "--auth-token-file", tokenFile,
      "--no-control",
      "--idle-timeout", "never",
      "--port", String(port),
      "--state-dir", dir,
    ]);
    const result = await waitForExit(proc);
    return { ...result, tokenFile };
  }

  it("refuses a group/world-readable token file", async () => {
    const r = await startWithTokenFile("loose-token", `${TOKEN}\n`, 0o644);
    assert.equal(r.code, 1);
    const payload = JSON.parse(r.stdout);
    assert.equal(payload.ok, false);
    assert.match(payload.error, /group\/world accessible/i);
    assert.ok(payload.error.includes(r.tokenFile), "the error must name the offending path");
  });

  it("refuses a token that cannot survive an HTTP header", async () => {
    const r = await startWithTokenFile("nonascii-token", "tökén-value\n", 0o600);
    assert.equal(r.code, 1);
    const payload = JSON.parse(r.stdout);
    assert.equal(payload.ok, false);
    assert.match(payload.error, /printable ASCII/i);
    assert.ok(payload.error.includes(r.tokenFile), "the error must name the offending path");
  });
});
