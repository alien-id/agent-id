#!/usr/bin/env node

// End-to-end test for `agent-id-proxy start --unlock-form`: the once-per-session
// unlock. The proxy serves a loopback form, the human submits the vault
// passphrase, the proxy unwraps the master key and starts listening — and the
// passphrase never appears on the agent-visible stdout/stderr. Agent-key
// auto-unlock is bypassed, so the agent cannot self-unlock.
//
// Run: node --test tests/test-proxy-unlock-form.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import net from "node:net";
import path from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { spawn } from "node:child_process";

import { initVault } from "../plugins/agent-id-vault/lib/vault.mjs";

const CLI = new URL("../plugins/agent-id-proxy/bin/cli.mjs", import.meta.url).pathname;

function freePort() {
  return new Promise((res) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => res(port));
    });
  });
}

// Resolve when the child's stderr matches `re`; reject on early exit / timeout.
function waitForStderr(child, re, ms, getBuf) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`timeout waiting for ${re}\n${getBuf()}`)), ms);
    const onData = () => {
      const m = getBuf().match(re);
      if (m) {
        clearTimeout(t);
        child.stderr.off("data", onData);
        resolve(m[0]);
      }
    };
    child.stderr.on("data", onData);
  });
}

test("proxy --unlock-form unlocks via the form; passphrase never hits the agent streams", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "unlockform-"));
  try {
    const PASS = "correct-horse-battery-staple";
    // Dev-mode vault, passphrase slot only (no agent key) — so the ONLY way in is
    // the human-typed passphrase.
    await initVault({ stateDir: dir, passphrase: PASS });

    const port = await freePort();
    const child = spawn(
      "node",
      [
        CLI, "start",
        "--unlock-form", "--no-control", "--no-agent-key",
        "--idle-timeout", "never", "--port", String(port), "--state-dir", dir,
      ],
      { env: { ...process.env, AGENT_ID_NO_BROWSER: "1" } },
    );
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));

    try {
      const url = await waitForStderr(child, /http:\/\/127\.0\.0\.1:\d+\/\?t=[a-f0-9]+/, 8000, () => stderr);
      const u = new URL(url);

      const res = await fetch(`http://127.0.0.1:${u.port}/submit`, {
        method: "POST",
        body: new URLSearchParams({ _token: u.searchParams.get("t"), passphrase: PASS }),
      });
      assert.equal(res.status, 200);

      // Unlock succeeded ⇒ the proxy starts listening.
      await waitForStderr(child, /agent-id-proxy listening on/, 8000, () => stderr);

      assert.ok(!stdout.includes(PASS), "stdout leaked the passphrase");
      assert.ok(!stderr.includes(PASS), "stderr leaked the passphrase");
    } finally {
      child.kill("SIGTERM");
      await new Promise((r) => child.on("exit", r));
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
