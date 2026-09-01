#!/usr/bin/env node

// The opt-in SessionStart auto-unlock hook (agent-id-proxy): a no-op unless the
// user opted in (marker file) and a vault exists; otherwise it launches
// `proxy start --unlock-form` so the unlock form pops once per session.
//
// Run: node --test tests/test-proxy-autounlock.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm, writeFile, readFile, access } from "node:fs/promises";
import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";

import { initVault } from "../plugins/agent-id-vault/lib/vault.mjs";

const PROXY_ROOT = new URL("../plugins/agent-id-proxy", import.meta.url).pathname;
const HOOK = path.join(PROXY_ROOT, "hooks", "session-unlock.sh");
const CLI = path.join(PROXY_ROOT, "bin", "cli.mjs");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function runHook(dir) {
  return spawnSync("bash", [HOOK], {
    encoding: "utf8",
    env: { ...process.env, AGENT_ID_STATE_DIR: dir, CLAUDE_PLUGIN_ROOT: PROXY_ROOT, AGENT_ID_NO_BROWSER: "1" },
  });
}

test("autounlock subcommand writes / removes the marker", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "autounlock-"));
  try {
    let r = spawnSync("node", [CLI, "autounlock", "--state-dir", dir], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    await access(path.join(dir, "autounlock")); // exists

    r = spawnSync("node", [CLI, "autounlock", "--off", "--state-dir", dir], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(existsSync(path.join(dir, "autounlock")), false);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("hook is a no-op without the marker, and without a vault", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "autounlock-"));
  try {
    assert.equal(runHook(dir).status, 0); // no marker
    assert.equal(existsSync(path.join(dir, "autounlock.log")), false, "must not launch without the marker");

    await writeFile(path.join(dir, "autounlock"), "", { mode: 0o600 }); // marker but no vault
    assert.equal(runHook(dir).status, 0);
    assert.equal(existsSync(path.join(dir, "autounlock.log")), false, "must not launch without a vault");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("hook launches the unlock form when opted in with a vault", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "autounlock-"));
  try {
    await initVault({ stateDir: dir, passphrase: "pw" }); // dev (passphrase) vault
    await writeFile(path.join(dir, "autounlock"), "", { mode: 0o600 });

    assert.equal(runHook(dir).status, 0);

    // The detached proxy reaches the unlock form; its log shows the prompt.
    let log = "";
    for (let i = 0; i < 60; i++) {
      log = await readFile(path.join(dir, "autounlock.log"), "utf8").catch(() => "");
      if (log.includes("unlock the credential vault")) break;
      await sleep(50);
    }
    assert.match(log, /unlock the credential vault/);
  } finally {
    spawnSync("pkill", ["-f", `start --unlock-form --state-dir ${dir}`]);
    await sleep(150);
    await rm(dir, { recursive: true, force: true });
  }
});
