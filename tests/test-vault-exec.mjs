import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";

const CLI = fileURLToPath(
  new URL("../plugins/agent-id-vault/bin/cli.mjs", import.meta.url)
);

function runCli(args, env = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    child.on("exit", (code) => resolve({ code, out, err }));
  });
}

async function tmp() {
  return mkdtemp(path.join(os.tmpdir(), "vexec-"));
}

// A dev-mode (passphrase) vault holding one `basic` credential, so the CLI can
// unlock via --passphrase-env without an on-disk agent key.
async function seed(dir) {
  await initVault({ stateDir: dir, passphrase: "test-pass" });
  const v = await openVault({ stateDir: dir, passphrase: "test-pass" });
  v.add({
    name: "svc",
    type: "basic",
    domains: ["example.com"],
    username: "the-user-id",
    password: "the-secret-value",
  });
  await v.save();
  v.lock();
}

test("exec injects credential fields into the child env; values never hit stderr", async () => {
  const dir = await tmp();
  try {
    await seed(dir);
    const childJs =
      "process.stdout.write((process.env.A||'')+'|'+(process.env.B||''))";
    const { code, out, err } = await runCli(
      [
        "exec",
        "--state-dir",
        dir,
        "--no-agent-key",
        "--passphrase-env",
        "VPASS",
        "--env",
        "A=svc.username",
        "--env",
        "B=svc.password",
        "--",
        process.execPath,
        "-e",
        childJs,
      ],
      { VPASS: "test-pass" }
    );
    assert.equal(code, 0);
    // The child saw exactly the stored values…
    assert.equal(out, "the-user-id|the-secret-value");
    // …but the secret was never logged, only the variable names + sources.
    assert.ok(
      !err.includes("the-secret-value"),
      "secret must not appear on stderr"
    );
    assert.match(err, /Injecting A=svc\.username, B=svc\.password/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("exec passes the child's exit code through", async () => {
  const dir = await tmp();
  try {
    await seed(dir);
    const { code } = await runCli(
      [
        "exec",
        "--state-dir",
        dir,
        "--no-agent-key",
        "--passphrase-env",
        "VPASS",
        "--env",
        "A=svc.username",
        "--",
        process.execPath,
        "-e",
        "process.exit(7)",
      ],
      { VPASS: "test-pass" }
    );
    assert.equal(code, 7);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("exec without a `--` separator errors", async () => {
  const dir = await tmp();
  try {
    await seed(dir);
    const { out } = await runCli([
      "exec",
      "--state-dir",
      dir,
      "--env",
      "A=svc.username",
    ]);
    const res = JSON.parse(out);
    assert.equal(res.ok, false);
    assert.match(res.error, /separator before the command/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("exec errors on an unknown credential", async () => {
  const dir = await tmp();
  try {
    await seed(dir);
    const { out } = await runCli(
      [
        "exec",
        "--state-dir",
        dir,
        "--no-agent-key",
        "--passphrase-env",
        "VPASS",
        "--env",
        "A=nope.value",
        "--",
        process.execPath,
        "-e",
        "0",
      ],
      { VPASS: "test-pass" }
    );
    const res = JSON.parse(out);
    assert.equal(res.ok, false);
    assert.match(res.error, /No credential named 'nope'/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
