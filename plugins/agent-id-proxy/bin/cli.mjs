#!/usr/bin/env node

// Alien Agent ID — Proxy plugin CLI.
//
// Subcommands:
//   start  — open the vault, listen on localhost, inject stubs into HTTP requests
//   status — read pidfile, report listening port + uptime
//   stop   — send SIGTERM to the running proxy
//
// Unlock inputs follow the vault CLI: --passphrase-file / --passphrase-env /
// auto via agent key / /dev/tty prompt.
//
// v1 scope: plain HTTP injection. HTTPS is CONNECT-tunneled without
// interception — see vault-proxy-mvp-proposal.md "next steps" for the
// local-CA spike.

import fs from "node:fs/promises";
import path from "node:path";

import {
  outputError,
  outputJson,
  resolveStateDir,
  runCli,
  stderr,
} from "../../agent-id-core/lib/cli-runtime.mjs";
import {
  ensureDir,
  statePaths,
} from "../../agent-id-core/lib/state.mjs";
import {
  loadAgentPrivateKey,
  openVault,
  vaultFileExists,
} from "../../agent-id-vault/lib/vault.mjs";
import {
  hasTty,
  promptSecret,
} from "../../agent-id-vault/lib/trusted-input.mjs";

import { createProxy, DEFAULT_IDLE_TIMEOUT_MS } from "../lib/proxy.mjs";

// Parse a duration string. Accepts "12h", "30m", "90s", "never" / "0", or a
// raw millisecond integer. Returns ms (Infinity for "never").
function parseDuration(raw) {
  if (raw == null) return null;
  const s = String(raw).trim().toLowerCase();
  if (s === "never" || s === "off" || s === "0") return Infinity;
  const m = /^(\d+)\s*(ms|s|m|h|d)?$/.exec(s);
  if (!m) throw new Error(`Bad duration: ${raw}`);
  const n = Number(m[1]);
  const unit = m[2] || "ms";
  const mult = { ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[unit];
  return n * mult;
}

function formatDuration(ms) {
  if (!Number.isFinite(ms)) return "never";
  if (ms >= 3_600_000) return `${(ms / 3_600_000).toFixed(2).replace(/\.?0+$/, "")}h`;
  if (ms >= 60_000) return `${Math.round(ms / 60_000)}m`;
  return `${Math.round(ms / 1000)}s`;
}

async function resolvePassphrase(flags) {
  if (flags["passphrase-file"]) {
    const raw = await fs.readFile(flags["passphrase-file"], "utf8");
    return raw.replace(/\n$/, "");
  }
  if (flags["passphrase-env"]) {
    const val = process.env[flags["passphrase-env"]];
    if (!val) throw new Error(`Env var ${flags["passphrase-env"]} is not set`);
    return val;
  }
  if (hasTty()) return promptSecret("Vault passphrase: ");
  return null;
}

async function loadVaultForProxy(stateDir, flags) {
  if (!(await vaultFileExists(stateDir))) {
    throw new Error(
      `No vault at ${statePaths(stateDir).vaultFile}. Run agent-id-vault init first.`,
    );
  }

  const useAgentKey = flags["agent-key"] !== false;
  const privateKeyPem = useAgentKey ? await loadAgentPrivateKey(stateDir) : null;

  if (privateKeyPem) {
    try {
      return await openVault({ stateDir, privateKeyPem });
    } catch (err) {
      if (err.code !== "VAULT_UNLOCK_FAILED") throw err;
      // fall through
    }
  }

  const passphrase = await resolvePassphrase(flags);
  if (!passphrase) throw new Error("No passphrase available to unlock vault");
  return openVault({ stateDir, privateKeyPem, passphrase });
}

async function writeProxyState(paths, info) {
  await ensureDir(path.dirname(paths.proxyState));
  await fs.writeFile(paths.proxyState, JSON.stringify(info, null, 2) + "\n", {
    encoding: "utf8",
    mode: 0o600,
  });
}

async function readProxyState(paths) {
  try {
    const raw = await fs.readFile(paths.proxyState, "utf8");
    return JSON.parse(raw);
  } catch (err) {
    if (err?.code === "ENOENT") return null;
    throw err;
  }
}

async function clearProxyState(paths) {
  try {
    await fs.unlink(paths.proxyState);
  } catch {
    // best effort
  }
}

// ─── Commands ───────────────────────────────────────────────────────────────────

async function cmdStart(flags) {
  const stateDir = resolveStateDir(flags);
  const paths = statePaths(stateDir);
  const port = Number(flags.port || process.env.AGENT_ID_PROXY_PORT || 48771);
  const host = String(flags.host || "127.0.0.1");

  const existing = await readProxyState(paths);
  if (existing && existing.pid) {
    try {
      process.kill(existing.pid, 0); // signal 0 = liveness check
      outputError(
        `Proxy already running (pid ${existing.pid}, port ${existing.port}). ` +
          "Run `stop` first or pick a different state-dir.",
      );
      return;
    } catch {
      // stale pidfile; fall through
      await clearProxyState(paths);
    }
  }

  // Control plane: phone-approved unlock + per-credential consent. On by
  // default; --no-control disables it. --await-mobile starts the proxy locked
  // (no eager vault open) so the first request triggers a phone unlock.
  const controlEnabled = flags.control !== false;
  const awaitMobile = !!flags["await-mobile"];
  const requireConsent = !!flags["require-consent"];

  if (awaitMobile && !controlEnabled) {
    outputError("--await-mobile requires the control plane (drop --no-control).");
    return;
  }

  const vault = awaitMobile ? null : await loadVaultForProxy(stateDir, flags);
  await ensureDir(path.dirname(paths.proxyLog));

  const idleTimeoutMs =
    flags["idle-timeout"] != null
      ? parseDuration(flags["idle-timeout"])
      : DEFAULT_IDLE_TIMEOUT_MS;

  const control = controlEnabled
    ? {
        listen: {
          port: Number(flags["control-port"] || process.env.AGENT_ID_CONTROL_PORT || 48772),
          host,
        },
        approvalTimeoutMs:
          flags["approval-timeout"] != null
            ? parseDuration(flags["approval-timeout"])
            : 2 * 60_000,
      }
    : null;

  const grantTtlMs =
    flags["grant-ttl"] != null ? parseDuration(flags["grant-ttl"]) : 60 * 60_000;

  const proxy = createProxy({
    vault,
    stateDir,
    logPath: paths.proxyLog,
    listen: { port, host },
    idleTimeoutMs,
    control,
    requireConsent,
    grantTtlMs,
    onLock: (reason) => {
      if (controlEnabled) {
        stderr(`Vault locked (${reason}). Next request will ask the phone to unlock.`);
      } else {
        stderr(`Vault locked (${reason}). Restart the proxy to re-unlock.`);
      }
    },
    onUnlock: () => stderr("Vault unlocked via phone approval."),
  });
  const addr = await proxy.listen();
  const controlAddr = proxy.controlAddress;
  await writeProxyState(paths, {
    pid: process.pid,
    host: addr.host,
    port: addr.port,
    controlHost: controlAddr ? controlAddr.host : null,
    controlPort: controlAddr ? controlAddr.port : null,
    startedAt: Date.now(),
    idleTimeoutMs: Number.isFinite(idleTimeoutMs) ? idleTimeoutMs : null,
    requireConsent,
    awaitMobile,
    stateDir,
  });

  stderr(`agent-id-proxy listening on http://${addr.host}:${addr.port}`);
  stderr(`  HTTP_PROXY=http://${addr.host}:${addr.port}`);
  if (controlAddr) {
    stderr(`Control plane: http://${controlAddr.host}:${controlAddr.port} (phone approvals)`);
  }
  stderr(`Vault: ${paths.vaultFile}${awaitMobile ? " (locked — awaiting phone unlock)" : ""}`);
  stderr(`Log:   ${paths.proxyLog}`);
  stderr(`Idle lock: ${formatDuration(idleTimeoutMs)}`);
  if (requireConsent) stderr(`Consent: per-credential, grant TTL ${formatDuration(grantTtlMs)}`);
  stderr("Press Ctrl-C to stop.");

  if (flags["print-config"]) {
    outputJson({
      ok: true,
      host: addr.host,
      port: addr.port,
      controlHost: controlAddr ? controlAddr.host : null,
      controlPort: controlAddr ? controlAddr.port : null,
      pid: process.pid,
      vault: paths.vaultFile,
      log: paths.proxyLog,
    });
  }

  if (flags.detach) {
    // Caller wants the proxy to keep running after we return. The Node
    // process holds the listening socket; we just stop emitting to stderr.
    stderr("(detach: relinquishing tty)");
    if (process.stdin && process.stdin.unref) process.stdin.unref();
  }

  const shutdown = async (signal) => {
    stderr(`Received ${signal}, shutting down…`);
    await proxy.close();
    vault?.lock();
    await clearProxyState(paths);
    process.exit(0);
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
}

async function cmdStatus(flags) {
  const stateDir = resolveStateDir(flags);
  const paths = statePaths(stateDir);
  const state = await readProxyState(paths);
  if (!state) {
    outputJson({ ok: true, running: false });
    return;
  }
  let alive = false;
  try {
    process.kill(state.pid, 0);
    alive = true;
  } catch {
    alive = false;
  }
  outputJson({
    ok: true,
    running: alive,
    ...state,
    idleTimeout: state.idleTimeoutMs
      ? formatDuration(state.idleTimeoutMs)
      : "never",
    uptimeMs: alive ? Date.now() - state.startedAt : null,
  });
}

async function cmdStop(flags) {
  const stateDir = resolveStateDir(flags);
  const paths = statePaths(stateDir);
  const state = await readProxyState(paths);
  if (!state) {
    outputError("No proxy running (no state file)");
    return;
  }
  try {
    process.kill(state.pid, "SIGTERM");
    stderr(`Sent SIGTERM to pid ${state.pid}.`);
    outputJson({ ok: true, pid: state.pid });
  } catch (err) {
    if (err.code === "ESRCH") {
      await clearProxyState(paths);
      outputError(`Process ${state.pid} not found; cleared stale state.`);
    } else {
      throw err;
    }
  }
}

function printHelp() {
  stderr(
    [
      "agent-id-proxy — local stub-translating HTTP proxy",
      "",
      "Subcommands:",
      "  start [--port N] [--host H] [--passphrase-file F | --passphrase-env V]",
      "        [--no-agent-key] [--idle-timeout 12h|30m|never]",
      "        [--no-control] [--control-port N] [--await-mobile]",
      "        [--require-consent] [--approval-timeout 2m] [--grant-ttl 1h]",
      "  status",
      "  stop",
      "",
      "Use with HTTP_PROXY=http://<host>:<port> set in the agent's environment.",
      "Stubs: `AgentVault <credential-name>` in headers or query parameter values.",
      "Idle lock: master key zeroed after `--idle-timeout` (default 12h). With the",
      "  control plane on (default), the next request re-unlocks via a phone approval;",
      "  otherwise restart the proxy. Use --idle-timeout never to disable.",
      "Control plane (default port 48772): the phone polls /pending and POSTs",
      "  /approve | /deny. --await-mobile starts locked so the first request prompts",
      "  the phone to unlock (sealed-box). --require-consent prompts per (cred,host).",
      "  Pair a device with `agent-id-vault rekey add-mobile --device-pubkey HEX`.",
      "v1: HTTP only. HTTPS is CONNECT-tunneled without injection — TLS MITM is the next spike.",
    ].join("\n"),
  );
}

const commands = {
  start: cmdStart,
  status: cmdStatus,
  stop: cmdStop,
};

runCli({ commands, printHelp });
