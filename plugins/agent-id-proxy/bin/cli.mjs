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
import http from "node:http";
import path from "node:path";
import { createRequire } from "node:module";

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
  readOwnerApprovalChallenge,
  recoverMasterKeyViaOwnerApproval,
  vaultFileExists,
} from "../../agent-id-vault/lib/vault.mjs";
import { requestUnlockSecret } from "../../agent-id-vault/lib/owner-approval.mjs";
import { SignatureEngine } from "../../agent-id-core/lib/signature-engine.mjs";
import {
  hasTty,
  promptSecret,
} from "../../agent-id-vault/lib/trusted-input.mjs";

import { createProxy, DEFAULT_IDLE_TIMEOUT_MS } from "../lib/proxy.mjs";
import { buildPairingPayload, pickReachableHost } from "../lib/pairing.mjs";

// The QR renderer is a CommonJS module vendored in agent-id-core.
const qrcode = createRequire(import.meta.url)("../../agent-id-core/bin/qrcode.cjs");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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

// ─── Owner-approval approver ──────────────────────────────────────────────────
//
// For a vault whose unlock method is an owner-approval slot, the proxy itself
// plays the approver role the phone plays for a mobile slot: when a request
// parks on a locked vault, the control plane lists an `unlock` request carrying
// the owner-approval `keyRef`. We drive the SSO release (which prompts the owner
// on their Alien app), recover the master key from the released KEK, and POST it
// to our own control plane's /approve.

function controlJson(host, port, method, p, body, token = null) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const headers = {};
    if (payload) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = Buffer.byteLength(payload);
    }
    if (token) headers["Authorization"] = `Bearer ${token}`;
    const req = http.request(
      {
        host,
        port,
        path: p,
        method,
        headers,
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"));
          } catch (err) {
            reject(err);
          }
        });
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}

// Returns a { stop() } handle, or null when there's nothing to drive (no
// owner-approval slot, or no agent key on disk).
async function startOwnerApprovalApprover({ stateDir, controlHost, controlPort, controlToken = null }) {
  const challenge = await readOwnerApprovalChallenge(stateDir);
  if (!challenge) return null;

  const engine = new SignatureEngine({ baseDir: stateDir });
  const main = await engine.ensureMainKey().catch(() => null);
  if (!main?.privateKeyPem) return null;

  const host = controlHost || "127.0.0.1";
  const state = { stop: false, seen: new Set() };

  (async function loop() {
    while (!state.stop) {
      try {
        const { pending } = await controlJson(host, controlPort, "GET", "/pending", null, controlToken);
        for (const entry of pending || []) {
          if (state.seen.has(entry.id)) continue;
          if (entry.action !== "unlock" || !entry.ownerApproval) continue;
          state.seen.add(entry.id);

          const session = await engine.ensureValidSession();
          if (!session?.accessToken) {
            stderr(
              "Owner-approval unlock needed, but no valid owner session. " +
                "Run `agent-id-core auth` to (re)bind the owner.",
            );
            try {
              await controlJson(host, controlPort, "POST", "/deny", {
                id: entry.id,
                reason: "no_owner_session",
              }, controlToken);
            } catch {
              /* best effort */
            }
            continue;
          }

          // SECURITY: pin the SSO to the locally-trusted owner session, never
          // the vault slot's ssoBaseUrl. Slot fields are cleartext in the vault
          // file (outside the AEAD wrap), so trusting slot.ssoBaseUrl would let a
          // tampered vault redirect the owner's access token + a valid DPoP proof
          // to an attacker-controlled host (token exfiltration). The slot value
          // is informational only.
          const ssoBaseUrl = session.ssoBaseUrl || session.issuer;
          if (!ssoBaseUrl) {
            stderr("Owner session has no SSO URL — cannot drive owner-approval unlock.");
            try {
              await controlJson(host, controlPort, "POST", "/deny", {
                id: entry.id,
                reason: "no_sso_url",
              }, controlToken);
            } catch {
              /* best effort */
            }
            continue;
          }
          if (
            entry.ownerApproval.ssoBaseUrl &&
            entry.ownerApproval.ssoBaseUrl !== ssoBaseUrl
          ) {
            stderr(
              `Note: vault slot names SSO ${entry.ownerApproval.ssoBaseUrl}, but using ` +
                `the owner session's ${ssoBaseUrl}.`,
            );
          }
          let secret;
          let mk;
          try {
            ({ secret } = await requestUnlockSecret({
              ssoBaseUrl,
              accessToken: session.accessToken,
              agentPrivateKeyPem: main.privateKeyPem,
              keyRef: entry.ownerApproval.keyRef,
              onPrompt: ({ deepLink }) => {
                stderr(
                  deepLink
                    ? `Approve the vault unlock in your Alien app: ${deepLink}`
                    : "Approve the vault unlock in your Alien app.",
                );
              },
            }));
            mk = await recoverMasterKeyViaOwnerApproval(stateDir, secret);
            await controlJson(host, controlPort, "POST", "/approve", {
              id: entry.id,
              masterKey: mk.toString("hex"),
            }, controlToken);
          } catch (err) {
            stderr(`Owner-approval unlock failed: ${err.message}`);
            try {
              await controlJson(host, controlPort, "POST", "/deny", {
                id: entry.id,
                reason: "owner_approval_failed",
              }, controlToken);
            } catch {
              /* best effort */
            }
          } finally {
            if (secret) secret.fill(0);
            if (mk) mk.fill(0);
          }
        }
      } catch {
        // control plane momentarily unavailable, or a stale id — retry
      }
      await sleep(250);
    }
  })();

  return { stop: () => { state.stop = true; } };
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

  // The control plane binds to its OWN host, defaulting to loopback — it is NOT
  // tied to the data plane's --host. Exposing it to the LAN (so a phone can
  // reach it) is an explicit --control-host choice, and the bearer token still
  // gates every credential-bearing route.
  const controlHost = String(
    flags["control-host"] || process.env.AGENT_ID_CONTROL_HOST || "127.0.0.1",
  );
  const controlIsLoopback =
    controlHost === "127.0.0.1" || controlHost === "::1" || controlHost === "localhost";
  const control = controlEnabled
    ? {
        listen: {
          port: Number(flags["control-port"] || process.env.AGENT_ID_CONTROL_PORT || 48772),
          host: controlHost,
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
    blockPrivateHosts: !!flags["block-private-hosts"],
    onLock: (reason) => {
      if (controlEnabled) {
        stderr(`Vault locked (${reason}). Next request will ask for an unlock approval.`);
      } else {
        stderr(`Vault locked (${reason}). Restart the proxy to re-unlock.`);
      }
    },
    onUnlock: () => stderr("Vault unlocked via owner approval."),
  });
  const addr = await proxy.listen();
  const controlAddr = proxy.controlAddress;
  // The control token is written to the 0600 proxy state file so same-user
  // tooling (and external approvers) can present it; it never goes to stdout.
  await writeProxyState(paths, {
    pid: process.pid,
    host: addr.host,
    port: addr.port,
    controlHost: controlAddr ? controlAddr.host : null,
    controlPort: controlAddr ? controlAddr.port : null,
    controlToken: proxy.controlToken || null,
    startedAt: Date.now(),
    idleTimeoutMs: Number.isFinite(idleTimeoutMs) ? idleTimeoutMs : null,
    requireConsent,
    awaitMobile,
    stateDir,
  });

  // For an owner-approval vault, the proxy drives its own unlocks against the
  // SSO (the phone plays this role for mobile slots). No-op without the slot.
  let approver = null;
  if (controlAddr) {
    approver = await startOwnerApprovalApprover({
      stateDir,
      controlHost: controlAddr.host,
      controlPort: controlAddr.port,
      controlToken: proxy.controlToken,
    });
  }

  stderr(`agent-id-proxy listening on http://${addr.host}:${addr.port}`);
  stderr(`  HTTP_PROXY=http://${addr.host}:${addr.port}`);
  if (controlAddr) {
    const how = approver ? "phone or owner approvals" : "phone approvals";
    stderr(`Control plane: http://${controlAddr.host}:${controlAddr.port} (${how})`);
    if (!controlIsLoopback) {
      stderr(
        `  ⚠ control plane on non-loopback ${controlHost}: a mobile-slot unlock POSTs the ` +
          "master key over plain HTTP, so it (and the token) cross this network in cleartext.",
      );
      stderr(
        "    Treat this as trusted-LAN only; for separate-device unlock without that exposure, " +
          "use owner-approval (relays via the SSO over TLS).",
      );
    }
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
    approver?.stop();
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

// `pair` — show a QR/deep-link a phone scans to learn the control URL + token,
// so the mobile-slot unlock flow can reach the (token-gated) control plane.
async function cmdPair(flags) {
  const stateDir = resolveStateDir(flags);
  const paths = statePaths(stateDir);
  const state = await readProxyState(paths);
  if (!state) {
    return outputError("No proxy running (no state file). Start it first, then pair.");
  }
  try {
    process.kill(state.pid, 0);
  } catch {
    await clearProxyState(paths);
    return outputError("Proxy not running (cleared stale state). Start it, then pair.");
  }
  if (!state.controlPort || !state.controlToken) {
    return outputError(
      "This proxy has no control plane (started with --no-control). Pairing needs it.",
    );
  }

  // The reachable host: an explicit override, else derive from the bound host.
  const reachableHost =
    flags["control-host"] || pickReachableHost(state.controlHost);
  if (!reachableHost) {
    return outputError(
      `Control plane is bound to ${state.controlHost} (loopback) — a phone on another ` +
        "device can't reach it. Restart the proxy with --control-host <lan-ip> (or " +
        "0.0.0.0), then re-run `pair`. Pass --control-host here to override the printed host.",
    );
  }

  const controlUrl = `http://${reachableHost}:${state.controlPort}`;
  const payload = buildPairingPayload({ controlUrl, token: state.controlToken });

  stderr("Scan with the Alien app to pair this phone for vault unlock:\n");
  await new Promise((resolve) => {
    qrcode.generate(payload, { small: true }, (code) => {
      process.stderr.write(code + "\n");
      resolve();
    });
  });
  stderr(`Control URL : ${controlUrl}`);
  stderr(`Pair token  : ${state.controlToken}`);
  stderr("This token authorizes /register, /pending, and /approve — keep it private.");
  stderr(
    "⚠ Mobile unlock POSTs the master key over plain HTTP — only pair on a trusted network.",
  );
  stderr(
    "  For separate-device unlock without that exposure, use owner-approval (SSO/TLS relay).",
  );
  outputJson({ ok: true, control: controlUrl, payload });
}

function printHelp() {
  stderr(
    [
      "agent-id-proxy — local stub-translating HTTP proxy",
      "",
      "Subcommands:",
      "  start [--port N] [--host H] [--passphrase-file F | --passphrase-env V]",
      "        [--no-agent-key] [--idle-timeout 12h|30m|never]",
      "        [--no-control] [--control-port N] [--control-host H] [--await-mobile]",
      "        [--require-consent] [--approval-timeout 2m] [--grant-ttl 1h]",
      "        [--block-private-hosts]",
      "  pair [--control-host H]   show a QR for a phone to scan (control URL + token)",
      "  status",
      "  stop",
      "",
      "Use with HTTP_PROXY=http://<host>:<port> set in the agent's environment.",
      "Stubs: `AgentVault <credential-name>` in headers or query parameter values.",
      "Idle lock: master key zeroed after `--idle-timeout` (default 12h). With the",
      "  control plane on (default), the next request re-unlocks via a phone approval;",
      "  otherwise restart the proxy. Use --idle-timeout never to disable.",
      "Control plane (default 127.0.0.1:48772, loopback only — NOT the data-plane",
      "  --host): the phone polls /pending and POSTs /approve | /deny. Those routes",
      "  (and /register) require a bearer token (auto-generated, written to the 0600",
      "  proxy state file); /status is open for liveness. Use --control-host to expose",
      "  it to a LAN phone. --await-mobile starts locked so the first request prompts",
      "  for an unlock. --require-consent prompts per (cred,host).",
      "  Unlock methods: pair a device with",
      "    `agent-id-vault rekey add-mobile --device-pubkey HEX`, or add an SSO",
      "    owner-approval slot with `agent-id-vault rekey add-owner-approval`",
      "    (the proxy then drives owner approvals itself — no phone app needed).",
      "SSRF guard: link-local (incl. 169.254.169.254 cloud metadata), unspecified,",
      "  and multicast upstreams are always refused (403 upstream_blocked).",
      "  --block-private-hosts also refuses loopback/RFC1918/ULA targets.",
      "v1: HTTP only. HTTPS is CONNECT-tunneled without injection — TLS MITM is the next spike.",
    ].join("\n"),
  );
}

const commands = {
  start: cmdStart,
  pair: cmdPair,
  status: cmdStatus,
  stop: cmdStop,
};

runCli({ commands, printHelp });
