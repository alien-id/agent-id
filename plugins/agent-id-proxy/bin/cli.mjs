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
import https from "node:https";
import path from "node:path";

import {
  outputError,
  outputJson,
  resolveStateDir,
  runCli,
  stderr,
} from "@alien-id/agent-id-core/lib/cli-runtime.mjs";
import {
  ensureDir,
  statePaths,
} from "@alien-id/agent-id-core/lib/state.mjs";
import {
  loadAgentPrivateKey,
  openVault,
  readOwnerApprovalChallenge,
  readPasskeyChallenges,
  recoverMasterKeyViaOwnerApproval,
  vaultFileExists,
} from "@alien-id/agent-id-vault/lib/vault.mjs";
import { authenticatePasskey } from "@alien-id/agent-id-vault/lib/passkey.mjs";
import { requestUnlockSecret } from "@alien-id/agent-id-vault/lib/owner-approval.mjs";
import { sealToPublicKey } from "@alien-id/agent-id-vault/lib/format.mjs";
import { SignatureEngine } from "@alien-id/agent-id-core/lib/signature-engine.mjs";
import {
  hasTty,
  promptSecret,
} from "@alien-id/agent-id-vault/lib/trusted-input.mjs";
import { collectViaForm } from "@alien-id/agent-id-core/lib/secure-form.mjs";
// Static, not createRequire: the compiled binary has no node_modules to resolve against.
import qrcode from "@alien-id/agent-id-core/bin/qrcode.cjs";

import { createProxy, DEFAULT_IDLE_TIMEOUT_MS } from "../lib/proxy.mjs";
import { loadOauthSecretsFile } from "../lib/oauth.mjs";
import { buildPairingPayload, pickReachableHost } from "../lib/pairing.mjs";
import { normalizeFingerprint } from "../lib/control-tls.mjs";

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
  // --unlock-form: the human types the passphrase into a one-shot localhost form
  // (the 1Password-style once-per-session unlock). It never crosses the agent's
  // stdin/transcript; the proxy holds the unwrapped master key for the session.
  if (flags["unlock-form"]) {
    const out = await collectViaForm({
      title: "Unlock the credential vault",
      description: "Unlocks for this session; re-locks when idle.",
      fields: [{ name: "passphrase", label: "Vault passphrase" }],
      label: "unlock the credential vault",
      submitLabel: "Unlock vault",
      security:
        "Run through <code>scrypt</code> to unwrap the <code>AES-256-GCM</code> vault key. Never stored or shown to the agent.",
    });
    return out.values.passphrase;
  }
  if (hasTty()) return promptSecret("Vault passphrase: ");
  return null;
}

// Returns { vault, viaAgentKey }. `viaAgentKey` is true only when the vault
// was unlocked through the agent-key slot — the one unlock method that needs
// no human, so it's also the only one a self-reopen (see `reopenVault` in
// cmdStart) can safely repeat later without prompting anyone.
async function loadVaultForProxy(stateDir, flags) {
  if (!(await vaultFileExists(stateDir))) {
    throw new Error(
      `No vault at ${statePaths(stateDir).vaultFile}. Run agent-id-vault init first.`,
    );
  }

  // --unlock-form deliberately does NOT auto-unlock with the agent key — the whole
  // point is that the agent can't self-unlock; a human must verify. Prefer a passkey
  // (Touch ID) slot if the vault has one, else collect a passphrase via the form.
  if (flags["unlock-form"]) {
    const passkeys = await readPasskeyChallenges(stateDir);
    if (passkeys.length) {
      const prfSecret = await authenticatePasskey(passkeys[0]);
      return { vault: await openVault({ stateDir, passkeyPrfSecret: prfSecret }), viaAgentKey: false };
    }
    const passphrase = await resolvePassphrase(flags);
    if (!passphrase) throw new Error("Unlock form was cancelled or returned no passphrase");
    // no privateKeyPem → passphrase slot only
    return { vault: await openVault({ stateDir, passphrase }), viaAgentKey: false };
  }

  const useAgentKey = flags["agent-key"] !== false;
  const privateKeyPem = useAgentKey ? await loadAgentPrivateKey(stateDir) : null;

  if (privateKeyPem) {
    try {
      return { vault: await openVault({ stateDir, privateKeyPem }), viaAgentKey: true, privateKeyPem };
    } catch (err) {
      if (err.code !== "VAULT_UNLOCK_FAILED") throw err;
      // fall through
    }
  }

  const passphrase = await resolvePassphrase(flags);
  if (!passphrase) throw new Error("No passphrase available to unlock vault");
  return { vault: await openVault({ stateDir, privateKeyPem, passphrase }), viaAgentKey: false };
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

// Pinning needs a full handshake every time (a resumed TLS session doesn't
// re-send the cert), so the https path disables session caching.
const pinAgent = new https.Agent({ maxCachedSessions: 0 });

// Speaks to the control plane. `tls` (when the plane is HTTPS) is { fingerprint }:
// the connection trusts no CA and instead pins that SHA-256 cert fingerprint.
function controlJson(host, port, method, p, body, token = null, tls = null) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const headers = {};
    if (payload) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = Buffer.byteLength(payload);
    }
    if (token) headers["Authorization"] = `Bearer ${token}`;
    const opts = { host, port, path: p, method, headers };
    if (tls) {
      opts.rejectUnauthorized = false;
      opts.agent = pinAgent;
    }
    const client = tls ? https : http;
    const req = client.request(opts, (res) => {
      if (tls) {
        const peer = normalizeFingerprint(res.socket.getPeerCertificate().fingerprint256);
        if (peer !== normalizeFingerprint(tls.fingerprint)) {
          res.destroy();
          return reject(new Error("control-plane TLS fingerprint pin mismatch"));
        }
      }
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"));
        } catch (err) {
          reject(err);
        }
      });
    });
    req.on("error", reject);
    req.end(payload);
  });
}

// Returns a { stop() } handle, or null when there's nothing to drive (no
// owner-approval slot, or no agent key on disk).
async function startOwnerApprovalApprover({
  stateDir,
  controlHost,
  controlPort,
  controlToken = null,
  controlPublicKey,
  controlTls = null,
}) {
  const challenge = await readOwnerApprovalChallenge(stateDir);
  if (!challenge) return null;

  const engine = new SignatureEngine({ baseDir: stateDir });
  const main = await engine.ensureMainKey().catch(() => null);
  if (!main?.privateKeyPem) return null;

  const host = controlHost || "127.0.0.1";
  const tls = controlTls; // { fingerprint } when the control plane is HTTPS
  const state = { stop: false, seen: new Set() };

  (async function loop() {
    while (!state.stop) {
      try {
        const { pending } = await controlJson(host, controlPort, "GET", "/pending", null, controlToken, tls);
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
              }, controlToken, tls);
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
              }, controlToken, tls);
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
            // Seal the master key to the proxy's control key — never send it in
            // cleartext, even over loopback.
            await controlJson(host, controlPort, "POST", "/approve", {
              id: entry.id,
              sealedMasterKey: sealToPublicKey(mk, controlPublicKey),
            }, controlToken, tls);
          } catch (err) {
            stderr(`Owner-approval unlock failed: ${err.message}`);
            try {
              await controlJson(host, controlPort, "POST", "/deny", {
                id: entry.id,
                reason: "owner_approval_failed",
              }, controlToken, tls);
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

  const loaded = awaitMobile ? null : await loadVaultForProxy(stateDir, flags);
  const vault = loaded ? loaded.vault : null;
  // Self-reopen is wired only for the agent-key path — the one unlock method
  // that needs no human, so repeating it later (on a credential miss or after
  // the idle lock) still needs nobody. Every other path (passphrase, passkey,
  // --unlock-form) leaves this undefined and the proxy behaves exactly as
  // before: a miss stays a miss, an idle lock stays a restart-to-recover.
  const reopenVault =
    loaded && loaded.viaAgentKey
      ? async () => openVault({ stateDir, privateKeyPem: loaded.privateKeyPem })
      : undefined;
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
        // Default: TLS iff non-loopback. --control-tls forces it on loopback too;
        // --no-control-tls opts out (only sane on loopback).
        ...(flags["control-tls"] ? { tls: true } : {}),
        ...(flags["control-tls"] === false ? { tls: false } : {}),
      }
    : null;

  const grantTtlMs =
    flags["grant-ttl"] != null ? parseDuration(flags["grant-ttl"]) : 60 * 60_000;

  // Per-connector OAuth client secrets (platform secrets — issue #72): a 0600
  // JSON file mapping clientId → clientSecret, named by path so the secret
  // itself never rides argv. Read once at spawn; the host respawns the proxy
  // to pick up a rotation.
  const oauthSecretsFile =
    flags["oauth-secrets-file"] || process.env.AGENT_ID_OAUTH_SECRETS_FILE || null;
  if (oauthSecretsFile === true) {
    outputError("--oauth-secrets-file needs a path");
    return;
  }
  const oauthClientSecrets = oauthSecretsFile
    ? await loadOauthSecretsFile(String(oauthSecretsFile))
    : null;

  const proxy = createProxy({
    vault,
    stateDir,
    logPath: paths.proxyLog,
    listen: { port, host },
    idleTimeoutMs,
    reopenVault,
    control,
    requireConsent,
    grantTtlMs,
    oauthClientSecrets,
    blockPrivateHosts: !!flags["block-private-hosts"],
    onLock: (reason) => {
      if (controlEnabled) {
        stderr(`Vault locked (${reason}). Next request will ask for an unlock approval.`);
      } else if (reopenVault) {
        stderr(`Vault locked (${reason}). Next request re-opens it via the agent key.`);
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
    controlPublicKey: proxy.controlPublicKey || null,
    controlScheme: proxy.controlScheme || "http",
    controlCertFingerprint: proxy.controlCertFingerprint || null,
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
    // The in-process approver is same-machine: connect over loopback when the
    // control plane is on a wildcard bind, else the specific bound host.
    const approverHost =
      controlAddr.host === "0.0.0.0" || controlAddr.host === "::"
        ? "127.0.0.1"
        : controlAddr.host;
    approver = await startOwnerApprovalApprover({
      stateDir,
      controlHost: approverHost,
      controlPort: controlAddr.port,
      controlToken: proxy.controlToken,
      controlPublicKey: proxy.controlPublicKey,
      controlTls:
        proxy.controlScheme === "https" ? { fingerprint: proxy.controlCertFingerprint } : null,
    });
  }

  stderr(`agent-id-proxy listening on http://${addr.host}:${addr.port}`);
  stderr(`  HTTP_PROXY=http://${addr.host}:${addr.port}`);
  if (controlAddr) {
    const how = approver ? "phone or owner approvals" : "phone approvals";
    const cScheme = proxy.controlScheme === "https" ? "https" : "http";
    stderr(`Control plane: ${cScheme}://${controlAddr.host}:${controlAddr.port} (${how})`);
    if (proxy.controlScheme === "https") {
      stderr(`  TLS on (self-signed, cert pinned via \`pair\`): ${proxy.controlCertFingerprint}`);
    } else if (!controlIsLoopback) {
      // Non-loopback without TLS only happens if explicitly disabled.
      stderr(
        `  ⚠ control plane on non-loopback ${controlHost} WITHOUT TLS (--no-control-tls): the ` +
          "bearer token rides plain HTTP and could be sniffed/replayed. Drop --no-control-tls.",
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
  if (!state.controlPort || !state.controlToken || !state.controlPublicKey) {
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

  const scheme = state.controlScheme === "https" ? "https" : "http";
  const controlUrl = `${scheme}://${reachableHost}:${state.controlPort}`;
  const payload = buildPairingPayload({
    controlUrl,
    token: state.controlToken,
    publicKey: state.controlPublicKey,
    fingerprint: scheme === "https" ? state.controlCertFingerprint : null,
  });

  stderr("Scan with the Alien app to pair this phone for vault unlock:\n");
  await new Promise((resolve) => {
    qrcode.generate(payload, { small: true }, (code) => {
      process.stderr.write(code + "\n");
      resolve();
    });
  });
  stderr(`Control URL : ${controlUrl}`);
  stderr(`Pair token  : ${state.controlToken}`);
  if (scheme === "https") {
    stderr(`Cert SHA-256: ${state.controlCertFingerprint}  (the phone pins this)`);
    stderr(
      "Master key is sealed to this proxy's key and the channel is TLS (cert pinned via this QR)",
    );
    stderr("  — the token is not exposed. Keep the token private regardless.");
  } else {
    stderr("This token authorizes /register, /pending, and /approve — keep it private.");
    stderr(
      "Note: control plane is plain HTTP (loopback). For a networked phone, restart with",
    );
    stderr("  --control-host <lan-ip> so the plane runs over TLS with the cert pinned here.");
  }
  outputJson({ ok: true, control: controlUrl, payload });
}

function printHelp() {
  stderr(
    [
      "agent-id-proxy — local stub-translating HTTP proxy",
      "",
      "Subcommands:",
      "  start [--port N] [--host H] [--passphrase-file F | --passphrase-env V]",
      "        [--unlock-form]   unlock once per session via an out-of-band localhost",
      "                          browser form (no agent-key auto-unlock; needs a passphrase slot)",
      "        [--no-agent-key] [--idle-timeout 12h|30m|never]",
      "        [--no-control] [--control-port N] [--control-host H] [--control-tls|--no-control-tls]",
      "        [--await-mobile]",
      "        [--require-consent] [--approval-timeout 2m] [--grant-ttl 1h]",
      "        [--block-private-hosts]",
      "        [--oauth-secrets-file F]   0600 JSON {clientId: clientSecret} consulted for",
      "                          oauth2 creds that carry no clientSecret of their own",
      "                          (platform-managed connectors; env: AGENT_ID_OAUTH_SECRETS_FILE)",
      "  pair [--control-host H]   show a QR for a phone to scan (control URL + token)",
      "  status",
      "  stop",
      "  autounlock [--off] [--idle-timeout T]   opt in/out of the SessionStart hook",
      "        that pops the unlock form once per session (needs a passphrase/dev vault)",
      "",
      "Use with HTTP_PROXY=http://<host>:<port> set in the agent's environment.",
      "Stubs: `AgentVault <credential-name>` in headers or query parameter values.",
      "Idle lock: master key zeroed after `--idle-timeout` (default 12h). With the",
      "  control plane on (default), the next request re-unlocks via a phone approval;",
      "  otherwise restart the proxy. Use --idle-timeout never to disable.",
      "Self-reopen: when unlocked via the agent key (default; not --unlock-form or",
      "  --no-agent-key), the proxy can re-open its own vault without a human — a",
      "  credential added after start is picked up on next use, and (without the",
      "  control plane) an idle lock recovers on the next request instead of needing",
      "  a restart.",
      "Control plane (default 127.0.0.1:48772, loopback only — NOT the data-plane",
      "  --host): the phone polls /pending and POSTs /approve | /deny. Those routes",
      "  (and /register) require a bearer token (auto-generated, written to the 0600",
      "  proxy state file); /status is open for liveness. The master key on /approve",
      "  is always sealed to the proxy's control key. Use --control-host to expose it",
      "  to a LAN phone — then it runs over TLS (self-signed, the phone pins the cert",
      "  fingerprint from `pair`); loopback stays plain HTTP. --await-mobile starts",
      "  locked so the first request prompts for an unlock. --require-consent prompts",
      "  per (cred,host).",
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

// `autounlock` — opt into (or out of) the SessionStart auto-unlock hook by
// writing/removing the marker file the hook checks. When enabled, the unlock form
// opens once at the start of each session (needs a passphrase/dev-mode vault).
async function cmdAutounlock(flags) {
  const stateDir = resolveStateDir(flags);
  await ensureDir(stateDir);
  const marker = path.join(stateDir, "autounlock");
  if (flags.off) {
    await fs.unlink(marker).catch(() => {});
    stderr("Session-start auto-unlock disabled.");
    return outputJson({ ok: true, autounlock: false });
  }
  // Optional extra `start` args (e.g. --idle-timeout) persisted into the marker.
  const extra = flags["idle-timeout"] ? `--idle-timeout ${flags["idle-timeout"]}` : "";
  await fs.writeFile(marker, extra ? `${extra}\n` : "", { mode: 0o600 });
  stderr(
    "Session-start auto-unlock enabled — the unlock form will open at the start of " +
      "each session. Needs a vault with a passphrase slot (dev mode).",
  );
  return outputJson({ ok: true, autounlock: true, marker, startArgs: extra || null });
}

const commands = {
  start: cmdStart,
  pair: cmdPair,
  status: cmdStatus,
  stop: cmdStop,
  autounlock: cmdAutounlock,
};

runCli({ commands, printHelp });
