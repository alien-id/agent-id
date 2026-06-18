#!/usr/bin/env node

// One-time interactive setup for the Gmail demo: "log in once, then the agent
// reads mail forever without ever seeing a token."
//
// This is the ONLY step that needs a human. It runs a loopback OAuth 2.0 flow
// (RFC 8252 — OAuth for native apps) against Google:
//
//   1. spin up a localhost HTTP server on an ephemeral port
//   2. open the owner's default browser to Google's consent screen
//      (their existing Google session is reused — they just click "Allow")
//   3. capture the authorization code on the loopback redirect
//   4. exchange it for a long-lived REFRESH token (access_type=offline)
//   5. hand the refresh token straight to `agent-id-vault add --type oauth2`
//      via a 0600 temp file that is unlinked immediately
//
// The refresh token, the access token, and the client secret are NEVER printed,
// never echoed to the transcript, and never placed on a command line / in shell
// history. After this runs, the proxy mints short-lived access tokens on demand
// and the agent only ever types the credential name ("gmail").
//
// Prerequisite — a Google OAuth client (one-time, in Google Cloud Console):
//   APIs & Services → Credentials → Create credentials → OAuth client ID
//   → Application type: "Desktop app".  Enable the Gmail API on the project.
//   You get a client_id and client_secret. Set the OAuth consent screen to
//   "In production" so the refresh token does not expire after 7 days.
//
// Usage:
//   node examples/gmail-login-bootstrap.mjs \
//     --client-id <CLIENT_ID> \
//     --client-secret-file <path-to-secret> \
//     --state-dir <VAULT_DIR> \
//     [--passphrase-file <path>]        # else the vault prompts on /dev/tty
//     [--name gmail]                    # credential name the agent will use
//     [--scope https://www.googleapis.com/auth/gmail.readonly]
//     [--domains gmail.googleapis.com]
//     [--no-browser]                    # just print the URL to open manually
//
// Read-only scope is the safe default for a "get my email" demo. Swap in
// gmail.modify / gmail.send only if the demo actually needs to act.

import http from "node:http";
import https from "node:https";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { mkdtemp, writeFile, rm, readFile } from "node:fs/promises";
import { rmSync } from "node:fs";

// Remove a temp path even if the user Ctrl-C's during the interactive vault
// prompt — the default SIGINT disposition skips `finally`, which would leave the
// cleartext refresh token / client secret in /tmp. Returns a disposer.
function guardTempPath(p) {
  const onSignal = (sig) => {
    try {
      rmSync(p, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
    process.exit(sig === "SIGTERM" ? 143 : 130);
  };
  process.on("SIGINT", onSignal);
  process.on("SIGTERM", onSignal);
  return () => {
    process.off("SIGINT", onSignal);
    process.off("SIGTERM", onSignal);
  };
}
import { parseArgs } from "node:util";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_VAULT_CLI = path.resolve(HERE, "../plugins/agent-id-vault/bin/cli.mjs");
const AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";

const { values: args } = parseArgs({
  options: {
    "client-id": { type: "string" },
    "client-secret-file": { type: "string" },
    "client-secret-env": { type: "string" },
    "state-dir": { type: "string" },
    "passphrase-file": { type: "string" },
    "vault-cli": { type: "string", default: DEFAULT_VAULT_CLI },
    name: { type: "string", default: "gmail" },
    scope: { type: "string", default: "https://www.googleapis.com/auth/gmail.readonly" },
    domains: { type: "string", default: "gmail.googleapis.com" },
    "token-endpoint": { type: "string", default: TOKEN_ENDPOINT },
    "no-browser": { type: "boolean", default: false },
  },
});

function die(msg) {
  console.error(`\n✗ ${msg}\n`);
  process.exit(1);
}

const clientId = args["client-id"] || process.env.GOOGLE_CLIENT_ID;
if (!clientId) die("--client-id (or GOOGLE_CLIENT_ID) is required");
if (!args["state-dir"]) die("--state-dir is required (where the vault.enc lives)");

// Resolve the client secret without ever putting it on a command line.
async function loadClientSecret() {
  if (args["client-secret-file"]) {
    return (await readFile(args["client-secret-file"], "utf8")).trim();
  }
  if (args["client-secret-env"]) {
    const v = process.env[args["client-secret-env"]];
    if (!v) die(`env var ${args["client-secret-env"]} is empty`);
    return v.trim();
  }
  if (process.env.GOOGLE_CLIENT_SECRET) return process.env.GOOGLE_CLIENT_SECRET.trim();
  // PKCE-only public clients can omit the secret; Desktop-app clients need it.
  return null;
}

// PKCE (RFC 7636) — protects the loopback redirect even though it's localhost.
function pkce() {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

function openBrowser(url) {
  const cmd =
    process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open";
  try {
    const child = spawn(cmd, [url], { stdio: "ignore", detached: true, shell: process.platform === "win32" });
    child.on("error", () => {});
    child.unref();
    return true;
  } catch {
    return false;
  }
}

// POST application/x-www-form-urlencoded to the token endpoint and parse JSON.
function postForm(urlString, form) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const client = url.protocol === "https:" ? https : http;
    const payload = Buffer.from(form.toString(), "utf8");
    const req = client.request(
      {
        hostname: url.hostname,
        port: url.port || (url.protocol === "https:" ? 443 : 80),
        method: "POST",
        path: `${url.pathname}${url.search}`,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
          "Content-Length": payload.length,
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          let body = null;
          try {
            body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          } catch {
            /* fall through */
          }
          resolve({ status: res.statusCode, body });
        });
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}

async function main() {
  const clientSecret = await loadClientSecret();
  const { verifier, challenge } = pkce();
  const state = crypto.randomBytes(16).toString("base64url");

  // Start the loopback listener first so we know the redirect port.
  const server = http.createServer();
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  const redirectUri = `http://127.0.0.1:${port}`;

  const codePromise = new Promise((resolve, reject) => {
    server.on("request", (req, res) => {
      const u = new URL(req.url, "http://127.0.0.1");
      const code = u.searchParams.get("code");
      const gotState = u.searchParams.get("state");
      const error = u.searchParams.get("error");
      const ok = code && gotState === state && !error;
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(
        `<!doctype html><meta charset=utf-8><title>Agent ID</title>` +
          `<body style="font:16px system-ui;margin:4rem auto;max-width:30rem;text-align:center">` +
          (ok
            ? `<h2>✓ Connected</h2><p>Setting up the vault — you can close this tab and return to the terminal.</p>`
            : `<h2>✗ Authorization failed</h2><p>${error || "state mismatch / no code"}. Re-run the bootstrap.</p>`) +
          `</body>`,
      );
      server.close();
      if (ok) resolve(code);
      else reject(new Error(error || "authorization failed"));
    });
  });

  const authUrl = new URL(AUTH_ENDPOINT);
  authUrl.search = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: args.scope,
    access_type: "offline", // ask for a refresh token
    prompt: "consent", // force the consent screen so a refresh token is always issued
    include_granted_scopes: "true",
    code_challenge: challenge,
    code_challenge_method: "S256",
    state,
  }).toString();

  console.error("\nAgent ID — Gmail one-time login");
  console.error(`  credential : ${args.name}`);
  console.error(`  scope      : ${args.scope}`);
  console.error(`  vault dir  : ${args["state-dir"]}`);
  console.error(`  redirect   : ${redirectUri}\n`);

  if (args["no-browser"] || !openBrowser(authUrl.href)) {
    console.error("Open this URL in your browser (your Google session is reused):\n");
    console.error(`  ${authUrl.href}\n`);
  } else {
    console.error("Opening your browser… approve access on the Google consent screen.");
    console.error("(If nothing opened, re-run with --no-browser to get the URL.)\n");
  }

  const code = await codePromise;

  // Exchange the authorization code for tokens.
  const form = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    client_id: clientId,
    redirect_uri: redirectUri,
    code_verifier: verifier,
  });
  if (clientSecret) form.set("client_secret", clientSecret);

  const { status, body } = await postForm(args["token-endpoint"], form);
  if (status < 200 || status >= 300 || !body || body.error) {
    die(`token exchange failed (${status}): ${body?.error_description || body?.error || "no body"}`);
  }
  const refreshToken = body.refresh_token;
  if (!refreshToken) {
    die(
      "Google did not return a refresh_token. Revoke prior access at " +
        "https://myaccount.google.com/permissions and re-run (we already send " +
        "access_type=offline & prompt=consent).",
    );
  }

  // Hand the refresh token to the vault via a 0600 temp file, then remove it.
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), "agentid-oauth-"));
  const rtFile = path.join(tmpDir, "rt");
  let secretFile = args["client-secret-file"] || null;
  let wroteSecret = false;
  const unguard = guardTempPath(tmpDir);
  try {
    await writeFile(rtFile, refreshToken, { mode: 0o600 });
    if (!secretFile && clientSecret) {
      secretFile = path.join(tmpDir, "cs");
      await writeFile(secretFile, clientSecret, { mode: 0o600 });
      wroteSecret = true;
    }

    const cliArgs = [
      args["vault-cli"],
      "add",
      "--state-dir",
      args["state-dir"],
      "--name",
      args.name,
      "--type",
      "oauth2",
      "--domains",
      args.domains,
      "--token-endpoint",
      args["token-endpoint"],
      "--client-id",
      clientId,
      "--refresh-token-file",
      rtFile,
      "--scope",
      args.scope,
    ];
    if (secretFile) cliArgs.push("--client-secret-file", secretFile);
    if (args["passphrase-file"]) cliArgs.push("--passphrase-file", args["passphrase-file"]);

    console.error("Storing the credential in the vault…\n");
    const code2 = await new Promise((resolve) => {
      // inherit stdio so the vault can prompt for the passphrase on /dev/tty
      const child = spawn(process.execPath, cliArgs, { stdio: "inherit" });
      child.on("close", resolve);
    });
    if (code2 !== 0) die(`vault add exited with code ${code2}`);
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
    unguard();
    void wroteSecret;
  }

  const host = args.domains.split(",")[0].trim();
  console.error("\n✓ Done. The agent can now read mail through the proxy with no secret in sight:\n");
  console.error(
    `   curl http://127.0.0.1:48771/${args.name}/${host}/gmail/v1/users/me/messages?maxResults=5\n`,
  );
  console.error("The proxy mints a fresh access token per request from the stored refresh token.");
  console.error("Nothing sensitive was printed; the temp files were removed (incl. on Ctrl-C).\n");
}

main().catch((err) => die(err.message || String(err)));
