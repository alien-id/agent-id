// Alien Agent ID — OAuth broker internals.
//
// Self-hosted OAuth 2.0 token brokering. Runs the Authorization Code (+ PKCE)
// flow with YOUR OWN OAuth app credentials, stores access/refresh tokens
// encrypted under the agent's Ed25519 key (the same AES-256-GCM vault used by
// the agent-id-vault plugin), refreshes them on demand, and detects when a
// requested scope was never granted (incremental consent). This replaces the
// role of a hosted auth engine (e.g. Arcade) for third-party providers.
//
// All secrets (client_secret, access_token, refresh_token) live only inside the
// encrypted bundle. Non-secret metadata (scopes, expiry) is kept in clear for
// fast checks without decrypting.

import path from "node:path";
import fs from "node:fs/promises";
import http from "node:http";
import { createHash, randomBytes } from "node:crypto";

import { statePaths, readJsonFile } from "../../agent-id-core/lib/state.mjs";
import { deriveVaultKey, vaultEncrypt, vaultDecrypt } from "../../agent-id-vault/lib/vault.mjs";
import {
  outputError,
  outputJson,
  resolveStateDir,
  stderr,
} from "../../agent-id-core/lib/cli-runtime.mjs";

// ─── Provider catalog ───────────────────────────────────────────────────────
// A starter set covering the common providers a hosted engine brokers. Anything
// not listed works too via the generic escape hatch (--authorize-url /
// --token-url / --scope-separator / --token-auth / --pkce / --scope-param).
// Per-provider quirks are expressed purely as data.
const PROVIDERS = {
  google: {
    authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    pkce: true,
    scopeSeparator: " ",
    // access_type=offline + prompt=consent are required to receive a refresh_token
    extraAuthParams: { access_type: "offline", prompt: "consent" },
  },
  microsoft: {
    authorizeUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    tokenUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    pkce: true,
    scopeSeparator: " ",
    extraAuthParams: { prompt: "consent" },
    // add the `offline_access` scope yourself to get a refresh_token
  },
  github: {
    authorizeUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    pkce: false,
    scopeSeparator: " ",
    // classic OAuth Apps issue non-expiring tokens with no refresh_token;
    // GitHub Apps with token expiration enabled do return refresh tokens.
  },
  slack: {
    authorizeUrl: "https://slack.com/oauth/v2/authorize",
    tokenUrl: "https://slack.com/api/oauth.v2.access",
    pkce: false,
    scopeSeparator: ",",
    scopeParam: "user_scope", // user-token scopes go here, not `scope`
    responseUserToken: true, // user token is nested under authed_user
  },
  notion: {
    authorizeUrl: "https://api.notion.com/v1/oauth/authorize",
    tokenUrl: "https://api.notion.com/v1/oauth/token",
    pkce: false,
    scopeSeparator: " ",
    tokenAuth: "basic",
    extraAuthParams: { owner: "user" },
  },
  linear: {
    authorizeUrl: "https://linear.app/oauth/authorize",
    tokenUrl: "https://api.linear.app/oauth/token",
    pkce: false,
    scopeSeparator: ",",
  },
  zoom: {
    authorizeUrl: "https://zoom.us/oauth/authorize",
    tokenUrl: "https://zoom.us/oauth/token",
    pkce: true,
    scopeSeparator: " ",
    tokenAuth: "basic",
  },
  spotify: {
    authorizeUrl: "https://accounts.spotify.com/authorize",
    tokenUrl: "https://accounts.spotify.com/api/token",
    pkce: true,
    scopeSeparator: " ",
    tokenAuth: "basic",
  },
  discord: {
    authorizeUrl: "https://discord.com/oauth2/authorize",
    tokenUrl: "https://discord.com/api/oauth2/token",
    pkce: false,
    scopeSeparator: " ",
  },
  atlassian: {
    authorizeUrl: "https://auth.atlassian.com/authorize",
    tokenUrl: "https://auth.atlassian.com/oauth/token",
    pkce: false,
    scopeSeparator: " ",
    extraAuthParams: { audience: "api.atlassian.com", prompt: "consent" },
  },
  x: {
    authorizeUrl: "https://twitter.com/i/oauth2/authorize",
    tokenUrl: "https://api.twitter.com/2/oauth2/token",
    pkce: true, // required by X
    scopeSeparator: " ",
    tokenAuth: "basic",
  },
  dropbox: {
    authorizeUrl: "https://www.dropbox.com/oauth2/authorize",
    tokenUrl: "https://api.dropboxapi.com/oauth2/token",
    pkce: true,
    scopeSeparator: " ",
    extraAuthParams: { token_access_type: "offline" },
  },
  hubspot: {
    authorizeUrl: "https://app.hubspot.com/oauth/authorize",
    tokenUrl: "https://api.hubapi.com/oauth/v1/token",
    pkce: false,
    scopeSeparator: " ",
  },
  asana: {
    authorizeUrl: "https://app.asana.com/-/oauth_authorize",
    tokenUrl: "https://app.asana.com/-/oauth_token",
    pkce: false,
    scopeSeparator: " ",
  },
};

const DEFAULT_PORT = 8723;
const EXPIRY_BUFFER_MS = 60_000; // refresh a minute before actual expiry

// ─── Small helpers ────────────────────────────────────────────────────────────

function b64url(buf) {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function safeName(name) {
  return String(name).replace(/[^a-zA-Z0-9._-]/g, "_");
}

function oauthDir(stateDir) {
  return path.join(stateDir, "oauth");
}

async function writeJsonPrivate(file, obj) {
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, JSON.stringify(obj, null, 2), { mode: 0o600 });
  await fs.chmod(file, 0o600).catch(() => {});
}

async function loadVaultKey(stateDir) {
  const paths = statePaths(stateDir);
  const key = await readJsonFile(paths.mainKey, null);
  if (!key?.privateKeyPem) {
    throw new Error("No agent keypair. Run `agent-id-core bootstrap` first.");
  }
  return deriveVaultKey(key.privateKeyPem);
}

// Resolve a provider config: catalog entry merged with any generic overrides.
function resolveProvider(name, flags) {
  const base = PROVIDERS[name] ? { ...PROVIDERS[name] } : {};
  const cfg = {
    scopeSeparator: " ",
    scopeParam: "scope",
    tokenAuth: "body",
    pkce: false,
    extraAuthParams: {},
    ...base,
  };
  if (flags["authorize-url"]) cfg.authorizeUrl = flags["authorize-url"];
  if (flags["token-url"]) cfg.tokenUrl = flags["token-url"];
  if (flags["scope-separator"]) cfg.scopeSeparator = flags["scope-separator"];
  if (flags["scope-param"]) cfg.scopeParam = flags["scope-param"];
  if (flags["token-auth"]) cfg.tokenAuth = flags["token-auth"];
  if (flags.pkce !== undefined) cfg.pkce = flags.pkce === true || flags.pkce === "true";
  if (!cfg.authorizeUrl || !cfg.tokenUrl) {
    throw new Error(
      `Unknown provider "${name}". Provide --authorize-url and --token-url to broker it generically, ` +
        `or use one of: ${Object.keys(PROVIDERS).join(", ")}.`,
    );
  }
  return cfg;
}

function parseScopes(s) {
  if (!s) return [];
  return String(s).split(/[\s,]+/).filter(Boolean);
}

// Bundle file: encrypted {client_id, client_secret, redirect_uri, tokens...}
function bundlePath(stateDir, provider) {
  return path.join(oauthDir(stateDir), `${safeName(provider)}.json`);
}
function pendingPath(stateDir, provider) {
  return path.join(oauthDir(stateDir), `${safeName(provider)}.pending.json`);
}

async function loadBundle(stateDir, provider, vaultKey) {
  const rec = await readJsonFile(bundlePath(stateDir, provider), null);
  if (!rec) return null;
  const secret = JSON.parse(vaultDecrypt(vaultKey, rec.encrypted));
  return { meta: rec, secret };
}

async function saveBundle(stateDir, provider, vaultKey, { client, tokens, scopes }) {
  const file = bundlePath(stateDir, provider);
  const existing = await readJsonFile(file, null);
  const secret = {
    client_id: client.client_id,
    client_secret: client.client_secret ?? null,
    redirect_uri: client.redirect_uri,
    access_token: tokens?.access_token ?? null,
    refresh_token: tokens?.refresh_token ?? null,
  };
  const expiry = tokens?.expires_in ? Date.now() + Number(tokens.expires_in) * 1000 : null;
  const rec = {
    version: 1,
    provider,
    scopes: scopes ?? existing?.scopes ?? [],
    expiry: expiry ?? existing?.expiry ?? null,
    hasRefreshToken: !!secret.refresh_token,
    encrypted: vaultEncrypt(vaultKey, JSON.stringify(secret)),
    createdAt: existing?.createdAt ?? Date.now(),
    updatedAt: Date.now(),
  };
  await writeJsonPrivate(file, rec);
  return rec;
}

// ─── HTTP: token exchange + refresh ─────────────────────────────────────────────

async function postToken(cfg, body, client) {
  const headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    Accept: "application/json",
  };
  const form = new URLSearchParams(body);
  if (cfg.tokenAuth === "basic") {
    const basic = Buffer.from(`${client.client_id}:${client.client_secret ?? ""}`).toString("base64");
    headers.Authorization = `Basic ${basic}`;
  } else {
    form.set("client_id", client.client_id);
    if (client.client_secret) form.set("client_secret", client.client_secret);
  }
  const res = await fetch(cfg.tokenUrl, { method: "POST", headers, body: form.toString() });
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    // some providers (rarely) return form-encoded; fall back
    json = Object.fromEntries(new URLSearchParams(text));
  }
  if (!res.ok || json.error || json.ok === false) {
    const detail = json.error_description || json.error || json.message || text;
    throw new Error(`Token endpoint error (${res.status}): ${detail}`);
  }
  // Slack-style: user token nested under authed_user
  if (cfg.responseUserToken && json.authed_user?.access_token) {
    return {
      access_token: json.authed_user.access_token,
      refresh_token: json.authed_user.refresh_token ?? json.refresh_token ?? null,
      expires_in: json.authed_user.expires_in ?? json.expires_in ?? null,
      scope: json.authed_user.scope ?? json.scope ?? null,
    };
  }
  return json;
}

function captureViaServer(port, expectedState, timeoutSec) {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const u = new URL(req.url, `http://localhost:${port}`);
      if (u.pathname !== "/callback") {
        res.writeHead(404).end();
        return;
      }
      const err = u.searchParams.get("error");
      const code = u.searchParams.get("code");
      const state = u.searchParams.get("state");
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(
        `<html><body style="font-family:system-ui;text-align:center;padding-top:3rem">` +
          `<h2>${err ? "Authorization failed" : "Authorized"}</h2>` +
          `<p>${err ? err : "You can close this tab and return to your terminal."}</p></body></html>`,
      );
      server.close();
      clearTimeout(timer);
      if (err) return reject(new Error(`Authorization failed: ${err}`));
      if (expectedState && state !== expectedState) {
        return reject(new Error("State mismatch — possible CSRF or stale login."));
      }
      resolve(code);
    });
    const timer = setTimeout(() => {
      server.close();
      reject(new Error(`Timed out after ${timeoutSec}s waiting for the OAuth callback.`));
    }, timeoutSec * 1000);
    server.on("error", reject);
    server.listen(port, () => {
      stderr(`Listening on http://localhost:${port}/callback for the OAuth redirect…`);
    });
  });
}

// ─── Commands (each takes the parsed flags object) ──────────────────────────────

// register: store YOUR OAuth app credentials (client_id/secret) for a provider.
export async function cmdRegister(flags) {
  const provider = flags.provider;
  if (!provider) return outputError("--provider <name> is required");
  if (!flags["client-id"]) return outputError("--client-id <id> is required");

  const cfg = resolveProvider(provider, flags); // validates endpoints exist
  const stateDir = resolveStateDir(flags);
  const vaultKey = await loadVaultKey(stateDir);

  const port = flags.port ? Number(flags.port) : DEFAULT_PORT;
  const redirectUri = flags["redirect-uri"] || `http://localhost:${port}/callback`;

  const clientSecret =
    flags["client-secret"] ||
    (flags["client-secret-env"] ? process.env[flags["client-secret-env"]] : null) ||
    null;

  const existing = await loadBundle(stateDir, provider, vaultKey);
  await saveBundle(stateDir, provider, vaultKey, {
    client: { client_id: flags["client-id"], client_secret: clientSecret, redirect_uri: redirectUri },
    tokens: existing?.secret
      ? { access_token: existing.secret.access_token, refresh_token: existing.secret.refresh_token }
      : null,
    scopes: existing?.meta.scopes,
  });

  stderr(`Registered OAuth app for "${provider}".`);
  outputJson({
    ok: true,
    provider,
    redirect_uri: redirectUri,
    authorize_endpoint: cfg.authorizeUrl,
    note: `Add "${redirectUri}" as an authorized redirect URI in your ${provider} OAuth app.`,
  });
}

// login (phase 1): build the authorize URL, persist PKCE verifier + state.
// Does NOT block — prints the URL so the caller can show it, then completes via
// `complete` (avoids the "URL must show before blocking" deadlock).
export async function cmdLogin(flags) {
  const provider = flags.provider;
  if (!provider) return outputError("--provider <name> is required");
  const cfg = resolveProvider(provider, flags);
  const stateDir = resolveStateDir(flags);
  const vaultKey = await loadVaultKey(stateDir);

  const bundle = await loadBundle(stateDir, provider, vaultKey);
  if (!bundle?.secret?.client_id) {
    return outputError(`No OAuth app registered for "${provider}". Run \`register\` first.`);
  }
  const client = bundle.secret;

  // Merge requested scopes with already-granted ones (incremental consent).
  const requested = parseScopes(flags.scopes);
  const merged = Array.from(new Set([...(bundle.meta.scopes || []), ...requested]));
  if (merged.length === 0) {
    return outputError('--scopes "<space/comma separated>" is required for the first login.');
  }

  const state = b64url(randomBytes(16));
  const params = new URLSearchParams({
    response_type: "code",
    client_id: client.client_id,
    redirect_uri: client.redirect_uri,
    state,
    ...cfg.extraAuthParams,
  });
  params.set(cfg.scopeParam, merged.join(cfg.scopeSeparator));

  let verifier = null;
  if (cfg.pkce) {
    verifier = b64url(randomBytes(32));
    const challenge = b64url(createHash("sha256").update(verifier).digest());
    params.set("code_challenge", challenge);
    params.set("code_challenge_method", "S256");
  }

  await writeJsonPrivate(pendingPath(stateDir, provider), {
    provider,
    state,
    verifier,
    scopes: merged,
    redirect_uri: client.redirect_uri,
    createdAt: Date.now(),
  });

  const authorizeUrl = `${cfg.authorizeUrl}?${params.toString()}`;
  outputJson({
    ok: true,
    provider,
    authorize_url: authorizeUrl,
    redirect_uri: client.redirect_uri,
    scopes: merged,
    next:
      `Open authorize_url, approve, then run \`complete --provider ${provider} --serve\` ` +
      `(auto-capture) or \`complete --provider ${provider} --callback-url "<redirected localhost URL>"\` ` +
      `(manual/remote).`,
  });
}

// complete (phase 2): finish the flow. Either runs a one-shot loopback server to
// auto-capture the code (--serve), or accepts a pasted callback URL / raw code
// (--callback-url / --code) for headless/remote use.
export async function cmdComplete(flags) {
  const provider = flags.provider;
  if (!provider) return outputError("--provider <name> is required");
  const cfg = resolveProvider(provider, flags);
  const stateDir = resolveStateDir(flags);
  const vaultKey = await loadVaultKey(stateDir);

  const pending = await readJsonFile(pendingPath(stateDir, provider), null);
  if (!pending) return outputError(`No pending login for "${provider}". Run \`login\` first.`);

  const bundle = await loadBundle(stateDir, provider, vaultKey);
  const client = bundle.secret;

  let code;
  if (flags.code) {
    code = flags.code;
  } else if (flags["callback-url"]) {
    const u = new URL(flags["callback-url"]);
    if (u.searchParams.get("error")) {
      return outputError(`Authorization failed: ${u.searchParams.get("error")}`);
    }
    if (pending.state && u.searchParams.get("state") !== pending.state) {
      return outputError("State mismatch — possible CSRF or stale login. Re-run `login`.");
    }
    code = u.searchParams.get("code");
  } else if (flags.serve) {
    const port = Number(new URL(client.redirect_uri).port) || DEFAULT_PORT;
    code = await captureViaServer(port, pending.state, Number(flags["timeout-sec"] || 300));
  } else {
    return outputError('Provide --serve, --callback-url "<url>", or --code "<code>".');
  }
  if (!code) return outputError("No authorization code obtained.");

  const body = { grant_type: "authorization_code", code, redirect_uri: client.redirect_uri };
  if (pending.verifier) body.code_verifier = pending.verifier;
  const tokens = await postToken(cfg, body, client);

  const grantedScopes = tokens.scope ? parseScopes(tokens.scope) : pending.scopes;
  await saveBundle(stateDir, provider, vaultKey, { client, tokens, scopes: grantedScopes });
  await fs.unlink(pendingPath(stateDir, provider)).catch(() => {});

  stderr(`Authorized "${provider}".`);
  outputJson({
    ok: true,
    provider,
    scopes: grantedScopes,
    has_refresh_token: !!tokens.refresh_token,
    expires_in: tokens.expires_in ?? null,
  });
}

// token: the broker core. Return a valid access token, refreshing if expired. If
// a requested scope was never granted, signal re-consent instead.
export async function cmdToken(flags) {
  const provider = flags.provider;
  if (!provider) return outputError("--provider <name> is required");
  const cfg = resolveProvider(provider, flags);
  const stateDir = resolveStateDir(flags);
  const vaultKey = await loadVaultKey(stateDir);

  const bundle = await loadBundle(stateDir, provider, vaultKey);
  if (!bundle?.secret?.access_token) {
    return outputError(`No tokens for "${provider}". Run \`login\` then \`complete\`.`);
  }

  // Incremental-consent check: requested scopes must be a subset of granted.
  const requested = parseScopes(flags.scopes);
  const granted = new Set(bundle.meta.scopes || []);
  const missing = requested.filter((s) => !granted.has(s));
  if (missing.length > 0) {
    return outputJson({
      ok: false,
      needs_consent: true,
      provider,
      missing_scopes: missing,
      granted_scopes: [...granted],
      action:
        `Run \`login --provider ${provider} --scopes "${[...granted, ...missing].join(" ")}"\` ` +
        `then \`complete\` to add the missing scope(s).`,
    });
  }

  let { access_token, refresh_token } = bundle.secret;
  let expiry = bundle.meta.expiry;
  const expired = expiry && Date.now() > expiry - EXPIRY_BUFFER_MS;

  if (expired) {
    if (!refresh_token) {
      return outputError(
        `Access token for "${provider}" expired and no refresh token is stored. ` +
          `Re-run \`login\` / \`complete\`.`,
      );
    }
    const refreshed = await postToken(cfg, { grant_type: "refresh_token", refresh_token }, bundle.secret);
    access_token = refreshed.access_token;
    // some providers rotate refresh tokens; keep the newest
    refresh_token = refreshed.refresh_token || refresh_token;
    await saveBundle(stateDir, provider, vaultKey, {
      client: bundle.secret,
      tokens: { access_token, refresh_token, expires_in: refreshed.expires_in },
      scopes: bundle.meta.scopes,
    });
    expiry = refreshed.expires_in ? Date.now() + Number(refreshed.expires_in) * 1000 : null;
    stderr(`Refreshed access token for "${provider}".`);
  }

  if (flags.raw) {
    process.stdout.write(`Authorization: Bearer ${access_token}\n`);
    return;
  }
  outputJson({
    ok: true,
    provider,
    access_token,
    header: `Authorization: Bearer ${access_token}`,
    scopes: bundle.meta.scopes,
    expires_at: expiry,
    refreshed: expired,
  });
}

export async function cmdList(flags) {
  const stateDir = resolveStateDir(flags);
  const dir = oauthDir(stateDir);
  let files;
  try {
    files = await fs.readdir(dir);
  } catch {
    return outputJson({ ok: true, providers: [] });
  }
  const providers = [];
  for (const f of files) {
    if (!f.endsWith(".json") || f.endsWith(".pending.json")) continue;
    const rec = await readJsonFile(path.join(dir, f), null);
    if (!rec?.provider) continue;
    providers.push({
      provider: rec.provider,
      scopes: rec.scopes,
      has_refresh_token: rec.hasRefreshToken,
      expires_at: rec.expiry,
      expired: rec.expiry ? Date.now() > rec.expiry : false,
      updatedAt: rec.updatedAt,
    });
  }
  outputJson({ ok: true, providers });
}

export async function cmdLogout(flags) {
  const provider = flags.provider;
  if (!provider) return outputError("--provider <name> is required");
  const stateDir = resolveStateDir(flags);
  let removed = false;
  for (const p of [bundlePath(stateDir, provider), pendingPath(stateDir, provider)]) {
    try {
      await fs.unlink(p);
      removed = true;
    } catch {
      /* ignore */
    }
  }
  if (!removed) return outputError(`Nothing stored for "${provider}".`);
  stderr(`Removed OAuth state for "${provider}".`);
  outputJson({ ok: true, provider });
}

export const SUPPORTED_PROVIDERS = Object.keys(PROVIDERS);
