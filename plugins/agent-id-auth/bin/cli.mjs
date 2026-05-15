#!/usr/bin/env node

// Alien Agent ID — Auth plugin CLI.
//
// DPoP-signed (RFC 9449) calls to Alien-aware services. Discover a service's
// manifest at /.well-known/alien-agent-id.json, render its capabilities,
// emit DPoP headers for one request, or one-shot a signed HTTP call.
//
// Subcommands: header, call, discover, capabilities, support.

import fs from "node:fs/promises";

import { createDPoPProof } from "../../agent-id-core/lib/crypto.mjs";

import {
  readJsonFile,
  statePaths,
} from "../../agent-id-core/lib/state.mjs";

import { SignatureEngine } from "../../agent-id-core/lib/signature-engine.mjs";

import {
  fetchServiceManifest,
  probeServiceSupportSignal,
  renderCapabilities,
} from "../lib/manifest.mjs";

import {
  outputError,
  outputJson,
  resolveStateDir,
  runCli,
  stderr,
} from "../../agent-id-core/lib/cli-runtime.mjs";

// ─── Helpers ────────────────────────────────────────────────────────────────────

// Build the DPoP-bound Authorization + DPoP headers for one request.
// RFC 9449 §4.2: the proof binds to a specific (method, URL) and is single-use.
// Returns null + writes an error if the agent isn't bootstrapped.
async function buildDPoPHeaders(stateDir, method, url) {
  const paths = statePaths(stateDir);
  const key = await readJsonFile(paths.mainKey, null);
  if (!key) {
    outputError("No agent keypair. Run `agent-id-setup bootstrap` first.");
    return null;
  }

  // Refresh the SSO session — access_token is rotated on a tight cadence.
  const engine = new SignatureEngine({ baseDir: stateDir });
  await engine.init();
  try {
    await engine.ensureValidSession();
  } catch {
    stderr("Warning: SSO session refresh failed.");
  }

  const session = await readJsonFile(paths.ownerSession, null);
  if (!session?.accessToken) {
    outputError("No bound session with access_token. Run `agent-id-setup bootstrap` or `bind` first.");
    return null;
  }

  const htm = String(method || "GET").toUpperCase();
  const htu = String(url);
  const proof = createDPoPProof({
    privateKeyPem: key.privateKeyPem,
    htm,
    htu,
    // RFC 9449 §4.2: `ath` binds the proof to this specific access token —
    // defends against proof reuse with a different captured token.
    accessToken: session.accessToken,
  });

  return { authorization: `DPoP ${session.accessToken}`, dpop: proof, method: htm, url: htu };
}

// ─── Commands ───────────────────────────────────────────────────────────────────

async function cmdHeader(flags) {
  if (!flags.url) {
    outputError("--url is required. The DPoP proof's `htu` claim binds to a specific request target (RFC 9449 §4.2).");
    return;
  }
  const headers = await buildDPoPHeaders(resolveStateDir(flags), flags.method, flags.url);
  if (!headers) return;

  if (flags.raw) {
    process.stdout.write(`Authorization: ${headers.authorization}\n`);
    process.stdout.write(`DPoP: ${headers.dpop}\n`);
    return;
  }
  outputJson({ ok: true, ...headers });
}

// One-shot signed request: generate DPoP headers, send, return the response.
// Eliminates the two-header / single-use-jti footgun for agents that just
// want to "call this endpoint with my identity attached."
async function cmdCall(flags) {
  if (!flags.url) {
    outputError("--url is required.");
    return;
  }
  const method = String(flags.method || "GET").toUpperCase();
  if (!/^[A-Z]+$/.test(method)) {
    outputError("--method must be an HTTP verb (GET, POST, PUT, DELETE, …)");
    return;
  }

  // Body: --body-file <path> or --body <inline>. Inline is convenient for
  // tiny payloads but visible in process listings, so the file form is
  // preferred for anything non-trivial.
  let body;
  if (flags["body-file"]) {
    try {
      body = await fs.readFile(String(flags["body-file"]), "utf8");
    } catch (err) {
      outputError(`Failed to read --body-file: ${err.message}`);
      return;
    }
  } else if (typeof flags.body === "string") {
    body = flags.body;
  }

  const headers = await buildDPoPHeaders(resolveStateDir(flags), method, flags.url);
  if (!headers) return;

  const fetchHeaders = {
    Authorization: headers.authorization,
    DPoP: headers.dpop,
  };
  if (body !== undefined) {
    fetchHeaders["Content-Type"] = flags["content-type"]
      ? String(flags["content-type"])
      : "application/json";
  }

  let res;
  try {
    res = await fetch(String(flags.url), { method, headers: fetchHeaders, body });
  } catch (err) {
    outputError(`Request failed: ${err.message}`);
    return;
  }

  const contentType = res.headers.get("content-type") || "";
  const text = await res.text();
  let parsed;
  if (/^application\/json\b/i.test(contentType)) {
    try { parsed = JSON.parse(text); } catch { /* fall back to raw text */ }
  }

  outputJson({
    ok: res.ok,
    status: res.status,
    method,
    url: String(flags.url),
    contentType,
    body: parsed !== undefined ? parsed : text,
  });
}

async function cmdSupport(flags) {
  const pageUrl = flags.url;
  if (!pageUrl) {
    outputError("Missing --url <page-url>");
    return;
  }
  const result = await probeServiceSupportSignal(String(pageUrl), {
    allowInsecure: flags["allow-insecure"] === true,
    timeoutMs: flags["timeout-ms"] ? Number(flags["timeout-ms"]) : undefined,
  });
  outputJson({ ok: true, ...result });
}

async function cmdDiscover(flags) {
  const serviceUrl = flags.url || flags.service;
  if (!serviceUrl) {
    outputError("Missing --url <service-url>");
    return;
  }
  const result = await fetchServiceManifest(String(serviceUrl), {
    allowInsecure: flags["allow-insecure"] === true,
    timeoutMs: flags["timeout-ms"] ? Number(flags["timeout-ms"]) : undefined,
  });
  outputJson({
    ok: true,
    manifestUrl: result.manifestUrl,
    allowedHost: result.allowedHost,
    manifest: result.manifest,
  });
}

async function cmdCapabilities(flags) {
  const serviceUrl = flags.url || flags.service;
  if (!serviceUrl) {
    outputError("Missing --url <service-url>");
    return;
  }
  const result = await fetchServiceManifest(String(serviceUrl), {
    allowInsecure: flags["allow-insecure"] === true,
    timeoutMs: flags["timeout-ms"] ? Number(flags["timeout-ms"]) : undefined,
  });
  const md = renderCapabilities(result.manifest);
  process.stdout.write(md.endsWith("\n") ? md : md + "\n");
}

function printHelp() {
  stderr(
    [
      "agent-id-auth — DPoP-signed calls to Alien-aware services",
      "",
      "Subcommands:",
      "  header --url <U> [--method M] [--raw]",
      "                                  Emit Authorization + DPoP headers for one request",
      "  call --url <U> [--method M] [--body S | --body-file F] [--content-type T]",
      "                                  One-shot signed HTTP request (preferred)",
      "  discover --url <U>              Fetch + validate /.well-known/alien-agent-id.json",
      "  capabilities --url <U>          Render a manifest's api.operations[] as markdown",
      "  support --url <U>               Probe a page for the <meta name=\"alien-agent-id\"> signal",
      "",
      "Common flags: --state-dir <path> (defaults to AGENT_ID_STATE_DIR or ~/.agent-id)",
      "              --allow-insecure --timeout-ms <N>",
    ].join("\n"),
  );
}

const commands = {
  header: cmdHeader,
  call: cmdCall,
  discover: cmdDiscover,
  capabilities: cmdCapabilities,
  support: cmdSupport,
};

runCli({ commands, printHelp });
