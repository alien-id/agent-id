#!/usr/bin/env node
// Alien Agent ID — Model Context Protocol server
//
// Exposes the CLI subcommands as typed MCP tools. Spawns `cli.mjs` per call so
// behavior is byte-identical to running the CLI directly; the tests, CI scripts,
// and the global `alien-agent-id` bin keep working unchanged.
//
// Protocol: JSON-RPC 2.0 over stdio, newline-delimited (MCP stdio transport).
// Zero npm dependencies — hand-rolled JSON-RPC matches the project's philosophy.

import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const CLI_PATH = path.join(SCRIPT_DIR, "cli.mjs");
const SERVER_NAME = "alien-agent-id";
const SERVER_VERSION = "4.0.0";
const PROTOCOL_VERSION = "2024-11-05";

// ─── Tool catalog ──────────────────────────────────────────────────────────────
//
// Each entry maps an MCP tool to a CLI subcommand. `inputSchema` is the
// JSONSchema the LLM sees. camelCase property names are auto-converted to
// `--kebab-case` flags; boolean `true` values become bare flags (`--push`),
// other values become `--flag value`.

const COMMON_STATE_DIR = {
  stateDir: {
    type: "string",
    description: "State directory (default: ~/.agent-id or $AGENT_ID_STATE_DIR).",
  },
};

const TOOLS = {
  bootstrap: {
    cli: "bootstrap",
    description:
      "One-command identity setup (init + auth + bind + git-setup). Blocks up to 5 min waiting for QR approval.",
    inputSchema: {
      type: "object",
      properties: {
        providerAddress: {
          type: "string",
          description: "Alien provider address (else ALIEN_PROVIDER_ADDRESS / default-provider.txt).",
        },
        ...COMMON_STATE_DIR,
      },
    },
  },
  setup_owner_session: {
    cli: "setup-owner-session",
    description: "Re-bind an existing agent (pre-v3 migration / re-auth). Preserves the keypair.",
    inputSchema: {
      type: "object",
      properties: {
        providerAddress: { type: "string" },
        ...COMMON_STATE_DIR,
      },
    },
  },
  init: {
    cli: "init",
    description: "Generate the agent's Ed25519 keypair and initialize the state directory.",
    inputSchema: { type: "object", properties: { ...COMMON_STATE_DIR } },
  },
  auth: {
    cli: "auth",
    description: "Start OIDC authorization. Returns deep link + QR code for the human to approve in the Alien App.",
    inputSchema: {
      type: "object",
      required: ["providerAddress"],
      properties: {
        providerAddress: { type: "string" },
        ssoUrl: { type: "string", description: "SSO base URL (default: https://sso.alien-api.com)." },
        oidcOrigin: { type: "string", description: "OIDC Origin header (default: http://localhost)." },
        ...COMMON_STATE_DIR,
      },
    },
  },
  bind: {
    cli: "bind",
    description: "Poll for user approval and create the owner binding. Blocks until approved or timeout.",
    inputSchema: {
      type: "object",
      properties: {
        timeoutSec: { type: "integer", description: "Poll timeout in seconds (default: 300)." },
        pollIntervalMs: { type: "integer", description: "Poll interval in ms (default: 3000)." },
        ...COMMON_STATE_DIR,
      },
    },
  },
  status: {
    cli: "status",
    description: "Show whether an Alien Agent ID exists and is bound. Cheap status probe.",
    inputSchema: { type: "object", properties: { ...COMMON_STATE_DIR } },
  },
  sign: {
    cli: "sign",
    description: "Sign an arbitrary operation and append it to the hash-chained audit trail.",
    inputSchema: {
      type: "object",
      required: ["type", "action", "payload"],
      properties: {
        type: { type: "string", description: "Operation type (e.g. TOOL_CALL, MESSAGE_SEND)." },
        action: { type: "string", description: "Action name (e.g. bash.exec, github.create-pr)." },
        payload: { type: "string", description: "Operation payload as a JSON string." },
        agentId: { type: "string", description: "Agent ID (default: main)." },
        ...COMMON_STATE_DIR,
      },
    },
  },
  verify: {
    cli: "verify",
    description: "Verify the entire state chain (audit log integrity).",
    inputSchema: { type: "object", properties: { ...COMMON_STATE_DIR } },
  },
  export_proof: {
    cli: "export-proof",
    description: "Export a portable proof bundle to stdout.",
    inputSchema: { type: "object", properties: { ...COMMON_STATE_DIR } },
  },
  git_setup: {
    cli: "git-setup",
    description: "Write SSH key files for commit signing under ~/.agent-id/ssh/.",
    inputSchema: {
      type: "object",
      properties: {
        email: { type: "string", description: "Email for the SSH key comment." },
        ...COMMON_STATE_DIR,
      },
    },
  },
  git_commit: {
    cli: "git-commit",
    description:
      "Create an SSH-signed commit with Agent-ID-* trailers, a v3 proof note, and an audit-trail entry.",
    inputSchema: {
      type: "object",
      required: ["message"],
      properties: {
        message: { type: "string", description: "Commit message." },
        allowEmpty: { type: "boolean", description: "Allow empty commits." },
        push: { type: "boolean", description: "Push commit + proof notes after committing." },
        remote: { type: "string", description: "Remote name (default: origin)." },
        ...COMMON_STATE_DIR,
      },
    },
  },
  git_verify: {
    cli: "git-verify",
    description:
      "Verify the provenance chain of a signed commit: SSH sig → agent_jwk → id_token cnf.jkt → SSO RS256 sig. Standalone — no bound identity required.",
    inputSchema: {
      type: "object",
      properties: {
        commit: { type: "string", description: "Commit hash to verify (default: HEAD)." },
        ssoUrl: { type: "string", description: "SSO base URL for id_token verification." },
        ...COMMON_STATE_DIR,
      },
    },
  },
  call: {
    cli: "call",
    description:
      "One-shot signed HTTP request to an Alien-aware service. Generates DPoP headers (RFC 9449) and sends the request.",
    inputSchema: {
      type: "object",
      required: ["url"],
      properties: {
        url: { type: "string", description: "Target URL." },
        method: { type: "string", description: "HTTP method (default: GET)." },
        body: { type: "string", description: "Request body as a literal string." },
        bodyFile: { type: "string", description: "Path to file containing request body (preferred over `body`)." },
        contentType: { type: "string", description: "Content-Type header (default: application/json with body)." },
        ...COMMON_STATE_DIR,
      },
    },
  },
  auth_header: {
    cli: "auth-header",
    description:
      "Emit RFC 9449 DPoP Authorization + DPoP headers for one request. Prefer `call` unless you specifically need to drive curl.",
    inputSchema: {
      type: "object",
      required: ["url"],
      properties: {
        url: { type: "string" },
        method: { type: "string", description: "HTTP method (default: GET)." },
        raw: { type: "boolean", description: "Output raw `Header: value` lines instead of JSON." },
        ...COMMON_STATE_DIR,
      },
    },
  },
  discover_service: {
    cli: "discover-service",
    description: "Fetch and validate `/.well-known/alien-agent-id.json` for the given service URL.",
    inputSchema: {
      type: "object",
      required: ["url"],
      properties: {
        url: { type: "string", description: "Service base URL (e.g. https://example.com)." },
        ...COMMON_STATE_DIR,
      },
    },
  },
  capabilities: {
    cli: "capabilities",
    description: "Fetch a service manifest and render its `api.operations[]` catalog as markdown.",
    inputSchema: {
      type: "object",
      required: ["url"],
      properties: {
        url: { type: "string" },
        ...COMMON_STATE_DIR,
      },
    },
  },
  service_support: {
    cli: "service-support",
    description:
      "Probe a page for the `<meta name=\"alien-agent-id\">` support signal. Returns { supported, version }.",
    inputSchema: {
      type: "object",
      required: ["url"],
      properties: {
        url: { type: "string" },
        ...COMMON_STATE_DIR,
      },
    },
  },
  refresh: {
    cli: "refresh",
    description:
      "Refresh SSO session tokens (access_token / refresh_token). `call` and `auth_header` refresh transparently — explicit refresh is rarely needed.",
    inputSchema: { type: "object", properties: { ...COMMON_STATE_DIR } },
  },
  vault_store: {
    cli: "vault-store",
    description:
      "Store an encrypted credential in the agent vault (AES-256-GCM, key derived via HKDF from the agent's private key).",
    inputSchema: {
      type: "object",
      required: ["service"],
      properties: {
        service: { type: "string", description: "Service name (also the lookup key)." },
        type: {
          type: "string",
          description: "Credential type.",
          enum: ["api-key", "password", "oauth", "bearer", "custom"],
        },
        credential: {
          type: "string",
          description: "Credential value (visible in ps/history — prefer credentialFile or credentialEnv).",
        },
        credentialFile: { type: "string", description: "Path to file containing the credential (preferred)." },
        credentialEnv: { type: "string", description: "Environment variable name to read the credential from." },
        url: { type: "string", description: "Optional service URL stored as metadata." },
        username: { type: "string", description: "Optional username." },
        ...COMMON_STATE_DIR,
      },
    },
  },
  vault_get: {
    cli: "vault-get",
    description: "Retrieve and decrypt a stored credential. Returns { service, type, credential, ... }.",
    inputSchema: {
      type: "object",
      required: ["service"],
      properties: {
        service: { type: "string" },
        ...COMMON_STATE_DIR,
      },
    },
  },
  vault_list: {
    cli: "vault-list",
    description: "List vault entries (metadata only — credentials never returned).",
    inputSchema: { type: "object", properties: { ...COMMON_STATE_DIR } },
  },
  vault_remove: {
    cli: "vault-remove",
    description: "Remove a credential from the vault.",
    inputSchema: {
      type: "object",
      required: ["service"],
      properties: {
        service: { type: "string" },
        ...COMMON_STATE_DIR,
      },
    },
  },
};

// ─── CLI invocation ────────────────────────────────────────────────────────────

function camelToKebab(name) {
  return name.replace(/[A-Z]/g, (m) => `-${m.toLowerCase()}`);
}

function buildArgs(cliCommand, input) {
  const args = [cliCommand];
  for (const [key, value] of Object.entries(input ?? {})) {
    if (value === undefined || value === null) continue;
    const flag = `--${camelToKebab(key)}`;
    if (value === true) {
      args.push(flag);
    } else if (value === false) {
      // Boolean false → omit the flag entirely.
    } else {
      args.push(flag, String(value));
    }
  }
  return args;
}

function runCli(cliCommand, input) {
  const args = buildArgs(cliCommand, input);
  return new Promise((resolve) => {
    const proc = spawn(process.execPath, [CLI_PATH, ...args], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (chunk) => (stdout += chunk));
    proc.stderr.on("data", (chunk) => (stderr += chunk));
    proc.on("error", (err) => {
      resolve({ ok: false, stdout: "", stderr: err.message, code: -1 });
    });
    proc.on("close", (code) => {
      resolve({ ok: code === 0, stdout, stderr, code });
    });
  });
}

// ─── MCP protocol ──────────────────────────────────────────────────────────────

function writeMessage(message) {
  process.stdout.write(JSON.stringify(message) + "\n");
}

function rpcResult(id, result) {
  writeMessage({ jsonrpc: "2.0", id, result });
}

function rpcError(id, code, message, data) {
  const error = { code, message };
  if (data !== undefined) error.data = data;
  writeMessage({ jsonrpc: "2.0", id, error });
}

function toolList() {
  return Object.entries(TOOLS).map(([name, def]) => ({
    name,
    description: def.description,
    inputSchema: def.inputSchema,
  }));
}

async function handleToolCall(id, params) {
  const name = params?.name;
  const def = TOOLS[name];
  if (!def) {
    rpcError(id, -32602, `Unknown tool: ${name}`);
    return;
  }
  const input = params?.arguments ?? {};
  const result = await runCli(def.cli, input);

  // MCP content blocks: combine stdout (the CLI's JSON output) and any stderr.
  // The CLI sends progress + errors to stderr; surface it as a separate block
  // so the agent sees diagnostic output without it polluting the parsed payload.
  const content = [];
  if (result.stdout) {
    content.push({ type: "text", text: result.stdout.trim() });
  }
  if (result.stderr) {
    content.push({ type: "text", text: `[stderr] ${result.stderr.trim()}` });
  }
  if (content.length === 0) {
    content.push({ type: "text", text: result.ok ? "{}" : `Exit code ${result.code}` });
  }

  rpcResult(id, { content, isError: !result.ok });
}

async function handleMessage(message) {
  const { id, method, params } = message;

  if (method === "initialize") {
    rpcResult(id, {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: { tools: {} },
      serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
    });
    return;
  }

  if (method === "initialized" || method === "notifications/initialized") {
    return; // notification, no response
  }

  if (method === "tools/list") {
    rpcResult(id, { tools: toolList() });
    return;
  }

  if (method === "tools/call") {
    await handleToolCall(id, params);
    return;
  }

  if (method === "ping") {
    rpcResult(id, {});
    return;
  }

  if (id !== undefined) {
    rpcError(id, -32601, `Method not found: ${method}`);
  }
}

// ─── Main ──────────────────────────────────────────────────────────────────────

const rl = createInterface({ input: process.stdin });
rl.on("line", async (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  let message;
  try {
    message = JSON.parse(trimmed);
  } catch (err) {
    rpcError(null, -32700, "Parse error", err.message);
    return;
  }
  try {
    await handleMessage(message);
  } catch (err) {
    rpcError(message.id ?? null, -32603, "Internal error", err.message);
  }
});

rl.on("close", () => process.exit(0));
