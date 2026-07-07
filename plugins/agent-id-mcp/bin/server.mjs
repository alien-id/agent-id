#!/usr/bin/env node
// Alien Agent ID — MCP server.
//
// Exposes agent-id (identity, vault, and — later — the vault-sealed browser) as
// MCP tools, so Claude Cowork can wire it in as a connector. Each tool maps to an
// agent-id-* CLI subcommand (see lib/tools.mjs); this file is just the MCP wiring.
//
// Transport: stdio (this file) for local/dev and the in-VM option. The hosted
// connector uses Streamable HTTP over the same tool registry (increment 3 —
// docs/COWORK-MCP.md).
//
// State: AGENT_ID_STATE_DIR selects the identity + vault. Under stdio it comes
// from the environment; the hosted transport maps each caller's bearer token to a
// per-user state dir before dispatching.

import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { TOOLS } from "../lib/tools.mjs";
import { PROBE_TOOLS } from "../lib/probe.mjs";
import { runCli } from "../lib/cli-adapter.mjs";

const NAME = "agent-id";
const VERSION = "7.2.0";

// A tool is either CLI-backed ({ kind, argv }) or handler-backed ({ handler }).
const ALL_TOOLS = [...PROBE_TOOLS, ...TOOLS];

// Build a server bound to a fixed state dir (stdio: from env; HTTP: per-request).
export function createServer({ stateDir = process.env.AGENT_ID_STATE_DIR } = {}) {
  const server = new Server({ name: NAME, version: VERSION }, { capabilities: { tools: {} } });

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: ALL_TOOLS.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
    })),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const tool = ALL_TOOLS.find((t) => t.name === req.params.name);
    if (!tool) {
      return {
        isError: true,
        content: [{ type: "text", text: JSON.stringify({ ok: false, error: "UNKNOWN_TOOL", message: req.params.name }) }],
      };
    }
    const args = req.params.arguments || {};
    // handler-backed (diagnostic) vs CLI-backed (the agent-id surface).
    let result;
    if (typeof tool.handler === "function") {
      try {
        result = await tool.handler(args);
      } catch (err) {
        result = { ok: false, error: "HANDLER_FAILED", message: String(err && err.message ? err.message : err) };
      }
    } else {
      result = await runCli(tool.kind, tool.argv(args), { stateDir });
    }
    // A tool's own {ok:false,...} becomes an MCP error result; ok:true passes through.
    const isError = result && typeof result === "object" && result.ok === false;
    return {
      ...(isError ? { isError: true } : {}),
      content: [{ type: "text", text: JSON.stringify(result) }],
    };
  });

  return server;
}

async function main() {
  const server = createServer();
  await server.connect(new StdioServerTransport());
  // stderr only — stdout is the MCP framing channel.
  process.stderr.write(`agent-id-mcp: ready (stdio, ${ALL_TOOLS.length} tools)\n`);
}

// True when this file is the process entry point — robust to symlinks (macOS
// /var→/private/var, and bundled single-file builds) where a naive
// `import.meta.url === file://${argv[1]}` comparison silently mismatches and the
// server would never start. Tests that `import` this module are NOT the entry.
function isMainEntry() {
  try {
    return (
      !!process.argv[1] &&
      realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))
    );
  } catch {
    return false;
  }
}

if (isMainEntry()) {
  main().catch((err) => {
    process.stderr.write(`agent-id-mcp: fatal: ${err && err.stack ? err.stack : err}\n`);
    process.exit(1);
  });
}
