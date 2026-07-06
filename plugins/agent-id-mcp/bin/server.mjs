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

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { TOOLS } from "../lib/tools.mjs";
import { runCli } from "../lib/cli-adapter.mjs";

const NAME = "agent-id";
const VERSION = "7.2.0";

// Build a server bound to a fixed state dir (stdio: from env; HTTP: per-request).
export function createServer({ stateDir = process.env.AGENT_ID_STATE_DIR } = {}) {
  const server = new Server({ name: NAME, version: VERSION }, { capabilities: { tools: {} } });

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
    })),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const tool = TOOLS.find((t) => t.name === req.params.name);
    if (!tool) {
      return {
        isError: true,
        content: [{ type: "text", text: JSON.stringify({ ok: false, error: "UNKNOWN_TOOL", message: req.params.name }) }],
      };
    }
    const args = req.params.arguments || {};
    const result = await runCli(tool.kind, tool.argv(args), { stateDir });
    // The CLI's own {ok:false,...} becomes an MCP error result; ok:true passes through.
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
  process.stderr.write(`agent-id-mcp: ready (stdio, ${TOOLS.length} tools)\n`);
}

// Run as a CLI (not when imported by the HTTP transport or tests).
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    process.stderr.write(`agent-id-mcp: fatal: ${err && err.stack ? err.stack : err}\n`);
    process.exit(1);
  });
}
