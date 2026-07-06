#!/usr/bin/env node

// Foundation test for the agent-id MCP server: a real MCP client speaks to the
// server over stdio and confirms the full path — MCP call → agent-id CLI
// subprocess → JSON → MCP tool result. Proves the connector shape Cowork consumes
// works end to end. Skips if the MCP SDK isn't installed.
//
// Run: node --test tests/test-mcp-server.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SERVER = path.join(HERE, "..", "plugins", "agent-id-mcp", "bin", "server.mjs");

let Client, StdioClientTransport;
try {
  ({ Client } = await import("@modelcontextprotocol/sdk/client/index.js"));
  ({ StdioClientTransport } = await import("@modelcontextprotocol/sdk/client/stdio.js"));
} catch {
  /* SDK not installed — tests below skip */
}
const skip = Client ? false : "@modelcontextprotocol/sdk not installed";

async function withClient(stateDir, fn) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER],
    env: { ...process.env, AGENT_ID_STATE_DIR: stateDir },
  });
  const client = new Client({ name: "agent-id-mcp-test", version: "1.0.0" });
  await client.connect(transport);
  try {
    return await fn(client);
  } finally {
    await client.close();
  }
}

const parse = (res) => JSON.parse(res.content[0].text);

test("lists the identity + vault tools with schemas", { skip }, async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "mcp-tools-"));
  try {
    await withClient(dir, async (client) => {
      const { tools } = await client.listTools();
      const names = tools.map((t) => t.name);
      for (const expected of ["agent_id_status", "agent_id_sign", "vault_list", "vault_add", "vault_remove", "vault_set_totp"]) {
        assert.ok(names.includes(expected), `missing tool ${expected}`);
      }
      // Every tool advertises a JSON Schema so schema-strict models can call it.
      for (const t of tools) {
        assert.equal(t.inputSchema.type, "object", `${t.name} needs an object inputSchema`);
      }
    });
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("agent_id_status flows CLI JSON back through the MCP result", { skip }, async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "mcp-status-"));
  try {
    await withClient(dir, async (client) => {
      const res = await client.callTool({ name: "agent_id_status", arguments: {} });
      const status = parse(res);
      // The core CLI's own structured status, verbatim: fresh dir → L0, unprovisioned.
      assert.equal(status.ok, true);
      assert.equal(status.initialized, false);
      assert.equal(status.level, 0);
      assert.equal(status.stateDir, dir, "the caller's state dir was honored");
    });
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("an unknown tool is a structured MCP error, not a crash", { skip }, async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "mcp-unknown-"));
  try {
    await withClient(dir, async (client) => {
      const res = await client.callTool({ name: "does_not_exist", arguments: {} });
      assert.equal(res.isError, true);
      assert.equal(parse(res).error, "UNKNOWN_TOOL");
    });
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
