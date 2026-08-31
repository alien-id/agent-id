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
const SERVER = path.join(
  HERE,
  "..",
  "plugins",
  "agent-id-mcp",
  "bin",
  "server.mjs"
);
const BUNDLE = path.join(
  HERE,
  "..",
  "plugins",
  "agent-id-mcp",
  "cowork",
  "server.bundle.mjs"
);

let Client, StdioClientTransport;
try {
  ({ Client } = await import("@modelcontextprotocol/sdk/client/index.js"));
  ({ StdioClientTransport } = await import(
    "@modelcontextprotocol/sdk/client/stdio.js"
  ));
} catch {
  /* SDK not installed — tests below skip */
}
const skip = Client ? false : "@modelcontextprotocol/sdk not installed";

async function withClient(stateDir, fn, { serverPath = SERVER, cwd } = {}) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [serverPath],
    env: { ...process.env, AGENT_ID_STATE_DIR: stateDir },
    ...(cwd ? { cwd } : {}),
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
      for (const expected of [
        "agent_id_status",
        "agent_id_sign",
        "vault_list",
        "vault_add",
        "vault_remove",
        "vault_set_totp",
      ]) {
        assert.ok(names.includes(expected), `missing tool ${expected}`);
      }
      // Every tool advertises a JSON Schema so schema-strict models can call it.
      for (const t of tools) {
        assert.equal(
          t.inputSchema.type,
          "object",
          `${t.name} needs an object inputSchema`
        );
      }
    });
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test(
  "agent_id_status flows CLI JSON back through the MCP result",
  { skip },
  async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "mcp-status-"));
    try {
      await withClient(dir, async (client) => {
        const res = await client.callTool({
          name: "agent_id_status",
          arguments: {},
        });
        const status = parse(res);
        // The core CLI's own structured status, verbatim: fresh dir → L0, unprovisioned.
        assert.equal(status.ok, true);
        assert.equal(status.initialized, false);
        assert.equal(status.level, 0);
        assert.equal(
          status.stateDir,
          dir,
          "the caller's state dir was honored"
        );
      });
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  }
);

test(
  "agent_id_probe_env reports the runtime + browser reachability",
  { skip },
  async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "mcp-probe-"));
    try {
      await withClient(dir, async (client) => {
        const probe = parse(
          await client.callTool({ name: "agent_id_probe_env", arguments: {} })
        );
        assert.equal(probe.ok, true);
        // The probe REPORTS the runtime — assert it's a known classification, not a
        // specific one (a macOS dev box is "host"; a Linux CI runner is
        // "unknown-linux"; the real Cowork VM would be "cowork-vm").
        assert.ok(
          ["host", "cowork-vm", "unknown-linux"].includes(probe.runtime),
          `unexpected runtime: ${probe.runtime}`
        );
        assert.equal(probe.platform, process.platform);
        assert.equal(typeof probe.localhostBindable, "boolean");
        assert.equal(typeof probe.chrome.found, "boolean");
        assert.ok(probe.verdict, "carries a plain-English verdict");
      });
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  }
);

test(
  "the Cowork bundle runs self-contained (no node_modules) — proves no runtime install",
  { skip },
  async () => {
    let bundleExists = true;
    try {
      await fs.access(BUNDLE);
    } catch {
      bundleExists = false;
    }
    if (!bundleExists) {
      // Bundle is a build output; regenerate with `bun run build:bundle` in plugins/agent-id-mcp.
      return; // nothing to assert without the artifact
    }
    // Copy ONLY the bundle into a fresh dir with no node_modules — this is the
    // Cowork condition (the SessionStart npm-install hook never runs there).
    const iso = await fs.mkdtemp(path.join(os.tmpdir(), "mcp-bundle-"));
    try {
      await fs.copyFile(BUNDLE, path.join(iso, "server.bundle.mjs"));
      await withClient(
        iso,
        async (client) => {
          const { tools } = await client.listTools();
          assert.ok(
            tools.some((t) => t.name === "agent_id_probe_env"),
            "probe tool present in the bundle"
          );
          const probe = parse(
            await client.callTool({ name: "agent_id_probe_env", arguments: {} })
          );
          assert.equal(
            probe.ok,
            true,
            "the bundled server answers with no node_modules present"
          );
        },
        { serverPath: path.join(iso, "server.bundle.mjs"), cwd: iso }
      );
    } finally {
      await fs.rm(iso, { recursive: true, force: true });
    }
  }
);

test(
  "an unknown tool is a structured MCP error, not a crash",
  { skip },
  async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "mcp-unknown-"));
    try {
      await withClient(dir, async (client) => {
        const res = await client.callTool({
          name: "does_not_exist",
          arguments: {},
        });
        assert.equal(res.isError, true);
        assert.equal(parse(res).error, "UNKNOWN_TOOL");
      });
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  }
);
