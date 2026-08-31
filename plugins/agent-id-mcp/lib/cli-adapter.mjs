// Resolve and run the agent-id-* CLIs as subprocesses, returning their JSON.
//
// The MCP server is a THIN adapter: every tool maps to a CLI subcommand (the same
// battle-tested surface the desktop host shells out to), so there is no
// re-implementation of command logic. Resolution mirrors the host's: an explicit
// AGENT_ID_{CORE,VAULT,BROWSER}_BIN override, else the CLI on PATH, else the dev
// workspace sibling. A `.mjs`/`.js` target is run with the current node.

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import fs from "node:fs";

const PKG_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

// kind: "core" | "vault" | "browser". Returns an argv PREFIX ([program, ...]) or
// null when the CLI can't be found.
export function resolveBin(kind) {
  const envKey = `AGENT_ID_${kind.toUpperCase()}_BIN`;
  const name = `agent-id-${kind}`;

  const asArgv = (p) =>
    /\.(mjs|js|cjs)$/.test(p) ? [process.execPath, p] : [p];

  const override = process.env[envKey];
  if (override && override.trim() && fs.existsSync(override)) return asArgv(override);

  const onPath = whichSync(name);
  if (onPath) return asArgv(onPath);

  // Dev workspace: plugins/agent-id-mcp/../agent-id-<kind>/bin/cli.mjs
  const sibling = path.join(PKG_DIR, "..", name, "bin", "cli.mjs");
  if (fs.existsSync(sibling)) return asArgv(sibling);

  return null;
}

// Minimal `which`: first executable named `name` on PATH.
function whichSync(name) {
  const dirs = (process.env.PATH || "").split(path.delimiter).filter(Boolean);
  for (const dir of dirs) {
    const cand = path.join(dir, name);
    try {
      fs.accessSync(cand, fs.constants.X_OK);
      return cand;
    } catch {
      /* not here */
    }
  }
  return null;
}

// Run a CLI subcommand and return its parsed JSON stdout (or a structured error).
// `stateDir` is passed as AGENT_ID_STATE_DIR so the child reads the right per-user
// identity + vault (the hosted transport maps the caller's bearer → a state dir).
export function runCli(kind, args, { stateDir, timeoutMs = 60000, env = {} } = {}) {
  const prefix = resolveBin(kind);
  if (!prefix) {
    return Promise.resolve({
      ok: false,
      error: "CLI_NOT_FOUND",
      message: `agent-id-${kind} not found (set AGENT_ID_${kind.toUpperCase()}_BIN or install it on PATH)`,
    });
  }
  const [program, ...prefixArgs] = prefix;
  const argv = [...prefixArgs, ...args];

  return new Promise((resolve) => {
    const child = spawn(program, argv, {
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        ...(stateDir ? { AGENT_ID_STATE_DIR: stateDir } : {}),
        ...env,
      },
    });
    let out = "";
    let err = "";
    const to = setTimeout(() => {
      child.kill("SIGKILL");
      resolve({ ok: false, error: "TIMEOUT", message: `agent-id-${kind} ${args[0] ?? ""} timed out` });
    }, timeoutMs);

    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    child.on("error", (e) => {
      clearTimeout(to);
      resolve({ ok: false, error: "SPAWN_FAILED", message: String(e && e.message ? e.message : e) });
    });
    child.on("close", () => {
      clearTimeout(to);
      const text = out.trim();
      // The CLIs print a single JSON object on stdout; pass it through verbatim
      // (parsed) so the MCP tool result is the CLI's own structured result.
      try {
        resolve(JSON.parse(text));
      } catch {
        resolve(
          text
            ? { ok: false, error: "BAD_OUTPUT", message: text.slice(0, 500) }
            : { ok: false, error: "NO_OUTPUT", message: err.trim().slice(0, 500) || "no output" },
        );
      }
    });
  });
}
