// Alien Agent ID — Shared CLI runtime.
//
// Output formatting (JSON to stdout, prose to stderr), argv parsing,
// state-dir resolution, child-process wrapper, and the common dispatch
// loop. Each per-plugin CLI (agent-id-vault/bin/cli.mjs, agent-id-git/…)
// defines a commands map and delegates dispatch to runCli().

import { execFile as execFileCb } from "node:child_process";
import os from "node:os";
import path from "node:path";

export function stderr(msg) {
  process.stderr.write(`${msg}\n`);
}

export function outputJson(obj) {
  process.stdout.write(JSON.stringify(obj, null, 2) + "\n");
}

export function outputError(message) {
  outputJson({ ok: false, error: message });
  process.exitCode = 1;
}

export function parseFlags(argv) {
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      if (key.startsWith("no-")) {
        flags[key.slice(3)] = false;
      } else if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
        flags[key] = argv[++i];
      } else {
        flags[key] = true;
      }
    }
  }
  return flags;
}

export function resolveStateDir(flags) {
  if (flags["state-dir"]) {
    return path.resolve(String(flags["state-dir"]));
  }
  if (process.env.AGENT_ID_STATE_DIR) {
    return path.resolve(process.env.AGENT_ID_STATE_DIR);
  }
  return path.join(os.homedir(), ".agent-id");
}

export function execFile(command, args, options = {}) {
  return new Promise((resolve) => {
    execFileCb(command, args, { timeout: 5000, ...options }, (err, stdout, stderrOut) => {
      resolve({
        code: err?.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER" ? 1 : err ? (err.code ?? 1) : 0,
        stdout: stdout || "",
        stderr: stderrOut || "",
      });
    });
  });
}

/**
 * Standard dispatch loop for a per-plugin CLI.
 *
 *   await runCli({
 *     commands: { "vault-store": cmdVaultStore, ... },
 *     printHelp: () => stderr("Usage: ..."),
 *   });
 *
 * - argv[0] is the subcommand (or "help"/"--help"/"-h" → printHelp)
 * - remaining argv is parsed into a flags object passed to the handler
 * - thrown errors are surfaced via outputError + process.exitCode = 1
 */
export async function runCli({ commands, printHelp }) {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === "help" || command === "--help" || command === "-h") {
    if (typeof printHelp === "function") printHelp();
    return;
  }

  const handler = commands[command];
  if (!handler) {
    outputError(`Unknown command: ${command}. Run with --help for usage.`);
    return;
  }

  const flags = parseFlags(args.slice(1));

  try {
    await handler(flags);
  } catch (err) {
    outputError(err instanceof Error ? err.message : String(err));
  }
}
