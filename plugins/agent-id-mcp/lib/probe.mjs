// Environment-probe tools. These answer, from INSIDE a running MCP host, the
// questions we can't settle from outside: does the host launch this stdio server
// on the real machine or inside a sandbox VM, and can it reach a browser + a
// localhost socket? Purely introspective (no CLI shell-out, no side effects) so a
// probe result never depends on the rest of the tool surface being wired up.

import os from "node:os";
import net from "node:net";
import fs from "node:fs";
import path from "node:path";

import { resolveBin } from "./cli-adapter.mjs";

// Cowork runs code in an Ubuntu VM whose host is literally `claude` on a
// 172.16.10.0/24 link (verified from coworkd). macOS/Windows → the real host.
function classifyRuntime() {
  const plat = process.platform;
  if (plat === "darwin" || plat === "win32") return "host";
  const host = os.hostname();
  const ifaces = Object.values(os.networkInterfaces()).flat().filter(Boolean);
  const looksCoworkVm =
    host === "claude" || ifaces.some((i) => String(i.address).startsWith("172.16.10."));
  if (plat === "linux" && looksCoworkVm) return "cowork-vm";
  return "unknown-linux";
}

// Is a real Chrome present (what the vault-sealed browser drives via channel:chrome)?
function findChrome() {
  const candidates = [
    process.env.AGENT_ID_BROWSER_CHROME,
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/opt/google/chrome/google-chrome",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
  ].filter(Boolean);
  for (const c of candidates) {
    try {
      if (fs.existsSync(c)) return { found: true, path: c };
    } catch {
      /* keep looking */
    }
  }
  // PATH lookup as a fallback.
  for (const name of ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"]) {
    for (const dir of (process.env.PATH || "").split(path.delimiter).filter(Boolean)) {
      const cand = path.join(dir, name);
      try {
        fs.accessSync(cand, fs.constants.X_OK);
        return { found: true, path: cand };
      } catch {
        /* keep looking */
      }
    }
  }
  return { found: false, path: null };
}

// Can we bind a loopback TCP port? The vault-sealed browser's control server does
// this; a hardened sandbox (gVisor) blocks raw sockets.
function canBindLocalhost() {
  return new Promise((resolve) => {
    const srv = net.createServer();
    const done = (v) => {
      try { srv.close(); } catch { /* already closed */ }
      resolve(v);
    };
    srv.once("error", () => done(false));
    try {
      srv.listen(0, "127.0.0.1", () => done(true));
    } catch {
      done(false);
    }
    setTimeout(() => done(false), 2000);
  });
}

async function probeEnv() {
  const localhostBindable = await canBindLocalhost();
  const chrome = findChrome();
  const ifaces = Object.entries(os.networkInterfaces())
    .flatMap(([name, addrs]) => (addrs || []).map((a) => ({ name, address: a.address, family: a.family, internal: a.internal })))
    .filter((a) => a.family === "IPv4");
  return {
    ok: true,
    runtime: classifyRuntime(),
    verdict: {
      // The two questions this whole probe exists to answer:
      canDriveLocalBrowser: chrome.found && localhostBindable,
      note:
        classifyRuntime() === "host"
          ? "Runs on the real machine — local vault-sealed browser is viable if Chrome is present."
          : classifyRuntime() === "cowork-vm"
            ? "Runs INSIDE the Cowork VM — no local Chrome path; use the hosted transport."
            : "Unrecognized Linux; inspect chrome/localhost/network below.",
    },
    platform: process.platform,
    osRelease: os.release(),
    arch: process.arch,
    hostname: os.hostname(),
    node: process.version,
    cwd: process.cwd(),
    env: {
      CLAUDE_PLUGIN_ROOT: process.env.CLAUDE_PLUGIN_ROOT ?? null,
      CLAUDE_PLUGIN_DATA: process.env.CLAUDE_PLUGIN_DATA ?? null,
      AGENT_ID_STATE_DIR: process.env.AGENT_ID_STATE_DIR ?? null,
    },
    chrome,
    localhostBindable,
    agentIdCli: {
      core: !!resolveBin("core"),
      vault: !!resolveBin("vault"),
      browser: !!resolveBin("browser"),
    },
    ipv4Interfaces: ifaces,
  };
}

export const PROBE_TOOLS = [
  {
    name: "agent_id_probe_env",
    description:
      "Diagnostic: report where this MCP server is running (real host vs a sandbox VM), whether a real Chrome and a bindable localhost socket are available, and whether the agent-id CLIs resolve. Use once after install to decide local-browser vs hosted. No side effects.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    handler: probeEnv,
  },
];
