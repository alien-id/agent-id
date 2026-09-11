// Alien Agent ID — pid liveness helpers for the proxy CLI.
//
// A bare `kill(pid, 0)` liveness check has two false positives: it succeeds
// for a zombie (already exited, not yet reaped) and for any live process
// that happens to have reused the pid after the daemon actually died. Both
// matter to a supervisor that restarts the proxy back-to-back — a stale
// `proxy.json` left behind by a killed daemon must not block the next
// `start`.

import fs from "node:fs/promises";

export async function isZombie(pid) {
  if (process.platform !== "linux") return false;
  try {
    const raw = await fs.readFile(`/proc/${pid}/stat`, "utf8");
    // Fields after the process name are space-separated; the name itself is
    // parenthesized and may itself contain spaces/parens, so split on the
    // *last* ')' rather than on whitespace from the start.
    const afterComm = raw.slice(raw.lastIndexOf(")") + 1).trim();
    const state = afterComm.split(/\s+/)[0];
    return state === "Z";
  } catch {
    return false;
  }
}

export async function proxyPidLooksAlive(pid) {
  try {
    process.kill(pid, 0);
  } catch {
    return false;
  }
  if (process.platform !== "linux") return true;
  if (await isZombie(pid)) return false;
  try {
    const raw = await fs.readFile(`/proc/${pid}/cmdline`, "utf8");
    const argv = raw.split("\0").filter(Boolean).join(" ");
    return argv.includes("agent-id-proxy");
  } catch {
    return false;
  }
}
