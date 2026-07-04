// Alien Agent ID — advisory vault write lock.
//
// Guards the read-reconcile-merge-save window of a sync against a concurrent
// CLI writer on the same stateDir. Best-effort `wx` lockfile with stale
// takeover; both sides fail EXPLICITLY rather than corrupt the vault.

import fs from "node:fs/promises";

import { statePaths } from "@alien-id/agent-id-core/lib/state.mjs";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function withVaultLock(stateDir, fn, { retries = 50, delayMs = 100, staleMs = 60_000 } = {}) {
  const lockPath = statePaths(stateDir).vaultFile + ".lock";
  for (let attempt = 0; ; attempt++) {
    try {
      const handle = await fs.open(lockPath, "wx");
      await handle.write(String(process.pid));
      await handle.close();
      break;
    } catch (err) {
      if (err?.code !== "EEXIST") throw err;
      const stat = await fs.stat(lockPath).catch(() => null);
      if (stat && Date.now() - stat.mtimeMs > staleMs) {
        await fs.unlink(lockPath).catch(() => {});
        continue;
      }
      if (attempt >= retries) {
        const busy = new Error(`vault is locked by another process (${lockPath})`);
        busy.code = "VAULT_BUSY";
        throw busy;
      }
      await sleep(delayMs);
    }
  }
  try {
    return await fn();
  } finally {
    await fs.unlink(lockPath).catch(() => {});
  }
}
