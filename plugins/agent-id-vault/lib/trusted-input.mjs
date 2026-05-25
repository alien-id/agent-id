// Alien Agent ID — Trusted-input channel.
//
// Reads a passphrase or credential value from the controlling terminal
// (`/dev/tty` on POSIX) without going through the parent process's stdin.
// Used when the agent invokes the CLI and we need a secret from the human
// in a way that does NOT enter the agent's transcript or stdin pipe.
//
// The CLI itself is a child of the agent. The agent sees what the CLI
// writes to stdout. The trusted-input reader opens /dev/tty directly,
// bypassing the inherited stdin pipe, so the typed value never crosses
// the agent's I/O boundary.
//
// Windows: not implemented in v1. CONIN$ direct open is the equivalent;
// flagged in the proposal and tracked separately.

import fs from "node:fs";
import { execFileSync } from "node:child_process";

const POSIX = process.platform !== "win32";

export class TrustedInputUnavailable extends Error {
  constructor(message) {
    super(message);
    this.code = "TRUSTED_INPUT_UNAVAILABLE";
  }
}

function openTty() {
  if (!POSIX) {
    throw new TrustedInputUnavailable(
      "Trusted input on Windows requires CONIN$ — not implemented in v1",
    );
  }
  try {
    return fs.openSync("/dev/tty", "r+");
  } catch (err) {
    throw new TrustedInputUnavailable(
      `Cannot open /dev/tty (${err.code || err.message}). ` +
        "Run interactively in a terminal, or use --passphrase-file / --credential-file.",
    );
  }
}

function writeTty(fd, msg) {
  fs.writeSync(fd, msg);
}

function readLineFromFd(fd) {
  const buf = Buffer.alloc(4096);
  let collected = "";
  while (true) {
    const n = fs.readSync(fd, buf, 0, buf.length, null);
    if (n === 0) break;
    const chunk = buf.slice(0, n).toString("utf8");
    const nl = chunk.indexOf("\n");
    if (nl >= 0) {
      collected += chunk.slice(0, nl);
      break;
    }
    collected += chunk;
  }
  return collected.replace(/\r$/, "");
}

// Read one line from /dev/tty with echo disabled. Saves and restores stty
// state so the terminal is usable afterwards even on Ctrl-C.
function readLineNoEcho(fd) {
  let savedStty = null;
  try {
    savedStty = execFileSync("stty", ["-g"], {
      stdio: ["inherit", "pipe", "ignore"],
    })
      .toString()
      .trim();
  } catch {
    // stty not available; fall through with no save and no echo-disable.
  }
  try {
    if (savedStty) {
      execFileSync("stty", ["-echo"], { stdio: "inherit" });
    }
    return readLineFromFd(fd);
  } finally {
    if (savedStty) {
      try {
        execFileSync("stty", [savedStty], { stdio: "inherit" });
      } catch {
        // best effort
      }
    }
    writeTty(fd, "\n");
  }
}

/**
 * Prompt for a secret on /dev/tty with echo disabled. Returns the typed
 * string (no trailing newline). Throws TrustedInputUnavailable if /dev/tty
 * cannot be opened.
 */
export function promptSecret(promptText) {
  const fd = openTty();
  try {
    writeTty(fd, promptText);
    return readLineNoEcho(fd);
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Prompt for non-secret text (echo enabled). Used for confirmation prompts
 * like "Allow agent X to use credential Y for host Z? [y/n]".
 */
export function promptText(promptText) {
  const fd = openTty();
  try {
    writeTty(fd, promptText);
    return readLineFromFd(fd);
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Prompt twice for a new passphrase, with confirmation. Re-prompts on
 * mismatch up to `attempts` times.
 */
export function promptNewPassphrase({
  prompt = "Passphrase: ",
  confirm = "Confirm: ",
  attempts = 3,
} = {}) {
  for (let i = 0; i < attempts; i++) {
    const a = promptSecret(prompt);
    if (!a) throw new Error("Empty passphrase");
    const b = promptSecret(confirm);
    if (a === b) return a;
    const fd = openTty();
    try {
      writeTty(fd, "Passphrases do not match. Try again.\n");
    } finally {
      fs.closeSync(fd);
    }
  }
  throw new Error("Too many passphrase mismatches");
}

export function hasTty() {
  if (!POSIX) return false;
  try {
    fs.accessSync("/dev/tty");
    return true;
  } catch {
    return false;
  }
}
