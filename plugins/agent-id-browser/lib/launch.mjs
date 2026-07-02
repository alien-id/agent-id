// Alien Agent ID — Hardened browser launcher (patchright).
//
// patchright is a stealth-patched Playwright drop-in. Its anti-detection lives
// in the DRIVER — patchright-core's patched automation framework (the CDP/runtime
// layer that hides navigator.webdriver, suppresses Runtime.enable leaks, etc.) —
// plus the launch flags below. It is NOT a patched browser binary, so the stealth
// applies equally when driving the user's own installed Chrome via
// channel:"chrome". (patchright patches Chromium-based browsers; system Chrome is
// Chromium-based.) This config is the one validated to pass Google's interactive
// login wall with the renderer sandbox kept ON:
//
//   channel:"chrome"            → drive the user's installed Chrome (no Chromium
//                                 download; more realistic fingerprint)
//   ignoreDefaultArgs:["--no-sandbox"] → patchright injects --no-sandbox; strip it
//                                 so the renderer sandbox stays on
//   args:["--test-type"]        → suppress the "unsupported flag" banner that the
//                                 load-bearing --disable-blink-features=
//                                 AutomationControlled flag would otherwise raise
//   viewport:null               → real window size, not a scripted viewport
//
// patchright is NOT bundled with the plugin (the marketplace ships no
// node_modules). A SessionStart hook installs it into the plugin's data dir on
// first run; resolvePatchright() then finds it. Because skill Bash commands don't
// get CLAUDE_PLUGIN_DATA in their env (only hooks/MCP do), the CLI bridges the
// skill-substituted --plugin-data path into process.env.CLAUDE_PLUGIN_DATA before
// anything here runs.

import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";

const require = createRequire(import.meta.url);
const PLUGIN_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

// Directories whose node_modules may hold patchright, highest priority first:
//   1. CLAUDE_PLUGIN_DATA — the per-plugin persistent dir the SessionStart hook
//      installs into (set in hook env directly; bridged from --plugin-data by the
//      CLI for ordinary skill invocations).
//   2. CLAUDE_PLUGIN_ROOT — the installed plugin dir, as a secondary location.
//   3. PLUGIN_DIR — this file's plugin dir, for a dev / direct `npm install`.
// require.resolve also consults global folders / NODE_PATH as a last resort.
function searchDirs() {
  const dirs = [];
  if (process.env.CLAUDE_PLUGIN_DATA) dirs.push(process.env.CLAUDE_PLUGIN_DATA);
  if (process.env.CLAUDE_PLUGIN_ROOT) dirs.push(process.env.CLAUDE_PLUGIN_ROOT);
  dirs.push(PLUGIN_DIR);
  return dirs;
}

// Resolve patchright's entry file across the candidate locations. Returns the
// absolute path or null. Exported for tests.
export function resolvePatchright() {
  try {
    return require.resolve("patchright", { paths: searchDirs() });
  } catch {
    return null;
  }
}

export async function loadChromium() {
  const entry = resolvePatchright();
  if (!entry) {
    const err = new Error(
      "patchright is not installed. Browser mode installs it on demand into the\n" +
        "plugin data dir via a SessionStart hook; if that has not run (e.g. first use\n" +
        "while offline), install it into the same dir and retry:\n" +
        '  cd "${CLAUDE_PLUGIN_DATA:-plugins/agent-id-browser}" && npm install\n' +
        'It drives your installed Chrome via channel="chrome" (no extra browser download).',
    );
    err.code = "PATCHRIGHT_MISSING";
    throw err;
  }
  const mod = require(entry);
  const chromium = mod?.chromium ?? mod?.default?.chromium;
  if (!chromium) {
    const err = new Error(`patchright loaded from ${entry} but exposes no chromium API`);
    err.code = "PATCHRIGHT_BROKEN";
    throw err;
  }
  return chromium;
}

function launchOptions(headless) {
  return {
    channel: "chrome",
    headless,
    viewport: null,
    ignoreDefaultArgs: ["--no-sandbox"],
    args: ["--test-type"],
    // Explicit (it's the modern default) so the session server's download
    // listener always gets Download objects rather than canceled downloads.
    acceptDownloads: true,
  };
}

// ── Headless User-Agent normalization ─────────────────────────────────────────
//
// Chrome tags the User-Agent with "HeadlessChrome" in headless mode. patchright
// (by design — upstream issue Kaliiiiiiiiii-Vinyzu/patchright-python#46, closed
// "not planned") does NOT strip it, even though it already normalizes the
// Sec-CH-UA client-hint header to "Google Chrome". That leaves the UA string as
// the ONE request signal that differs between headed and headless, and the lone
// "Headless" token is a well-known bot-detection trigger (it flips Google,
// Reddit, etc. into a challenge). We normalize it so a headless session is
// byte-identical to a headed one on the wire and in JS.
//
// We do NOT invent a UA (patchright rightly warns a mismatched UA is itself a
// tell). We read the browser's OWN headless UA and strip only the "Headless"
// token, then apply it via Playwright's `userAgent` option — which overrides at
// the CDP layer, so `navigator.userAgent` still reports [native code] (not a
// detectable JS patch) and Sec-CH-UA / userAgentData stay consistent. Verified:
// after this, every request header and JS surface matches a headed Chrome.
//
// The value is resolved once per process by a minimal throwaway launch (~0.5s,
// no profile, no navigation) and memoized. Only headless launches pay it;
// headed launches already report a clean UA. On any probe failure we fall back
// to the unmodified UA rather than break the launch.
let headlessUserAgentPromise = null;
async function resolveHeadlessUserAgent() {
  if (!headlessUserAgentPromise) {
    headlessUserAgentPromise = (async () => {
      const chromium = await loadChromium();
      const browser = await chromium.launch({
        channel: "chrome",
        headless: true,
        ignoreDefaultArgs: ["--no-sandbox"],
        args: ["--test-type"],
      });
      try {
        const page = await browser.newPage();
        const ua = await page.evaluate(() => navigator.userAgent);
        // Strip the token: "HeadlessChrome/149…" → "Chrome/149…". No-op if the
        // build already reports a clean UA (nothing to normalize).
        return /Headless/i.test(ua) ? ua.replace(/Headless/gi, "") : null;
      } finally {
        await browser.close();
      }
    })().catch(() => null);
  }
  return headlessUserAgentPromise;
}

// Launch a persistent context on the given (already-unsealed) profile dir.
// headless defaults to true; pass false for the one-time headed login.
// `contextOptions` merges extra Playwright context options (e.g. the access
// guard's serviceWorkers:"block" for read-only profiles).
export async function launchContext({ profileDir, headless = true, contextOptions = {} }) {
  const chromium = await loadChromium();
  const opts = { ...launchOptions(headless), ...contextOptions };
  // Headless only: normalize the "HeadlessChrome" UA to match a headed browser.
  // A caller-supplied userAgent (contextOptions) wins.
  if (headless && opts.userAgent == null) {
    const ua = await resolveHeadlessUserAgent();
    if (ua) opts.userAgent = ua;
  }
  return chromium.launchPersistentContext(profileDir, opts);
}
