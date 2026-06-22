// Alien Agent ID — Hardened browser launcher (patchright).
//
// patchright is a stealth-patched Playwright drop-in. The launch config below
// is the one validated to pass Google's interactive-login wall while keeping the
// renderer sandbox ON:
//
//   channel: "chrome"             → drive the user's installed Chrome (no bundled
//                                   Chromium download; more realistic fingerprint)
//   ignoreDefaultArgs:["--no-sandbox"] → patchright injects --no-sandbox by
//                                   default; we strip it so the renderer sandbox
//                                   stays on (critical when driving arbitrary
//                                   sites with a live session in the profile)
//   args:["--test-type"]          → suppress Chrome's "unsupported flag" banner
//                                   (the load-bearing stealth flag,
//                                   --disable-blink-features=AutomationControlled,
//                                   which hides navigator.webdriver, otherwise
//                                   triggers it). --enable-automation is NOT used,
//                                   since it re-exposes automation to detection.
//   viewport: null                → real window size, not a scripted viewport.
//
// patchright is an optional dependency: it is dynamically imported so the rest of
// the agent-id toolchain installs and runs without it. Browser mode needs it.

export async function loadChromium() {
  try {
    const mod = await import("patchright");
    return mod.chromium;
  } catch {
    const err = new Error(
      "patchright is not installed. Browser mode needs it:\n" +
        "  cd plugins/agent-id-browser && npm install\n" +
        "It drives your installed Chrome via channel=\"chrome\" (no extra browser download).",
    );
    err.code = "PATCHRIGHT_MISSING";
    throw err;
  }
}

function launchOptions(headless) {
  return {
    channel: "chrome",
    headless,
    viewport: null,
    ignoreDefaultArgs: ["--no-sandbox"],
    args: ["--test-type"],
  };
}

// Launch a persistent context on the given (already-unsealed) profile dir.
// headless defaults to true; pass false for the one-time headed login.
export async function launchContext({ profileDir, headless = true }) {
  const chromium = await loadChromium();
  return chromium.launchPersistentContext(profileDir, launchOptions(headless));
}
