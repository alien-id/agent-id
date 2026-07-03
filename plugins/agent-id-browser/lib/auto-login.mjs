// Alien Agent ID — auto-login engine.
//
// Drives the sealed browser through a service's login form using a stored `login`
// credential (username + password, + a 2FA policy), so an agent can establish an
// authenticated session where no full desktop browser is on hand. A 2FA step is
// answered either from a stored TOTP seed (`otp: "totp"`) or by asking the human
// for the current code over the abstracted secure-prompt channel
// (`otp: "interactive"`) — the same channel used to enter the credential.
//
// Two ways to locate the form fields:
//   - recipe: an explicit, reliable list of steps (the same action vocabulary as
//     the interactive session: navigate/fill/click/press/type/wait) with runtime
//     placeholders {username}/{password}/{otp}. The recommended path for anything
//     beyond a trivial form (multi-step IdPs, etc.).
//   - heuristic: a best-effort default — fill a password field and the nearest
//     username/email field, submit. Targets simple single/two-step forms; big-IdP
//     SSO (Google/Microsoft) should be bootstrapped once via the headed `login`.
//
// The password is typed by this (vault-unlocked) process straight into the page —
// the same trust boundary as the proxy injecting `basic`; the agent never sees it.
//
// The browser-driving functions take a `page` object (a patchright Page), so the
// pure pieces (applyVars / stepNeedsOtp / runRecipe / resolveOtp-totp) unit-test
// against a stub page with no real browser.

import { generateTotp } from "@alien-id/agent-id-core/lib/totp.mjs";
import { collectSecret } from "@alien-id/agent-id-core/lib/secure-prompt.mjs";
import { classifyLogin } from "./login-detect.mjs";
import { humanClick, humanDriver, humanType } from "./human-input.mjs";

// Type a secret (password / OTP) with human cadence, guarding against a
// keyboard/fill error that could echo the value — auto-login errors propagate to
// the agent, so the raw error must never carry the secret. Mirrors the
// session-server fill-secret guard.
async function typeSecret(page, selector, value, opts = {}) {
  try {
    await humanType(page, selector, value, opts);
  } catch {
    throw new Error(`could not type into "${selector}" — element not visible/editable`);
  }
}

const PLACEHOLDER_FIELDS = ["url", "value", "text", "selector", "key"];

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

// Scheme+host origin of a URL (e.g. "https://www.reddit.com"), or null.
export function originOf(url) {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

// Is the login URL a DEEP link (a real path like /login) rather than the bare
// origin root? A warmup navigation only helps for deep links — if the login URL
// is already the root there is nothing to warm up first.
export function isDeepLoginUrl(url) {
  try {
    const u = new URL(url);
    return u.pathname !== "/" && u.pathname !== "";
  } catch {
    return false;
  }
}

// A URL path segment that names a login / auth / challenge step. Matched against
// whole segments (so "/authors/x" is NOT login-ish, but "/login/" and
// "/oauth2/authorize" are) to keep the "still on the login page" check precise.
const LOGIN_SEGMENT_RE = /^(log[-_]?in|sign[-_]?in|signin|auth|authorize|sso|oauth2?|challenge|checkpoint|verify)$/i;

export function isLoginishPath(pathname) {
  return String(pathname || "")
    .split("/")
    .some((seg) => LOGIN_SEGMENT_RE.test(seg));
}

// Are we still sitting on the login/auth host+path after the form cleared? A real
// login LEAVES the login page (redirect to the app/feed). If the password field
// merely vanished while we're still on a login-ish path — an SPA re-render, or a
// redirect into a bot-challenge wall like Reddit's /login?...js_challenge — that
// is NOT a completed login, and sealing it yields a session with no auth cookie.
// This is the positive-confirmation backstop for "logged-in" (paired with the
// "blocked" classifier, which catches walls that carry visible block copy).
export function stillOnLoginPage(currentUrl, loginUrl) {
  let cur, login;
  try {
    cur = new URL(currentUrl);
  } catch {
    return false;
  }
  try {
    login = new URL(loginUrl);
  } catch {
    return false;
  }
  // Left the auth host entirely → definitely progressed.
  if (cur.hostname !== login.hostname) return false;
  // Same host: only "stuck" if we're on a login-ish path.
  return isLoginishPath(cur.pathname);
}

// Substitute {username}/{password}/{otp} in a string. Pure.
export function applyVars(str, vars = {}) {
  if (typeof str !== "string") return str;
  return str
    .replaceAll("{username}", vars.username ?? "")
    .replaceAll("{password}", vars.password ?? "")
    .replaceAll("{otp}", vars.otp ?? "");
}

// Does this recipe step reference {otp} anywhere (so we must resolve a code)? Pure.
export function stepNeedsOtp(step) {
  return PLACEHOLDER_FIELDS.some(
    (k) => typeof step[k] === "string" && step[k].includes("{otp}"),
  );
}

/**
 * Execute recipe `steps` against a page. `{otp}` is resolved lazily via `getOtp()`
 * the first time a step needs it (so a recipe whose login fails before the OTP
 * step never prompts). Actions: navigate, fill, type, click, press, wait.
 */
// `driver` maps the action vocabulary to page interactions; it defaults to the
// human-input driver (curved motion, key-by-key typing) and is injectable so the
// mapping/{otp}-lazy-resolution logic unit-tests without a browser.
export async function runRecipe(
  page,
  steps,
  { username, password, getOtp, driver = humanDriver },
) {
  let otp;
  const sub = async (s) => {
    if (typeof s !== "string") return s;
    if (s.includes("{otp}") && otp === undefined) otp = await getOtp();
    return applyVars(s, { username, password, otp });
  };
  // A step whose template injects the password/otp must never surface the raw
  // value in an error (the recipe path is otherwise unguarded, unlike the
  // heuristic/Microsoft fills). Run it under a value-free catch.
  const carriesSecret = (tpl) =>
    typeof tpl === "string" && (tpl.includes("{password}") || tpl.includes("{otp}"));
  const guarded = async (tpl, run) => {
    if (!carriesSecret(tpl)) return run();
    try {
      return await run();
    } catch {
      throw new Error(`recipe step '${tpl}' failed while entering a secret value`);
    }
  };
  for (const step of steps) {
    switch (step.action) {
      case "navigate":
        await driver.navigate(page, await sub(step.url));
        break;
      case "fill":
        await guarded(step.value, async () =>
          driver.fill(page, await sub(step.selector), await sub(step.value)),
        );
        break;
      case "type": // alias of fill (kept for parity with the session vocabulary)
        await guarded(step.text, async () =>
          driver.type(page, await sub(step.selector), await sub(step.text)),
        );
        break;
      case "click":
        await driver.click(page, await sub(step.selector));
        break;
      case "press":
        await driver.press(page, await sub(step.selector), step.key || "Enter");
        break;
      case "wait":
        await driver.wait(page, Number(step.ms) || 1000);
        break;
      default:
        throw new Error(`unknown recipe action: ${step.action}`);
    }
  }
}

// Resolve the current 2FA code for a `login` credential: generate it from a stored
// seed, or ask the human over the secure-prompt channel.
export async function resolveOtp(cred, { env = process.env, log = () => {}, now } = {}) {
  if (cred.otp === "totp") {
    if (!cred.totpSecret) throw new Error(`login '${cred.name}': otp=totp but no totpSecret stored`);
    return generateTotp({
      secret: cred.totpSecret,
      period: cred.period,
      digits: cred.digits,
      algorithm: cred.algorithm,
      ...(now != null ? { now } : {}),
    });
  }
  log("Waiting for the current 2FA code via the secure prompt…");
  const { values } = await collectSecret(
    {
      title: `2FA code for ${cred.name}`,
      description: cred.loginUrl ? `Sign-in to ${hostOf(cred.loginUrl)} needs your current code` : "",
      fields: [{ name: "otp", label: "Current 2FA code" }],
      label: `enter the 2FA code for "${cred.name}"`,
      security: "Used once to complete sign-in; never stored or shown to the agent.",
      timeoutMs: 5 * 60 * 1000,
    },
    { env },
  );
  return String(values.otp || "").trim();
}

// A visible CAPTCHA / anti-automation challenge WIDGET, matched by well-known
// vendor markers rather than page copy — so it flags a challenge wall no matter
// what language the page is in (the text classifier is inherently localized; a
// datacenter host gets pages in the region's language). LinkedIn's post-login
// checkpoint embeds an Arkose FunCaptcha; reCAPTCHA/hCaptcha/PerimeterX are the
// other common ones. An automated login can't solve any of these, so a VISIBLE
// one means "blocked" (the caller advises a one-time headed login). We match only
// the interactive widgets — NOT reCAPTCHA v3's always-present `.grecaptcha-badge`
// — and require visibility, so a routine invisible token doesn't trip it.
// Exported for tests.
export const CHALLENGE_WIDGET_SEL = [
  'iframe[src*="captcha" i]',
  'iframe[src*="arkoselabs" i]',
  'iframe[src*="funcaptcha" i]',
  'iframe[title*="captcha" i]',
  'iframe[title*="challenge" i]',
  ".g-recaptcha",
  ".h-captcha",
  "#px-captcha",
  '[id*="arkose" i]',
  '[class*="arkose" i]',
].join(",");

// Snapshot the page into the shape classifyLogin expects (browser-side).
async function detectPageState(page) {
  return page.evaluate((challengeSel) => {
    const all = (sel) => Array.from(document.querySelectorAll(sel));
    const visible = (e) => !!(e.offsetParent !== null || e.getClientRects().length);
    const hasPasswordField = all('input[type="password"]').some(visible);
    const hasOtpField = all('input[autocomplete="one-time-code"]').some(visible);
    const otpFieldNames = all(
      'input[type="text"],input[type="tel"],input[type="number"],input[inputmode="numeric"]',
    )
      .map((e) => `${e.name || ""} ${e.id || ""} ${e.placeholder || ""} ${e.autocomplete || ""}`.trim())
      .filter(Boolean);
    const bodyText = (document.body && document.body.innerText ? document.body.innerText : "").slice(0, 4000);
    // Language-independent block signal: a visible challenge widget. Fed to
    // classifyLogin via its `blocked` input so it wins over "logged-in".
    const blocked = all(challengeSel).some(visible);
    return { hasPasswordField, hasOtpField, otpFieldNames, bodyText, blocked };
  }, CHALLENGE_WIDGET_SEL);
}

// Best-effort fill of the OTP field, then submit.
async function typeOtp(page, code) {
  const sel =
    'input[autocomplete="one-time-code"], input[name*="otp" i], input[id*="otp" i], ' +
    'input[name*="code" i], input[id*="code" i], input[name*="verif" i], input[id*="verif" i], ' +
    'input[inputmode="numeric"]';
  // The OTP code is low-sensitivity (single-use, seconds-lived) but still typed
  // with human cadence and the value-free error guard, for consistency.
  await typeSecret(page, sel, code);
  // ADFS / Entra submit via a button; generic forms submit on Enter.
  if (await page.locator("#submitButton").count()) {
    await humanClick(page, "#submitButton").catch(() => {});
  } else if (await page.locator("#idSubmit_SAOTCC_Continue").count()) {
    await humanClick(page, "#idSubmit_SAOTCC_Continue").catch(() => {});
  } else {
    await page.locator(sel).first().press("Enter").catch(() => {});
  }
}

// ── Microsoft ADFS / Entra (Azure AD) driver ──────────────────────────────────
// ADFS and Entra forms use stable element IDs across every deployment/theme, so
// one driver serves any service fronted by them (the heuristic can't, because the
// real password field is hidden behind a "Next" step and a JS-driven submit span).

async function detectMicrosoftFlow(page) {
  return page
    .evaluate(() => {
      if (document.getElementById("userNameInput") && document.getElementById("submitButton")) {
        return "adfs";
      }
      if (document.querySelector('input[name="loginfmt"]')) return "entra";
      return null;
    })
    .catch(() => null);
}

async function clickIfPresent(page, selector) {
  const loc = page.locator(selector).first();
  if (await loc.count()) {
    await humanClick(page, selector, { timeout: 8000 }).catch(() => {});
    return true;
  }
  return false;
}

// Fill a field with human cadence once it's visible. `secret:true` routes through
// the value-free error guard (for passwords).
async function fillWhenVisible(page, selector, value, { timeout = 15000, secret = false } = {}) {
  await page.waitForSelector(selector, { state: "visible", timeout }).catch(() => {});
  if (secret) await typeSecret(page, selector, value, { timeout });
  else await humanType(page, selector, value, { timeout });
}

// Drive a Microsoft ADFS or Entra forms login: username → (Next) → password →
// Sign in. The 2FA step, if any, is then handled by the generic OTP loop in
// autoLogin (stored seed or the secure prompt). Verified against ADFS; Entra is
// best-effort by the same well-known selectors.
export async function microsoftLogin(page, cred, log = () => {}) {
  const flow = await detectMicrosoftFlow(page);
  if (flow === "entra") {
    log("Detected Microsoft Entra (Azure AD) login");
    await fillWhenVisible(page, 'input[name="loginfmt"]', cred.username);
    await clickIfPresent(page, "#idSIButton9"); // Next
    await fillWhenVisible(page, 'input[name="passwd"]', cred.password, { secret: true });
    await clickIfPresent(page, "#idSIButton9"); // Sign in
    return;
  }
  log("Detected Microsoft ADFS login");
  await fillWhenVisible(page, "#userNameInput", cred.username);
  // Paginated ADFS: a "Next" button reveals the password page.
  if (await page.locator("#nextButton").count()) await clickIfPresent(page, "#nextButton");
  await fillWhenVisible(page, "#passwordInput", cred.password, { secret: true });
  const kmsi = page.locator("#kmsiInput"); // "keep me signed in", if offered
  if (await kmsi.count()) await kmsi.check().catch(() => {});
  await clickIfPresent(page, "#submitButton");
}

export { detectMicrosoftFlow };

// Heuristic fallback: fill a username/email field and the password field, submit.
// Handles a simple two-step flow (username page → password page).
async function heuristicLogin(page, { username, password }) {
  const userSel =
    'input[type="email"], input[name*="user" i], input[name*="email" i], ' +
    'input[id*="user" i], input[id*="email" i], input[autocomplete="username"], input[type="text"]';
  const pwSel = 'input[type="password"]';

  const fillFirst = async (sel, value, secret = false) => {
    const loc = page.locator(sel).first();
    if ((await loc.count()) === 0) return false;
    if (!(await loc.isVisible().catch(() => false))) return false;
    if (secret) await typeSecret(page, sel, value);
    else await humanType(page, sel, value);
    return true;
  };

  await fillFirst(userSel, username);
  // If the password field isn't on this page yet, advance (two-step IdP) and retry.
  if ((await page.locator(pwSel).count()) === 0) {
    await page.keyboard.press("Enter").catch(() => {});
    await page.waitForTimeout(1500);
  }
  const filledPw = await fillFirst(pwSel, password, true);
  if (filledPw) await page.locator(pwSel).first().press("Enter").catch(() => {});
}

/**
 * Drive a full auto-login against `cred` (a `login` record). Returns
 * { ok, outcome, finalUrl }. Does NOT seal the profile — the caller does that
 * after closing the context. `page` is a patchright Page.
 */
export async function autoLogin({
  page,
  cred,
  env = process.env,
  log = () => {},
  maxRounds = 6,
  settleMs = 1500,
}) {
  if (!cred.loginUrl) throw new Error(`login '${cred.name}': loginUrl is required for auto-login`);
  const getOtp = () => resolveOtp(cred, { env, log });

  // Warm up before a deep login link. Some sites (e.g. Reddit) wall a COLD
  // deep-link straight to /login with a "blocked by network security" bot block,
  // but let it through once the ORIGIN has loaded and the anti-bot's clearance
  // cookie is set — which is how a human arrives (homepage → click "Log in"), not
  // by cold deep-link. General + best-effort: one harmless extra navigation for
  // sites without such a wall, skipped when the login URL is already the origin
  // root or when the credential opts out with `warmup: false`. The clearance
  // applies on the NEXT navigation, so we deliberately don't inspect this page —
  // the origin itself may still show the block while the cookie is being set.
  const origin = originOf(cred.loginUrl);
  if (origin && isDeepLoginUrl(cred.loginUrl) && cred.warmup !== false) {
    log("auto-login: warming up via the site origin before the login page");
    try {
      await page.goto(origin, { waitUntil: "domcontentloaded", timeout: 30000 });
      await page.waitForTimeout(Math.max(settleMs * 2, 4000));
    } catch {
      /* warmup is best-effort — proceed to the login URL regardless */
    }
  }

  await page.goto(cred.loginUrl, { waitUntil: "domcontentloaded", timeout: 30000 });
  await page.waitForTimeout(settleMs);

  if (Array.isArray(cred.recipe) && cred.recipe.length) {
    await runRecipe(page, cred.recipe, { username: cred.username, password: cred.password, getOtp });
  } else if (await detectMicrosoftFlow(page)) {
    // Microsoft ADFS / Entra: stable element IDs the heuristic can't drive.
    await microsoftLogin(page, cred, log);
  } else {
    await heuristicLogin(page, cred);
  }
  await page.waitForTimeout(settleMs);

  for (let round = 0; round < maxRounds; round++) {
    const outcome = classifyLogin(await detectPageState(page));
    log(`auto-login: ${outcome}`);
    // A bot-block / human-verification wall never clears by waiting — stop and
    // report it (the caller advises a headed login, which a human can clear).
    if (outcome === "blocked") return { ok: false, outcome: "blocked", finalUrl: page.url() };
    if (outcome === "logged-in") {
      // Positive confirmation: the form is gone AND we've left the login page.
      // Without this, a vanished password field on a block/challenge or SPA
      // re-render sealed an unauthenticated session while reporting success.
      if (!stillOnLoginPage(page.url(), cred.loginUrl)) {
        return { ok: true, outcome, finalUrl: page.url() };
      }
      log("auto-login: form cleared but still on the login page — awaiting redirect");
    } else if (outcome === "failed") {
      return { ok: false, outcome, finalUrl: page.url() };
    } else if (outcome === "otp-required") {
      if (cred.otp === "none") {
        return { ok: false, outcome: "otp-unexpected", finalUrl: page.url() };
      }
      await typeOtp(page, await getOtp());
      await page.waitForTimeout(settleMs);
      continue;
    }
    await page.waitForTimeout(settleMs); // unknown / unconfirmed — settle, re-check
  }
  return { ok: false, outcome: "timeout", finalUrl: page.url() };
}
