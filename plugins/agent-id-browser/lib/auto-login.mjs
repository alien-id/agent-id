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
// Recipes are authored by the agent from page content, so two things are checked
// against the credential's `domains`: every navigation target, and the live origin
// of every step that resolves {password} or {otp} — the latter twice, before and
// after the value is resolved, because resolving it can await a human for minutes.
// A step whose value is a literal string is NOT gated; nothing secret is at stake
// in one. Without this a recipe could navigate anywhere and type a secret into it,
// which is a credential-exfiltration primitive driven by whatever the page said.
// `domains` is therefore load-bearing for `login`, not advisory — and editable
// after the fact with `agent-id-vault set-domains`, since a sign-in only reveals
// which hosts it needs once it has been driven.
//
// The browser-driving functions take a `page` object (a patchright Page), so the
// pure pieces (applyVars / stepNeedsOtp / runRecipe / resolveOtp-totp) unit-test
// against a stub page with no real browser.

import { generateTotp } from "@alien-id/agent-id-core/lib/totp.mjs";
import { collectSecret } from "@alien-id/agent-id-core/lib/secure-prompt.mjs";
import { notifyHost } from "@alien-id/agent-id-core/lib/notice.mjs";
import { assertHostAllowed } from "@alien-id/agent-id-vault/lib/store.mjs";
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

// Does this step resolve a secret value anywhere in it? Every placeholder field is
// substituted, so a {password}/{otp} in `selector` reaches the page as surely as
// one in `value`. Pure.
function stepCarriesSecret(step) {
  return PLACEHOLDER_FIELDS.some(
    (k) =>
      typeof step?.[k] === "string" &&
      (step[k].includes("{password}") || step[k].includes("{otp}")),
  );
}

/**
 * Execute recipe `steps` against a page. `{otp}` is resolved lazily via `getOtp()`
 * the first time a step needs it (so a recipe whose login fails before the OTP
 * step never prompts). Actions: navigate, fill, type, click, press, wait.
 *
 * `domains` is the credential's allowlist and is required: every navigation
 * target, and the live origin of every step that types {password} or {otp}, is
 * checked against it before the step runs.
 */
// `driver` maps the action vocabulary to page interactions; it defaults to the
// human-input driver (curved motion, key-by-key typing) and is injectable so the
// mapping/{otp}-lazy-resolution logic unit-tests without a browser.
export async function runRecipe(
  page,
  steps,
  { username, password, getOtp, domains, driver = humanDriver },
) {
  if (!Array.isArray(domains)) {
    throw new Error("runRecipe requires the credential's `domains` allowlist");
  }
  let otp;
  const sub = async (s) => {
    if (typeof s !== "string") return s;
    if (s.includes("{otp}") && otp === undefined) otp = await getOtp();
    return applyVars(s, { username, password, otp });
  };
  // A step whose template injects the password/otp must never surface the raw
  // value in an error. Run it under a value-free catch.
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
  // Refuse a secret-bearing step on an origin the credential was never scoped to.
  // Called TWICE per step, and both calls earn their place: once before `sub`, so
  // a step we are going to refuse never costs the owner a card; once after,
  // because resolving {otp} awaits a human for up to ten minutes and the page is
  // free to navigate in that window — the second call is what actually confines
  // the secret. Checked per STEP, not per field: `selector` is substituted too.
  const gateSecret = (step, where) => {
    if (stepCarriesSecret(step)) {
      assertHostAllowed(hostOf(page.url()), domains, `${where}: refusing`);
    }
  };
  for (const step of steps) {
    switch (step.action) {
      case "navigate": {
        // A sign-in never needs a secret in a URL, and allowing one would be the
        // exfiltration channel this gate exists to close — refuse before `sub`
        // can resolve it.
        if (stepCarriesSecret(step)) {
          throw new Error("recipe navigate: a URL must not carry {password} or {otp}");
        }
        const url = await sub(step.url);
        assertHostAllowed(hostOf(url), domains, "recipe navigate: refusing");
        await driver.navigate(page, url);
        break;
      }
      // Each of the four below resolves its values FIRST, re-checks the origin, and
      // only then touches the page. The order is the point: `sub` can block on the
      // owner for minutes, so the origin that mattered at the top of the step is
      // not necessarily the one the value would land on.
      case "fill": {
        gateSecret(step, "recipe fill");
        const selector = await sub(step.selector);
        const value = await sub(step.value);
        gateSecret(step, "recipe fill");
        await guarded(step.value, () => driver.fill(page, selector, value));
        break;
      }
      case "type": {
        // alias of fill (kept for parity with the session vocabulary)
        gateSecret(step, "recipe type");
        const selector = await sub(step.selector);
        const text = await sub(step.text);
        gateSecret(step, "recipe type");
        await guarded(step.text, () => driver.type(page, selector, text));
        break;
      }
      case "click": {
        gateSecret(step, "recipe click");
        const selector = await sub(step.selector);
        gateSecret(step, "recipe click");
        await driver.click(page, selector);
        break;
      }
      case "press": {
        gateSecret(step, "recipe press");
        const selector = await sub(step.selector);
        gateSecret(step, "recipe press");
        await driver.press(page, selector, step.key || "Enter");
        break;
      }
      case "wait":
        await driver.wait(page, Number(step.ms) || 1000);
        break;
      default:
        throw new Error(`unknown recipe action: ${step.action}`);
    }
  }
}

// What the code card says. On a passwordless login the code is the FIRST and only
// factor, not a second one — a card headed "2FA code" would be telling the owner
// something untrue about the account they are signing into. Pure; exported so the
// wording is testable without standing up a prompt provider.
export function otpPromptWording(cred) {
  const host = cred.loginUrl ? hostOf(cred.loginUrl) : "";
  if (cred.passwordless) {
    return {
      title: `Sign-in code for ${cred.name}`,
      description: host ? `${host} just sent you a code — enter it to finish signing in` : "",
      label: "Sign-in code",
      ask: `enter the sign-in code for "${cred.name}"`,
    };
  }
  return {
    title: `2FA code for ${cred.name}`,
    description: host ? `Sign-in to ${host} needs your current code` : "",
    label: "Current 2FA code",
    ask: `enter the 2FA code for "${cred.name}"`,
  };
}

// Resolve the one-time code for a `login` credential: generate it from a stored
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
  const wording = otpPromptWording(cred);
  log(`Waiting for the ${wording.label.toLowerCase()} via the secure prompt…`);
  const { values } = await collectSecret(
    {
      title: wording.title,
      description: wording.description,
      fields: [{ name: "otp", label: wording.label }],
      label: wording.ask,
      security: "Used once to complete sign-in; never stored or shown to the agent.",
      // A mailed code costs a trip to another app and back, so the card outlives
      // the 5 minutes a TOTP app needs. The ceiling is the host's, not ours: the
      // lethe hub expires a pending request at 15 minutes and kills this process
      // at 16, which is also why one run only ever asks once (see maxOtpAsks).
      timeoutMs: 10 * 60 * 1000,
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
// What a sign-in asks for FIRST, as a selector. Phone-first flows (Airbnb, Uber,
// Telegram) are as common as e-mail-first ones, and omitting the `tel` forms made
// their opening screen — no password field, no code copy — read as a finished
// login. A code input that merely uses type="tel" for the numeric keypad is not
// mistaken for an identifier: classifyLogin checks the code affordances first.
//
// Module-level and passed into the page like CHALLENGE_WIDGET_SEL, because a
// function handed to page.evaluate cannot close over anything.
const IDENTIFIER_FIELD_SEL = [
  'input[type="email"]',
  'input[type="tel"]',
  'input[autocomplete="username"]',
  'input[autocomplete="email"]',
  'input[autocomplete="tel"]',
  'input[autocomplete="tel-national"]',
].join(",");

export async function detectPageState(page) {
  return page.evaluate(([challengeSel, identifierSel]) => {
    const all = (sel) => Array.from(document.querySelectorAll(sel));
    const visible = (e) => !!(e.offsetParent !== null || e.getClientRects().length);
    const hasPasswordField = all('input[type="password"]').some(visible);
    const hasIdentifierField = all(identifierSel).some(visible);
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
    // The page's own error/alert copy, surfaced verbatim in a failure report so
    // a rejection the classifier cannot read is still visible to the caller.
    const errorText =
      all('[role="alert"], [aria-live="assertive"], [class*="error" i], [class*="alert" i], [class*="invalid" i]')
        .filter(visible)
        .map((e) => (e.innerText || "").trim())
        .filter(Boolean)
        .join(" | ")
        .slice(0, 300) || null;
    return {
      hasPasswordField,
      hasIdentifierField,
      hasOtpField,
      otpFieldNames,
      bodyText,
      blocked,
      errorText,
    };
  }, [CHALLENGE_WIDGET_SEL, IDENTIFIER_FIELD_SEL]);
}

// One line of page state for the trace: what the classifier saw, never any
// secret (field values are not read).
function describeState(s) {
  const bits = [`pw=${s.hasPasswordField ? "visible" : "gone"}`];
  if (s.hasOtpField) bits.push("otp-field");
  if (s.blocked) bits.push("challenge-widget");
  if (s.errorText) bits.push(`error="${s.errorText.slice(0, 120)}"`);
  return bits.join(" ");
}

// Best-effort fill of the OTP field, then submit.
async function typeOtp(page, code) {
  const sel =
    'input[autocomplete="one-time-code"], input[name*="otp" i], input[id*="otp" i], ' +
    'input[name*="code" i], input[id*="code" i], input[name*="verif" i], input[id*="verif" i], ' +
    'input[inputmode="numeric"]';
  // The OTP code is low-sensitivity (single-use, seconds-lived) but still typed
  // with human cadence and the value-free error guard, for consistency.
  const before = page.url();
  await typeSecret(page, sel, code);
  // Many code screens submit themselves the moment the last box is filled. Then
  // there is nothing left to click, and hunting for a button on the page we just
  // landed on costs a full element-wait per candidate.
  if (page.url() !== before) return;
  await submitCode(page, sel);
}

// Buttons that advance a code screen, by their visible text. Deliberately excludes
// the ones that undo the step — "resend", "send again", "use another method",
// "back" — because clicking one of those discards a code the owner just typed.
// Every probe in submitCode is bounded: the page may have navigated out from under
// us the instant the code completed, and a missing control must cost a beat rather
// than the 30s default element wait, ten times over.
const SUBMIT_TIMEOUT = 3000;

export const CODE_SUBMIT_TEXT_RE =
  /^(verify|verify code|continue|submit|confirm|next|done|sign ?in|log ?in|check code)$/i;

// Get a typed code accepted. Enter alone is not enough: Chrome only submits a form
// implicitly when it has a submit button or a single field, and a code screen built
// from six one-character boxes has neither — so on those the code sat there, typed
// and unsent, until auto-login ran out of rounds. Found driving a real browser.
async function submitCode(page, fieldSel) {
  // Vendor-specific first: these have stable ids and no useful text.
  for (const known of ["#submitButton", "#idSubmit_SAOTCC_Continue"]) {
    const button = page.locator(known).first();
    if ((await button.count()) && (await button.isVisible().catch(() => false))) {
      await humanClick(page, known, { timeout: SUBMIT_TIMEOUT }).catch(() => {});
      return;
    }
  }
  // A real submit control belonging to the code field's OWN form. Page-wide would
  // hand the click to a header search box or a newsletter footer, and the label
  // branch below would never run.
  const SUBMIT_SEL = 'button[type="submit"], input[type="submit"]';
  const ownForm = page.locator(fieldSel).first().locator("xpath=ancestor::form[1]");
  const ownSubmit = ownForm.locator(SUBMIT_SEL).first();
  if ((await ownSubmit.count()) && (await ownSubmit.isVisible().catch(() => false))) {
    await ownSubmit.click({ timeout: SUBMIT_TIMEOUT }).catch(() => {});
    return;
  }
  // Otherwise a button whose label says it advances. Read the labels rather than
  // guessing selectors — these screens differ everywhere.
  const buttons = page.locator('button, [role="button"], a[href="#"]');
  const count = Math.min(await buttons.count(), 20);
  for (let i = 0; i < count; i++) {
    const button = buttons.nth(i);
    if (!(await button.isVisible().catch(() => false))) continue;
    const label = (
      (await button.textContent({ timeout: SUBMIT_TIMEOUT }).catch(() => "")) || ""
    ).trim();
    if (!CODE_SUBMIT_TEXT_RE.test(label)) continue;
    await humanClick(page, button, { timeout: SUBMIT_TIMEOUT }).catch(() => {});
    return;
  }
  // Nothing to click: a single-field form, or a screen that submits on its own
  // once the last box is filled. Enter is correct for the first and harmless for
  // the second.
  await page
    .locator(fieldSel)
    .first()
    .press("Enter", { timeout: SUBMIT_TIMEOUT })
    .catch(() => {});
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
// Handles a simple two-step flow (username page → password page), and the
// passwordless flow where submitting the identifier is the entire step.
async function heuristicLogin(page, { username, password, passwordless }) {
  // Ordered widest-signal-first, and it must cover everything IDENTIFIER_FIELD_SEL
  // recognises — a screen the classifier calls an identifier step and this cannot
  // fill is a stall, which is what phone-first sign-ins used to do.
  const userSel =
    'input[type="email"], input[type="tel"], input[autocomplete="username"], ' +
    'input[autocomplete="email"], input[autocomplete^="tel"], ' +
    'input[name*="user" i], input[name*="email" i], input[name*="phone" i], ' +
    'input[id*="user" i], input[id*="email" i], input[id*="phone" i], input[type="text"]';
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
  // Passwordless: submitting the identifier IS the whole step — it is what makes
  // the site send the code. Stop here deliberately rather than falling into the
  // password hunt below, which would press Enter a second time and re-submit a
  // form that has already advanced.
  if (passwordless) {
    await page.keyboard.press("Enter").catch(() => {});
    return;
  }
  // If the password field isn't on this page yet, advance (two-step IdP) and retry.
  if ((await page.locator(pwSel).count()) === 0) {
    await page.keyboard.press("Enter").catch(() => {});
    await page.waitForTimeout(1500);
  }
  const filledPw = await fillFirst(pwSel, password, true);
  if (filledPw) await page.locator(pwSel).first().press("Enter").catch(() => {});
}

/**
 * Surface a "confirm on your phone" card once, then wait for the page to move
 * on by itself. Returns true when the challenge cleared, false on timeout.
 *
 * The prompt text is lifted from the page so the card can echo a number-match
 * challenge ("tap 42"), which is useless to the owner if we paraphrase it.
 */
async function awaitDeviceConfirmation(page, cred, { log, settleMs, budgetMs }) {
  const hint = await page
    .evaluate(() => (document.body ? document.body.innerText : ""))
    .catch(() => "");
  const prompt = String(hint)
    .split("\n")
    .map((line) => line.trim())
    .find((line) => /tap (?:yes|\d{1,3})\b|check your phone|sent a (?:notification|prompt)/i.test(line));

  log("auto-login: awaiting device confirmation");
  await notifyHost("browser.confirmation_required", {
    profile: cred.profile || cred.name || null,
    cred: cred.name || null,
    url: page.url(),
    prompt: prompt || null,
    message:
      "Approve the sign-in on your phone to continue. Nothing needs to be typed here.",
  });

  // The card has no natural end: the owner approves on a device the harness
  // cannot see, so without this the "approve on your phone" prompt would sit
  // there after they already did. Mirrors `secure_input.resolved`.
  const resolve = async (outcome) => {
    await notifyHost("browser.confirmation_resolved", {
      profile: cred.profile || cred.name || null,
      cred: cred.name || null,
      outcome,
    });
  };

  const deadline = Date.now() + budgetMs;
  while (Date.now() < deadline) {
    await page.waitForTimeout(settleMs);
    const state = classifyLogin({
      ...(await detectPageState(page)),
      onLoginPage: stillOnLoginPage(page.url(), cred.loginUrl),
    });
    // Anything other than "still asking" ends the wait — including a block or a
    // denial, which the main loop then classifies on its own terms.
    if (state !== "confirm-on-device" && state !== "unknown") {
      await resolve("approved");
      return true;
    }
    if (!stillOnLoginPage(page.url(), cred.loginUrl)) {
      await resolve("approved");
      return true;
    }
  }
  log("auto-login: device confirmation timed out");
  await resolve("timeout");
  return false;
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
  // The identifier step now legitimately spends rounds: a screen asking only for
  // an e-mail or phone classifies as "unknown" until the site advances, where it
  // used to short-circuit to a (wrong) "logged-in" on the first look. Six rounds
  // left ~9s for that transition, which a slow sign-in can outlast.
  maxRounds = 10,
  settleMs = 1500,
  // A device-approval prompt is answered by a human reaching for their phone,
  // so it gets its own budget: the ordinary rounds are far too short, and
  // spending them here would report a timeout while the owner is still walking
  // to the desk.
  confirmWaitMs = 180000,
}) {
  if (!cred.loginUrl) throw new Error(`login '${cred.name}': loginUrl is required for auto-login`);
  // The whole run — warmup, the login page, every recipe step — happens on the
  // credential's own origins. Checked once here so a loginUrl pointing off the
  // allowlist fails before a browser goes anywhere, not after.
  assertHostAllowed(hostOf(cred.loginUrl), cred.domains, "loginUrl: refusing");
  const getOtp = () => resolveOtp(cred, { env, log });
  // How many times one run may answer a code challenge. A stored seed costs
  // nothing to regenerate, so a few attempts are fine there. Asking a HUMAN is
  // bounded by arithmetic, not taste: the card waits up to 10 minutes and the host
  // kills this process at 16 (lethe's HUMAN_TIMEOUT), so a second full-length ask
  // does not fit. One ask, then report it — a fresh auto-login gets a fresh budget
  // and makes the site send a fresh code, which is the better retry anyway.
  const maxOtpAsks = cred.otp === "totp" ? 3 : 1;
  let otpAsks = 0;

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
    await runRecipe(page, cred.recipe, {
      username: cred.username,
      password: cred.password,
      getOtp,
      domains: cred.domains,
    });
  } else if (await detectMicrosoftFlow(page)) {
    // Microsoft ADFS / Entra: stable element IDs the heuristic can't drive.
    await microsoftLogin(page, cred, log);
  } else {
    await heuristicLogin(page, cred);
  }
  await page.waitForTimeout(settleMs);

  let errorText = null;
  for (let round = 0; round < maxRounds; round++) {
    const onLoginPage = stillOnLoginPage(page.url(), cred.loginUrl);
    const state = { ...(await detectPageState(page)), onLoginPage };
    const outcome = classifyLogin(state);
    errorText = state.errorText || errorText;
    log(`auto-login: round ${round + 1}/${maxRounds} ${outcome} (${describeState(state)}) at ${page.url()}`);
    // A bot-block / human-verification wall never clears by waiting — stop and
    // report it (the caller advises a headed login, which a human can clear).
    if (outcome === "blocked") return { ok: false, outcome: "blocked", finalUrl: page.url(), errorText };
    // Neither of these can be finished from here at all: a mailed link
    // authenticates whichever browser the owner opens it in — never this sealed
    // profile — and a QR code is drawn inside a browser they cannot see. There is
    // nothing to type either way, so waiting only burns the budget before
    // reporting a timeout. Name it and let the caller hand the browser over.
    if (outcome === "magic-link" || outcome === "qr-sign-in") {
      return { ok: false, outcome, finalUrl: page.url(), errorText };
    }
    if (outcome === "logged-in") {
      // Never believe it on the first look. A heavy SPA a second into loading has
      // no form, no code and no error, which is indistinguishable from success —
      // caught live on web.whatsapp.com, whose sign-in lives at the origin root so
      // stillOnLoginPage has no login-ish path to catch it with. The classifier
      // cannot tell these apart from text alone (a real signed-in page can be just
      // as terse), but a second look after a settle can: an unrendered page has
      // moved on by then, a signed-in one says the same thing twice.
      if (round === 0) {
        log("auto-login: looks signed in on the first look — settling and re-checking");
        await page.waitForTimeout(settleMs);
        continue;
      }
      // Positive confirmation: the form is gone AND we've left the login page.
      // Without this, a vanished password field on a block/challenge or SPA
      // re-render sealed an unauthenticated session while reporting success.
      if (!onLoginPage) {
        return { ok: true, outcome, finalUrl: page.url() };
      }
      log("auto-login: form cleared but still on the login page — awaiting redirect");
    } else if (outcome === "failed") {
      return { ok: false, outcome, finalUrl: page.url(), errorText };
    } else if (outcome === "confirm-on-device") {
      // Nothing to type: the owner approves on their own device and the page
      // advances by itself. Tell them once, then poll until it does. This is
      // the cheapest challenge to satisfy — unlike a password or a TOTP seed it
      // needs no secret stored anywhere, so it is a good outcome, not a failure.
      const confirmed = await awaitDeviceConfirmation(page, cred, {
        log,
        settleMs,
        budgetMs: confirmWaitMs,
      });
      if (!confirmed) {
        return { ok: false, outcome: "confirm-timeout", finalUrl: page.url() };
      }
      continue;
    } else if (outcome === "otp-required") {
      if (cred.otp === "none") {
        return { ok: false, outcome: "otp-unexpected", finalUrl: page.url() };
      }
      if (otpAsks >= maxOtpAsks) {
        // The site is still asking after we answered. Looping here re-asks the
        // owner for a code the site has already refused once, and each ask is
        // another ten minutes of a budget that does not have them to give.
        // The page's own copy is the diagnosis here — "that code has expired" vs
        // "incorrect code" is the difference between retrying and giving up.
        return { ok: false, outcome: "otp-rejected", finalUrl: page.url(), errorText };
      }
      otpAsks += 1;
      await typeOtp(page, await getOtp());
      await page.waitForTimeout(settleMs);
      continue;
    }
    await page.waitForTimeout(settleMs); // unknown / unconfirmed — settle, re-check
  }
  return { ok: false, outcome: "timeout", finalUrl: page.url(), errorText };
}
