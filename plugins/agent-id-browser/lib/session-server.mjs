// Alien Agent ID — Persistent interactive browser session.
//
// `open` launches the (unsealed) profile under patchright and runs a small
// localhost control server that holds the live context. Fine-grained action
// commands (snapshot/click/type/…) connect to it, so the agent can observe the
// page and act on it across many calls — like Playwright-MCP, but on our
// stealth patchright launch with the profile sealed in the vault.
//
// Observation model (Playwright-MCP style): `snapshot` tags every visible
// interactive element with a `data-aibref="eN"` attribute and returns a flat
// accessibility list [{ref, role, name, …}]. Actions then target an element by
// its ref (resolved to the `[data-aibref="eN"]` selector). Refs are valid until
// the next snapshot / navigation. Elements inside iframes get frame-prefixed
// refs ("f1e3"); the snapshot's frame→prefix map lives in the session state and
// every ref-based action resolves through it.
//
// The session tracks ALL tabs (ctx "page" events): actions run on the CURRENT
// tab, `tabs`/`tab-switch` move between them, and per-page listeners feed the
// console ring buffer, the downloads ledger, and the JS-dialog policy.
//
// Protocol: line-delimited JSON over a 127.0.0.1 TCP socket, gated by a random
// per-session token. Session coordinates live in
// <stateDir>/browser-sessions/<name>.json (0600).

import net from "node:net";
import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";

import { launchContext } from "./launch.mjs";
import { sealProfile } from "./profile-store.mjs";
import { startStreamServer } from "./stream-server.mjs";
import { loadCodecConfig } from "./stream-encoder.mjs";
import {
  openVault,
  loadAgentPrivateKey,
} from "@alien-id/agent-id-vault/lib/vault.mjs";
import {
  SECRET_FIELDS,
  assertHostAllowed,
} from "@alien-id/agent-id-vault/lib/store.mjs";
import {
  otpBoxes,
  otpCardHints,
  otpModeCorrection,
  resolveOtp,
} from "./auto-login.mjs";
import {
  applyAccessGuard,
  assertActionAllowed,
  contextOptionsForAccess,
  guardDecision,
} from "./access-guard.mjs";
import { looksLoggedOut } from "./session.mjs";
import {
  humanClick,
  humanHover,
  humanMove,
  humanScroll,
  humanType,
  typeCodeAcrossBoxes,
  humanTypeFocused,
} from "./human-input.mjs";

function sessionsDir(stateDir) {
  return path.join(stateDir, "browser-sessions");
}
export function sessionFilePath(stateDir, name) {
  return path.join(sessionsDir(stateDir), `${name}.json`);
}

// Is the daemon that wrote a session file still running? Signal 0 delivers
// nothing and only asks the question, and it answers it on every platform we
// run on (a /proc probe does not — desktop is macOS). EPERM means the pid
// exists and belongs to someone else, which still counts as alive.
//
// This is only the cheap first gate. On hosts where the state dir outlives the
// container, a leftover file's pid routinely collides with some unrelated live
// process in the fresh PID namespace — the pid answer alone then calls a dead
// session alive. Callers that must be sure follow up with probeSession().
export function sessionAlive(info) {
  const pid = Number(info?.pid);
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err?.code === "EPERM";
  }
}

// Does the daemon that wrote this session file ANSWER for it? Speaks one line
// of the control protocol — `{token, action: "info"}` — and classifies the
// outcome. Only the daemon that wrote the file holds this token, so `ok: true`
// proves identity where a pid or a connectable port cannot: both are recycled
// by the OS and can belong to a stranger.
//
//   "ours"   — replied ok:true: the session's own daemon.
//   "gone"   — nothing listening, connection dropped, or the token was
//              rejected (a stranger on a recycled port).
//   "unsure" — could not disprove: connected but no reply line in time (a
//              daemon mid-action answers late), or the file predates the
//              control server and carries nothing to speak to.
export function probeSession(info, timeoutMs = 450) {
  return new Promise((resolve) => {
    const port = Number(info?.port);
    if (!Number.isInteger(port) || port <= 0 || !info?.token) return resolve("unsure");
    const sock = net.connect(port, "127.0.0.1");
    let buf = "";
    let settled = false;
    const finish = (verdict) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      sock.destroy();
      resolve(verdict);
    };
    const timer = setTimeout(() => finish("unsure"), timeoutMs);
    sock.on("connect", () => {
      sock.write(JSON.stringify({ token: info.token, action: "info" }) + "\n");
    });
    sock.on("data", (d) => {
      buf += d.toString("utf8");
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      let reply;
      try {
        reply = JSON.parse(buf.slice(0, nl));
      } catch {
        return finish("gone");
      }
      finish(reply?.ok === true ? "ours" : "gone");
    });
    sock.on("error", () => finish("gone"));
    sock.on("close", () => finish("gone"));
  });
}

// Drop session files whose daemon is gone. A clean `close` reseals and removes
// its own file (see finalize), but a killed container — or any abrupt death —
// leaves the file behind while the container's home directory persists. Those
// orphans still advertise a streamPort, so a viewer that picks "the newest
// session" can dial a dead port and show nothing, and `status` reports sessions
// that do not exist. Best effort by design: a file we cannot read or unlink is
// skipped rather than failing the caller's real work. Returns the pruned names.
export async function pruneDeadSessions(stateDir) {
  const pruned = [];
  const live = new Set();
  let entries;
  try {
    entries = await fs.readdir(sessionsDir(stateDir));
  } catch {
    return pruned; // no sessions dir yet
  }
  for (const entry of entries) {
    if (!entry.endsWith(".json")) continue;
    const name = entry.replace(/\.json$/, "");
    const file = path.join(sessionsDir(stateDir), entry);
    try {
      const info = JSON.parse(await fs.readFile(file, "utf8"));
      // The pid gate alone false-positives on recycled pids (see
      // sessionAlive); only a token handshake proves the daemon behind the
      // file is the one answering. "unsure" keeps the file: pruning a LIVE
      // session's registration would orphan its unsealed profile.
      if (sessionAlive(info) && (await probeSession(info)) !== "gone") {
        live.add(name);
        continue;
      }
      await fs.rm(file, { force: true });
      pruned.push(name);
    } catch {
      /* unreadable or already gone — leave it alone */
    }
  }
  // `<name>.work` is the UNSEALED profile — cookies in plaintext, outside the
  // vault. A clean close wipes it; an abrupt death leaves it on disk
  // indefinitely (found weeks-old copies for sessions long gone). Remove the
  // ones whose session is gone, but only once they are old enough that they
  // cannot belong to an open still unsealing into them: the session file is
  // written after the unseal, so a young dir with no session file may be a
  // live launch, not an orphan.
  const STALE_WORK_MS = 60 * 60 * 1000;
  for (const entry of entries) {
    if (!entry.endsWith(".work")) continue;
    const name = entry.replace(/\.work$/, "");
    if (live.has(name)) continue;
    const dir = path.join(sessionsDir(stateDir), entry);
    try {
      const st = await fs.stat(dir);
      if (Date.now() - st.mtimeMs < STALE_WORK_MS) continue;
      await fs.rm(dir, { recursive: true, force: true });
      pruned.push(entry);
    } catch {
      /* gone or unreadable — nothing to do */
    }
  }
  return pruned;
}

// Body of <name>.json. The profile name must ride IN the body, not just the
// filename: viewers discover a session by scanning these files for stream
// coordinates, and a body without `profile` left them picking blind (newest
// startedAt wins) — attaching the watch feed to the wrong profile.
export function sessionRecord(name, fields) {
  return { profile: name, ...fields };
}

// THE SHARED REF SPACE — keep this selector, and the numbering loop that walks
// it, byte-identical in snapshotInPage and formSnapshotInPage.
//
// Both observation modes tag the DOM, and both clear every existing tag first.
// When they numbered over *different* element sets (snapshot: links/buttons/
// inputs; form-inspect: form controls only) the same string meant different
// elements in each: after a form-inspect "e7" was the First Name input, after a
// snapshot it was a toolbar button. Nothing detected the difference, so a
// form-fill using form-inspect refs silently drove the wrong elements — or, if
// the page had also navigated, bounced off a "ref is stale" error whose advice
// ("run form-inspect or snapshot again") pointed at two tools that disagreed.
//
// The fix is to number over the UNION of both selectors, in document order,
// independently of what each mode chooses to report. Numbering therefore does
// NOT skip invisible elements — reporting still does — so ref numbers are
// sparse in the returned list, and stable across modes. These two functions
// cannot share a module constant: page functions are serialised into the page
// and cannot close over module scope. tests/test-browser-ref-space.mjs asserts
// they stay in agreement.
//
// `prefix` namespaces refs per frame: "" for the main frame ("e1", "e2", …),
// "f1" for the first iframe ("f1e1", …) — so a ref is self-describing about
// which frame it lives in.
export function snapshotInPage(arg) {
  const { prefix, generation } = arg && typeof arg === "object" ? arg : { prefix: arg, generation: 0 };
  const pre = `${generation ?? 0}:${prefix || ""}`;
  const SEL = [
    "a[href]", "button", "input:not([type=hidden])", "textarea", "select",
    "[role=button]", "[role=link]", "[role=textbox]", "[role=combobox]",
    "[role=checkbox]", "[role=radio]", "[role=tab]", "[role=menuitem]",
    "[role=option]", "[contenteditable=true]", "summary",
    "[tabindex]:not([tabindex='-1'])",
  ].join(",");
  // Clear refs from a previous snapshot first: forms that swap in place (e.g.
  // multi-step IdP logins) leave stale data-aibref attributes, so a reused ref
  // like "e2" could match BOTH an old hidden element and a new one — and an action
  // would target the wrong (often invisible) element.
  for (const old of document.querySelectorAll("[data-aibref]")) old.removeAttribute("data-aibref");
  const out = [];
  let i = 0;
  const seen = new Set();
  for (const el of document.querySelectorAll(SEL)) {
    if (seen.has(el)) continue;
    seen.add(el);
    // Numbered before the visibility test so the counter tracks the shared ref
    // space rather than this mode's reporting filter.
    const ref = pre + "e" + ++i;
    el.setAttribute("data-aibref", ref);
    const r = el.getBoundingClientRect();
    const st = window.getComputedStyle(el);
    if (r.width === 0 || r.height === 0 || st.visibility === "hidden" || st.display === "none") {
      continue;
    }
    // el.value is a useful *label* only for button-like inputs (submit/button/
    // reset), where the value IS the visible caption. For any text-entry field
    // el.value is user-entered content that could be a secret — OTP/2FA fields
    // are type=text/tel, and a show-password toggle flips a password field to
    // type=text — so never surface it here (a subsequent snapshot would hand the
    // agent a value the vault typed in). Also never surface a field the vault
    // marked tainted ("data-aib-secret" — must match SECRET_TAINT_ATTR).
    // Non-secret values stay readable on demand via `get --what value`.
    const valueLabel =
      el.tagName === "INPUT" &&
      ["submit", "button", "reset"].includes(el.type) &&
      !el.hasAttribute("data-aib-secret")
        ? el.value
        : "";
    const name = (
      el.getAttribute("aria-label") ||
      el.getAttribute("placeholder") ||
      valueLabel ||
      el.innerText ||
      el.getAttribute("title") ||
      el.getAttribute("name") ||
      ""
    ).replace(/\s+/g, " ").trim().slice(0, 100);
    out.push({
      ref,
      role: el.getAttribute("role") || el.tagName.toLowerCase(),
      name,
      ...(el.getAttribute("type") ? { type: el.getAttribute("type") } : {}),
    });
  }
  return { url: location.href, title: document.title, elements: out };
}

// Compact, form-specific observation. Unlike the generic accessibility
// snapshot it includes CSS-hidden checkbox/radio/file inputs because modern
// forms commonly render a styled label over the real control. Values from text
// inputs are deliberately never returned; validation reports lengths/matches,
// not the contents the user or vault supplied.
export function formSnapshotInPage(arg) {
  const { prefix, generation } = arg && typeof arg === "object" ? arg : { prefix: arg, generation: 0 };
  const pre = `${generation ?? 0}:${prefix || ""}`;
  // Identical to snapshotInPage's selector and numbering loop — see the note
  // there. This mode reports only form controls, but it must NUMBER the same
  // union so a ref means the same element in both modes.
  const SEL = [
    "a[href]", "button", "input:not([type=hidden])", "textarea", "select",
    "[role=button]", "[role=link]", "[role=textbox]", "[role=combobox]",
    "[role=checkbox]", "[role=radio]", "[role=tab]", "[role=menuitem]",
    "[role=option]", "[contenteditable=true]", "summary",
    "[tabindex]:not([tabindex='-1'])",
  ].join(",");
  const REPORTED = [
    "input:not([type=hidden])", "textarea", "select", "button",
    "[role=textbox]", "[role=combobox]", "[role=checkbox]", "[role=radio]",
    "[contenteditable=true]",
  ].join(",");
  for (const old of document.querySelectorAll("[data-aibref]")) old.removeAttribute("data-aibref");

  const clip = (value, max = 120) =>
    String(value || "").replace(/\s+/g, " ").trim().slice(0, max);
  const labelledBy = (el) =>
    clip(
      (el.getAttribute("aria-labelledby") || "")
        .split(/\s+/)
        .filter(Boolean)
        .map((id) => document.getElementById(id)?.textContent || "")
        .join(" ")
    );
  const labelOf = (el) => {
    const native = Array.from(el.labels || []).map((label) => label.textContent || "").join(" ");
    const wrapped = el.closest("label")?.textContent || "";
    const legend = el.closest("fieldset")?.querySelector("legend")?.textContent || "";
    return clip(
      el.getAttribute("aria-label") ||
        labelledBy(el) ||
        native ||
        wrapped ||
        el.getAttribute("placeholder") ||
        el.getAttribute("title") ||
        el.getAttribute("name") ||
        legend
    );
  };
  const visibleOf = (el) => {
    const r = el.getBoundingClientRect();
    const st = window.getComputedStyle(el);
    return (
      r.width > 0 &&
      r.height > 0 &&
      st.visibility !== "hidden" &&
      st.display !== "none"
    );
  };
  // Laid out is not the same as being asked for. Booking.com's e-mail step carries
  // a fully styled password input — 162x26, `visibility: visible`, `opacity: 1`,
  // inside the viewport — in an `aria-hidden` wrapper, and an agent that inspected
  // the form read it as "this site wants a password" and stored a credential the
  // site has no use for. `inert` says the same in the modern spelling.
  //
  // The same attribute also masks a whole page behind a modal — a cookie banner, a
  // consent dialog — and there every control under it is wanted, just covered. What
  // separates the two is whether the page is asking for anything ELSE: a staged step
  // sits beside a live field, a masked page has none. Buttons do not count towards
  // that (a dialog's "Accept" would answer for the page it is covering).
  //
  // A staged control moves to `staged`, it is not dropped and it is not left among
  // the fields on offer. Flagging it inside `controls` was read straight past — an
  // agent saw a password entry, said "I saw a technical password field in the
  // markup", and stored a credential the site has no use for. Dropping it was worse:
  // `asksSomethingElse` is satisfied by ANY live input anywhere, so a cookie banner
  // carrying a checkbox took a whole sign-in form out of reach, with no ref left to
  // recover it. A separate list says the same thing without either failure.
  //
  // `detectPageState` in auto-login.mjs carries the same rule. Both run inside the
  // page, so neither can import it; the duplication is the price of that.
  const staged = (el) => !!el.closest('[aria-hidden="true"], [inert]');
  const asksSomethingElse = Array.from(
    document.querySelectorAll(
      'input:not([type="hidden"]):not([type="submit"]):not([type="button"]),select,textarea'
    )
  ).some((el) => visibleOf(el) && !staged(el));
  const stagedOf = (el) => staged(el) && asksSomethingElse;

  const controls = [];
  const stagedControls = [];
  let i = 0;
  const seen = new Set();
  for (const el of document.querySelectorAll(SEL)) {
    if (seen.has(el)) continue;
    seen.add(el);
    // Numbered over the shared union first; only then filtered down to what
    // this mode reports. Numbering must not depend on the filter.
    const ref = pre + "e" + ++i;
    el.setAttribute("data-aibref", ref);
    if (!el.matches(REPORTED)) continue;
    const tag = el.tagName.toLowerCase();
    const type = clip(
      el.getAttribute("type") ||
        (tag === "input"
          ? el.type || "text"
          : tag === "select"
          ? "select"
          : tag),
      40
    ).toLowerCase();
    const laidOut = visibleOf(el);
    const visible = laidOut && !stagedOf(el);
    // Hidden native controls remain actionable through setChecked/setInputFiles.
    if (!laidOut && !["checkbox", "radio", "file"].includes(type)) continue;
    const isStaged = stagedOf(el);
    const form = el.closest("form");
    const role = el.getAttribute("role") || tag;
    const entry = {
      ref,
      role,
      type,
      label: labelOf(el),
      ...(el.getAttribute("name") ? { name: clip(el.getAttribute("name"), 100) } : {}),
      // What a sign-in page states about a field, and the one signal it gives that
      // no wording heuristic can match: `autocomplete="username"` is never a
      // newsletter box.
      ...(el.getAttribute("autocomplete") ? { autocomplete: clip(el.getAttribute("autocomplete"), 40) } : {}),
      ...(el.required ? { required: true } : {}),
      ...(el.disabled || el.getAttribute("aria-disabled") === "true" ? { disabled: true } : {}),
      ...(el.readOnly ? { readonly: true } : {}),
      ...(!laidOut ? { hidden: true } : {}),
      ...(form
        ? {
            form: clip(
              form.getAttribute("name") ||
                form.id ||
                form.getAttribute("action") ||
                "form",
              160
            ),
          }
        : {}),
    };
    if (type === "checkbox" || type === "radio" || role === "checkbox" || role === "radio") {
      entry.checked = el.checked === true || el.getAttribute("aria-checked") === "true";
    }
    if (tag === "select") {
      entry.multiple = !!el.multiple;
      entry.options = Array.from(el.options).slice(0, 100).map((option) => ({
        value: clip(option.value, 160),
        label: clip(option.label || option.textContent, 160),
        ...(option.disabled ? { disabled: true } : {}),
        ...(option.selected ? { selected: true } : {}),
      }));
    }
    if (type === "file") {
      entry.multiple = !!el.multiple;
      if (el.accept) entry.accept = clip(el.accept, 200);
    }
    (isStaged ? stagedControls : controls).push(entry);
  }
  // The conclusion, not the evidence. An agent deciding what kind of credential a
  // site needs was left to infer it from the control list, and inferred wrong on
  // the first real site it met: Booking stages a password on its e-mail screen, and
  // "there is a password control" won over everything else. Saying it outright is
  // what a caller acts on; a flag on one control is something it has to interpret.
  //
  // Only claimed where it means something. An identifier field alone is not a
  // sign-in: a newsletter box in a footer is one, and answering
  // `passwordAsked: false` for it tells the caller a site has no password — the same
  // wrong conclusion from the other end. So a submit in the same form is required,
  // and the identifier has to look like one: `autocomplete` is the strong signal a
  // sign-in page gives, `name` and the label are the fallback, and a search box is
  // excluded by type rather than left to the label to rule out.
  //
  // `passwordAsked` is about what the page ASKS for, so a staged password is not
  // one — the same rule `controls` follows above.
  const identifierish = (c) => {
    if (c.type === "search") return false;
    if (/username|email|tel/i.test(c.autocomplete || "")) return true;
    if (c.type !== "email" && c.type !== "tel" && c.type !== "text") return false;

    return /user|email|e-mail|phone|mobile|login/i.test(`${c.name || ""} ${c.label || ""}`);
  };
  const identifier = controls.find(identifierish);
  const submits = controls.some(
    (c) =>
      (c.type === "submit" || c.role === "button" || c.type === "button") &&
      c.form === identifier?.form
  );
  const signIn =
    identifier && submits
      ? {
          identifier: true,
          passwordAsked: controls.some((c) => c.type === "password"),
        }
      : null;

  return {
    url: location.href,
    title: document.title,
    controls,
    ...(stagedControls.length ? { staged: stagedControls } : {}),
    ...(signIn ? { signIn } : {}),
  };
}

const sel = (ref) => `[data-aibref="${String(ref).replace(/["\\]/g, "")}"]`;
const ACTION_TIMEOUT = 15000;

// How long a session may sit unused (no agent action, no viewer input, nobody
// watching) before it closes itself. Long enough that an owner reading a page
// or stepping away mid-task is not cut off, short enough that a forgotten
// session does not hold a browser for the life of the container. Override with
// AGENT_ID_BROWSER_IDLE_MS; 0 disables.
const DEFAULT_IDLE_MS = 20 * 60_000;
const IDLE_POLL_MS = 30_000;
const MAX_FRAMES = 12; // iframes snapshotted per page (ad-heavy pages have dozens)
const CONSOLE_CAP = 300; // ring-buffer size for captured console/pageerror entries

// "f1e3" → "f1"; plain main-frame refs ("e3") → null. Exported for tests.
// A ref carries the observation it came from: "3:e7", "3:f1e2". The generation
// prefix makes staleness a *synchronous string check* instead of something we
// discover by acting on whatever now happens to hold that number.
//
// Clearing every data-aibref on each scan is not enough on its own: the next
// scan re-tags a possibly different element with the same "e7", so a ref held
// across two observations still resolves — silently, to the wrong element. The
// version prefix is what the agent copies back verbatim, so a ref from an older
// observation is refused by name rather than executed.
export function refGenerationOf(ref) {
  const m = /^(\d+):/.exec(String(ref ?? ""));
  return m ? Number(m[1]) : null;
}

export function frameRefId(ref) {
  const m = /^(?:\d+:)?(f\d+)e\d+$/.exec(String(ref ?? ""));
  return m ? m[1] : null;
}

// A download's suggested filename, made safe to join under the sessions dir
// (no separators / traversal, bounded length). Exported for tests.
export function safeFilename(name) {
  const cleaned = String(name || "").replace(/[^\w.-]+/g, "_").replace(/^\.+/, "");
  return (cleaned || "file").slice(0, 80);
}

// Screenshot pixels → viewport (CSS) pixels. The image is captured at the context's
// devicePixelRatio (retina = 2×); page.mouse takes CSS px, so divide by dpr.
// `--css` skips this (coords already CSS px). Pure — exported for tests.
export function imageToViewport(x, y, dpr) {
  const d = Number(dpr) > 0 ? Number(dpr) : 1;
  return { x: Number(x) / d, y: Number(y) / d };
}

// The live devicePixelRatio (1 when --css). One place for the dpr rule every
// coordinate action shares. Best-effort: a page that can't run JS reports dpr 1.
async function liveDpr(page, css) {
  if (css) return 1;
  return page.evaluate(() => window.devicePixelRatio || 1).catch(() => 1);
}

// The focus-typing actions (`type-text`/`fill-text`) type into whatever is
// focused — they have no ref parameter. Passing one reads as targeting that
// element, so accepting it silently sends the text wherever focus happened to
// be and reports success: observed on an SAP careers form, where "Switzerland"
// typed at a country combobox by ref never reached the filter and the widget
// answered "There were no results". Name the ref-taking tool instead of
// dropping the argument.
export function refuseRef(action, p, alternative) {
  if (p.ref === undefined || p.ref === null || p.ref === "") return;
  throw new Error(
    `${action} types into the FOCUSED element and takes no --ref (got "${p.ref}"). ` +
      `Use \`${alternative}\` to drive an element by ref, or focus it first ` +
      `(click/click-xy) and re-run ${action} without --ref.`
  );
}

// Convert an agent-supplied screenshot pixel to a viewport CSS point, rejecting
// non-numeric coords with an action-specific message.
function toXY(x, y, dpr, label) {
  const pt = imageToViewport(x, y, dpr);
  if (!Number.isFinite(pt.x) || !Number.isFinite(pt.y)) {
    throw new Error(`${label} needs numeric --x and --y`);
  }
  return pt;
}

// A screenshot region [x0,y0,x1,y1] in image px → a Playwright `clip` in CSS px
// (crop for `screenshot --region` / `zoom`). Order-agnostic (min/abs), divides by
// dpr like imageToViewport. Pure — exported for tests.
export function regionToClip(region, dpr) {
  const d = Number(dpr) > 0 ? Number(dpr) : 1;
  const [x0, y0, x1, y1] = region.map(Number);
  return {
    x: Math.min(x0, x1) / d,
    y: Math.min(y0, y1) / d,
    width: Math.abs(x1 - x0) / d,
    height: Math.abs(y1 - y0) / d,
  };
}

// Screenshot encoding. Default to JPEG: a fraction of the equivalent retina PNG's
// bytes, so it's quicker to read off disk and send. This buys transfer latency,
// NOT tokens — images bill by pixel dimensions (⌈w/28⌉ × ⌈h/28⌉ visual tokens),
// so the same shot costs the same either way; shrink the image to spend less.
// Emit lossless PNG only when the caller's --path asks for it by a
// `.png` extension. `quality` (JPEG only — invalid for PNG) is tunable via
// AGENT_ID_SCREENSHOT_QUALITY, clamped to 1..100, default 80 (kept high so `zoom`
// crops of tiny text/icons stay legible). Pure — exported for tests.
export function screenshotEncoding(outPath, quality) {
  if (/\.png$/i.test(String(outPath || ""))) return {};
  const raw = typeof quality === "string" ? quality.trim() : quality;
  const n = Number(raw);
  const set = raw != null && raw !== "" && Number.isFinite(n);
  return {
    type: "jpeg",
    quality: set ? Math.min(100, Math.max(1, Math.round(n))) : 80,
  };
}

// Clamp a clip (CSS px) to the viewport: an oversized region degrades to its
// visible part, and one fully outside collapses to zero/negative area for the
// caller to reject with a readable error (instead of Playwright's raw "clipped
// area outside image"). Unknown viewport (JS-hostile page — the capture must
// still be attempted) passes the clip through. Pure — exported for tests.
export function clampClipToViewport(clip, viewport) {
  if (!viewport) return { ...clip };
  const x = Math.max(0, Math.min(clip.x, viewport.width));
  const y = Math.max(0, Math.min(clip.y, viewport.height));
  return {
    x,
    y,
    width: Math.min(clip.width, viewport.width - x),
    height: Math.min(clip.height, viewport.height - y),
  };
}

// Resolve the Frame (or current Page, which proxies its main frame) a ref
// points into. Child-frame refs are only valid until the next snapshot —
// same contract as the refs themselves.
function frameForRef(state, ref) {
  if (!state.refsValid) {
    throw new Error(
      `ref '${ref}' is stale (${
        state.refsInvalidReason || "page changed"
      }) — run form-inspect or snapshot again`
    );
  }
  // Snapshot versioning: refuse a ref minted by an earlier observation instead
  // of resolving it against the current tagging. Only meaningful when both
  // sides carry a generation — an unversioned ref, or a caller driving fillForm
  // directly against a hand-built state, is let through unchanged.
  const generation = refGenerationOf(ref);
  if (generation !== null && typeof state.refGeneration === "number" && generation !== state.refGeneration) {
    throw new Error(
      `ref '${ref}' is from observation ${generation}, but the page has been observed again since (now ${state.refGeneration}) — re-run form-inspect (or snapshot) and use the refs it returns`
    );
  }
  const id = frameRefId(ref);
  if (!id) return state.current;
  const frame = state.frames.get(id);
  if (!frame || frame.isDetached()) {
    throw new Error(`frame for ref '${ref}' is gone — re-snapshot and retry`);
  }
  return frame;
}

function invalidateRefs(state, reason = "page changed") {
  state.refsValid = false;
  state.refsInvalidReason = reason;
  state.frames.clear();
}

// Commit the generation the page was just tagged with. The number is chosen
// *before* the scan (the page functions stamp it into every ref), so it is
// passed in rather than incremented here.
function activateRefs(state, generation) {
  state.refGeneration = generation;
  state.refsValid = true;
  state.refsInvalidReason = null;
  return generation;
}

// A field the vault typed a secret into is tagged with this attribute (see
// markSecretField). It rides on the DOM element, not the ref — a re-snapshot
// invalidates refs but only clears "data-aibref", so the taint survives across
// snapshots as long as the site keeps the node. Kept in sync with the literal
// hard-coded inside snapshotInPage (page functions can't close over module scope).
export const SECRET_TAINT_ATTR = "data-aib-secret";

// Tag the element a fill-secret/fill-otp just wrote to, so every later read-back
// (get --what value, get --what attr value, and the snapshot el.value name
// fallback) refuses it — REGARDLESS of the input's `type`. This is what closes
// the leak for non-password fields: OTP/2FA inputs are type=text/tel, and a
// show-password toggle flips a password field to type=text, so a type-only test
// misses them. Best-effort: if the site has already swapped the node out there
// is nothing (and no value) left to tag.
export async function markSecretField(target, selector) {
  await target
    .$eval(selector, (el, attr) => el.setAttribute(attr, "1"), SECRET_TAINT_ATTR)
    .catch(() => {});
}

// The same tag, for a code spread across a row of boxes. `markSecretField` names
// one element through the ref's selector, and a row holds one character of the
// code in each of its boxes — so tagging the ref alone leaves the rest readable
// through `get --what value`. Every box written to is tainted, including after a
// partial fill, because a partial fill is exactly when those characters are still
// sitting there.
export async function markSecretBoxes(boxes) {
  await Promise.all(
    boxes.map((box) =>
      box
        .evaluate((el, attr) => el.setAttribute(attr, "1"), SECRET_TAINT_ATTR)
        .catch(() => {})
    )
  );
}

// `get --what value|attr value` must not read back a field that holds an injected
// secret: the vault may have just typed one there (fill-secret/fill-otp), and
// returning it would hand the agent the very value the vault exists to withhold.
// Refuse a password-type input AND any field the vault tagged tainted — the
// latter catches secrets typed into a non-password field (see markSecretField).
export async function refusePasswordRead(target, selector) {
  const refuse = await target
    .$eval(
      selector,
      (el, attr) =>
        (el.tagName === "INPUT" && el.type === "password") ||
        el.hasAttribute(attr),
      SECRET_TAINT_ATTR
    )
    .catch(() => false);
  if (refuse) {
    throw new Error("refusing to read a field that holds a password or an injected secret");
  }
}

function pushConsole(state, entry) {
  state.console.push({ ...entry, at: Date.now() });
  if (state.console.length > CONSOLE_CAP) {
    state.console.splice(0, state.console.length - CONSOLE_CAP);
  }
}

// Per-page listeners: console + pageerror feed the ring buffer, downloads are
// saved under the sessions dir and ledgered, JS dialogs are answered per the
// session's armed policy (default: dismiss — Playwright would otherwise
// auto-dismiss silently), and closing the current tab falls back to another.
function attachPage(state, page) {
  page.on("console", (msg) =>
    pushConsole(state, {
      type: msg.type(),
      text: String(msg.text()).slice(0, 500),
    })
  );
  page.on("pageerror", (err) =>
    pushConsole(state, {
      type: "error",
      text: String(err && err.message ? err.message : err).slice(0, 500),
    })
  );
  page.on("dialog", (d) => {
    state.lastDialog = {
      type: d.type(),
      message: String(d.message()).slice(0, 500),
      handled: state.dialog.mode,
      at: Date.now(),
    };
    const done =
      state.dialog.mode === "accept" ? d.accept(state.dialog.text ?? undefined) : d.dismiss();
    done.catch(() => {});
  });
  page.on("download", (d) => {
    const entry = {
      url: String(d.url()).slice(0, 500),
      suggestedFilename: d.suggestedFilename(),
      file: null,
      state: "saving",
      at: Date.now(),
    };
    state.downloads.push(entry);
    const file = path.join(
      sessionsDir(state.stateDir),
      `download-${Date.now()}-${safeFilename(d.suggestedFilename())}`
    );
    d.saveAs(file)
      .then(() => {
        entry.state = "saved";
        entry.file = file;
      })
      .catch((err) => {
        entry.state = "failed";
        entry.error = String(err && err.message ? err.message : err).slice(0, 200);
      });
  });
  page.on("framenavigated", () => invalidateRefs(state, "page navigated"));
  page.on("close", () => {
    if (state.current !== page) return;
    const left = state.ctx.pages().filter((pg) => pg !== page);
    if (left.length) {
      state.current = left[left.length - 1];
      invalidateRefs(state, "current tab changed");
    }
  });
}

// Unlock the vault non-interactively (agent-key slot) inside the session process,
// so a secret can be injected straight into the page without the controlling agent
// ever seeing the value.
async function openVaultAgentKey(stateDir) {
  const pk = await loadAgentPrivateKey(stateDir);
  if (!pk) throw new Error("vault: no agent key available to unlock");
  return openVault({ stateDir, privateKeyPem: pk });
}

// The hostname of a page URL ("" for about:blank / unparseable). Exported for tests.
export function hostOfUrl(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

// Authorize typing a credential into the current page. Two checks the rest of the
// codebase already enforces elsewhere, applied here before any value reaches the DOM:
//   - SEAL: an in-vault-generated secret (exportable:false) must never leave the
//     vault — mirrors cmdShow (redacts) and cmdExec (refuses). Only applied when a
//     specific secret `field` is being read (fill-secret), not for a derived OTP code.
//   - AUDIENCE: the page host must be on the credential's `domains` allowlist —
//     mirrors the proxy's hostMatchesAllowlist — so a secret can't be driven to an
//     attacker-chosen origin (about:blank / a foreign host is denied).
// Pure (no page object) so it unit-tests without a browser. Throws on violation.
export function assertFillAllowed(rec, host, field = null) {
  if (!rec) throw new Error("no such credential");
  if (field && rec.exportable === false && SECRET_FIELDS.includes(field)) {
    throw new Error(
      `"${field}" is sealed (generated in-vault) and cannot be typed into a page — use the proxy`
    );
  }
  assertHostAllowed(host, rec.domains, "refusing to type this credential on");
}

async function uploadFiles(page, target, ref, files) {
  const paths = (Array.isArray(files) ? files : []).map(String).filter(Boolean);
  if (!paths.length) throw new Error("upload needs at least one file");
  for (const file of paths) {
    try {
      await fs.access(file);
    } catch {
      throw new Error(`upload: file not found: ${file}`);
    }
  }
  const selector = sel(ref);
  const isFileInput = await target
    .$eval(selector, (el) => el.tagName === "INPUT" && el.type === "file")
    .catch(() => false);
  if (isFileInput) {
    await target.setInputFiles(selector, paths, { timeout: ACTION_TIMEOUT });
  } else {
    const [chooser] = await Promise.all([
      page.waitForEvent("filechooser", { timeout: ACTION_TIMEOUT }),
      target.click(selector, { timeout: ACTION_TIMEOUT }),
    ]);
    await chooser.setFiles(paths);
  }
  return paths.length;
}

function safeFormError(error, secret = "") {
  let message = String(error?.message || error || "form operation failed").replace(/\s+/g, " ");
  if (secret) message = message.split(secret).join("[value]");
  return message.slice(0, 300);
}

async function validateTaggedControls(state) {
  if (!state.refsValid) return { stale: true, invalid: [] };
  const targets = [state.current, ...new Set(state.frames.values())];
  const invalid = [];
  for (const target of targets) {
    const entries = await target
      .$$eval("[data-aibref]", (elements) =>
        elements
          .filter((el) => el.willValidate === true && el.checkValidity() === false)
          .map((el) => ({
            ref: el.getAttribute("data-aibref"),
            reason: String(el.validationMessage || "invalid").slice(0, 160),
          }))
      )
      .catch(() => []);
    invalid.push(...entries);
  }
  return { valid: invalid.length === 0, invalid };
}

// Atomic, fast form executor: one model/tool round-trip fills ordinary fields,
// toggles styled controls, selects options, and attaches files. Every operation
// is checked after it runs and failures are returned individually so one bad
// field cannot discard the successful half of a long application form.
// Drive an ARIA combobox (an <input> that opens a listbox) the way a person
// does: focus it, type enough to filter, then click the matching option.
//
// Deliberately does NOT use `fill()` — autocompletes listen for keystrokes, and
// a value set in one shot usually leaves the listbox closed and the site's
// internal model empty, so the form submits blank. `pressSequentially` emits
// real key events.
//
// Only one value is supported: multi-select comboboxes are a different widget
// (chips/tags) and pretending otherwise would silently drop values.
async function pickCombobox(target, ref, values) {
  if (values.length !== 1) {
    throw new Error("combobox takes exactly one value (multi-select comboboxes are not supported)");
  }
  const wanted = values[0];
  const input = target.locator(sel(ref));
  await input.click({ timeout: ACTION_TIMEOUT });
  await input.fill("", { timeout: ACTION_TIMEOUT }).catch(() => {});
  await input.pressSequentially(wanted, { delay: 25, timeout: ACTION_TIMEOUT });

  // The listbox is usually a sibling/portal rather than a descendant, so look
  // page-wide for visible options and match on text.
  const options = target.locator(
    "[role=option]:visible, li[role=option], [role=listbox] li"
  );
  const exact = options.filter({
    hasText: new RegExp(`^\\s*${escapeForRegex(wanted)}\\s*$`, "i"),
  });
  const chosen =
    (await exact.count().catch(() => 0)) > 0 ? exact.first() : options.first();
  try {
    await chosen.waitFor({ state: "visible", timeout: ACTION_TIMEOUT });
  } catch {
    throw new Error(
      `combobox '${ref}' opened no option list for "${wanted}" — the site may need a different value spelling, or the widget is not a listbox combobox`
    );
  }
  const label = ((await chosen.innerText().catch(() => "")) || "").replace(/\s+/g, " ").trim().slice(0, 160);
  await chosen.click({ timeout: ACTION_TIMEOUT });

  // Verify against the control's own value, not against what we clicked: a
  // combobox that rejects the pick leaves the field empty or reverted, and that
  // must surface as a failure rather than a cheerful ok:true.
  const settled = ((await input.inputValue().catch(() => "")) || "").trim();
  if (!settled)
    throw new Error(
      `combobox '${ref}' did not retain a value after picking "${
        label || wanted
      }"`
    );
  return {
    value: settled,
    ...(label && label !== settled ? { option: label } : {}),
  };
}

function escapeForRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export async function fillForm(state, p) {
  const fields = Array.isArray(p.fields) ? p.fields : [];
  const checks = Array.isArray(p.checks) ? p.checks : [];
  const selects = Array.isArray(p.selects) ? p.selects : [];
  const uploads = Array.isArray(p.uploads) ? p.uploads : [];
  const operationCount = fields.length + checks.length + selects.length + uploads.length;
  if (!operationCount) throw new Error("form-fill needs fields, checks, selects, or uploads");
  if (operationCount > 50) throw new Error("form-fill: max 50 controls");
  if (!state.refsValid) frameForRef(state, fields[0]?.ref || checks[0]?.ref || selects[0]?.ref || uploads[0]?.ref || "?");

  const results = [];
  for (const field of fields) {
    const ref = String(field?.ref || "");
    const value = String(field?.value ?? "");
    try {
      const target = frameForRef(state, ref);
      const locator = target.locator(sel(ref));
      const secretTarget = await locator.evaluate(
        (el, attr) =>
          (el.tagName === "INPUT" && el.type === "password") ||
          el.hasAttribute(attr),
        SECRET_TAINT_ATTR
      );
      if (secretTarget) throw new Error("password/secret fields require fill-secret or fill-otp");
      await locator.fill(value, { timeout: ACTION_TIMEOUT });
      const matches = await locator.evaluate((el, expected) => {
        const actual = "value" in el ? el.value : el.textContent || "";
        return { matches: actual === expected, length: String(actual).length };
      }, value);
      if (!matches.matches) throw new Error("page did not retain the supplied value");
      results.push({ ref, kind: "field", ok: true, length: matches.length });
    } catch (error) {
      results.push({
        ref,
        kind: "field",
        ok: false,
        error: safeFormError(error, value),
      });
    }
  }
  for (const check of checks) {
    const ref = String(check?.ref || "");
    const checked = check?.checked !== false;
    try {
      const locator = frameForRef(state, ref).locator(sel(ref));
      const native = await locator.evaluate((el) => ({
        native: el.tagName === "INPUT" && ["checkbox", "radio"].includes(el.type),
        visible: !!(el.getBoundingClientRect().width && el.getBoundingClientRect().height) &&
          getComputedStyle(el).visibility !== "hidden" && getComputedStyle(el).display !== "none",
      }));
      if (native.native && !native.visible) {
        // Styled controls often hide the native input completely. Playwright's
        // check action still insists on visibility even with force in patched
        // drivers, so update the real control and emit the same bubbling events
        // frameworks observe.
        await locator.evaluate((el, desired) => {
          const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "checked")?.set;
          if (setter) setter.call(el, desired);
          else el.checked = desired;
          el.dispatchEvent(new Event("input", { bubbles: true }));
          el.dispatchEvent(new Event("change", { bubbles: true }));
        }, checked);
      } else if (native.native) {
        await locator.setChecked(checked, { timeout: ACTION_TIMEOUT });
      } else {
        const before = (await locator.getAttribute("aria-checked")) === "true";
        if (before !== checked) await locator.click({ timeout: ACTION_TIMEOUT });
      }
      const actual = native.native
        ? await locator.isChecked()
        : (await locator.getAttribute("aria-checked")) === "true";
      if (actual !== checked) throw new Error("page did not retain the checked state");
      results.push({ ref, kind: "check", ok: true, checked: actual });
    } catch (error) {
      results.push({
        ref,
        kind: "check",
        ok: false,
        error: safeFormError(error),
      });
    }
  }
  for (const select of selects) {
    const ref = String(select?.ref || "");
    const values = (Array.isArray(select?.values) ? select.values : [select?.value]).filter((v) => v != null).map(String);
    try {
      const target = frameForRef(state, ref);
      // Dispatch on what the control actually IS. `selectOption` only works on
      // a native <select>; driving an ARIA combobox with it fails every time
      // with "Element is not a <select> element", which no amount of retrying
      // fixes — and enterprise forms (Oracle/Taleo/Workday) render their
      // country/nationality pickers as <input role="combobox"> autocompletes.
      const kind = await target.locator(sel(ref)).evaluate((el) =>
        el.tagName.toLowerCase() === "select"
          ? "select"
          : el.getAttribute("role") === "combobox" || el.getAttribute("aria-autocomplete")
            ? "combobox"
            : el.tagName.toLowerCase()
        );
      if (kind === "select") {
        const selected = await target.selectOption(sel(ref), values, {
          timeout: ACTION_TIMEOUT,
        });
        const matches = values.every((value) => selected.includes(value));
        if (!matches) throw new Error("page did not retain the selected option(s)");
        results.push({ ref, kind: "select", ok: true, selected });
      } else if (kind === "combobox") {
        const selected = await pickCombobox(target, ref, values);
        results.push({
          ref,
          kind: "select",
          ok: true,
          control: "combobox",
          selected,
        });
      } else {
        throw new Error(
          `ref '${ref}' is a <${kind}>, not a select or combobox — use fields for text input, or act/click for a custom widget`
        );
      }
    } catch (error) {
      results.push({
        ref,
        kind: "select",
        ok: false,
        error: safeFormError(error),
      });
    }
  }
  for (const upload of uploads) {
    const ref = String(upload?.ref || "");
    try {
      const count = await uploadFiles(state.current, frameForRef(state, ref), ref, upload?.files);
      results.push({ ref, kind: "upload", ok: true, files: count });
    } catch (error) {
      results.push({
        ref,
        kind: "upload",
        ok: false,
        error: safeFormError(error),
      });
    }
  }

  const failed = results.filter((result) => !result.ok).length;
  let submitted = false;
  if (!failed && p.submit) {
    const ref = String(p.submit);
    await frameForRef(state, ref).click(sel(ref), { timeout: ACTION_TIMEOUT });
    submitted = true;
  }
  const validation = await validateTaggedControls(state);
  return {
    ok: failed === 0 && validation.invalid.length === 0,
    completed: results.length - failed,
    failed,
    results,
    validation,
    ...(submitted ? { submitted: true } : {}),
  };
}

// One CDP window-bounds resize; returns the achieved INNER viewport (null on a
// JS-hostile page). Shared by the `resize` action (outer-size semantics) and
// the stream's viewer resize (viewport semantics, via resizeToViewport).
async function resizeWindow(state, page, width, height) {
  const before = await page
    .evaluate(() => [window.innerWidth, window.innerHeight])
    .catch(() => null);
  const cdp = await state.ctx.newCDPSession(page);
  try {
    const { windowId } = await cdp.send("Browser.getWindowForTarget");
    // Two steps: exit maximized/fullscreen FIRST, else Chrome applies the
    // state change and ignores the bounds in the same call.
    await cdp
      .send("Browser.setWindowBounds", {
        windowId,
        bounds: { windowState: "normal" },
      })
      .catch(() => {});
    await cdp.send("Browser.setWindowBounds", {
      windowId,
      bounds: { width, height },
    });
  } catch (err) {
    throw new Error(`resize failed (CDP window bounds unavailable — needs a headed/cloud Chrome): ${err.message || err}`);
  } finally {
    await cdp.detach().catch(() => {});
  }
  // setWindowBounds acks before the renderer re-lays-out — wait for the inner
  // size to actually change (best-effort) so the returned viewport isn't stale.
  if (before) {
    await page
      .waitForFunction(
        (b) => window.innerWidth !== b[0] || window.innerHeight !== b[1],
        before,
        { timeout: 3000 }
      )
      .catch(() => {});
  }
  return page
    .evaluate(() => ({ width: window.innerWidth, height: window.innerHeight }))
    .catch(() => null);
}

// Second-pass OUTER size that should land the INNER viewport on `want`, given
// what a straight outer resize to `want` actually yielded (`got`) — the delta
// between the two is the window chrome. null when the first pass already
// landed, or when the page could not be measured. Exported for tests.
export function chromeCompensatedBounds(want, got) {
  if (!got) return null;
  const width = want.width + Math.max(0, want.width - got.width);
  const height = want.height + Math.max(0, want.height - got.height);
  if (width === want.width && height === want.height) return null;
  return { width, height };
}

// Viewer-driven resize (stream protocol `resize` message): width/height are
// the viewer's SCREEN — i.e. the desired page VIEWPORT, not the outer window
// size the `resize` action takes. A phone watching the stream sends its own
// dimensions and the page reflows into its mobile layout instead of staying a
// shrunken desktop. One compensation pass converts viewport → outer: resize to
// the requested size, measure the chrome the window ate, grow by that delta.
async function resizeToViewport(state, width, height) {
  const page = state.current;
  if (!page || page.isClosed?.()) return null;
  const first = await resizeWindow(state, page, width, height);
  const second = chromeCompensatedBounds({ width, height }, first);
  if (!second) return first;
  return (
    (await resizeWindow(state, page, second.width, second.height)) ?? first
  );
}

// Exported for tests: the suspend/resume contract around credential fills is
// only observable here.
export async function dispatch(state, msg, policy = null) {
  const p = msg.params || {};
  const page = state.current;
  // Read-only sessions refuse the un-auditable/secret-bearing actions here;
  // everything else stays available because the network gate (applyAccessGuard)
  // is what actually stops mutations from reaching the service.
  if (policy) assertActionAllowed(policy, msg.action);
  switch (msg.action) {
    case "info":
      return {
        url: page.url(),
        title: await page.title().catch(() => ""),
        tabs: state.ctx.pages().length,
      };
    case "navigate": {
      const resp = await page.goto(String(p.url), {
        waitUntil: "domcontentloaded",
        timeout: 30000,
      });
      return { url: page.url(), status: resp ? resp.status() : null };
    }
    case "back":
      await page.goBack({ waitUntil: "domcontentloaded" }).catch(() => {});
      return { url: page.url() };
    // `read` / `fetch` also exist as one-shot CLI commands that unseal a COPY of
    // the profile. That copy is stale while a session is open — the live cookies
    // only reach the vault on `close` — so a one-shot reports "logged out" for a
    // session that is signed in. The CLI routes to these when a session exists.
    case "read": {
      const resp = p.url
        ? await page.goto(String(p.url), {
            waitUntil: "domcontentloaded",
            timeout: 30000,
          })
        : null;
      const finalUrl = page.url();
      const title = await page.title().catch(() => "");
      let text = "";
      try {
        text = await page.evaluate(() =>
          document.body ? document.body.innerText : ""
        );
      } catch {
        /* page navigated/destroyed mid-read — leave text empty */
      }
      const httpStatus = resp ? resp.status() : null;
      return {
        httpStatus,
        finalUrl,
        title,
        loggedOut: looksLoggedOut({ finalUrl, bodyText: text, httpStatus }),
        text: String(text).slice(0, Number(p.maxChars || 8000)),
      };
    }
    case "fetch": {
      const url = String(p.url);
      // ctx.request bypasses route interception, so the policy is checked here
      // the same way the one-shot path checks it. A null policy means the
      // profile carries no restriction at all — the same convention the action
      // allowlist above follows.
      const decision = policy
        ? guardDecision(policy, { method: "GET", url, postData: null })
        : { allowed: true };
      if (!decision.allowed) {
        throw new Error(`access level blocks GET ${url} (${decision.reason})`);
      }
      const resp = await state.ctx.request.get(url, { timeout: 30000 });
      const httpStatus = resp.status();
      let body = "";
      try {
        body = await resp.text();
      } catch {
        /* binary or empty body */
      }
      return {
        httpStatus,
        finalUrl: resp.url(),
        loggedOut: looksLoggedOut({
          finalUrl: resp.url(),
          bodyText: body,
          httpStatus,
        }),
        body: String(body).slice(0, Number(p.maxChars || 8000)),
      };
    }
    case "snapshot": {
      state.frames.clear();
      // Chosen before the scan so the page can stamp it into every ref.
      const generation = state.refGeneration + 1;
      const main = await page.evaluate(snapshotInPage, {
        prefix: "",
        generation,
      });
      const frames = [];
      let skipped = 0;
      let fCount = 0;
      for (const f of page.frames()) {
        if (f === page.mainFrame()) continue;
        if (fCount >= MAX_FRAMES) {
          skipped++;
          continue;
        }
        let snap;
        try {
          snap = await f.evaluate(snapshotInPage, {
            prefix: `f${fCount + 1}`,
            generation,
          });
        } catch {
          continue; // detached / navigating frame — nothing was tagged
        }
        fCount++;
        state.frames.set(`f${fCount}`, f);
        if (snap.elements.length) {
          frames.push({
            frame: `f${fCount}`,
            url: String(snap.url).slice(0, 200),
            elements: snap.elements.length,
          });
          main.elements.push(...snap.elements);
        }
      }
      const tabs = state.ctx.pages().length;
      activateRefs(state, generation);
      return {
        ...main,
        generation,
        ...(frames.length ? { frames } : {}),
        ...(skipped ? { framesSkipped: skipped } : {}),
        ...(tabs > 1 ? { tabs, tab: state.ctx.pages().indexOf(page) } : {}),
      };
    }
    case "form-inspect": {
      state.frames.clear();
      const generation = state.refGeneration + 1;
      const main = await page.evaluate(formSnapshotInPage, {
        prefix: "",
        generation,
      });
      const frames = [];
      let skipped = 0;
      let fCount = 0;
      for (const frame of page.frames()) {
        if (frame === page.mainFrame()) continue;
        if (fCount >= MAX_FRAMES) {
          skipped++;
          continue;
        }
        let snap;
        try {
          snap = await frame.evaluate(formSnapshotInPage, {
            prefix: `f${fCount + 1}`,
            generation,
          });
        } catch {
          continue;
        }
        fCount++;
        state.frames.set(`f${fCount}`, frame);
        if (snap.controls.length) {
          frames.push({
            frame: `f${fCount}`,
            url: String(snap.url).slice(0, 200),
            controls: snap.controls.length,
          });
          main.controls.push(...snap.controls);
        }
      }
      activateRefs(state, generation);
      return {
        ...main,
        generation,
        ...(frames.length ? { frames } : {}),
        ...(skipped ? { framesSkipped: skipped } : {}),
      };
    }
    case "form-fill":
      return fillForm(state, p);
    case "text":
      return {
        text: String(
          await page.evaluate(() =>
            document.body ? document.body.innerText : ""
          )
        ).slice(0, Number(p.maxChars || 6000)),
      };
    case "click":
      await humanClick(page, sel(p.ref), {
        timeout: ACTION_TIMEOUT,
        root: frameForRef(state, p.ref),
      });
      return { clicked: p.ref };
    case "dblclick":
      await frameForRef(state, p.ref).dblclick(sel(p.ref), {
        timeout: ACTION_TIMEOUT,
      });
      return { dblclicked: p.ref };
    case "check":
      await frameForRef(state, p.ref).check(sel(p.ref), {
        timeout: ACTION_TIMEOUT,
      });
      return { checked: p.ref };
    case "uncheck":
      await frameForRef(state, p.ref).uncheck(sel(p.ref), {
        timeout: ACTION_TIMEOUT,
      });
      return { unchecked: p.ref };
    case "type":
      await humanType(page, sel(p.ref), String(p.text ?? ""), {
        timeout: ACTION_TIMEOUT,
        submit: !!p.submit,
        root: frameForRef(state, p.ref),
      });
      return { typed: p.ref, submit: !!p.submit };
    case "fill": {
      const fields = Array.isArray(p.fields) ? p.fields : [];
      for (const f of fields) {
        await frameForRef(state, f.ref).fill(sel(f.ref), String(f.value ?? ""), { timeout: ACTION_TIMEOUT });
      }
      return { filled: fields.map((f) => f.ref) };
    }
    case "fill-secret": {
      // Inject a vaulted secret into the element the agent identified. The agent
      // supplies { ref, cred: "name.field" } — never the value; nothing about the
      // value is returned or logged.
      const dot = String(p.cred || "").lastIndexOf(".");
      if (dot <= 0) throw new Error(`fill-secret needs cred "name.field" (got "${p.cred}")`);
      const credName = String(p.cred).slice(0, dot);
      const field = String(p.cred).slice(dot + 1);
      const target = frameForRef(state, p.ref);
      // Viewport-stream blackout while the value is on its way into the page —
      // watchers see nothing and viewer input is ignored until resume.
      state.stream?.suspend();
      // Everything after the suspend must be inside this try: unlocking the
      // vault can fail (locked, no agent-key slot, timeout), and when that
      // throw escaped the blackout was never lifted — the feed stayed
      // suspended for the rest of the session, so every later viewer got
      // "screencasting" and not one frame. Seen in the wild after a failed
      // auto-login: the owner opened the browser view to sign in and watched a
      // blank canvas. `fill-otp` below already had this shape.
      try {
        const vault = await openVaultAgentKey(msg._stateDir);
        try {
          const rec = vault.get(credName);
          if (!rec) throw new Error(`no credential "${credName}"`);
          // Refuse a sealed field, and refuse a page whose host isn't on the
          // credential's allowlist — BEFORE reading the value into memory. When
          // the field lives in an iframe, the frame's origin is where the value
          // actually goes, so BOTH the top page and the frame must pass.
          assertFillAllowed(rec, hostOfUrl(page.url()), field);
          if (target !== page) assertFillAllowed(rec, hostOfUrl(target.url()), field);
          const value = rec[field];
          if (typeof value !== "string" || !value) {
            throw new Error(`"${credName}.${field}" is not a usable string field`);
          }
          // CRITICAL: a fill/keyboard error can echo the value being typed, so
          // never let the raw error escape — it would leak the secret to the agent.
          try {
            await humanType(page, sel(p.ref), value, {
              timeout: ACTION_TIMEOUT,
              submit: !!p.submit,
              root: target,
            });
          } catch {
            throw new Error(`fill-secret: could not fill "${p.ref}" — element not visible/editable (re-snapshot and retry)`);
          }
          // Tag the field so a later read-back is refused whatever its input type.
          await markSecretField(target, sel(p.ref));
        } finally {
          vault.lock();
        }
      } finally {
        state.stream?.resume();
      }
      return { filled: p.ref, cred: p.cred };
    }
    case "fill-otp": {
      // Resolve the current 2FA code for a login/totp cred — generated from a
      // stored seed, or asked via the secure prompt — and type it.
      const credName = String(p.cred || "");
      const target = frameForRef(state, p.ref);
      // Same viewport-stream blackout as fill-secret: an OTP is typed into a
      // visible text/tel input, so watchers must not see the keystrokes.
      state.stream?.suspend();
      try {
        const vault = await openVaultAgentKey(msg._stateDir);
        let code;
        try {
          const rec = vault.get(credName);
          if (!rec) throw new Error(`no credential "${credName}"`);
          // Audience binding: a live OTP code must not be typed into a foreign
          // origin — top page AND (for an iframe field) the frame itself.
          assertFillAllowed(rec, hostOfUrl(page.url()));
          if (target !== page) assertFillAllowed(rec, hostOfUrl(target.url()));
          const otpCred =
            rec.type === "totp"
              ? {
                  name: credName,
                  otp: "totp",
                  totpSecret: rec.secret,
                  period: rec.period,
                  digits: rec.digits,
                  algorithm: rec.algorithm,
                }
              : rec;
          // The page is right there, and it is the only thing that knows how long
          // the code is and where it was sent. Without this the card raised by
          // hand is the same card with both facts missing.
          const hints = await otpCardHints(target);
          // Why a row was or was not found, in the one place it matters: the
          // predicate groups boxes by their parent, and a site that wraps each box
          // in its own element defeats that silently.
          const shape = await target
            .evaluate((sel) => {
              const visible = (e) => !!(e.offsetParent !== null || e.getClientRects().length);
              const found = Array.from(document.querySelectorAll(sel)).filter(visible);
              const groups = new Map();
              for (const e of found) {
                const key = e.parentElement;
                groups.set(key, (groups.get(key) || 0) + 1);
              }
              return `candidates=${found.length} groups=${[...groups.values()].join(",") || "-"}`;
            }, 'input[type="text"],input[type="tel"],input[type="number"],input[inputmode="numeric"],input[autocomplete="one-time-code"]')
            .catch(() => "shape unavailable");
          process.stderr.write(`fill-otp: row shape ${shape}\n`);
          process.stderr.write(
            `fill-otp: code hints length=${hints.length ?? "?"} destination=${
              hints.destination ?? "?"
            }\n`
          );
          // Reaching this line means a code is being asked for, which settles what
          // the record only guessed. Auto-login corrects the same claim the same
          // way; a sign-in driven by hand arrives here instead and must not leave
          // the record to mislead the next one.
          const correction = otpModeCorrection(rec);

          try {
            code = await resolveOtp(otpCred, hints);
          } catch (err) {
            // The owner closed the card. Nothing broke and nothing timed out, so
            // the one thing that must not happen is the same card going straight
            // back up — which is what a bare fault invites, because the sensible
            // reply to a fault is a retry.
            if (err?.code === "FORM_CANCELLED") {
              throw new Error(
                "fill-otp: the owner dismissed the code card — they were asked and said no. " +
                  "Do not raise it again unless they ask for it."
              );
            }
            throw err;
          }

          // Written only now, and only if the owner answered. `fill_otp` inspects
          // no page state, so until a code comes back the sole evidence that this
          // site asks for one is that the model said so — and a mistaken call
          // would overwrite the owner's explicit `--otp none` for good, with no
          // way back. Answering the card is the site being asked and the owner
          // agreeing; that is worth writing down. A dismissal is not.
          if (correction) {
            try {
              rec.otp = correction;
              vault.add(rec);
              await vault.save();
              process.stderr.write(
                `fill-otp: '${credName}' said otp=none but a code is being asked for — corrected\n`
              );
            } catch (err) {
              // Bookkeeping. The owner has the code in hand and the sign-in is
              // mid-flight; losing the correction costs one re-learn, losing the
              // sign-in costs the whole thing.
              process.stderr.write(
                `fill-otp: could not record the corrected otp mode: ${err.message}\n`
              );
            }
          }
        } finally {
          vault.lock();
        }
        // Same leak guard as fill-secret: never surface the value-bearing error.
        let row = null;
        try {
          // A row of boxes needs the code spread across it, and the ref names only
          // the first one. Typing into that one and trusting the page to advance
          // the focus is what leaves the row half-entered and the submit dead.
          const boxes = await otpBoxes(target);
          if (boxes.length > 0) {
            // Tainted before the code goes in, not after: every path out of the
            // typing below — a throw mid-row, a partial fill, a row that submits
            // itself — leaves characters in these boxes, and only the tag stops
            // them being read back one at a time.
            await markSecretBoxes(boxes);
            const typed = await typeCodeAcrossBoxes(page, boxes, code);
            row = { count: boxes.length, ...typed };
            // A row that submitted itself has already moved the page on; pressing
            // Enter then lands on whatever screen came next.
            const stillHere = await boxes[0].isVisible().catch(() => false);
            if (!row.submitted && stillHere && p.submit !== false)
              await page.keyboard.press("Enter");
          } else {
            await humanType(page, sel(p.ref), code, {
              timeout: ACTION_TIMEOUT,
              submit: p.submit !== false,
              root: target,
            });
          }
        } catch {
          throw new Error(`fill-otp: could not fill "${p.ref}" — element not visible/editable (re-snapshot and retry)`);
        }
        // Outside the guard above, which rewrites everything it catches into a
        // visibility problem. A row that would not take the code is not that, and
        // sending the model to re-snapshot over it is advice for the wrong fault.
        if (row && !row.complete) {
          throw new Error(
            row.submitted
              ? "fill-otp: the code was submitted and the site refused it — ask for a fresh one"
              : `fill-otp: the code did not land in all ${row.count} boxes (re-snapshot and retry)`
          );
        }
        // A derived OTP isn't sealed at fill time (see assertFillAllowed), so the
        // read-back guard is what protects it: tag the field so its value can't be
        // read back regardless of the input's type (OTP inputs are text/tel).
        await markSecretField(target, sel(p.ref));
        return { filled: p.ref, otp: true };
      } finally {
        state.stream?.resume();
      }
    }
    case "select": {
      // Same dispatch as form-fill's selects — a bare `select` on an ARIA
      // combobox would otherwise fail identically here.
      const target = frameForRef(state, p.ref);
      const values = (Array.isArray(p.values) ? p.values : [p.values]).filter((v) => v != null).map(String);
      const kind = await target.locator(sel(p.ref)).evaluate((el) =>
        el.tagName.toLowerCase() === "select"
          ? "select"
          : el.getAttribute("role") === "combobox" || el.getAttribute("aria-autocomplete")
            ? "combobox"
            : el.tagName.toLowerCase()
        );
      if (kind === "combobox") {
        return {
          selected: p.ref,
          control: "combobox",
          ...(await pickCombobox(target, p.ref, values)),
        };
      }
      await target.selectOption(sel(p.ref), values, {
        timeout: ACTION_TIMEOUT,
      });
      return { selected: p.ref };
    }
    case "hover":
      await humanHover(page, sel(p.ref), {
        timeout: ACTION_TIMEOUT,
        root: frameForRef(state, p.ref),
      });
      return { hovered: p.ref };
    case "press":
      if (p.ref) await frameForRef(state, p.ref).press(sel(p.ref), String(p.key));
      else await page.keyboard.press(String(p.key));
      return { pressed: p.key };
    case "upload": {
      // Attach local files to a file input (or a picker button that opens the
      // native chooser). Refused on read-only sessions: sending the owner's
      // local file content to a site is a write in spirit, even though the
      // resulting POST would also die at the network gate.
      const t = frameForRef(state, p.ref);
      const count = await uploadFiles(page, t, p.ref, p.files);
      return { uploaded: p.ref, files: count };
    }
    case "drag": {
      const from = frameForRef(state, p.ref);
      if (from !== frameForRef(state, p.to)) {
        throw new Error("drag: source and target must be in the same frame");
      }
      await from.dragAndDrop(sel(p.ref), sel(p.to), {
        timeout: ACTION_TIMEOUT,
      });
      return { dragged: p.ref, to: p.to };
    }
    case "scroll":
      await humanScroll(page, Number(p.dx || 0), Number(p.dy || 600));
      return { scrolled: true };
    case "scroll-xy": {
      // Wheel-scroll with the cursor positioned at a screenshot pixel. `scroll`
      // wheels wherever the cursor happens to be; `scroll-xy` puts it at (x,y)
      // first — needed for zoom-toward-point (maps zoom on the cursor) and for
      // scrolling an inner pane rather than the page. dx/dy are wheel deltas
      // (dy>0 scrolls down; sites map that to zoom-out, negative to zoom-in).
      const { x, y } = toXY(p.x, p.y, await liveDpr(page, p.css), "scroll-xy");
      await humanMove(page, x, y);
      const dx = Number(p.dx || 0);
      const dy = Number(p.dy || 0);
      await page.mouse.wheel(dx, dy);
      return { scrolled: { x, y, dx, dy } };
    }
    // Coordinate (vision) actions — the hybrid to ref-based clicking. The agent
    // points at a screenshot pixel; toXY converts to viewport CSS px (÷dpr) and
    // page.mouse acts. Coords address the VIEWPORT — scroll into view first and
    // use a viewport screenshot (not --full) as the reference.
    case "click-xy": {
      const { x, y } = toXY(p.x, p.y, await liveDpr(page, p.css), "click-xy");
      const button = ["left", "right", "middle"].includes(String(p.button)) ? String(p.button) : "left";
      await humanMove(page, x, y); // stealth trail; the click itself lands at (x,y)
      await page.mouse.click(x, y, { button, clickCount: p.double ? 2 : 1 });
      return {
        clicked: { x, y },
        button,
        ...(p.double ? { double: true } : {}),
      };
    }
    case "move-xy": {
      const { x, y } = toXY(p.x, p.y, await liveDpr(page, p.css), "move-xy");
      await humanMove(page, x, y);
      return { moved: { x, y } };
    }
    case "drag-xy": {
      const dpr = await liveDpr(page, p.css);
      const from = imageToViewport(p.x, p.y, dpr);
      const to = imageToViewport(p.tox, p.toy, dpr);
      if (![from.x, from.y, to.x, to.y].every(Number.isFinite)) {
        throw new Error("drag-xy needs numeric --x --y --tox --toy");
      }
      await humanMove(page, from.x, from.y);
      await page.mouse.down();
      await humanMove(page, to.x, to.y);
      await page.mouse.up();
      return { dragged: { from, to } };
    }
    case "type-text": {
      // Keyboard typing into whatever is focused (usually after a click-xy).
      // PLAINTEXT ONLY — secrets stay ref-based via fill-secret/fill-otp. Note it
      // APPENDS (no clear) unlike ref-based `type`; click a field's clear/select-all
      // first if replacing. Only the length leaves the session, never the text.
      // Cadence comes from humanTypeFocused — the same jittered per-key delays as
      // ref-based `type`; a fixed inter-key interval is itself a bot fingerprint.
      refuseRef("type-text", p, "type --ref eN --text T");
      const text = String(p.text ?? "");
      await humanTypeFocused(page, text, { submit: !!p.submit });
      return { typed: text.length, submit: !!p.submit };
    }
    case "fill-text": {
      // Paste-style counterpart to `type-text`: insert the whole text at the
      // caret in one shot (insertText — an `input` event, no per-key keydown/
      // keyup), the way a clipboard paste lands. Use it for long text where
      // per-keystroke typing is slow or where key handlers mangle input; use
      // `type-text` when the page needs real keystrokes (search-as-you-type,
      // autocomplete). Same contract otherwise: PLAINTEXT ONLY (secrets stay
      // ref-based via fill-secret/fill-otp), APPENDS at the caret (no clear),
      // and only the length leaves the session, never the text.
      refuseRef("fill-text", p, 'fill --fields \'[{"ref":"eN","value":"V"}]\'');
      const text = String(p.text ?? "");
      await page.keyboard.insertText(text);
      if (p.submit) await page.keyboard.press("Enter");
      return { filled: text.length, submit: !!p.submit };
    }
    case "probe-xy": {
      // Read-only vision→DOM bridge: what element sits under a screenshot pixel?
      // Runs a fixed elementFromPoint (not agent JS like `eval`), reads no input
      // `value`, mutates nothing — so it is allowed on read-only sessions.
      const { x, y } = toXY(p.x, p.y, await liveDpr(page, p.css), "probe-xy");
      const element = await page.evaluate(
        ([px, py]) => {
          const el = document.elementFromPoint(px, py);
          if (!el) return null;
          const r = el.getBoundingClientRect();
          const clip = (s) =>
            s ? String(s).replace(/\s+/g, " ").trim().slice(0, 100) : "";
          return {
            tag: el.tagName.toLowerCase(),
            role: el.getAttribute("role") || null,
            type: el.getAttribute("type") || null,
            ref: el.getAttribute("data-aibref") || null, // present only after a snapshot
            name: clip(
              el.getAttribute("aria-label") ||
                el.getAttribute("placeholder") ||
                el.getAttribute("title") ||
                el.textContent
            ),
            href: el.getAttribute("href") || null,
            box: {
              x: Math.round(r.x),
              y: Math.round(r.y),
              width: Math.round(r.width),
              height: Math.round(r.height),
            },
          };
        },
        [x, y]
      );
      return { at: { x, y }, element };
    }
    case "resize": {
      // Resize the live browser window. viewport:null ties the page viewport to
      // the real window, so a scripted setViewportSize is rejected — drive window
      // bounds over CDP. width/height are the OUTER window size; the resulting
      // INNER viewport (what coordinate actions use) is smaller and is returned.
      const width = Math.round(Number(p.width));
      const height = Math.round(Number(p.height));
      if (![width, height].every(Number.isFinite) || width < 200 || height < 200) {
        throw new Error("resize needs numeric --width and --height (min 200 each)");
      }
      const viewport = await resizeWindow(state, page, width, height);
      return { resized: { width, height }, ...(viewport ? { viewport } : {}) };
    }
    case "zoom":
      // At the CLI `zoom` is sugar that the client maps onto `screenshot` with
      // requireRegion set — but `batch` re-enters dispatch() by raw action name,
      // so the alias must exist here too (SKILL.md promises batch runs any
      // action). Force the region requirement and fall into the handler.
      p.requireRegion = true;
    // fallthrough
    case "screenshot": {
      const out = p.path ? String(p.path) : path.join(sessionsDir(msg._stateDir), `shot-${Date.now()}.jpg`);
      const enc = screenshotEncoding(out, process.env.AGENT_ID_SCREENSHOT_QUALITY);
      const format = enc.type || "png";
      // dims are BEST-EFFORT and must never block the capture: a JS-hostile page
      // (PDF viewer, chrome://, mid-navigation) can't run this evaluate, but the
      // pixel capture is exactly what you still want there. Default dpr=1, no
      // viewport, on failure. `image` echoes the pixel bounds the agent can point
      // within; a --full shot is taller than the viewport, so `image` is omitted.
      const info = await page
        .evaluate(() => ({
          dpr: window.devicePixelRatio || 1,
          viewport: { width: window.innerWidth, height: window.innerHeight },
        }))
        .catch(() => ({ dpr: 1, viewport: null }));
      // --region [x0,y0,x1,y1] (image px) crops a zoomed-in view of a UI area. If
      // --region is given it MUST be 4 finite numbers — otherwise error, never
      // silently fall through to a full shot the agent would mistake for a crop.
      let region = null;
      if (p.region != null) {
        region = Array.isArray(p.region) ? p.region.map(Number) : null;
        if (!region || region.length !== 4 || !region.every(Number.isFinite)) {
          throw new Error("screenshot --region needs 4 numbers: x0,y0,x1,y1");
        }
      }
      // `zoom` sets requireRegion — a region-less zoom is a mistake, not a full shot.
      if (p.requireRegion && !region) throw new Error("zoom needs --region x0,y0,x1,y1");
      if (region) {
        // Clamp to the viewport so an over-large region gives a helpful error
        // instead of a raw Playwright "clipped area outside image".
        const clip = clampClipToViewport(regionToClip(region, p.css ? 1 : info.dpr), info.viewport);
        if (clip.width < 1 || clip.height < 1) {
          throw new Error("screenshot --region has zero area (or lies outside the viewport)");
        }
        // Guard the capture too: when viewport was unknown (JS-hostile page) we
        // couldn't clamp, so a raw clip error becomes a readable one.
        try {
          await page.screenshot({ path: out, clip, ...enc });
        } catch (err) {
          throw new Error(`screenshot --region could not capture (region likely outside the page): ${err.message || err}`);
        }
        return {
          screenshot: out,
          format,
          dpr: info.dpr,
          region,
          image: {
            width: Math.round(clip.width * info.dpr),
            height: Math.round(clip.height * info.dpr),
          },
        };
      }
      await page.screenshot({ path: out, fullPage: !!p.fullPage, ...enc });
      const result = { screenshot: out, format, dpr: info.dpr };
      if (info.viewport) result.viewport = info.viewport;
      if (p.fullPage) {
        result.fullPage = true; // spans the whole page — not a valid click reference
      } else if (info.viewport) {
        result.image = {
          width: Math.round(info.viewport.width * info.dpr),
          height: Math.round(info.viewport.height * info.dpr),
        };
      }
      return result;
    }
    case "eval":
      return { result: await page.evaluate(String(p.expression)) };
    case "wait":
      if (p.text) await page.getByText(String(p.text)).first().waitFor({ timeout: Number(p.ms || 15000) });
      else if (p.url) {
        const needle = String(p.url);
        await page.waitForURL((u) => u.href.includes(needle), {
          timeout: Number(p.ms || 15000),
        });
      } else if (p.load) {
        const stateName = String(p.load);
        if (!["load", "domcontentloaded", "networkidle"].includes(stateName)) {
          throw new Error("wait --load must be load|domcontentloaded|networkidle");
        }
        await page.waitForLoadState(stateName, {
          timeout: Number(p.ms || 15000),
        });
      } else await page.waitForTimeout(Number(p.ms || 1000));
      return { waited: true, url: page.url() };
    case "get": {
      const what = String(p.what || "text");
      if (what === "url") return { url: page.url() };
      if (what === "title") return { title: await page.title().catch(() => "") };
      if (!p.ref) throw new Error(`get --what ${what} needs --ref`);
      const t = frameForRef(state, p.ref);
      const s = sel(p.ref);
      const cap = Number(p.maxChars || 4000);
      switch (what) {
        case "text":
          return {
            text: String(
              await t.innerText(s, { timeout: ACTION_TIMEOUT })
            ).slice(0, cap),
          };
        case "html":
          return {
            html: String(
              await t.innerHTML(s, { timeout: ACTION_TIMEOUT })
            ).slice(0, cap),
          };
        case "value":
          await refusePasswordRead(t, s);
          return { value: await t.inputValue(s, { timeout: ACTION_TIMEOUT }) };
        case "attr": {
          if (!p.attr) throw new Error("get --what attr needs --attr NAME");
          if (String(p.attr).toLowerCase() === "value")
            await refusePasswordRead(t, s);
          return {
            attr: p.attr,
            value: await t.getAttribute(s, String(p.attr), {
              timeout: ACTION_TIMEOUT,
            }),
          };
        }
        default:
          throw new Error(`get: unknown --what '${what}' (text|html|value|attr|url|title)`);
      }
    }
    case "is": {
      const what = String(p.what || "visible");
      const t = frameForRef(state, p.ref);
      const s = sel(p.ref);
      switch (what) {
        case "visible":
          return { visible: await t.isVisible(s) };
        case "enabled":
          return { enabled: await t.isEnabled(s, { timeout: ACTION_TIMEOUT }) };
        case "checked":
          return { checked: await t.isChecked(s, { timeout: ACTION_TIMEOUT }) };
        case "editable":
          return {
            editable: await t.isEditable(s, { timeout: ACTION_TIMEOUT }),
          };
        default:
          throw new Error(`is: unknown --what '${what}' (visible|enabled|checked|editable)`);
      }
    }
    case "tabs": {
      const pages = state.ctx.pages();
      return {
        tabs: await Promise.all(
          pages.map(async (pg, index) => ({
            index,
            url: pg.url(),
            title: await pg.title().catch(() => ""),
            ...(pg === state.current ? { current: true } : {}),
          }))
        ),
      };
    }
    case "tab-new": {
      const pg = await state.ctx.newPage();
      if (p.url)
        await pg.goto(String(p.url), {
          waitUntil: "domcontentloaded",
          timeout: 30000,
        });
      state.current = pg;
      invalidateRefs(state, "current tab changed");
      return { index: state.ctx.pages().indexOf(pg), url: pg.url() };
    }
    case "tab-switch": {
      const pages = state.ctx.pages();
      const index = Number(p.index);
      if (!Number.isInteger(index) || index < 0 || index >= pages.length) {
        throw new Error(`no tab ${p.index} (open tabs: 0..${pages.length - 1})`);
      }
      state.current = pages[index];
      invalidateRefs(state, "current tab changed");
      await state.current.bringToFront().catch(() => {});
      return {
        index,
        url: state.current.url(),
        title: await state.current.title().catch(() => ""),
      };
    }
    case "tab-close": {
      const pages = state.ctx.pages();
      if (pages.length <= 1) {
        throw new Error("tab-close: closing the last tab would end the session — use `close`");
      }
      const index = p.index != null ? Number(p.index) : pages.indexOf(state.current);
      if (!Number.isInteger(index) || index < 0 || index >= pages.length) {
        throw new Error(`no tab ${p.index} (open tabs: 0..${pages.length - 1})`);
      }
      await pages[index].close(); // "close" listener re-points state.current if needed
      return { closed: index, tabs: state.ctx.pages().length };
    }
    case "dialog": {
      // Arm how JS dialogs (alert/confirm/prompt/beforeunload) are answered
      // from now on; without --mode, just report the policy + last dialog seen.
      if (p.mode != null) {
        const mode = String(p.mode);
        if (!["accept", "dismiss"].includes(mode)) throw new Error("dialog --mode must be accept|dismiss");
        state.dialog = { mode, text: p.text != null ? String(p.text) : null };
      }
      return {
        mode: state.dialog.mode,
        promptText: state.dialog.text,
        last: state.lastDialog,
      };
    }
    case "downloads":
      return { downloads: state.downloads.slice(-Number(p.max || 20)) };
    case "console": {
      // Best-effort: patchright's stealth driver suppresses Runtime.enable
      // (that's the point of it), which is the CDP channel console/pageerror
      // events ride on — so on most pages this buffer stays empty. Say so,
      // rather than letting an empty list read as "the page logged nothing".
      const level = p.level ? String(p.level) : null;
      let entries = state.console;
      if (level === "error") entries = entries.filter((e) => e.type === "error");
      else if (level === "warn") entries = entries.filter((e) => e.type === "error" || e.type === "warning");
      return {
        messages: entries.slice(-Number(p.max || 50)),
        ...(state.console.length === 0
          ? {
              note: "empty is expected: the stealth driver suppresses most console events — use `eval` to probe page state instead",
            }
          : {}),
      };
    }
    case "cookies": {
      // Metadata only — values are session tokens, which stay sealed in the
      // session by design (the agent never handles a secret).
      const cookies = await state.ctx.cookies(p.url ? String(p.url) : undefined);
      return {
        cookies: cookies.map((c) => ({
          name: c.name,
          domain: c.domain,
          path: c.path,
          expires: c.expires,
          httpOnly: c.httpOnly,
          secure: c.secure,
          sameSite: c.sameSite,
        })),
      };
    }
    case "batch": {
      // Run a short scripted sequence in one round trip. Sub-actions go back
      // through dispatch(), so per-action policy checks (read-only denials) still
      // apply to each step, AND coordinate actions (click-xy/drag-xy/scroll-xy/…)
      // work here too. Stops at the first failure. Optional --delay MS pauses
      // between steps (capped 5s) for sites that need time to settle (animations,
      // canvas repaints) before the next action.
      const actions = Array.isArray(p.actions) ? p.actions : [];
      if (!actions.length) throw new Error('batch needs --actions \'[{"action":"click","params":{"ref":"e1"}}, …]\'');
      if (actions.length > 20) throw new Error("batch: max 20 actions");
      const delay = Number(p.delay) > 0 ? Math.min(Number(p.delay), 5000) : 0;
      const results = [];
      for (const a of actions) {
        const name = a && typeof a.action === "string" ? a.action : null;
        if (!name || name === "batch" || name === "close") {
          throw new Error(`batch: unsupported action '${name}'`);
        }
        try {
          const r = await dispatch(state, { action: name, params: a.params || {}, _stateDir: msg._stateDir }, policy);
          results.push({ action: name, ok: true, ...r });
        } catch (err) {
          results.push({
            action: name,
            ok: false,
            error: err.message || String(err),
          });
          return { completed: results.length - 1, stopped: true, results };
        }
        if (delay) await new Promise((r) => setTimeout(r, delay));
      }
      return { completed: results.length, results };
    }
    default:
      throw new Error(`unknown action: ${msg.action}`);
  }
}

// Launch the session and serve actions until `close` (or a signal). Blocks.
// `policy` is the profile record's access policy ({access, accessRules}) —
// enforced HERE, in the process holding the live cookies, not in the client.
export async function runSession({
  stateDir,
  name,
  headless,
  dekHex,
  profileFile,
  workDir,
  policy = null,
  startUrl = null,
}) {
  const ctx = await launchContext({
    profileDir: workDir,
    headless,
    contextOptions: policy ? contextOptionsForAccess(policy) : {},
  });
  if (policy) {
    await applyAccessGuard(ctx, policy, {
      log: (m) => process.stderr.write(`${m}\n`),
    });
  }
  const page = ctx.pages()[0] || (await ctx.newPage());

  // Live session state: the current tab, the frame map from the latest
  // snapshot, and the ledgers the per-page listeners feed. Every page —
  // including tabs the site opens later (target=_blank, window.open) — gets
  // listeners via the context "page" event; the ro network gate is
  // context-level routing, so new tabs are inside it automatically.
  const state = {
    ctx,
    stateDir,
    current: page,
    frames: new Map(),
    refsValid: false,
    refsInvalidReason: "no snapshot yet",
    refGeneration: 0,
    downloads: [],
    console: [],
    dialog: { mode: "dismiss", text: null },
    lastDialog: null,
  };
  state.invalidateRefs = (reason) => invalidateRefs(state, reason);
  for (const pg of ctx.pages()) attachPage(state, pg);
  ctx.on("page", (pg) => attachPage(state, pg));

  // Live viewport stream (pair browsing). Its port +
  // token ride in the session file so the host runtime can relay it to the
  // owner's client; the feed and viewer input are suspended while fill-secret
  // / fill-otp inject credential values (see those dispatch cases).
  // Idle shutdown. A session holds a Chrome and a node process for as long as
  // it lives, and nothing used to end one: an agent that opened a browser and
  // moved on (or failed a login and gave up) left it running until the
  // container did, so profiles piled up holding memory and muddying "which
  // browser is this?". Any agent action or viewer input counts as use, and a
  // session with someone watching is never idle however quiet it is — the
  // owner may be reading a page or part-way through a sign-in.
  let lastActivityAt = Date.now();
  const touch = () => {
    lastActivityAt = Date.now();
  };
  const stream = await startStreamServer(state, {
    log: (m) => process.stderr.write(`${m}\n`),
    // h264 becomes the default for codec=auto viewers ONLY on a host the
    // owner provisioned via `agent-id-browser install-codecs`.
    h264Config: await loadCodecConfig(stateDir),
    resize: (width, height) => resizeToViewport(state, width, height),
    onActivity: touch,
  });
  state.stream = stream;

  // Single, idempotent shutdown: close the browser, RESEAL the refreshed profile,
  // wipe the plaintext working copy, remove the session file, then exit. Guarded
  // so the ctx "close" event (which ctx.close() itself fires) can't re-enter and
  // call process.exit before the reseal/cleanup finishes.
  let finalizing = false;
  async function finalize() {
    if (finalizing) return;
    finalizing = true;
    try {
      await ctx.close();
    } catch {
      /* already gone */
    }
    try {
      await sealProfile({
        stateDir,
        file: profileFile,
        dekHex,
        sourceDir: workDir,
      });
    } catch {
      /* best effort */
    }
    try {
      await fs.rm(workDir, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
    try {
      await fs.rm(sessionFilePath(stateDir, name), { force: true });
    } catch {
      /* best effort */
    }
    try {
      stream.close();
    } catch {
      /* not listening */
    }
    try {
      server.close();
    } catch {
      /* not listening */
    }
    process.exit(0);
  }

  // Closing on idle is the SAFE direction: finalize reseals the profile into
  // the vault first, so a signed-in session that times out keeps its cookies
  // and simply reopens next time. Set AGENT_ID_BROWSER_IDLE_MS=0 to disable.
  const idleMs = (() => {
    const raw = Number(process.env.AGENT_ID_BROWSER_IDLE_MS);
    if (Number.isFinite(raw)) return Math.max(0, raw);
    return DEFAULT_IDLE_MS;
  })();
  if (idleMs > 0) {
    const reaper = setInterval(() => {
      if (finalizing) return;
      if (stream.viewers() > 0) {
        touch(); // being watched is being used
        return;
      }
      if (Date.now() - lastActivityAt < idleMs) return;
      const forHuman =
        idleMs >= 60_000 ? `${Math.round(idleMs / 60_000)} min` : `${Math.round(idleMs / 1000)}s`;
      process.stderr.write(
        `Session '${name}' idle for ${forHuman} with no viewer — closing ` +
          `(profile is resealed; reopen with \`open --name ${name}\`).\n`
      );
      void finalize();
    }, IDLE_POLL_MS);
    reaper.unref?.();
  }

  const token = crypto.randomBytes(24).toString("hex");
  const server = net.createServer((sock) => {
    let buf = "";
    sock.on("data", async (d) => {
      buf += d.toString("utf8");
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      const line = buf.slice(0, nl);
      let msg;
      try { msg = JSON.parse(line); } catch { sock.end(JSON.stringify({ ok: false, error: "bad json" }) + "\n"); return; }
      if (msg.token !== token) { sock.end(JSON.stringify({ ok: false, error: "bad token" }) + "\n"); return; }
      if (msg.action === "close") {
        sock.end(JSON.stringify({ ok: true, closed: true }) + "\n");
        finalize(); // reseals, wipes, and exits (once cleanup completes)
        return;
      }
      msg._stateDir = stateDir;
      touch();
      try {
        const result = await dispatch(state, msg, policy);
        sock.end(JSON.stringify({ ok: true, ...result }) + "\n");
      } catch (err) {
        sock.end(JSON.stringify({ ok: false, error: err.message || String(err) }) + "\n");
      }
    });
    sock.on("error", () => {});
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  await fs.mkdir(sessionsDir(stateDir), { recursive: true, mode: 0o700 });
  await fs.writeFile(
    sessionFilePath(stateDir, name),
    JSON.stringify(
      sessionRecord(name, {
        port,
        token,
        pid: process.pid,
        headless,
        startedAt: Date.now(),
        streamPort: stream.port,
        streamToken: stream.token,
      })
    ),
    { mode: 0o600 }
  );
  // Optional start page: navigate BEFORE the ready line so "ready" means "up
  // and on the requested page". Non-fatal — a bad/slow URL still yields a
  // usable session; the outcome rides along in the ready JSON.
  let navigation = null;
  if (startUrl) {
    try {
      const resp = await page.goto(String(startUrl), {
        waitUntil: "domcontentloaded",
        timeout: 30000,
      });
      navigation = { url: page.url(), status: resp ? resp.status() : null };
    } catch (err) {
      navigation = {
        url: String(startUrl),
        error: String(err?.message || err),
      };
    }
  }
  // Readiness signal: the agent runs `open` in the background and waits for this
  // line before issuing actions.
  process.stdout.write(
    JSON.stringify({
      ok: true,
      ready: true,
      session: name,
      headless,
      port,
      ...(navigation ? { navigation } : {}),
    }) + "\n"
  );

  // Reseal + clean up if the browser dies or we're terminated. finalize() handles
  // the exit itself, so these just invoke it (idempotent).
  ctx.on("close", () => { finalize(); });
  for (const sig of ["SIGINT", "SIGTERM"]) {
    process.on(sig, () => { finalize(); });
  }
  return { port };
}

// Close a live session daemon for `name` (if any) and wait until it has
// re-sealed its profile and exited. Returns true when a session was closed,
// false when none was open.
//
// Every command that SEALS a profile (`login`, `auto-login`) must call this
// first. A daemon holds an unsealed copy of the profile taken at `open` time,
// and `finalize()` re-seals that copy on close — so sealing a fresh login
// underneath a live daemon is lost twice over: the next `open` reuses the
// running daemon (never re-reading the vault), and its eventual close writes
// the stale, logged-out copy back over the new session. Observed end to end:
// auto-login reported `logged-in`, `open` of the same profile showed the login
// form, and the sealed login was gone after the close.
//
// Waiting for the session FILE to disappear is what makes this safe: finalize()
// removes it only after the reseal, so once it is gone the profile file is
// stable and ours to overwrite. A stale file (daemon died without finalize) is
// removed so the next open does not keep trying to reach it.
export async function closeLiveSession(stateDir, name, { log = () => {}, timeoutMs = 30000 } = {}) {
  const file = sessionFilePath(stateDir, name);
  let info = null;
  try {
    info = JSON.parse(await fs.readFile(file, "utf8"));
  } catch {
    return false;
  }
  log(`Closing the open '${name}' session (pid ${info.pid ?? "?"}) so the new login is not overwritten by its stale copy.`);
  try {
    await callSession(stateDir, name, "close", {}, timeoutMs);
  } catch (err) {
    if (err && err.code === "NO_SESSION") {
      await fs.rm(file, { force: true }).catch(() => {});
      return false;
    }
    throw err;
  }
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await fs.access(file);
    } catch {
      return true;
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  const e = new Error(
    `session '${name}' did not finish closing within ${Math.round(
      timeoutMs / 1000
    )}s — ` +
      "its re-seal would race the new login; retry once it is gone (`sessions` lists it)"
  );
  e.code = "SESSION_BUSY";
  throw e;
}

// Client: send one action to a running session, return its JSON reply.
export async function callSession(stateDir, name, action, params = {}, timeoutMs = 35000) {
  let info = null;
  for (let attempt = 0; attempt < 10 && !info; attempt++) {
    try {
      info = JSON.parse(await fs.readFile(sessionFilePath(stateDir, name), "utf8"));
    } catch {
      await new Promise((r) => setTimeout(r, 300)); // tolerate the open→ready race
    }
  }
  if (!info) {
    const e = new Error(`no open session named '${name}' — run \`open --name ${name}\` first`);
    e.code = "NO_SESSION";
    throw e;
  }
  return await new Promise((resolve, reject) => {
    const sock = net.connect(info.port, "127.0.0.1");
    let buf = "";
    const to = setTimeout(() => { sock.destroy(); reject(new Error("session timed out")); }, timeoutMs);
    sock.on("connect", () => sock.write(JSON.stringify({ token: info.token, action, params }) + "\n"));
    sock.on("data", (d) => {
      buf += d.toString("utf8");
      const nl = buf.indexOf("\n");
      if (nl >= 0) {
        clearTimeout(to);
        try { resolve(JSON.parse(buf.slice(0, nl))); } catch (e) { reject(e); }
        sock.end();
      }
    });
    sock.on("error", (err) => { clearTimeout(to); const e = new Error(`session unreachable: ${err.message}`); e.code = "NO_SESSION"; reject(e); });
  });
}
