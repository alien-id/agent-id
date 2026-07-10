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
import { captureSessionCookies, sealProfile } from "./profile-store.mjs";
import { openVault, loadAgentPrivateKey } from "@alien-id/agent-id-vault/lib/vault.mjs";
import { SECRET_FIELDS, hostMatchesAllowlist } from "@alien-id/agent-id-vault/lib/store.mjs";
import { resolveOtp } from "./auto-login.mjs";
import {
  applyAccessGuard,
  assertActionAllowed,
  contextOptionsForAccess,
} from "./access-guard.mjs";
import {
  humanClick,
  humanHover,
  humanMove,
  humanScroll,
  humanType,
  humanTypeFocused,
} from "./human-input.mjs";

function sessionsDir(stateDir) {
  return path.join(stateDir, "browser-sessions");
}
export function sessionFilePath(stateDir, name) {
  return path.join(sessionsDir(stateDir), `${name}.json`);
}

// Runs in the page (once per frame). Tags visible interactive elements and
// returns a flat list. `prefix` namespaces refs per frame: "" for the main
// frame ("e1", "e2", …), "f1" for the first iframe ("f1e1", …) — so a ref is
// self-describing about which frame it lives in.
export function snapshotInPage(prefix) {
  const pre = prefix || "";
  const SEL = [
    "a[href]", "button", "input:not([type=hidden])", "textarea", "select",
    "[role=button]", "[role=link]", "[role=textbox]", "[role=checkbox]",
    "[role=radio]", "[role=tab]", "[role=menuitem]", "[role=option]",
    "[contenteditable=true]", "summary", "[tabindex]:not([tabindex='-1'])",
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
    const r = el.getBoundingClientRect();
    const st = window.getComputedStyle(el);
    if (r.width === 0 || r.height === 0 || st.visibility === "hidden" || st.display === "none") {
      continue;
    }
    const ref = pre + "e" + ++i;
    el.setAttribute("data-aibref", ref);
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

const sel = (ref) => `[data-aibref="${String(ref).replace(/["\\]/g, "")}"]`;
const ACTION_TIMEOUT = 15000;
const MAX_FRAMES = 12; // iframes snapshotted per page (ad-heavy pages have dozens)
const CONSOLE_CAP = 300; // ring-buffer size for captured console/pageerror entries

// "f1e3" → "f1"; plain main-frame refs ("e3") → null. Exported for tests.
export function frameRefId(ref) {
  const m = /^(f\d+)e\d+$/.exec(String(ref ?? ""));
  return m ? m[1] : null;
}

// A download's suggested filename, made safe to join under the sessions dir
// (no separators / traversal, bounded length). Exported for tests.
export function safeFilename(name) {
  const cleaned = String(name || "").replace(/[^\w.-]+/g, "_").replace(/^\.+/, "");
  return (cleaned || "file").slice(0, 80);
}

// Screenshot pixels → viewport (CSS) pixels. The PNG is captured at the context's
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
  const id = frameRefId(ref);
  if (!id) return state.current;
  const frame = state.frames.get(id);
  if (!frame || frame.isDetached()) {
    throw new Error(`frame for ref '${ref}' is gone — re-snapshot and retry`);
  }
  return frame;
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

// `get --what value|attr value` must not read back a field that holds an injected
// secret: the vault may have just typed one there (fill-secret/fill-otp), and
// returning it would hand the agent the very value the vault exists to withhold.
// Refuse a password-type input AND any field the vault tagged tainted — the
// latter catches secrets typed into a non-password field (see markSecretField).
export async function refusePasswordRead(target, selector) {
  const refuse = await target
    .$eval(
      selector,
      (el, attr) => (el.tagName === "INPUT" && el.type === "password") || el.hasAttribute(attr),
      SECRET_TAINT_ATTR,
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
  page.on("console", (msg) => pushConsole(state, { type: msg.type(), text: String(msg.text()).slice(0, 500) }));
  page.on("pageerror", (err) => pushConsole(state, { type: "error", text: String(err && err.message ? err.message : err).slice(0, 500) }));
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
      `download-${Date.now()}-${safeFilename(d.suggestedFilename())}`,
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
  page.on("close", () => {
    if (state.current !== page) return;
    const left = state.ctx.pages().filter((pg) => pg !== page);
    if (left.length) {
      state.current = left[left.length - 1];
      state.frames.clear();
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
      `"${field}" is sealed (generated in-vault) and cannot be typed into a page — use the proxy`,
    );
  }
  if (!hostMatchesAllowlist(host, rec.domains)) {
    throw new Error(
      `refusing to type this credential on "${host || "(no host)"}" — not on its domain ` +
        `allowlist (${(rec.domains || []).join(", ") || "none"}). Add the host to the ` +
        "credential's domains (wildcards like *.example.com are allowed).",
    );
  }
}

async function dispatch(state, msg, policy = null) {
  const p = msg.params || {};
  const page = state.current;
  // Read-only sessions refuse the un-auditable/secret-bearing actions here;
  // everything else stays available because the network gate (applyAccessGuard)
  // is what actually stops mutations from reaching the service.
  if (policy) assertActionAllowed(policy, msg.action);
  switch (msg.action) {
    case "info":
      return { url: page.url(), title: await page.title().catch(() => ""), tabs: state.ctx.pages().length };
    case "navigate": {
      const resp = await page.goto(String(p.url), { waitUntil: "domcontentloaded", timeout: 30000 });
      return { url: page.url(), status: resp ? resp.status() : null };
    }
    case "back":
      await page.goBack({ waitUntil: "domcontentloaded" }).catch(() => {});
      return { url: page.url() };
    case "snapshot": {
      state.frames.clear();
      const main = await page.evaluate(snapshotInPage, "");
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
          snap = await f.evaluate(snapshotInPage, `f${fCount + 1}`);
        } catch {
          continue; // detached / navigating frame — nothing was tagged
        }
        fCount++;
        state.frames.set(`f${fCount}`, f);
        if (snap.elements.length) {
          frames.push({ frame: `f${fCount}`, url: String(snap.url).slice(0, 200), elements: snap.elements.length });
          main.elements.push(...snap.elements);
        }
      }
      const tabs = state.ctx.pages().length;
      return {
        ...main,
        ...(frames.length ? { frames } : {}),
        ...(skipped ? { framesSkipped: skipped } : {}),
        ...(tabs > 1 ? { tabs, tab: state.ctx.pages().indexOf(page) } : {}),
      };
    }
    case "text":
      return { text: String(await page.evaluate(() => (document.body ? document.body.innerText : ""))).slice(0, Number(p.maxChars || 6000)) };
    case "click":
      await humanClick(page, sel(p.ref), { timeout: ACTION_TIMEOUT, root: frameForRef(state, p.ref) });
      return { clicked: p.ref };
    case "dblclick":
      await frameForRef(state, p.ref).dblclick(sel(p.ref), { timeout: ACTION_TIMEOUT });
      return { dblclicked: p.ref };
    case "check":
      await frameForRef(state, p.ref).check(sel(p.ref), { timeout: ACTION_TIMEOUT });
      return { checked: p.ref };
    case "uncheck":
      await frameForRef(state, p.ref).uncheck(sel(p.ref), { timeout: ACTION_TIMEOUT });
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
        await humanType(page, sel(f.ref), String(f.value ?? ""), {
          timeout: ACTION_TIMEOUT,
          root: frameForRef(state, f.ref),
        });
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
      return { filled: p.ref, cred: p.cred };
    }
    case "fill-otp": {
      // Resolve the current 2FA code for a login/totp cred — generated from a
      // stored seed, or asked via the secure prompt — and type it.
      const credName = String(p.cred || "");
      const target = frameForRef(state, p.ref);
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
            ? { name: credName, otp: "totp", totpSecret: rec.secret, period: rec.period, digits: rec.digits, algorithm: rec.algorithm }
            : rec;
        code = await resolveOtp(otpCred, {});
      } finally {
        vault.lock();
      }
      // Same leak guard as fill-secret: never surface the value-bearing error.
      try {
        await humanType(page, sel(p.ref), code, {
          timeout: ACTION_TIMEOUT,
          submit: p.submit !== false,
          root: target,
        });
      } catch {
        throw new Error(`fill-otp: could not fill "${p.ref}" — element not visible/editable (re-snapshot and retry)`);
      }
      // A derived OTP isn't sealed at fill time (see assertFillAllowed), so the
      // read-back guard is what protects it: tag the field so its value can't be
      // read back regardless of the input's type (OTP inputs are text/tel).
      await markSecretField(target, sel(p.ref));
      return { filled: p.ref, otp: true };
    }
    case "select":
      await frameForRef(state, p.ref).selectOption(sel(p.ref), p.values, { timeout: ACTION_TIMEOUT });
      return { selected: p.ref };
    case "hover":
      await humanHover(page, sel(p.ref), { timeout: ACTION_TIMEOUT, root: frameForRef(state, p.ref) });
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
      const files = (Array.isArray(p.files) ? p.files : []).map(String).filter(Boolean);
      if (!files.length) throw new Error("upload needs --files /path/a[,/path/b]");
      for (const f of files) {
        try {
          await fs.access(f);
        } catch {
          throw new Error(`upload: file not found: ${f}`);
        }
      }
      const t = frameForRef(state, p.ref);
      const s = sel(p.ref);
      const isFileInput = await t
        .$eval(s, (el) => el.tagName === "INPUT" && el.type === "file")
        .catch(() => false);
      if (isFileInput) {
        await t.setInputFiles(s, files, { timeout: ACTION_TIMEOUT });
      } else {
        // Not a bare <input type=file>: click it and feed the native chooser.
        const [chooser] = await Promise.all([
          page.waitForEvent("filechooser", { timeout: ACTION_TIMEOUT }),
          t.click(s, { timeout: ACTION_TIMEOUT }),
        ]);
        await chooser.setFiles(files);
      }
      return { uploaded: p.ref, files: files.length };
    }
    case "drag": {
      const from = frameForRef(state, p.ref);
      if (from !== frameForRef(state, p.to)) {
        throw new Error("drag: source and target must be in the same frame");
      }
      await from.dragAndDrop(sel(p.ref), sel(p.to), { timeout: ACTION_TIMEOUT });
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
      return { clicked: { x, y }, button, ...(p.double ? { double: true } : {}) };
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
      const element = await page.evaluate(([px, py]) => {
        const el = document.elementFromPoint(px, py);
        if (!el) return null;
        const r = el.getBoundingClientRect();
        const clip = (s) => (s ? String(s).replace(/\s+/g, " ").trim().slice(0, 100) : "");
        return {
          tag: el.tagName.toLowerCase(),
          role: el.getAttribute("role") || null,
          type: el.getAttribute("type") || null,
          ref: el.getAttribute("data-aibref") || null, // present only after a snapshot
          name: clip(
            el.getAttribute("aria-label") ||
              el.getAttribute("placeholder") ||
              el.getAttribute("title") ||
              el.textContent,
          ),
          href: el.getAttribute("href") || null,
          box: { x: Math.round(r.x), y: Math.round(r.y), width: Math.round(r.width), height: Math.round(r.height) },
        };
      }, [x, y]);
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
      const before = await page
        .evaluate(() => [window.innerWidth, window.innerHeight])
        .catch(() => null);
      const cdp = await state.ctx.newCDPSession(page);
      try {
        const { windowId } = await cdp.send("Browser.getWindowForTarget");
        // Two steps: exit maximized/fullscreen FIRST, else Chrome applies the
        // state change and ignores the bounds in the same call.
        await cdp.send("Browser.setWindowBounds", { windowId, bounds: { windowState: "normal" } }).catch(() => {});
        await cdp.send("Browser.setWindowBounds", { windowId, bounds: { width, height } });
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
            { timeout: 3000 },
          )
          .catch(() => {});
      }
      const viewport = await page
        .evaluate(() => ({ width: window.innerWidth, height: window.innerHeight }))
        .catch(() => null);
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
      const out = p.path ? String(p.path) : path.join(sessionsDir(msg._stateDir), `shot-${Date.now()}.png`);
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
          await page.screenshot({ path: out, clip });
        } catch (err) {
          throw new Error(`screenshot --region could not capture (region likely outside the page): ${err.message || err}`);
        }
        return {
          screenshot: out,
          dpr: info.dpr,
          region,
          image: { width: Math.round(clip.width * info.dpr), height: Math.round(clip.height * info.dpr) },
        };
      }
      await page.screenshot({ path: out, fullPage: !!p.fullPage });
      const result = { screenshot: out, dpr: info.dpr };
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
        await page.waitForURL((u) => u.href.includes(needle), { timeout: Number(p.ms || 15000) });
      } else if (p.load) {
        const stateName = String(p.load);
        if (!["load", "domcontentloaded", "networkidle"].includes(stateName)) {
          throw new Error("wait --load must be load|domcontentloaded|networkidle");
        }
        await page.waitForLoadState(stateName, { timeout: Number(p.ms || 15000) });
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
          return { text: String(await t.innerText(s, { timeout: ACTION_TIMEOUT })).slice(0, cap) };
        case "html":
          return { html: String(await t.innerHTML(s, { timeout: ACTION_TIMEOUT })).slice(0, cap) };
        case "value":
          await refusePasswordRead(t, s);
          return { value: await t.inputValue(s, { timeout: ACTION_TIMEOUT }) };
        case "attr": {
          if (!p.attr) throw new Error("get --what attr needs --attr NAME");
          if (String(p.attr).toLowerCase() === "value") await refusePasswordRead(t, s);
          return { attr: p.attr, value: await t.getAttribute(s, String(p.attr), { timeout: ACTION_TIMEOUT }) };
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
          return { editable: await t.isEditable(s, { timeout: ACTION_TIMEOUT }) };
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
          })),
        ),
      };
    }
    case "tab-new": {
      const pg = await state.ctx.newPage();
      if (p.url) await pg.goto(String(p.url), { waitUntil: "domcontentloaded", timeout: 30000 });
      state.current = pg;
      state.frames.clear();
      return { index: state.ctx.pages().indexOf(pg), url: pg.url() };
    }
    case "tab-switch": {
      const pages = state.ctx.pages();
      const index = Number(p.index);
      if (!Number.isInteger(index) || index < 0 || index >= pages.length) {
        throw new Error(`no tab ${p.index} (open tabs: 0..${pages.length - 1})`);
      }
      state.current = pages[index];
      state.frames.clear();
      await state.current.bringToFront().catch(() => {});
      return { index, url: state.current.url(), title: await state.current.title().catch(() => "") };
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
      return { mode: state.dialog.mode, promptText: state.dialog.text, last: state.lastDialog };
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
          ? { note: "empty is expected: the stealth driver suppresses most console events — use `eval` to probe page state instead" }
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
          results.push({ action: name, ok: false, error: err.message || String(err) });
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
    downloads: [],
    console: [],
    dialog: { mode: "dismiss", text: null },
    lastDialog: null,
  };
  for (const pg of ctx.pages()) attachPage(state, pg);
  ctx.on("page", (pg) => attachPage(state, pg));

  // Single, idempotent shutdown: close the browser, RESEAL the refreshed profile,
  // wipe the plaintext working copy, remove the session file, then exit. Guarded
  // so the ctx "close" event (which ctx.close() itself fires) can't re-enter and
  // call process.exit before the reseal/cleanup finishes.
  let finalizing = false;
  async function finalize() {
    if (finalizing) return;
    finalizing = true;
    try { await captureSessionCookies({ context: ctx, profileDir: workDir }); } catch { /* already gone */ }
    try { await ctx.close(); } catch { /* already gone */ }
    try { await sealProfile({ stateDir, file: profileFile, dekHex, sourceDir: workDir }); } catch { /* best effort */ }
    try { await fs.rm(workDir, { recursive: true, force: true }); } catch { /* best effort */ }
    try { await fs.rm(sessionFilePath(stateDir, name), { force: true }); } catch { /* best effort */ }
    try { server.close(); } catch { /* not listening */ }
    process.exit(0);
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
    JSON.stringify({ port, token, pid: process.pid, headless, startedAt: Date.now() }),
    { mode: 0o600 },
  );
  // Readiness signal: the agent runs `open` in the background and waits for this
  // line before issuing actions.
  process.stdout.write(JSON.stringify({ ok: true, ready: true, session: name, headless, port }) + "\n");

  // Reseal + clean up if the browser dies or we're terminated. finalize() handles
  // the exit itself, so these just invoke it (idempotent).
  ctx.on("close", () => { finalize(); });
  for (const sig of ["SIGINT", "SIGTERM"]) {
    process.on(sig, () => { finalize(); });
  }
  return { port };
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
