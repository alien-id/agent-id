// Alien Agent ID — Secure-prompt provider abstraction.
//
// One interface for "ask a human to type a secret, out of band, so it never
// crosses the agent's stdin/stdout/transcript." It decouples the secure-entry
// *surface* from any single mechanism: today a loopback browser form or the
// controlling terminal's /dev/tty; tomorrow a mobile-app form or a hosted
// harness's secure widget — selected per environment with a deterministic
// fallback chain.
//
// A provider implements:
//   name          — short id ("browser" | "tty" | "hosted" | …)
//   isAvailable() — usable in this environment right now?
//   capabilities()→ { multiField, secret, multiline }
//   collect(spec) → Promise<{ values: { <fieldName>: string } }>
//   runCeremony?(webauthn, spec?) — OPTIONAL, browser-only (passkey PRF). WebAuthn
//                 is deliberately NOT part of collect(): it serves a different page
//                 and returns ceremony bytes, not typed values, and is intrinsically
//                 browser-only (localhost rpId, Touch ID). Passkey callers use
//                 collectViaForm({webauthn}) directly; runCeremony exists only so a
//                 provider can advertise the capability.
//
// `spec` is exactly the shape collectViaForm already accepts:
//   { title, description, fields, label, security, submitLabel, timeoutMs }
//   fields: [{ name, label?, secret?=true, required?=true, multiline?, placeholder? }]
//
// resolveSecurePrompt() picks the first available provider whose capabilities
// satisfy the spec, in order: hosted → …extraProviders (e.g. mobile) → browser → tty.
// The browser form is the guaranteed last resort (it degrades to printing a URL the
// human can open over SSH), so there is always a provider. Most callers just use
// collectSecret(spec).

import { statSync } from "node:fs";
import http from "node:http";

import { collectViaForm } from "./secure-form.mjs";
import {
  promptSecret,
  promptText,
  hasTty,
  notifyTty,
} from "./trusted-input.mjs";

// ─── Browser loopback form (the existing mechanism, wrapped) ─────────────────────

export class BrowserFormProvider {
  constructor({ env = process.env } = {}) {
    this.name = "browser";
    this._env = env;
  }
  isAvailable() {
    // Disabled only by explicit opt-out (AGENT_ID_NO_BROWSER); otherwise usable —
    // it auto-opens a browser window, or prints the URL for the human to open by
    // hand, so it works headless / over an SSH tunnel too.
    return !this._env.AGENT_ID_NO_BROWSER;
  }
  capabilities() {
    return { multiField: true, secret: true, multiline: true };
  }
  collect(spec) {
    return collectViaForm(spec);
  }
  // Browser-only passkey ceremony passthrough (see module header).
  runCeremony(webauthn, spec = {}) {
    return collectViaForm({ ...spec, webauthn });
  }
}

// ─── /dev/tty prompt (the no-GUI fallback) ───────────────────────────────────────

export class TtyProvider {
  constructor() {
    this.name = "tty";
  }
  isAvailable() {
    return hasTty();
  }
  capabilities() {
    // readLineNoEcho reads to the first newline → single-line input only.
    return { multiField: true, secret: true, multiline: false };
  }
  async collect(spec) {
    const fields = Array.isArray(spec.fields) ? spec.fields : [];
    // Show the non-secret context on the terminal (the same surface as the
    // prompts) — stderr may be piped to the agent.
    if (spec.title) notifyTty(`\n${spec.title}`);
    if (spec.description) notifyTty(spec.description);
    const values = {};
    for (const f of fields) {
      const label = f.label || f.name;
      const opt = f.required === false ? " (optional)" : "";
      const prompt = `  ${label}${opt}: `;
      values[f.name] = f.secret === false ? promptText(prompt) : promptSecret(prompt);
    }
    return { values };
  }
}

// ─── Hosted harness form (experimental seam) ─────────────────────────────────────
//
// SECURITY: the entry surface is provided by the HOSTING HARNESS over a
// unix-domain socket it owns (owner-only perms). We deliberately accept ONLY a
// unix socket — never a TCP/URL endpoint — because a TCP endpoint chosen from an
// agent-influenced env var could be pointed at a listener the agent controls,
// turning the "out-of-band" channel into a secret-harvesting MITM. The socket
// path is set by the harness (a more-privileged principal); enabling this is a
// harness-owner trust decision, not an agent opt-in. Experimental until a concrete
// harness ships against the protocol below.
//
// Protocol: POST / on the socket with the JSON `spec`; the harness presents its
// secure surface, collects the values, and replies 200 `{ values: {<name>:str} }`.

const HOSTED_SOCK_ENV = "AGENT_ID_SECURE_PROMPT_SOCK";

// Validated unix-socket path from the env, or null. Refuses URLs/TCP and anything
// that isn't an existing socket.
function hostedSocketPath(env) {
  const p = env[HOSTED_SOCK_ENV];
  if (!p || typeof p !== "string" || p.includes("://")) return null;
  try {
    return statSync(p).isSocket() ? p : null;
  } catch {
    return null;
  }
}

// Why a card was dismissed, when the host said. Unreadable or absent leaves the
// plain dismissal, which is what every host that predates the button sends.
function readDismissalReason(body) {
  try {
    const reason = JSON.parse(body.toString("utf8"))?.reason;
    return typeof reason === "string" && reason ? reason : null;
  } catch {
    return null;
  }
}

export class HostedHarnessProvider {
  constructor({ env = process.env } = {}) {
    this.name = "hosted";
    this._env = env;
  }
  isAvailable() {
    return hostedSocketPath(this._env) != null;
  }
  capabilities() {
    return { multiField: true, secret: true, multiline: true };
  }
  collect(spec) {
    const socketPath = hostedSocketPath(this._env);
    if (!socketPath) return Promise.reject(new Error("hosted secure prompt is not configured"));
    const payload = JSON.stringify({
      title: spec.title || "",
      description: spec.description || "",
      fields: spec.fields || [],
      label: spec.label || "",
      security: spec.security || "",
      submitLabel: spec.submitLabel || "",
      timeoutMs: spec.timeoutMs || null,
    });
    return new Promise((resolve, reject) => {
      const req = http.request(
        {
          socketPath,
          path: "/",
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(payload),
          },
        },
        (res) => {
          const chunks = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => {
            if (res.statusCode !== 200) {
              // 409 is the owner closing the card, not a fault: the host says so
              // explicitly. Without a code of its own it arrives as a bare HTTP
              // error, and a caller that cannot tell "they declined" from "it
              // broke" retries — putting the same card back in front of someone
              // who has just dismissed it.
              //
              // The body may also say HOW it was closed. `use_browser` is the
              // card's own button: the owner still means to sign in, just not
              // here, and a caller that cannot tell that from a refusal reports
              // the task abandoned when it was only handed over.
              const reason =
                res.statusCode === 409
                  ? readDismissalReason(Buffer.concat(chunks))
                  : null;
              const error = new Error(
                res.statusCode !== 409
                  ? `hosted secure prompt: HTTP ${res.statusCode}`
                  : reason === "use_browser"
                    ? "hosted secure prompt: the owner will sign in through the browser instead"
                    : "hosted secure prompt: the owner dismissed the card"
              );
              if (res.statusCode === 409) {
                error.code =
                  reason === "use_browser" ? "FORM_USE_BROWSER" : "FORM_CANCELLED";
              }
              reject(error);
              return;
            }
            try {
              const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
              if (!body || typeof body.values !== "object" || body.values == null) {
                reject(new Error("hosted secure prompt: response missing { values }"));
                return;
              }
              resolve({ values: body.values });
            } catch (err) {
              reject(new Error(`hosted secure prompt: bad JSON response (${err.message})`));
            }
          });
        }
      );
      req.on("error", reject);
      if (spec.timeoutMs) {
        req.setTimeout(spec.timeoutMs, () => {
          // The same reason the dismissal above carries a code: callers tell an
          // expiry from a fault by `err.code`, and without one this arrived as an
          // ordinary error. Auto-login's `otp-timeout` outcome was unreachable
          // whenever the card came from the hosted provider — which is the first
          // one tried, and the one a card on a phone comes from.
          const error = new Error("hosted secure prompt timed out");
          error.code = "FORM_TIMEOUT";
          req.destroy(error);
        });
      }
      req.end(payload);
    });
  }
}

// ─── Resolver ────────────────────────────────────────────────────────────────────

function specNeeds(spec) {
  const fields = spec && Array.isArray(spec.fields) ? spec.fields : [];
  return { multiline: fields.some((f) => f && f.multiline) };
}

/**
 * Pick the first available provider whose capabilities satisfy `need`, in order:
 *   hosted → …extraProviders (e.g. a mobile/push provider) → browser → tty
 * Falls back to the browser form (always works — prints a URL when it can't open a
 * window) so there is always a provider.
 *
 *   env            — environment to read (default process.env)
 *   extraProviders — caller-supplied providers (e.g. a control-plane mobile
 *                    provider) inserted right after `hosted`
 *   need           — { multiline? } capability requirements
 */
export function resolveSecurePrompt({
  env = process.env,
  extraProviders = [],
  need = {},
} = {}) {
  const browser = new BrowserFormProvider({ env });
  // Explicit operator override: AGENT_ID_SECURE_PROMPT=browser|tty|hosted (or the
  // name of an extraProvider, e.g. "mobile") forces that backend regardless of the
  // usual availability ordering. An unknown name falls through to normal resolution.
  const forced = env.AGENT_ID_SECURE_PROMPT;
  if (forced) {
    const extra = extraProviders.find((p) => p && p.name === forced);
    if (extra) return extra;
    if (forced === "browser") return browser;
    if (forced === "tty") return new TtyProvider();
    if (forced === "hosted") return new HostedHarnessProvider({ env });
  }
  const chain = [
    new HostedHarnessProvider({ env }),
    ...extraProviders,
    browser,
    new TtyProvider(),
  ];
  for (const p of chain) {
    if (!p.isAvailable || !p.isAvailable()) continue;
    const caps = (p.capabilities && p.capabilities()) || {};
    if (need.multiline && !caps.multiline) continue;
    return announce(p, env);
  }
  return announce(browser, env); // guaranteed last resort (prints the URL when it can't open)
}

// Which backend the owner's card is about to be asked through, and — when it is
// not the hosted one — why not. Silence here cost a production week: a card that
// never left the machine and a card the owner ignored produced exactly the same
// logs, so the only visible symptom was a tool that waited and asked nobody.
function announce(provider, env) {
  const name = provider && provider.name ? provider.name : "unknown";
  if (name !== "hosted") {
    const sock = env.AGENT_ID_SECURE_PROMPT_SOCK;
    const why = !sock
      ? "AGENT_ID_SECURE_PROMPT_SOCK is not set"
      : `no socket at ${sock}`;
    process.stderr.write(
      `secure prompt: asking through '${name}', NOT the owner's device — ${why}\n`
    );
  }

  return provider;
}

/**
 * Resolve a provider for `spec` (inferring capability needs from its fields) and
 * collect the values. The ergonomic entry point for call sites that previously
 * called collectViaForm directly. Returns { values: { <fieldName>: string } }.
 */
export function collectSecret(
  spec,
  { env = process.env, extraProviders = [] } = {}
) {
  const provider = resolveSecurePrompt({
    env,
    extraProviders,
    need: specNeeds(spec),
  });
  return provider.collect(spec);
}
