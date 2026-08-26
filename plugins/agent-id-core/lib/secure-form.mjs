// Alien Agent ID — Out-of-band secure entry form.
//
// A one-shot HTML form served on 127.0.0.1 so a human can type a secret (a new
// credential value, or the vault unlock passphrase) WITHOUT it ever crossing the
// agent's stdin/stdout/transcript. The value travels browser → loopback → this
// process; the form opens directly in the human's browser (the URL is printed only
// as a headless fallback), so the agent that spawned the CLI only sees a "waiting…"
// notice and a name-only result.
//
// Why a loopback browser form (vs native dialogs / tty): one zero-dep code path,
// works on every OS that has a browser, works headless via an SSH tunnel, and is
// natural for multi-field entry and the unlock page. /dev/tty (trusted-input.mjs)
// remains the no-GUI fallback.
//
// Security: binds 127.0.0.1 only; random port; a 256-bit one-time token gates
// every request (defeats other local processes and cross-site POSTs); single-use
// then shuts down; request body capped; values are never logged. The residual
// same-uid limit (a co-resident same-user process could scrape this process's
// memory) is unchanged — the hard boundary is running the proxy as a separate
// principal; this module closes the transcript-exposure and agent-self-serve gaps.

import http from "node:http";
import { spawn, execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { randomBytes, timingSafeEqual } from "node:crypto";

const BODY_CAP_BYTES = 1 << 20; // 1 MiB — secrets are small; cap abuse.

// Headers for every page response. The page is fully self-contained (inline style
// + script, no external anything) and may only POST to itself — a strict CSP is
// cheap defense-in-depth on top of the per-field HTML escaping.
const PAGE_HEADERS = {
  "Content-Type": "text/html; charset=utf-8",
  "Cache-Control": "no-store",
  "Referrer-Policy": "no-referrer",
  "Content-Security-Policy":
    "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'",
};

function htmlEscape(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]),
  );
}

function tokenEquals(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

// Does `bin` exist? Absolute path → stat it; bare command → which/where it.
function resolvesBin(bin) {
  if (bin.includes("/") || bin.includes("\\")) return existsSync(bin);
  try {
    execFileSync(process.platform === "win32" ? "where" : "which", [bin], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

// Ordered launch candidates. We prefer a Chromium browser in APP mode
// (`--app=<url> --window-size=W,H`): its own dedicated window, sized to the form,
// with no tab strip or address bar — so it reads as a secure dialog, not a tab in
// whatever the user was doing. Firefox falls back to `--new-window`; only when no
// known browser is found do we use the generic opener (which may reuse a tab).
function browserCandidates(url, w, h) {
  const app = (bin) => ({ bin, args: [`--app=${url}`, `--window-size=${w},${h}`] });
  if (process.platform === "darwin") {
    return [
      app("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
      app("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
      app("/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"),
      app("/Applications/Arc.app/Contents/MacOS/Arc"),
      app("/Applications/Chromium.app/Contents/MacOS/Chromium"),
      { bin: "/Applications/Firefox.app/Contents/MacOS/firefox", args: ["--new-window", url] },
      { bin: "open", args: [url] }, // last resort: default browser (likely a tab)
    ];
  }
  if (process.platform === "win32") {
    const PF = process.env["ProgramFiles"] || "C:\\Program Files";
    const PF86 = process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)";
    return [
      app("chrome"),
      app(`${PF}\\Google\\Chrome\\Application\\chrome.exe`),
      app(`${PF86}\\Google\\Chrome\\Application\\chrome.exe`),
      app("msedge"),
      app(`${PF86}\\Microsoft\\Edge\\Application\\msedge.exe`),
      { bin: "firefox", args: ["--new-window", url] },
      { bin: "cmd", args: ["/c", "start", "", url] }, // fallback (tab)
    ];
  }
  return [
    app("google-chrome"),
    app("google-chrome-stable"),
    app("chromium"),
    app("chromium-browser"),
    app("microsoft-edge"),
    app("brave-browser"),
    { bin: "firefox", args: ["--new-window", url] },
    { bin: "xdg-open", args: [url] }, // fallback (tab)
  ];
}

// Open `url` in its own browser window sized to `size` (best-effort). Returns true
// if a launcher was spawned. AGENT_ID_NO_BROWSER forces the print-the-URL fallback.
export function openBrowser(url, size = { width: 470, height: 470 }) {
  if (process.env.AGENT_ID_NO_BROWSER) return false;
  for (const c of browserCandidates(url, size.width, size.height)) {
    if (!resolvesBin(c.bin)) continue;
    try {
      const child = spawn(c.bin, c.args, { stdio: "ignore", detached: true });
      child.on("error", () => {});
      child.unref();
      return true;
    } catch {
      // try the next candidate
    }
  }
  return false;
}

// WebAuthn PRF on macOS: only Safari surfaces Apple's platform PRF (Touch ID); the
// Chrome → iCloud-Keychain path reports the extension unsupported. So the passkey
// ceremony opens in Safari on macOS. Safari ignores in-page window.resizeTo() for a
// script-less tab, so we open a NEW window and size it from outside via AppleScript
// bounds (first use may show a one-time "control Safari" prompt). Elsewhere the
// normal browser handles WebAuthn fine.
function openForWebauthn(url, size) {
  if (process.env.AGENT_ID_NO_BROWSER) return false;
  if (process.platform === "darwin") {
    const w = Math.max((size && size.width) || 360, 372);
    const h = ((size && size.height) || 300) + 120; // room for Safari's toolbar + tab bar
    const L = 160;
    const T = 130;
    const script =
      `tell application "Safari"\n` +
      `  activate\n` +
      `  make new document with properties {URL:"${url}"}\n` +
      `  delay 0.2\n` +
      `  set bounds of front window to {${L}, ${T}, ${L + w}, ${T + h}}\n` +
      `end tell`;
    try {
      // Synchronous so we can detect an Automation-denied / AppleScript error and
      // fall back; the form server resumes serving the moment this returns.
      execFileSync("osascript", ["-e", script], { stdio: "ignore", timeout: 20000 });
      return true;
    } catch {
      // Denied or no AppleScript: just open a Safari tab (unsized, still works).
      try {
        const child = spawn("open", ["-a", "Safari", url], { stdio: "ignore", detached: true });
        child.on("error", () => {});
        child.unref();
        return true;
      } catch {
        // fall through to the default opener
      }
    }
  }
  return openBrowser(url, size);
}

// Tight initial size; the page's resize script then shrinks the window to the
// content's true size once rendered (app windows are script-resizable).
function windowSizeFor(fields) {
  const rows = Array.isArray(fields) ? fields.length : 1;
  const multiline = Array.isArray(fields) && fields.some((f) => f.multiline);
  return { width: 360, height: 250 + 66 * rows + (multiline ? 130 : 0) };
}

// Inline padlock — the "secure" logo. Stroke follows currentColor.
const LOCK = `<svg viewBox="0 0 24 24" width="1em" height="1em" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" style="vertical-align:-.15em"><rect x="3.5" y="11" width="17" height="10" rx="2.2"/><path d="M7.5 11V7.2a4.5 4.5 0 0 1 9 0V11"/></svg>`;

// Green "secure" theme. No rounded corners; compact, natural-height card with a
// thin green frame (the body background). A small script then resizes the window
// to the card's true size, so it opens snug to the form.
const SECURE_CSS = `
 :root{color-scheme:light dark}
 *{border-radius:0;box-sizing:border-box}
 html,body{margin:0}
 body{font:13.5px/1.45 -apple-system,Segoe UI,Roboto,sans-serif;background:Canvas;color:CanvasText;
   min-height:100vh;display:flex;align-items:center;justify-content:center;padding:8px}
 .card{width:336px;max-width:100%;background:Canvas;color:CanvasText;padding:14px 16px 16px;
   border:1px solid #16a34a55}
 .badge{display:inline-flex;align-items:center;gap:.35rem;background:#16a34a;color:#fff;
   padding:.18rem .5rem;font-size:.66rem;font-weight:800;letter-spacing:.07em}
 h1{font-size:1rem;margin:.5rem 0 .12rem}
 .desc{color:#6b7280;margin:0 0 .1rem;font-size:.8rem}
 .why{display:flex;gap:.4rem;align-items:flex-start;margin:.55rem 0 .75rem;
   background:#16a34a14;border-left:3px solid #16a34a;padding:.42rem .55rem;
   color:#15803d;font-size:.75rem;line-height:1.4}
 @media (prefers-color-scheme:dark){.why{color:#86efac}}
 .why svg{flex:0 0 auto;margin-top:.1rem}
 .why code{font-family:ui-monospace,Menlo,Consolas,monospace}
 label{display:block;margin:.5rem 0 .16rem;font-weight:600;font-size:.84rem}
 .opt{font-weight:400;color:#9ca3af}
 input,textarea{width:100%;padding:.46rem .52rem;font:inherit;border:1px solid #16a34a66;
   background:Field;color:FieldText}
 textarea{resize:vertical;min-height:4.2rem}
 input:focus,textarea:focus{outline:2px solid #16a34a;border-color:#16a34a}
 button{margin-top:.9rem;width:100%;padding:.52rem;border:0;background:#16a34a;color:#fff;
   font:inherit;font-weight:800;cursor:pointer}
 button:hover{background:#15803d}
 .pk-status{margin-top:.7rem;color:#6b7280;font-size:.8rem;min-height:1.1em;text-align:center}`;

// The in-browser WebAuthn PRF ceremony. Runs navigator.credentials.create/get
// with the PRF extension (user-verification required → Touch ID / Face ID /
// security key), then POSTs the PRF output (hex) + credentialId back to /submit.
// The Node side never sees the authenticator; it only receives the PRF bytes.
function webauthnJs(token, cfg) {
  return `<script>
(function(){
 var TOKEN=${JSON.stringify(token)}, CFG=${JSON.stringify(cfg)};
 function hexToBytes(h){var u=new Uint8Array(h.length/2);for(var i=0;i<u.length;i++)u[i]=parseInt(h.substr(i*2,2),16);return u;}
 function bytesToHex(b){var u=new Uint8Array(b),s='';for(var i=0;i<u.length;i++)s+=u[i].toString(16).padStart(2,'0');return s;}
 function b64u(b){var u=new Uint8Array(b),s='';for(var i=0;i<u.length;i++)s+=String.fromCharCode(u[i]);return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');}
 function unb64u(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';var b=atob(s),u=new Uint8Array(b.length);for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u;}
 function rnd(n){var u=new Uint8Array(n);crypto.getRandomValues(u);return u;}
 function st(m){var e=document.getElementById('pk-status');if(e)e.textContent=m;}
 async function submit(f){var b=new URLSearchParams();b.set('_token',TOKEN);for(var k in f)b.set(k,f[k]);await fetch('/submit',{method:'POST',body:b});document.body.innerHTML='<div class="card"><span class="badge">\\uD83D\\uDD12 SECURE</span><h1 style="margin:.4rem 0 .15rem">\\u2713 Done</h1><p class="desc">You can close this window.</p></div>';}
 function prfOf(c){return c&&c.getClientExtensionResults&&c.getClientExtensionResults().prf;}
 function prfFirst(c){var r=prfOf(c);return r&&r.results&&r.results.first;}
 function prfState(p){if(p===undefined)return 'n/a';if(!p)return 'absent';if(p.results&&p.results.first)return 'ok';return 'enabled='+JSON.stringify(p.enabled);}
 async function reg(att){
  st('Follow your device prompt\\u2026');
  var salt=hexToBytes(CFG.prfSalt);
  var sel={userVerification:'required',residentKey:'preferred'};
  if(att) sel.authenticatorAttachment=att;
  var cred=await navigator.credentials.create({publicKey:{challenge:rnd(32),rp:{id:location.hostname,name:CFG.rpName||'Alien Vault'},user:{id:rnd(16),name:CFG.userName||'vault',displayName:CFG.userName||'vault'},pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],authenticatorSelection:sel,timeout:120000,extensions:{prf:{eval:{first:salt}}}}});
  var id=b64u(cred.rawId), c1=prfOf(cred), out=c1&&c1.results&&c1.results.first, c2;
  if(!out){var a=await navigator.credentials.get({publicKey:{challenge:rnd(32),rpId:location.hostname,timeout:120000,allowCredentials:[{type:'public-key',id:unb64u(id)}],userVerification:'required',extensions:{prf:{eval:{first:salt}}}}});c2=prfOf(a);out=c2&&c2.results&&c2.results.first;}
  if(!out){console.log('passkey PRF unavailable [create:'+prfState(c1)+' get:'+prfState(c2)+']');st('This authenticator doesn\\u2019t support PRF, so it can\\u2019t derive the vault key. Chrome\\u2019s built-in Touch ID on macOS (iCloud Keychain) lacks PRF — use the phone / security-key link below, or open this page in Safari.');return;}
  await submit({credentialId:id,rpId:location.hostname,prfSecret:bytesToHex(out)});
 }
 async function auth(){
  st('Follow your device prompt\\u2026');
  var salt=hexToBytes(CFG.prfSalt);
  var a=await navigator.credentials.get({publicKey:{challenge:rnd(32),rpId:CFG.rpId,timeout:120000,allowCredentials:[{type:'public-key',id:unb64u(CFG.credentialId)}],userVerification:'required',extensions:{prf:{eval:{first:salt}}}}});
  var out=prfFirst(a);
  if(!out){st('Your authenticator did not return the PRF secret. Retry with the same device you enrolled.');return;}
  await submit({prfSecret:bytesToHex(out)});
 }
 window.__pk=async function(att){try{if(!window.PublicKeyCredential){st('This browser has no passkey support.');return;}if(CFG.mode==='register')await reg(att);else await auth();}catch(e){st('Failed: '+(e&&e.message||e)+'. You can retry.');}};
})();
</script>`;
}

// Shrink the window to the card once laid out (app windows allow this).
const FIT_SCRIPT = `<script>onload=function(){try{var c=document.querySelector('.card').getBoundingClientRect();window.resizeTo(Math.min((c.width|0)+12,screen.availWidth-20),Math.min((c.height|0)+52,screen.availHeight-20))}catch(e){}}</script>`;

const DEFAULT_SECURITY =
  "Encrypted with <code>AES-256-GCM</code>; never shown to the agent.";

function renderForm({ token, title, description, fields, security, submitLabel, webauthn }) {
  let inner;
  if (webauthn) {
    if (webauthn.mode === "register") {
      // Touch ID first (platform authenticator), with a phone/security-key fallback.
      inner = `<button type="button" onclick="__pk('platform')">${LOCK} Use Touch ID (this Mac)</button>
 <p style="text-align:center;margin:.55rem 0 0"><a href="#" onclick="__pk('cross-platform');return false" style="color:#16a34a;font-size:.8rem;text-decoration:none">Use a phone or security key instead →</a></p>
 <p id="pk-status" class="pk-status"></p>`;
    } else {
      const btn = submitLabel || "Use Touch ID / passkey";
      inner = `<button type="button" onclick="__pk()">${LOCK} ${htmlEscape(btn)}</button>
 <p id="pk-status" class="pk-status"></p>`;
    }
  } else {
    const rows = fields
      .map((f) => {
        const id = htmlEscape(f.name);
        const label = htmlEscape(f.label || f.name);
        const req = f.required === false ? "" : "required";
        const ph = f.placeholder ? `placeholder="${htmlEscape(f.placeholder)}"` : "";
        const input = f.multiline
          ? `<textarea id="${id}" name="${id}" rows="5" ${req} ${ph} autocomplete="off"></textarea>`
          : `<input id="${id}" name="${id}" type="${f.secret === false ? "text" : "password"}" ${req} ${ph} autocomplete="off" autocapitalize="off" spellcheck="false">`;
        const opt = f.required === false ? ' <span class="opt">(optional)</span>' : "";
        return `<label for="${id}">${label}${opt}</label>${input}`;
      })
      .join("\n");
    inner = `<form method="POST" action="/submit">
  <input type="hidden" name="_token" value="${htmlEscape(token)}">
  ${rows}
  <button type="submit">${LOCK} ${htmlEscape(submitLabel || "Save to vault")}</button>
 </form>`;
  }
  return `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${htmlEscape(title)}</title>
<style>${SECURE_CSS}</style></head><body>
<div class="card">
 <span class="badge">${LOCK} SECURE</span>
 <h1>${htmlEscape(title)}</h1>
 ${description ? `<p class="desc">${htmlEscape(description)}</p>` : ""}
 <div class="why">${LOCK}<span>${security || DEFAULT_SECURITY}</span></div>
 ${inner}
</div>${FIT_SCRIPT}${webauthn ? webauthnJs(token, webauthn) : ""}
</body></html>`;
}

const DONE_PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>Done</title>
<style>${SECURE_CSS}</style></head><body>
<div class="card">
 <span class="badge">${LOCK} SECURE</span>
 <h1 style="margin:.4rem 0 .15rem">✓ Done</h1>
 <p class="desc">Handled with <code>AES-256-GCM</code>. You can close this window.</p>
</div>${FIT_SCRIPT}
</body></html>`;

/**
 * Serve a one-shot secure form and resolve with the submitted field values.
 *
 *   title, description — shown on the page
 *   fields   — [{ name, label?, secret?=true, required?=true, multiline?, placeholder? }]
 *   label    — short phrase for the waiting notice ("unlock the vault", …)
 *   timeoutMs — default 5 min; rejects (code FORM_TIMEOUT) if no submit
 *   open      — auto-open the browser (default true)
 *   onUrl     — optional callback(url) for programmatic callers/tests; NOT used
 *               for human messaging
 *
 * Opens the form in the user's browser and prints a one-line "waiting" notice
 * with NO url. Only when a browser could not be opened (headless/SSH, or
 * AGENT_ID_NO_BROWSER) does it fall back to printing the URL so the human can
 * open it manually. Resolves { values: { <name>: <string> } } (never logged);
 * throws on timeout. The HTTP server is always torn down before returning.
 */
export function collectViaForm({
  title = "Enter a secret",
  description = "",
  fields,
  label = "",
  security = "", // trusted HTML describing the cryptography (callers control it)
  submitLabel = "",
  timeoutMs = 5 * 60 * 1000,
  open = true,
  host = "127.0.0.1",
  onUrl = null,
  webauthn = null, // { mode: "register"|"authenticate", rpName?, userName?, credentialId?, rpId?, prfSalt }
} = {}) {
  // A WebAuthn ceremony: the "fields" become the ceremony outputs the browser
  // posts back, and the page MUST be served on localhost (WebAuthn forbids IP
  // rpIds, so 127.0.0.1 won't work as an origin/rpId).
  const effFields = webauthn
    ? webauthn.mode === "register"
      ? [{ name: "credentialId" }, { name: "rpId" }, { name: "prfSecret" }]
      : [{ name: "prfSecret" }]
    : fields;
  const effHost = webauthn ? "localhost" : host;
  if (!Array.isArray(effFields) || effFields.length === 0) {
    return Promise.reject(new Error("collectViaForm: fields[] (or webauthn) is required"));
  }
  const token = randomBytes(32).toString("hex");
  const sockets = new Set();

  return new Promise((resolve, reject) => {
    let settled = false;
    let timer = null;

    const server = http.createServer((req, res) => {
      const url = new URL(req.url, `http://${effHost}`);
      const presented = url.searchParams.get("t");

      // GET /  — serve the form (token in the URL so only the URL holder sees it).
      if (req.method === "GET" && url.pathname === "/") {
        if (!presented || !tokenEquals(presented, token)) {
          res.writeHead(403).end("forbidden");
          return;
        }
        const body = renderForm({ token, title, description, fields: effFields, security, submitLabel, webauthn });
        res.writeHead(200, PAGE_HEADERS);
        res.end(body);
        return;
      }

      // POST /submit — token in the form body.
      if (req.method === "POST" && url.pathname === "/submit") {
        let size = 0;
        const chunks = [];
        req.on("data", (c) => {
          size += c.length;
          if (size > BODY_CAP_BYTES) {
            res.writeHead(413).end("too large");
            req.destroy();
            return;
          }
          chunks.push(c);
        });
        req.on("end", () => {
          const params = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
          if (!tokenEquals(params.get("_token") || "", token)) {
            res.writeHead(403).end("forbidden");
            return;
          }
          const values = {};
          for (const f of effFields) values[f.name] = params.get(f.name) ?? "";
          res.writeHead(200, PAGE_HEADERS);
          // Resolve only once the done-page has flushed to the browser.
          res.end(DONE_PAGE, () => finish(() => resolve({ values })));
        });
        return;
      }

      res.writeHead(404).end("not found");
    });

    server.on("connection", (s) => {
      sockets.add(s);
      s.on("close", () => sockets.delete(s));
    });

    function shutdown() {
      if (timer) clearTimeout(timer);
      for (const s of sockets) s.destroy();
      server.close();
    }
    function finish(action) {
      if (settled) return;
      settled = true;
      // Let the response flush before tearing down sockets.
      setImmediate(() => {
        shutdown();
        action();
      });
    }

    server.on("error", (err) => {
      if (settled) return;
      settled = true;
      shutdown();
      reject(err);
    });

    server.listen(0, effHost, () => {
      const { port } = server.address();
      const url = `http://${effHost}:${port}/?t=${token}`;
      if (typeof onUrl === "function") onUrl(url); // programmatic access (e.g. tests)
      const winSize = webauthn ? { width: 360, height: 290 } : windowSizeFor(effFields);
      const opened = open && (webauthn ? openForWebauthn(url, winSize) : openBrowser(url, winSize));
      const what = label ? ` to ${label}` : "";
      const where = webauthn && process.platform === "darwin" ? " (in Safari, for Touch ID)" : "";
      // Happy path: the browser opened — tell the human to look there, no URL.
      // Fallback only (headless / AGENT_ID_NO_BROWSER): print the URL to open by hand.
      // The budget is quoted from `timeoutMs`, not a constant: this line is what
      // the person decides against ("can I go fetch that code and come back?"), so
      // a caller that widens the window must not be contradicted by the copy.
      const budget = `${Math.round(timeoutMs / 60000)} min`;
      process.stderr.write(
        opened
          ? `→ Opened a secure form in your browser${where}${what} — fill it in there (waiting up to ${budget})…\n`
          : `→ Open this URL in a browser${what} (waiting up to ${budget}):\n  ${url}\n`,
      );
      timer = setTimeout(() => {
        finish(() => {
          const err = new Error("timed out waiting for the secure form to be submitted");
          err.code = "FORM_TIMEOUT";
          reject(err);
        });
      }, timeoutMs);
    });
  });
}
