// Alien Agent ID — a page-shaped adapter over the agent-browser RPC port.
//
// auto-login was written against a patchright `Page`. The browser it drives is
// now agent-browser, a CDP-speaking server on a TCP port (`--rpc host:port`),
// so this module offers the same handful of methods the engine actually uses —
// `url/goto/evaluate/waitForTimeout/waitForSelector/keyboard` and a small
// `locator` — and nothing else. The engine keeps its logic; only the transport
// under it changed.
//
// Two things are worth knowing about how it works:
//
// **Locating.** A recipe names elements with CSS (and one xpath: the ancestor
// form of a code field), which the RPC has no verb for. So a locator is
// resolved IN THE PAGE — one `Runtime.evaluate` walks the chain, applies the
// visible/nth filters, and stamps the winner with a private attribute. The
// stamp is then a CSS selector the browser's own `Session.dom.snapshot` takes
// as its `root`, which answers with the element's ref — and a ref is what
// `Session.dom.click/type` act on. Two round trips buy the browser's own
// actionability: it reveals the element, and it refuses rather than missing
// when something covers it.
//
// **Human input is not ours any more.** The browser's `Session.dom.click`
// jitters within the element's box and its `Session.dom.type` sends one real
// keyDown/char/keyUp per character. Adding a second layer of cadence on top of
// that would only fight the browser's own timing.
//
// One POST is one command: the process is short-lived and the flow is
// sequential, so there is no websocket here and no events to receive.

const STAMP_ATTR = "data-agentid-el";

/** Virtual-key codes for the named keys a login flow presses. The browser keys
 *  on `windowsVirtualKeyCode` — CDP's `key`/`code` are accepted and ignored,
 *  because CEF has nowhere to put them. */
const VK = {
  Enter: 13,
  Tab: 9,
  Escape: 27,
  Backspace: 8,
  Delete: 46,
  ArrowLeft: 37,
  ArrowUp: 38,
  ArrowRight: 39,
  ArrowDown: 40,
  Space: 32,
};

/** The character a key types, if it types one. */
function charFor(key) {
  if (key === "Enter") return "\r";
  if (key === "Tab") return "\t";
  if (key === "Space") return " ";
  return [...key].length === 1 ? key : null;
}

function vkFor(key) {
  if (VK[key] != null) return VK[key];
  if ([...key].length === 1) {
    const c = key.toUpperCase();
    return c.charCodeAt(0);
  }
  return 0;
}

/** Walks a locator chain in the page and stamps the element it lands on.
 *
 *  Sent as source text rather than a closure: it runs in the page, where
 *  nothing of this module exists. Returns what every locator method needs, so
 *  one round trip answers `count`/`isVisible`/`textContent`/`boundingBox` and
 *  leaves the element addressable by its stamp.
 */
const RESOLVER = `(function (chain, stamp, attr) {
  var visible = function (e) {
    return !!(e.offsetParent !== null || e.getClientRects().length);
  };
  var nodes = [document];
  for (var i = 0; i < chain.length; i++) {
    var step = chain[i];
    var next = [];
    if (step.xpath) {
      for (var j = 0; j < nodes.length; j++) {
        var ctx = nodes[j] === document ? document.documentElement : nodes[j];
        var r = document.evaluate(step.xpath, ctx, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
        for (var k = 0; k < r.snapshotLength; k++) next.push(r.snapshotItem(k));
      }
    } else if (step.css) {
      for (var j2 = 0; j2 < nodes.length; j2++) {
        var found = nodes[j2].querySelectorAll(step.css);
        for (var k2 = 0; k2 < found.length; k2++) next.push(found[k2]);
      }
    } else if (step.firstVisible) {
      // A page can render a HIDDEN duplicate of a field before the real one —
      // acting on the first match then times out against something nobody can
      // see. Prefer the first visible match; fall back to the first, so the
      // caller still gets a normal "not visible" wait rather than nothing.
      var shown = nodes.filter(function (e) { return e !== document && visible(e); });
      next = shown.length ? [shown[0]] : nodes.slice(0, 1);
    } else if (step.nth != null) {
      var idx = step.nth < 0 ? nodes.length + step.nth : step.nth;
      if (nodes[idx]) next = [nodes[idx]];
    }
    nodes = next;
    if (!nodes.length) break;
  }
  var el = nodes[0] && nodes[0] !== document ? nodes[0] : null;
  var out = { count: nodes.length, url: location.href, stamped: false };
  if (!el) return out;
  var prior = document.querySelectorAll("[" + attr + '="' + stamp + '"]');
  for (var p = 0; p < prior.length; p++) prior[p].removeAttribute(attr);
  el.setAttribute(attr, stamp);
  out.stamped = true;
  out.visible = visible(el);
  out.text = (el.textContent || "").trim().slice(0, 300);
  var box = el.getBoundingClientRect();
  out.box = { x: box.x, y: box.y, width: box.width, height: box.height };
  out.tag = el.tagName.toLowerCase();
  out.type = (el.getAttribute("type") || "").toLowerCase();
  return out;
})`;

/** A chain of steps, resolved lazily — the shape playwright's locators have and
 *  the only part of them the engine uses. */
class Locator {
  constructor(page, chain) {
    this.page = page;
    this.chain = chain;
  }

  /** A sub-selector, or `xpath=…` for the one place the engine walks upward. */
  locator(selector) {
    return new Locator(this.page, [...this.chain, stepFor(selector)]);
  }

  first() {
    return this.nth(0);
  }

  nth(index) {
    return new Locator(this.page, [...this.chain, { nth: index }]);
  }

  async #resolve() {
    return this.page._resolve(this.chain);
  }

  /** The chain an ACTION resolves through. A locator narrowed by hand (`nth`,
   *  `first`) is taken exactly as spelled; anything else prefers the first
   *  visible match, which is what makes a hidden duplicate harmless. Querying
   *  (`count`, `isVisible`) stays positional either way — a caller asking
   *  whether the first match is visible must get that answer. */
  #actionChain() {
    const last = this.chain[this.chain.length - 1];
    return last && last.nth != null ? this.chain : [...this.chain, { firstVisible: true }];
  }

  async #resolveForAction() {
    return this.page._resolve(this.#actionChain());
  }

  async count() {
    return (await this.#resolve()).count;
  }

  async isVisible() {
    const info = await this.#resolve();
    return !!info.visible;
  }

  async textContent() {
    const info = await this.#resolve();
    return info.stamped ? info.text : null;
  }

  async boundingBox() {
    const info = await this.#resolve();
    return info.stamped && info.box.width > 0 ? info.box : null;
  }

  /** Wait for the element to exist and (by default) be visible — resolved the
   *  way an action on it would resolve, so the wait and the act agree. */
  async waitFor({ state = "visible", timeout = 15000 } = {}) {
    const deadline = Date.now() + timeout;
    for (;;) {
      const info = await this.#resolveForAction();
      if (info.stamped && (state !== "visible" || info.visible)) return;
      if (Date.now() >= deadline) {
        throw new Error(`locator ${describe(this.chain)} was not ${state} within ${timeout}ms`);
      }
      await this.page.waitForTimeout(120);
    }
  }

  /** The browser's own click: it reveals the element and refuses when
   *  something else owns the point, which a coordinate click cannot do. */
  async click({ timeout = 15000 } = {}) {
    const ref = await this.#ref(timeout);
    await this.page._call("Session.dom.click", { ref });
  }

  /** Replace the field's contents with `value`, typed as real keys. */
  async fill(value, { timeout = 15000 } = {}) {
    const ref = await this.#ref(timeout);
    await this.page._call("Session.dom.type", { ref, text: String(value ?? ""), clear: true });
  }

  async press(key, { timeout = 15000 } = {}) {
    const ref = await this.#ref(timeout);
    const text = charFor(key);
    // `\n` and `\t` are what the browser's own type() turns into Enter and Tab,
    // and they arrive at the element rather than at whatever holds focus.
    if (key === "Enter" || key === "Tab") {
      await this.page._call("Session.dom.type", { ref, text: key === "Enter" ? "\n" : "\t" });
      return;
    }
    if (text) {
      await this.page._call("Session.dom.type", { ref, text });
      return;
    }
    await this.page._call("Session.dom.click", { ref });
    await this.page.keyboard.press(key);
  }

  /** Tick a checkbox that is not already ticked. */
  async check({ timeout = 15000 } = {}) {
    const info = await this.#resolveForAction();
    if (!info.stamped) throw new Error(`locator ${describe(this.chain)} matched nothing`);
    const checked = await this.page.evaluate(
      `(function (sel) { var e = document.querySelector(sel); return !!(e && e.checked); })`,
      this.page._stampSelector(),
    );
    if (!checked) await this.click({ timeout });
  }

  async scrollIntoViewIfNeeded() {
    await this.#resolveForAction();
    await this.page.evaluate(
      `(function (sel) { var e = document.querySelector(sel); if (e) e.scrollIntoView({ block: "center" }); return true; })`,
      this.page._stampSelector(),
    );
  }

  /** Stamp the element, then ask the browser for the ref that names it. */
  async #ref(timeout) {
    await this.waitFor({ state: "visible", timeout });
    return this.page._refForStamp();
  }
}

/** `xpath=…` is playwright's own spelling and the engine uses it once. */
function stepFor(selector) {
  const text = String(selector);
  if (text.startsWith("xpath=")) return { xpath: text.slice(6) };
  return { css: text };
}

function describe(chain) {
  return chain
    .map((s) => (s.css ? s.css : s.xpath ? `xpath=${s.xpath}` : s.nth != null ? `nth=${s.nth}` : "visible"))
    .join(" › ");
}

/** Everything the auto-login engine calls on a page. */
class RpcPage {
  constructor(endpoint) {
    this.endpoint = endpoint;
    this._url = "about:blank";
    this._stamp = 0;
    this.keyboard = {
      press: (key) => this._key(key),
      type: async (text) => {
        for (const ch of String(text)) await this._key(ch);
      },
    };
  }

  url() {
    return this._url;
  }

  async _call(method, params = {}) {
    const res = await fetch(this.endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id: 1, method, params }),
    });
    if (!res.ok) throw new Error(`browser rpc ${method}: HTTP ${res.status}`);
    const reply = await res.json();
    if (reply.error) {
      const err = new Error(`${reply.error.message} (${method})`);
      err.code = reply.error.code;
      throw err;
    }
    return reply.result ?? {};
  }

  /** The session belongs to whoever called this command, not to this process.
   *
   *  One browser is one user at a time, and which user is a `Session.start`
   *  name — a profile directory under the browser's --data. This command has no
   *  notion of profiles: it is handed a port and a credential, so it can
   *  neither name the profile it wants nor move a browser that is currently
   *  being somebody else (a `Session.start` against an active session answers
   *  "already active", leaving the sign-in to land in that other user's tab,
   *  with their cookies).
   *
   *  It used to start one anyway, unnamed, from back when a session had no
   *  profile to name. Against a browser that has them, that call is simply an
   *  error — so the honest move is to require the session and say who should
   *  have opened it. */
  async ensureSession() {
    const state = await this._call("Session.state");
    if (state.active) {
      await this._refreshUrl();
      return;
    }
    const err = new Error(
      "the browser has no active session, and this command does not open one: the caller " +
        "chooses the profile a sign-in lands in (Session.start with a name) and must open " +
        "the session before handing the port over",
    );
    err.code = "NO_SESSION";
    throw err;
  }

  async _refreshUrl() {
    try {
      const state = await this._call("Session.nav.state");
      if (state.url) this._url = state.url;
    } catch {
      /* the url is a convenience; a failed read must not fail a step */
    }
  }

  async goto(url) {
    const result = await this._call("Session.nav.open", { url, timeout: 30 });
    this._url = result.url || url;
    return result;
  }

  async waitForTimeout(ms) {
    await new Promise((r) => setTimeout(r, Math.max(0, Number(ms) || 0)));
    await this._refreshUrl();
  }

  /** Run a function in the page and get its value back. `fn` may be a function
   *  (serialized to source — it must close over nothing, which is how the
   *  engine already writes them) or source text. */
  async evaluate(fn, arg) {
    const source = typeof fn === "function" ? fn.toString() : String(fn);
    const expression = `(${source})(${JSON.stringify(arg ?? null)})`;
    const result = await this._call("Runtime.evaluate", {
      expression,
      returnByValue: true,
      awaitPromise: true,
    });
    if (result.exceptionDetails) {
      const text =
        result.exceptionDetails?.exception?.description ||
        result.exceptionDetails?.text ||
        "the page script threw";
      throw new Error(String(text).slice(0, 300));
    }
    return result.result?.value;
  }

  async waitForSelector(selector, { state = "visible", timeout = 15000 } = {}) {
    await this.locator(selector).waitFor({ state, timeout });
  }

  locator(selector) {
    return new Locator(this, [stepFor(selector)]);
  }

  async click(selector, opts) {
    await this.locator(selector).click(opts);
  }

  async fill(selector, value, opts) {
    await this.locator(selector).fill(value, opts);
  }

  async press(selector, key, opts) {
    await this.locator(selector).press(key, opts);
  }

  async hover(selector) {
    const box = await this.locator(selector).boundingBox();
    if (!box) return;
    await this._call("Session.input.dispatchMouseEvent", {
      type: "mouseMoved",
      x: box.x + box.width / 2,
      y: box.y + box.height / 2,
    });
  }

  async title() {
    const state = await this._call("Session.nav.state");
    return state.title || "";
  }

  _stampSelector() {
    return `[${STAMP_ATTR}="${this._stamp}"]`;
  }

  /** Resolve a chain in the page, stamping whatever it lands on. */
  async _resolve(chain) {
    this._stamp += 1;
    const info = await this.evaluateWithArgs(RESOLVER, [chain, String(this._stamp), STAMP_ATTR]);
    if (info?.url) this._url = info.url;
    return info ?? { count: 0, stamped: false };
  }

  /** `evaluate` for a function of several arguments (the resolver's own shape). */
  async evaluateWithArgs(source, args) {
    const expression = `(${source}).apply(null, ${JSON.stringify(args)})`;
    const result = await this._call("Runtime.evaluate", {
      expression,
      returnByValue: true,
      awaitPromise: true,
    });
    if (result.exceptionDetails) {
      throw new Error(String(result.exceptionDetails?.exception?.description || "resolver failed").slice(0, 300));
    }
    return result.result?.value;
  }

  /** The ref naming the currently stamped element: the browser's snapshot,
   *  rooted at the stamp, prints it as its first body line. An element with no
   *  ref of its own (a bare wrapper the snapshot passes through) is an error
   *  here — the engine only ever drives controls. */
  async _refForStamp() {
    const snapshot = await this._call("Session.dom.snapshot", { root: this._stampSelector() });
    const lines = String(snapshot.text || "").split("\n");
    const body = lines.slice(Math.max(0, lines.length - (snapshot.lines || 0)));
    for (const line of body) {
      const match = /^\.*([0-9:]+)\s/.exec(line);
      if (match) return match[1];
    }
    throw new Error("the element is not one the browser can act on");
  }

  /** One keystroke to whatever holds focus: the browser wants a keyDown, then
   *  a `char` for the character (CEF's convention — a keyDown carrying text
   *  types nothing), then a keyUp. */
  async _key(key) {
    const vk = vkFor(key);
    const text = charFor(key);
    await this._call("Session.input.dispatchKeyEvent", {
      type: "keyDown",
      windowsVirtualKeyCode: vk,
      nativeVirtualKeyCode: vk,
    });
    if (text) {
      await this._call("Session.input.dispatchKeyEvent", {
        type: "char",
        text,
        unmodifiedText: text,
        windowsVirtualKeyCode: vk,
      });
    }
    await this._call("Session.input.dispatchKeyEvent", {
      type: "keyUp",
      windowsVirtualKeyCode: vk,
      nativeVirtualKeyCode: vk,
    });
  }
}

/** Connect to an agent-browser RPC port and hand back a page to drive.
 *
 *  `rpc` is `host:port` (or a full http url). Nothing is started or stopped
 *  here beyond making sure a session exists: the browser is somebody else's
 *  process, with its own profile and its own lifetime. */
export async function openRpcPage(rpc) {
  const target = String(rpc || "").trim();
  if (!target) throw new Error("--rpc <host:port> is required (the agent-browser RPC address)");
  const endpoint = /^https?:\/\//.test(target) ? target : `http://${target}`;
  const page = new RpcPage(endpoint);
  await page.ensureSession();
  await page._refreshUrl();
  return page;
}

export { RpcPage, Locator, RESOLVER, STAMP_ATTR };
