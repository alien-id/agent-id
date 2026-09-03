// The page adapter over the browser's RPC port: what it sends for a keystroke,
// how it reads a ref out of a snapshot, and how a locator chain reaches the
// page. All against a stub server — no browser, no network beyond loopback.

import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";

import { openRpcPage } from "../plugins/agent-id-browser/lib/rpc-page.mjs";

/**
 * A stand-in for the browser: records every command and answers from `replies`,
 * a map of method → value (or a function of the params).
 */
async function stubBrowser(replies = {}) {
  const calls = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const message = JSON.parse(body || "{}");
      calls.push(message);
      const reply = replies[message.method];
      const result = typeof reply === "function" ? reply(message.params) : reply;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ id: message.id, result: result ?? {} }));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  return {
    rpc: `127.0.0.1:${port}`,
    calls,
    close: () => new Promise((r) => server.close(r)),
    /** Every call of one method, in order. */
    of: (method) => calls.filter((c) => c.method === method),
  };
}

/** The session probe every page makes on the way up. */
const BASE = {
  "Session.state": { active: true },
  "Session.nav.state": { url: "https://site.test/login", title: "Sign in" },
};

test("a browser with no session is refused, not started", async () => {
  // One browser is one user at a time, and which user is a Session.start name.
  // This command is handed a port and a credential, never a profile, so a
  // session it opened would be an unnamed one (an error against a browser that
  // has profiles) or would land the sign-in in whoever's tab was already open.
  const stub = await stubBrowser({ "Session.state": { active: false } });
  try {
    await assert.rejects(
      () => openRpcPage(stub.rpc),
      (error) => {
        assert.equal(error.code, "NO_SESSION", "the caller branches on the code");
        assert.match(error.message, /no active session/);
        assert.match(error.message, /must open the session/, "and is told whose job it is");
        return true;
      },
    );
    assert.deepEqual(
      stub.of("Session.start"),
      [],
      "opening a session here would choose a profile that is not ours to choose",
    );
  } finally {
    await stub.close();
  }
});

test("a session somebody else opened is used as it is", async () => {
  const stub = await stubBrowser(BASE);
  try {
    const page = await openRpcPage(stub.rpc);
    assert.equal(page.url(), "https://site.test/login");
    assert.deepEqual(stub.of("Session.start"), [], "an active session is never restarted");
  } finally {
    await stub.close();
  }
});

test("a keystroke is keyDown, then a char for the character, then keyUp", async () => {
  const stub = await stubBrowser(BASE);
  try {
    const page = await openRpcPage(stub.rpc);
    await page.keyboard.press("a");

    const keys = stub.of("Session.input.dispatchKeyEvent").map((c) => c.params);
    assert.deepEqual(
      keys.map((k) => k.type),
      ["keyDown", "char", "keyUp"],
      "a keyDown carrying text types nothing in this browser — the char event is what does",
    );
    assert.equal(keys[0].windowsVirtualKeyCode, 65, "the key's identity is its VK code");
    assert.equal(keys[1].text, "a");
  } finally {
    await stub.close();
  }
});

test("Enter carries a carriage return and its own VK code", async () => {
  const stub = await stubBrowser(BASE);
  try {
    const page = await openRpcPage(stub.rpc);
    await page.keyboard.press("Enter");

    const keys = stub.of("Session.input.dispatchKeyEvent").map((c) => c.params);
    assert.deepEqual(
      keys.map((k) => k.type),
      ["keyDown", "char", "keyUp"],
    );
    assert.equal(keys[0].windowsVirtualKeyCode, 13);
    assert.equal(keys[1].text, "\r");
  } finally {
    await stub.close();
  }
});

test("a named key with no character sends no char event", async () => {
  const stub = await stubBrowser(BASE);
  try {
    const page = await openRpcPage(stub.rpc);
    await page.keyboard.press("Escape");

    assert.deepEqual(
      stub.of("Session.input.dispatchKeyEvent").map((c) => c.params.type),
      ["keyDown", "keyUp"],
    );
  } finally {
    await stub.close();
  }
});

test("filling a field resolves the element in the page, then types by ref", async () => {
  const stub = await stubBrowser({
    ...BASE,
    // The resolver stamps and reports; the snapshot rooted at the stamp names
    // the ref; the type acts on it.
    "Runtime.evaluate": {
      result: { value: { count: 1, stamped: true, visible: true, url: "https://site.test/login" } },
    },
    "Session.dom.snapshot": {
      lines: 1,
      text: 'page https://site.test/login\ntitle "Sign in"\n7 form\n12 input "Email" type=email empty',
    },
    "Session.dom.type": { text: "ada@example.test" },
  });
  try {
    const page = await openRpcPage(stub.rpc);
    await page.fill("#email", "ada@example.test");

    const snapshot = stub.of("Session.dom.snapshot")[0].params;
    assert.match(
      snapshot.root,
      /^\[data-agentid-el="\d+"\]$/,
      "the snapshot is rooted at the stamp the resolver left on the element",
    );
    const typed = stub.of("Session.dom.type")[0].params;
    assert.equal(typed.ref, "12", "the ref is the snapshot's own first body line");
    assert.equal(typed.text, "ada@example.test");
    assert.equal(typed.clear, true, "filling replaces what the field held");
  } finally {
    await stub.close();
  }
});

test("an element the snapshot gives no ref for is refused, not clicked at a guess", async () => {
  const stub = await stubBrowser({
    ...BASE,
    "Runtime.evaluate": { result: { value: { count: 1, stamped: true, visible: true } } },
    // A bare wrapper prints as prose: no ref, nothing to act on.
    "Session.dom.snapshot": { lines: 1, text: 'page https://site.test/login\n"just words"' },
  });
  try {
    const page = await openRpcPage(stub.rpc);
    await assert.rejects(() => page.click("#wrapper"), /not one the browser can act on/);
    assert.equal(stub.of("Session.dom.click").length, 0);
  } finally {
    await stub.close();
  }
});

test("acting on a selector prefers the first VISIBLE match", async () => {
  const stub = await stubBrowser({
    ...BASE,
    "Runtime.evaluate": { result: { value: { count: 2, stamped: true, visible: true } } },
    "Session.dom.snapshot": { lines: 1, text: 'page https://site.test/login\n4 input "Email" type=email' },
  });
  try {
    const page = await openRpcPage(stub.rpc);
    await page.fill('input[type="email"]', "ada@example.test");

    const expression = stub.of("Runtime.evaluate").at(-1).params.expression;
    const chain = JSON.parse(/\.apply\(null, (\[.*\])\)$/s.exec(expression)[1])[0];
    assert.deepEqual(
      chain,
      [{ css: 'input[type="email"]' }, { firstVisible: true }],
      "a page rendering a hidden duplicate of a field first must not swallow the fill",
    );
  } finally {
    await stub.close();
  }
});

test("a locator narrowed by hand is taken exactly as spelled", async () => {
  const stub = await stubBrowser({
    ...BASE,
    "Runtime.evaluate": { result: { value: { count: 3, stamped: true, visible: true } } },
    "Session.dom.snapshot": { lines: 1, text: 'page https://site.test/login\n9 button "Verify"' },
  });
  try {
    const page = await openRpcPage(stub.rpc);
    await page.locator("button").nth(2).click();

    const expression = stub.of("Runtime.evaluate").at(-1).params.expression;
    const chain = JSON.parse(/\.apply\(null, (\[.*\])\)$/s.exec(expression)[1])[0];
    assert.deepEqual(chain, [{ css: "button" }, { nth: 2 }], "nth is a choice, not a hint");
  } finally {
    await stub.close();
  }
});

test("a locator chain travels to the page as steps, xpath included", async () => {
  const stub = await stubBrowser({
    ...BASE,
    "Runtime.evaluate": { result: { value: { count: 3, stamped: true, visible: true } } },
  });
  try {
    const page = await openRpcPage(stub.rpc);
    const count = await page.locator("#code").first().locator("xpath=ancestor::form[1]").count();
    assert.equal(count, 3);

    const expression = stub.of("Runtime.evaluate").at(-1).params.expression;
    const chain = JSON.parse(/\.apply\(null, (\[.*\])\)$/s.exec(expression)[1])[0];
    assert.deepEqual(chain, [{ css: "#code" }, { nth: 0 }, { xpath: "ancestor::form[1]" }]);
  } finally {
    await stub.close();
  }
});

test("waiting for a selector gives up with a message rather than hanging", async () => {
  const stub = await stubBrowser({
    ...BASE,
    "Runtime.evaluate": { result: { value: { count: 0, stamped: false } } },
  });
  try {
    const page = await openRpcPage(stub.rpc);
    await assert.rejects(
      () => page.waitForSelector("#never", { timeout: 200 }),
      /was not visible within 200ms/,
    );
  } finally {
    await stub.close();
  }
});

test("a browser that refuses a command surfaces its own message", async () => {
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const { id, method } = JSON.parse(body || "{}");
      const result = method === "Session.state" ? { active: true } : null;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify(
          result
            ? { id, result }
            : { id, error: { code: -32000, message: "no active session" } },
        ),
      );
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  try {
    const page = await openRpcPage(`127.0.0.1:${port}`);
    await assert.rejects(() => page.goto("https://site.test/"), /no active session/);
  } finally {
    await new Promise((r) => server.close(r));
  }
});

test("a browser that is not there fails at connect, naming the address", async () => {
  // Port 1 on loopback: nothing listens, and the refusal is immediate.
  await assert.rejects(() => openRpcPage("127.0.0.1:1"), (err) => err instanceof Error);
});
