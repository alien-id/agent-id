#!/usr/bin/env node

// Tests for the secure-prompt provider abstraction (lib/secure-prompt.mjs):
// resolver order + capability filtering, the hosted unix-socket provider, the
// browser-form delegation, and the trusted-input shim's class identity.
//
// Run: node --test tests/test-secure-prompt.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";

import {
  BrowserFormProvider,
  TtyProvider,
  resolveSecurePrompt,
  collectSecret,
} from "../plugins/agent-id-core/lib/secure-prompt.mjs";

// A stub provider for deterministic ordering/capability tests (no real surface).
function stub(name, { available = true, multiline = true } = {}) {
  return {
    name,
    isAvailable: () => available,
    capabilities: () => ({ multiField: true, secret: true, multiline }),
    collect: async () => ({ values: {} }),
  };
}

// Spin up an HTTP server on a unix socket (the hosted-harness protocol).
function startHostedSocket(handler) {
  const sock = path.join(os.tmpdir(), `agentid-sp-${process.pid}-${Date.now()}.sock`);
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {};
      handler(body, res);
    });
  });
  return new Promise((resolve) => server.listen(sock, () => resolve({ sock, server })));
}

test("resolver: default environment selects the browser form", () => {
  assert.equal(resolveSecurePrompt({ env: {} }).name, "browser");
});

test("BrowserFormProvider.isAvailable() honors AGENT_ID_NO_BROWSER", () => {
  assert.equal(new BrowserFormProvider({ env: {} }).isAvailable(), true);
  assert.equal(
    new BrowserFormProvider({
      env: { AGENT_ID_NO_BROWSER: "1" },
    }).isAvailable(),
    false
  );
});

test("resolver: AGENT_ID_NO_BROWSER disables the browser form, falling to a /dev/tty when present", () => {
  // With the browser form opted out, a controlling terminal takes over; on a
  // host with no tty either, the guaranteed last resort is the (print-URL) form.
  const p = resolveSecurePrompt({ env: { AGENT_ID_NO_BROWSER: "1" } });
  assert.equal(p.name, new TtyProvider().isAvailable() ? "tty" : "browser");
});

test("resolver: an available extraProvider is preferred over the browser form", () => {
  const p = resolveSecurePrompt({ env: {}, extraProviders: [stub("mobile")] });
  assert.equal(p.name, "mobile");
});

test("resolver: an unavailable extraProvider is skipped", () => {
  const p = resolveSecurePrompt({
    env: {},
    extraProviders: [stub("mobile", { available: false })],
  });
  assert.equal(p.name, "browser");
});

test("resolver: a multiline spec skips providers that can't do multiline", () => {
  const single = stub("single", { multiline: false });
  // Non-multiline need → the single-line provider is fine.
  assert.equal(resolveSecurePrompt({ env: {}, extraProviders: [single], need: {} }).name, "single");
  // Multiline need → it is filtered out, the browser form wins.
  assert.equal(
    resolveSecurePrompt({
      env: {},
      extraProviders: [single],
      need: { multiline: true },
    }).name,
    "browser"
  );
});

test("TtyProvider is single-line only (multiline:false)", () => {
  assert.equal(new TtyProvider().capabilities().multiline, false);
});

test("resolver: AGENT_ID_SECURE_PROMPT forces a backend (overriding availability + order)", () => {
  // Forces tty even though a browser is available…
  assert.equal(resolveSecurePrompt({ env: { AGENT_ID_SECURE_PROMPT: "tty" } }).name, "tty");
  // …and forces browser even when AGENT_ID_NO_BROWSER would normally disable it.
  assert.equal(
    resolveSecurePrompt({
      env: { AGENT_ID_SECURE_PROMPT: "browser", AGENT_ID_NO_BROWSER: "1" },
    }).name,
    "browser"
  );
  // Can also pin a named extraProvider.
  assert.equal(
    resolveSecurePrompt({
      env: { AGENT_ID_SECURE_PROMPT: "mobile" },
      extraProviders: [stub("mobile")],
    }).name,
    "mobile"
  );
  // An unknown name falls through to normal resolution.
  assert.equal(resolveSecurePrompt({ env: { AGENT_ID_SECURE_PROMPT: "nope" } }).name, "browser");
});

test("hosted: a card closed through its button says which button", async () => {
  // "Use the browser instead" is not a refusal — the owner still means to sign
  // in, just not here. Arriving as a plain dismissal it reads as "they said no",
  // and the sign-in is reported abandoned rather than handed over.
  const { sock, server } = await startHostedSocket((_body, res) => {
    const payload = JSON.stringify({ error: "cancelled", reason: "use_browser" });
    res.writeHead(409, {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(payload),
    });
    res.end(payload);
  });
  try {
    const provider = resolveSecurePrompt({ env: { AGENT_ID_SECURE_PROMPT_SOCK: sock } });
    const err = await provider.collect({ fields: [{ name: "otp" }], timeoutMs: 5000 }).then(
      () => null,
      (e) => e,
    );

    assert.ok(err, "a dismissal must not resolve as values");
    assert.equal(err.code, "FORM_USE_BROWSER");
    assert.notEqual(err.code, "FORM_CANCELLED", "the two must not be confused");
    assert.match(err.message, /browser/i);
  } finally {
    server.close();
  }
});

test("hosted: a card the owner dismissed is refused with a code, not a bare status", async () => {
  // The host answers 409 for a dismissal. Without a code of its own it reaches
  // the caller as `HTTP 409` — indistinguishable from a fault, and the sensible
  // reply to a fault is a retry, which puts the card back in front of someone who
  // has just closed it.
  const { sock, server } = await startHostedSocket((_body, res) => {
    const payload = JSON.stringify({ error: "cancelled" });
    res.writeHead(409, {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(payload),
    });
    res.end(payload);
  });
  try {
    const provider = resolveSecurePrompt({
      env: { AGENT_ID_SECURE_PROMPT_SOCK: sock },
    });
    const err = await provider
      .collect({ fields: [{ name: "otp" }], timeoutMs: 5000 })
      .then(
        () => null,
        (e) => e
      );

    assert.ok(err, "a dismissal must not resolve as values");
    assert.equal(err.code, "FORM_CANCELLED");
    assert.match(err.message, /dismissed/i);
  } finally {
    server.close();
  }
});

test("hosted: selected for a valid unix socket; collect() round-trips values; URLs refused", async () => {
  const { sock, server } = await startHostedSocket((body, res) => {
    // Echo a value keyed by the requested field name, proving the spec arrived.
    const name = body.fields?.[0]?.name || "value";
    const payload = JSON.stringify({ values: { [name]: "from-harness" } });
    res.writeHead(200, {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(payload),
    });
    res.end(payload);
  });
  try {
    const env = { AGENT_ID_SECURE_PROMPT_SOCK: sock };
    const provider = resolveSecurePrompt({ env });
    assert.equal(provider.name, "hosted");

    const { values } = await provider.collect({
      fields: [{ name: "otp" }],
      timeoutMs: 5000,
    });
    assert.equal(values.otp, "from-harness");

    // collectSecret routes through the same resolver.
    const out = await collectSecret({ fields: [{ name: "password" }] }, { env });
    assert.equal(out.values.password, "from-harness");

    // A URL (TCP) value is refused — the agent can't redirect the channel.
    assert.equal(
      resolveSecurePrompt({
        env: { AGENT_ID_SECURE_PROMPT_SOCK: "http://127.0.0.1:9/" },
      }).name,
      "browser"
    );
  } finally {
    server.close();
    try {
      fs.unlinkSync(sock);
    } catch {
      /* best effort */
    }
  }
});

test("BrowserFormProvider.collect delegates to collectViaForm (driven via onUrl, no browser)", async () => {
  const provider = new BrowserFormProvider();
  let resolveUrl;
  const urlReady = new Promise((r) => (resolveUrl = r));
  const done = provider.collect({
    fields: [{ name: "value" }],
    open: false,
    onUrl: resolveUrl,
  });
  done.catch(() => {});
  const u = new URL(await urlReady);
  const token = u.searchParams.get("t");
  await fetch(`http://127.0.0.1:${u.port}/submit`, {
    method: "POST",
    body: new URLSearchParams({ _token: token, value: "sekret" }),
  });
  const { values } = await done;
  assert.equal(values.value, "sekret");
});

test("trusted-input shim preserves the core class identity (instanceof works across the boundary)", async () => {
  const core = await import("../plugins/agent-id-core/lib/trusted-input.mjs");
  const shim = await import("../plugins/agent-id-vault/lib/trusted-input.mjs");
  assert.equal(shim.TrustedInputUnavailable, core.TrustedInputUnavailable);
  assert.equal(typeof shim.promptSecret, "function");
  assert.equal(typeof shim.notifyTty, "function");
});
