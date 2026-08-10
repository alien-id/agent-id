#!/usr/bin/env node

// WebAuthn off-switch for driven browser sessions (webauthn-off.mjs).
//
// The driven browser has no authenticator, so a passkey ceremony started by a
// site can never complete — navigator.credentials.get() hangs and the page's
// fallback links are inert while it is pending (alien-id/agent-id#99). The
// off-switch makes the browser look passkey-incapable instead: the
// PublicKeyCredential interface is gone (sites feature-detect it and fall back
// to password/OTP up front), and a publicKey get/create that is issued anyway
// rejects immediately with the NotAllowedError every WebAuthn call site
// already handles as "cancelled".
//
// Pure tests cover the env opt-out and the wiring contract; the LIVE test
// proves the page-visible surface in a real Chrome and skips when patchright /
// Chrome are not installed.
//
// Run: node --test tests/test-browser-webauthn-off.mjs

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { resolvePatchright, launchContext } from "../plugins/agent-id-browser/lib/launch.mjs";
import { webauthnKept, suppressWebAuthn } from "../plugins/agent-id-browser/lib/webauthn-off.mjs";

const patchrightAvailable = !!resolvePatchright();

// ── Pure ──────────────────────────────────────────────────────────────────────

test("webauthnKept: only the literal '1' keeps WebAuthn native", () => {
  assert.equal(webauthnKept({}), false);
  assert.equal(webauthnKept({ AGENT_ID_BROWSER_KEEP_WEBAUTHN: "1" }), true);
  assert.equal(webauthnKept({ AGENT_ID_BROWSER_KEEP_WEBAUTHN: "0" }), false);
  assert.equal(webauthnKept({ AGENT_ID_BROWSER_KEEP_WEBAUTHN: "true" }), false);
  assert.equal(webauthnKept({ AGENT_ID_BROWSER_KEEP_WEBAUTHN: "" }), false);
});

test("suppressWebAuthn installs one init script and reports it", async () => {
  const installed = [];
  const ctx = { addInitScript: async (fn) => installed.push(fn) };
  assert.equal(await suppressWebAuthn(ctx, {}), true);
  assert.equal(installed.length, 1);
  assert.equal(typeof installed[0], "function");
});

test("suppressWebAuthn is a no-op when the env keeps WebAuthn", async () => {
  const installed = [];
  const ctx = { addInitScript: async (fn) => installed.push(fn) };
  assert.equal(await suppressWebAuthn(ctx, { AGENT_ID_BROWSER_KEEP_WEBAUTHN: "1" }), false);
  assert.equal(installed.length, 0);
});

// ── LIVE (real Chrome; skips without patchright) ─────────────────────────────

let server;
let base;

function startServer() {
  return new Promise((resolve) => {
    server = http.createServer((req, res) => {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end("<!doctype html><title>fake-signin</title><h1>Sign in</h1>");
    });
    server.listen(0, "127.0.0.1", () => {
      base = `http://127.0.0.1:${server.address().port}`;
      resolve();
    });
  });
}

before(async () => {
  if (patchrightAvailable) await startServer();
});
after(async () => {
  if (server) await new Promise((r) => server.close(r));
});

// Launch a context on a throwaway profile, navigate to the local page, and
// evaluate the WebAuthn surface the page sees. The probe MUST run in the MAIN
// world — patchright's evaluate defaults to an isolated world (stealth), whose
// pristine natives are invisible to page scripts; the third `evaluate` argument
// (isolatedContext:false) selects the world the page's own code runs in.
async function probeWebAuthn(launchExtras = {}) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "webauthn-off-"));
  let ctx;
  try {
    ctx = await launchContext({ profileDir: dir, headless: true, ...launchExtras });
    const page = ctx.pages()[0] || (await ctx.newPage());
    await page.goto(`${base}/`, { waitUntil: "domcontentloaded" });
    return await page.evaluate(async () => {
      const out = { pkc: typeof window.PublicKeyCredential };
      const timing = async (label, run) => {
        const t0 = Date.now();
        try {
          const value = await run();
          out[label] = { outcome: "resolved", value: value === null ? null : typeof value };
        } catch (e) {
          out[label] = { outcome: "rejected", name: e.name };
        }
        out[label].ms = Date.now() - t0;
      };
      await timing("get", () =>
        navigator.credentials.get({ publicKey: { challenge: new Uint8Array(16) } }),
      );
      await timing("create", () =>
        navigator.credentials.create({
          publicKey: {
            challenge: new Uint8Array(16),
            rp: { name: "t" },
            user: { id: new Uint8Array(8), name: "t", displayName: "t" },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          },
        }),
      );
      // Non-publicKey credential types must pass through to the native
      // implementation (no stored password → resolves null).
      await timing("passwordGet", () => navigator.credentials.get({ password: true }));
      return out;
    }, undefined, false);
  } finally {
    if (ctx) await ctx.close().catch(() => {});
    await fs.rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

test(
  "a driven session shows no WebAuthn: feature-detect fails, ceremonies reject instantly",
  { skip: patchrightAvailable ? false : "patchright/Chrome not installed" },
  async () => {
    const s = await probeWebAuthn();

    assert.equal(s.pkc, "undefined", "PublicKeyCredential must be gone (feature detection)");
    assert.equal(s.get.outcome, "rejected");
    assert.equal(s.get.name, "NotAllowedError", "a publicKey get must look like a cancelled ceremony");
    assert.ok(s.get.ms < 2000, `the rejection must be immediate, not a hang (took ${s.get.ms}ms)`);
    assert.equal(s.create.outcome, "rejected");
    assert.equal(s.create.name, "NotAllowedError");
    assert.ok(s.create.ms < 2000, `the rejection must be immediate, not a hang (took ${s.create.ms}ms)`);
    assert.deepEqual(
      { outcome: s.passwordGet.outcome, value: s.passwordGet.value },
      { outcome: "resolved", value: null },
      "non-publicKey credential calls must reach the native implementation",
    );
  },
);

test(
  "nativeWebAuthn:true (the headed owner login) keeps the WebAuthn surface",
  { skip: patchrightAvailable ? false : "patchright/Chrome not installed" },
  async () => {
    const s = await probeWebAuthn({ nativeWebAuthn: true });
    assert.equal(s.pkc, "function", "the owner's headed login must keep WebAuthn native");
  },
);

test(
  "AGENT_ID_BROWSER_KEEP_WEBAUTHN=1 keeps WebAuthn native in a driven session",
  { skip: patchrightAvailable ? false : "patchright/Chrome not installed" },
  async () => {
    process.env.AGENT_ID_BROWSER_KEEP_WEBAUTHN = "1";
    try {
      const s = await probeWebAuthn();
      assert.equal(s.pkc, "function");
    } finally {
      delete process.env.AGENT_ID_BROWSER_KEEP_WEBAUTHN;
    }
  },
);
