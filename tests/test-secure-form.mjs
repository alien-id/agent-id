#!/usr/bin/env node

// Tests for the out-of-band secure entry form (lib/secure-form.mjs).
// Drives the loopback server programmatically (no browser) to prove it is
// token-gated and returns the submitted values without ever printing them.
//
// Run: node --test tests/test-secure-form.mjs

import { test } from "node:test";
import assert from "node:assert/strict";

import { collectViaForm } from "../plugins/agent-id-core/lib/secure-form.mjs";

// Start a form and capture its URL via the onUrl callback (deterministic, no sleep).
function startForm(opts) {
  let resolveUrl;
  const urlReady = new Promise((r) => (resolveUrl = r));
  const done = collectViaForm({ ...opts, open: false, onUrl: resolveUrl });
  // Swallow rejection here so an unrelated test failure doesn't crash the process;
  // callers that care await `done` explicitly.
  done.catch(() => {});
  return { urlReady, done };
}

test("serves a token-gated form and returns the submitted value", async () => {
  const { urlReady, done } = startForm({
    title: "Add credential: github-pat",
    fields: [{ name: "value", label: "Token" }],
  });
  const url = await urlReady;
  const u = new URL(url);
  const token = u.searchParams.get("t");
  const origin = `http://127.0.0.1:${u.port}`;

  // The form renders, carries the field, and embeds the token.
  const formRes = await fetch(url);
  assert.equal(formRes.status, 200);
  const html = await formRes.text();
  assert.match(html, /name="value"/);
  assert.match(html, new RegExp(token));

  // GET without the token is refused.
  assert.equal((await fetch(`${origin}/`)).status, 403);

  // Submitting with the token returns the value to the caller.
  const body = new URLSearchParams({ _token: token, value: "ghp_secret_123" });
  const sub = await fetch(`${origin}/submit`, { method: "POST", body });
  assert.equal(sub.status, 200);
  assert.match(await sub.text(), /close this window/i);

  const { values } = await done;
  assert.equal(values.value, "ghp_secret_123");
});

test("collects multiple fields (e.g. basic auth) in one submit", async () => {
  const { urlReady, done } = startForm({
    fields: [
      { name: "username", secret: false },
      { name: "password" },
    ],
  });
  const u = new URL(await urlReady);
  const token = u.searchParams.get("t");
  const body = new URLSearchParams({ _token: token, username: "admin", password: "s3cr3t" });
  await fetch(`http://127.0.0.1:${u.port}/submit`, { method: "POST", body });
  const { values } = await done;
  assert.deepEqual(values, { username: "admin", password: "s3cr3t" });
});

test("rejects a submit with the wrong token and keeps waiting (then times out)", async () => {
  const { urlReady, done } = startForm({
    fields: [{ name: "value" }],
    timeoutMs: 600,
  });
  const u = new URL(await urlReady);
  const bad = await fetch(`http://127.0.0.1:${u.port}/submit`, {
    method: "POST",
    body: new URLSearchParams({ _token: "wrong-token", value: "x" }),
  });
  assert.equal(bad.status, 403);
  // The wrong token did not resolve the form; it times out.
  await assert.rejects(done, (e) => e.code === "FORM_TIMEOUT");
});

test("webauthn register: serves the passkey UI on localhost, returns the ceremony output", async () => {
  const { urlReady, done } = startForm({
    title: "Create a passkey",
    webauthn: { mode: "register", rpName: "Alien Vault", prfSalt: "00ff" },
  });
  const u = new URL(await urlReady);
  assert.equal(u.hostname, "localhost", "WebAuthn must be served on localhost, not an IP");
  const token = u.searchParams.get("t");
  const origin = `http://localhost:${u.port}`;

  const html = await (await fetch(`${origin}/?t=${token}`)).text();
  assert.match(html, /__pk\('platform'\)/); // Touch ID button wired
  assert.match(html, /__pk\('cross-platform'\)/); // phone / security-key fallback
  assert.match(html, /navigator\.credentials\.create/); // ceremony JS present
  assert.doesNotMatch(html, /<input[^>]*type="password"/); // no text field

  // Simulate the browser completing the ceremony.
  const body = new URLSearchParams({ _token: token, credentialId: "Y3JlZA", rpId: "localhost", prfSecret: "deadbeef" });
  assert.equal((await fetch(`${origin}/submit`, { method: "POST", body })).status, 200);

  const { values } = await done;
  assert.deepEqual(values, { credentialId: "Y3JlZA", rpId: "localhost", prfSecret: "deadbeef" });
});

test("webauthn authenticate: returns just the PRF secret", async () => {
  const { urlReady, done } = startForm({
    webauthn: { mode: "authenticate", credentialId: "Y3JlZA", rpId: "localhost", prfSalt: "00ff" },
  });
  const u = new URL(await urlReady);
  const token = u.searchParams.get("t");
  const html = await (await fetch(`http://localhost:${u.port}/?t=${token}`)).text();
  assert.match(html, /navigator\.credentials\.get/);
  await fetch(`http://localhost:${u.port}/submit`, {
    method: "POST",
    body: new URLSearchParams({ _token: token, prfSecret: "cafe" }),
  });
  const { values } = await done;
  assert.deepEqual(values, { prfSecret: "cafe" });
});

test("the wait budget printed to the human matches the caller's timeoutMs", async () => {
  // The line a person reads to decide "can I go fetch that code and come back?".
  // It used to be the constant "5 min" while the real budget came from timeoutMs,
  // so any caller that widened the window was contradicted by its own copy.
  const captured = [];
  const original = process.stderr.write.bind(process.stderr);
  process.stderr.write = (chunk, ...rest) => {
    captured.push(typeof chunk === "string" ? chunk : String(chunk));
    return true;
  };
  try {
    const { urlReady, done } = startForm({
      title: "Sign-in code for booking",
      fields: [{ name: "otp", label: "Sign-in code" }],
      timeoutMs: 10 * 60 * 1000,
    });
    const url = await urlReady;
    const said = captured.join("");
    assert.match(said, /waiting up to 10 min/);
    assert.ok(!/waiting up to 5 min/.test(said), "must not quote a budget it is not using");

    // Close the form so the test does not sit on the 10-minute timer.
    const u = new URL(url);
    await fetch(`http://127.0.0.1:${u.port}/submit`, {
      method: "POST",
      body: new URLSearchParams({ _token: u.searchParams.get("t"), otp: "483920" }),
    });
    const { values } = await done;
    assert.equal(values.otp, "483920");
  } finally {
    process.stderr.write = original;
  }
});

test("the wait budget still reads 5 min when the caller does not widen it", async () => {
  const captured = [];
  const original = process.stderr.write.bind(process.stderr);
  process.stderr.write = (chunk) => {
    captured.push(typeof chunk === "string" ? chunk : String(chunk));
    return true;
  };
  try {
    const { urlReady, done } = startForm({
      title: "Add credential: x",
      fields: [{ name: "value", label: "Token" }],
    });
    const url = await urlReady;
    assert.match(captured.join(""), /waiting up to 5 min/);
    const u = new URL(url);
    await fetch(`http://127.0.0.1:${u.port}/submit`, {
      method: "POST",
      body: new URLSearchParams({ _token: u.searchParams.get("t"), value: "v" }),
    });
    await done;
  } finally {
    process.stderr.write = original;
  }
});
