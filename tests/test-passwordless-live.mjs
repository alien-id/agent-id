#!/usr/bin/env node

// LIVE test of the passwordless sign-in path in a real Chrome, against a local
// fixture that reproduces the shapes real services use:
//   step 1 — an identifier-only screen (no password field anywhere)
//   step 2 — a code screen built from SIX separate one-character inputs, which is
//            what Slack / Notion / Airbnb / Vercel render, not one wide field
//   step 3 — a signed-in page
//
// This is the part unit tests cannot reach: detectPageState's selectors run inside
// page.evaluate against real DOM, and typing a 6-digit code into split boxes only
// works if the keystrokes are real events the page's auto-advance can react to.
//
// Skips automatically when patchright / Chrome are not installed.
//
// Run: node --test tests/test-passwordless-live.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";
import http from "node:http";

import { resolvePatchright, launchContext } from "../plugins/agent-id-browser/lib/launch.mjs";
import { autoLogin, detectPageState } from "../plugins/agent-id-browser/lib/auto-login.mjs";
import { classifyLogin } from "../plugins/agent-id-browser/lib/login-detect.mjs";

const patchrightAvailable = !!resolvePatchright();
const skip = patchrightAvailable ? false : "patchright/Chrome not installed";

const SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const IDENTIFIER = "daniel@example.com";

// Six one-character boxes that advance focus on input — the pattern that breaks a
// naive fill() of the whole code into the first field.
const CODE_BOXES = Array.from(
  { length: 6 },
  (_, i) =>
    `<input class=box id=d${i} type=tel inputmode=numeric maxlength=1 ` +
    `${i === 0 ? 'autocomplete="one-time-code"' : ""}>`,
).join("");

// `submit` picks how the code screen accepts the code — the three ways real
// services do it. "auto" fires on the last box, "button" needs a Verify click,
// "enter" is a single wide field that submits implicitly.
function fixtureServer({ submit = "button", acceptCode = true } = {}) {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    res.setHeader("content-type", "text/html; charset=utf-8");
    if (url.pathname === "/code") {
      const field =
        submit === "enter"
          ? '<input id=code name=code autocomplete="one-time-code" inputmode=numeric>'
          : CODE_BOXES;
      res.end(`<!doctype html><meta charset=utf-8><title>code</title>
<h1>Check your email for a code</h1>
<p>We've sent a six-digit code to ${IDENTIFIER}. It expires shortly.</p>
<form action="/search"><input name=q><button type=submit>Search</button></form>
<form id=f>${field}
  ${submit === "button" ? "<button type=button id=go>Verify</button><button type=button id=resend>Resend code</button>" : ""}
</form>
<script>
  const boxes = [...document.querySelectorAll('.box')];
  const read = () => boxes.length ? boxes.map(b => b.value).join('') : document.getElementById('code').value;
  const go = () => { location.href = '/done?code=' + read(); };
  boxes.forEach((b, i) => b.addEventListener('input', () => {
    if (b.value && boxes[i + 1]) boxes[i + 1].focus();
    ${submit === "auto" ? "if (read().length === 6) go();" : ""}
  }));
  const btn = document.getElementById('go');
  if (btn) btn.addEventListener('click', go);
  const resend = document.getElementById('resend');
  if (resend) resend.addEventListener('click', () => { location.href = '/code?resent=1'; });
  document.getElementById('f').addEventListener('submit', (e) => { e.preventDefault(); go(); });
</script>`);
      return;
    }
    if (url.pathname === "/done") {
      const code = url.searchParams.get("code") || "";
      if (!acceptCode) {
        // Bounce straight back to the code screen, the way a site does when the
        // code was mistyped or expired.
        res.writeHead(302, { location: "/code?bad=1" });
        res.end();
        return;
      }
      res.end(`<!doctype html><meta charset=utf-8><title>done</title>
<h1>${code.length === 6 ? "Welcome back, Daniel" : "Something went wrong"}</h1>
<p>code=${code}</p><p>My trips. Account settings. Saved lists.</p>`);
      return;
    }
    // Step 1: an identifier and nothing else. No password input exists at all.
    res.end(`<!doctype html><meta charset=utf-8><title>sign-in</title>
<h1>Sign in or create an account</h1>
<form action="/code" method="get">
  <label for=u>Email address</label>
  <input id=u name=username type=email autocomplete=username>
  <button type=submit>Continue with email</button>
</form>`);
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () =>
      resolve({ server, port: server.address().port }),
    );
  });
}

async function withBrowser(fn) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "pwless-live-"));
  const context = await launchContext({ profileDir: dir, headless: true });
  try {
    return await fn(context);
  } finally {
    await context.close().catch(() => {});
    await fs.rm(dir, { recursive: true, force: true });
  }
}

for (const submit of ["button", "auto", "enter"]) {
  test(
    `a passwordless sign-in runs end to end in a real browser (code screen submits by: ${submit})`,
    { skip },
    async () => {
      const { server, port } = await fixtureServer({ submit });
      try {
        const result = await withBrowser(async (context) => {
          const page = await context.newPage();
          return autoLogin({
            page,
            cred: {
              name: "fixture",
              type: "login",
              username: IDENTIFIER,
              passwordless: true,
              otp: "totp",
              totpSecret: SEED,
              loginUrl: `http://127.0.0.1:${port}/`,
              domains: ["127.0.0.1"],
              warmup: false,
            },
            settleMs: 400,
          });
        });
        assert.equal(result.ok, true, `auto-login failed: ${result.outcome}`);
        // Six digits arrived, so the code landed in every box — a fill() of the
        // whole string into the first one delivers a single digit and the fixture
        // reports it. Deliberately NOT compared against a freshly generated TOTP:
        // the code is generated during the run and this assertion happens after
        // it, so under load the window rotates between the two and the test fails
        // for a reason that has nothing to do with what it is testing. Exact-code
        // equality is covered by the injectable-`now` test in test-auto-login.mjs.
        assert.match(result.finalUrl, /code=\d{6}$/);
      } finally {
        server.close();
      }
    },
  );
}

test(
  "the identifier screen and the code screen are read correctly off real DOM",
  { skip },
  async () => {
    const { server, port } = await fixtureServer();
    try {
      await withBrowser(async (context) => {
        const page = await context.newPage();

        await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: "domcontentloaded" });
        const step1 = await detectPageState(page);
        assert.equal(step1.hasPasswordField, false);
        assert.equal(step1.hasIdentifierField, true, "the e-mail input must be seen");
        // The whole point: a screen with no password is not a finished login —
        // while we are still standing on it. `onLoginPage` is what the caller
        // knows and the snapshot does not; off the sign-in page the same e-mail
        // input is a newsletter box.
        assert.equal(classifyLogin({ ...step1, onLoginPage: true }), "unknown");
        assert.equal(classifyLogin({ ...step1, onLoginPage: false }), "logged-in");

        await page.goto(`http://127.0.0.1:${port}/code`, { waitUntil: "domcontentloaded" });
        const step2 = await detectPageState(page);
        assert.equal(step2.hasOtpField, true, "the one-time-code box must be seen");
        assert.equal(classifyLogin({ ...step2, onLoginPage: true }), "otp-required");

        await page.goto(`http://127.0.0.1:${port}/done?code=483920`, {
          waitUntil: "domcontentloaded",
        });
        assert.equal(classifyLogin(await detectPageState(page)), "logged-in");
      });
    } finally {
      server.close();
    }
  },
);

test(
  "a code the site keeps refusing is asked for once, not once per round",
  { skip },
  async () => {
    // With one card per round this was ten consecutive 10-minute asks inside a
    // 16-minute host budget. `otp: interactive` cannot afford a second full-length
    // ask, so the run reports instead of looping.
    const { server, port } = await fixtureServer({ submit: "button", acceptCode: false });
    try {
      let asks = 0;
      const result = await withBrowser(async (context) => {
        const page = await context.newPage();
        return autoLogin({
          page,
          cred: {
            name: "fixture",
            type: "login",
            username: IDENTIFIER,
            passwordless: true,
            // `interactive` without a hub resolves through the tty/browser
            // provider, which we never reach: the seed answers the first ask.
            otp: "totp",
            totpSecret: SEED,
            loginUrl: `http://127.0.0.1:${port}/`,
            domains: ["127.0.0.1"],
            warmup: false,
          },
          settleMs: 300,
          log: (m) => {
            if (m.includes("otp-required")) asks += 1;
          },
        });
      });
      assert.equal(result.ok, false);
      assert.equal(result.outcome, "otp-rejected");
      // A stored seed is cheap to regenerate, so it gets a few tries — but a
      // bounded few, not one per round.
      assert.ok(asks <= 4, `asked ${asks} times; the budget is meant to stop it`);
    } finally {
      server.close();
    }
  },
);

test(
  "a search box elsewhere on the code screen does not steal the submit",
  { skip },
  async () => {
    // The submit probe used to be page-wide, so a header form's real
    // `button[type=submit]` won over the code form's Verify and the label branch
    // never ran. The fixture now carries exactly that decoy.
    const { server, port } = await fixtureServer({ submit: "button" });
    try {
      const result = await withBrowser(async (context) => {
        const page = await context.newPage();
        return autoLogin({
          page,
          cred: {
            name: "fixture",
            type: "login",
            username: IDENTIFIER,
            passwordless: true,
            otp: "totp",
            totpSecret: SEED,
            loginUrl: `http://127.0.0.1:${port}/`,
            domains: ["127.0.0.1"],
            warmup: false,
          },
          settleMs: 400,
        });
      });
      assert.equal(result.ok, true, `auto-login failed: ${result.outcome}`);
      assert.match(result.finalUrl, /code=\d{6}$/);
      assert.ok(!result.finalUrl.includes("/search"), "the decoy form must not win");
    } finally {
      server.close();
    }
  },
);
