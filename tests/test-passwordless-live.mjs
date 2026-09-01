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

import {
  resolvePatchright,
  launchContext,
} from "../plugins/agent-id-browser/lib/launch.mjs";
import {
  autoLogin,
  detectPageState,
  otpBoxes,
  otpCardHints,
} from "../plugins/agent-id-browser/lib/auto-login.mjs";
import { typeCodeAcrossBoxes } from "../plugins/agent-id-browser/lib/human-input.mjs";
import { classifyLogin } from "../plugins/agent-id-browser/lib/login-detect.mjs";
import { formSnapshotInPage } from "../plugins/agent-id-browser/lib/session-server.mjs";

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
    `${i === 0 ? 'autocomplete="one-time-code"' : ""}>`
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
    if (url.pathname === "/otp-boxes") {
      res.end(`<!doctype html><meta charset=utf-8><title>code</title>
<h1>Enter the code we sent you</h1>
<form>${Array.from({ length: 6 }, (_, i) => `<input name=d${i} type=text inputmode=numeric maxlength=1>`).join("")}</form>`);
      return;
    }
    if (url.pathname === "/otp-boxes-self-submitting") {
      // A row that navigates on the last character, the way many code screens do.
      // The boxes are gone before anything can be read back, so a read-back that
      // calls that a failure fails the case that worked.
      res.end(`<!doctype html><meta charset=utf-8><title>code</title>
<h1>Enter the code we sent you</h1>
<form>${Array.from(
        { length: 6 },
        (_, i) => `<input name=d${i} type=text inputmode=numeric maxlength=1>`
      ).join("")}</form>
<script>
 var boxes = Array.from(document.querySelectorAll("input"));
 boxes.forEach(function (box, i) {
   box.addEventListener("input", function () {
     if (box.value && boxes[i + 1]) boxes[i + 1].focus();
     if (boxes.every(function (b) { return b.value; })) location.href = "/done?code=" + boxes.map(function (b) { return b.value; }).join("");
   });
 });
</script>`);
      return;
    }
    if (url.pathname === "/otp-boxes-stubborn") {
      // Boxes that do NOT advance the focus themselves. Typing into the first one
      // leaves five empty and the submit dead — which is what a live sign-in was
      // reporting, and what typing key-by-key cannot fix on its own.
      res.end(`<!doctype html><meta charset=utf-8><title>code</title>
<h1>Enter the code we sent you</h1>
<form>${Array.from(
        { length: 6 },
        (_, i) => `<input name=d${i} type=text inputmode=numeric maxlength=1>`
      ).join("")}</form>`);
      return;
    }
    if (url.pathname === "/otp-declared-twice") {
      // Two code fields on one page — a docs page demonstrating the component,
      // or a screen offering e-mail and SMS side by side. Which one the code goes
      // into is not knowable from here, so neither length is.
      res.end(`<!doctype html><meta charset=utf-8><title>code</title>
<h1>Enter the code we sent you</h1>
<form><input autocomplete=one-time-code inputmode=numeric maxlength=6></form>
<form><input autocomplete=one-time-code inputmode=numeric maxlength=4></form>`);
      return;
    }
    if (url.pathname === "/otp-declared-field") {
      // shadcn's InputOTP shape, measured on its own docs: the cells are drawn,
      // and the whole code goes into ONE field carrying `one-time-code` with the
      // length in `maxlength`. A great many sites take their code screen from
      // that component, and all of them were getting the plain fallback.
      const len = Number(url.searchParams.get("len") || 6);
      res.end(`<!doctype html><meta charset=utf-8><title>code</title>
<h1>Enter the code we sent you</h1>
<form><input id=code autocomplete=one-time-code inputmode=numeric maxlength=${len}></form>`);
      return;
    }
    if (url.pathname === "/otp-boxes-wrapped") {
      // Booking.com's actual shape, measured on a live sign-in:
      // `candidates=6 groups=1,1,1,1,1,1` — every box wrapped in an element of
      // its own, so a row grouped by the direct parent is six groups of one and
      // no row at all. The card went out with no cell count on the very site
      // this was built for.
      res.end(`<!doctype html><meta charset=utf-8><title>code</title>
<h1>Enter the code we sent you</h1>
<form><div class=row>${Array.from(
        { length: 6 },
        (_, i) => `<div class=cell><input name=d${i} type=text inputmode=numeric></div>`,
      ).join("")}</div></form>`);
      return;
    }
    if (url.pathname === "/otp-boxes-unmarked") {
      // What Booking.com actually renders: a row of boxes with no maxlength at
      // all, constrained in script. Counting only maxlength="1" missed it — on
      // the very site this was built for.
      res.end(`<!doctype html><meta charset=utf-8><title>code</title>
<h1>Enter the code we sent you</h1>
<form>${Array.from(
        { length: 6 },
        (_, i) => `<input name=d${i} type=text inputmode=numeric>`
      ).join("")}</form>`);
      return;
    }
    if (url.pathname === "/otp-not-a-code") {
      res.end(`<!doctype html><meta charset=utf-8><title>address</title>
<form>${["street", "city", "state", "zip", "country"]
        .map((n) => `<input name=${n} type=text>`)
        .join("")}</form>`);
      return;
    }
    // One ordinary field with room to spare and nothing declaring it a code
    // field: `maxlength` here is a bound, not a length, and drawing eight cells
    // for a six-character code strands a correct answer.
    if (url.pathname === "/otp-single") {
      res.end(`<!doctype html><meta charset=utf-8><title>code</title>
<h1>Enter the code we sent you</h1>
<form><input name=code type=text inputmode=numeric maxlength=8></form>`);
      return;
    }
    if (url.pathname === "/otp-unbounded") {
      res.end(`<!doctype html><meta charset=utf-8><title>code</title>
<h1>Enter the code we sent you</h1>
<form><input name=code type=text inputmode=numeric></form>`);
      return;
    }
    if (url.pathname === "/checkout-numeric") {
      // Four numeric fields, which is all "≥ 4 boxish inputs" ever asked for.
      // Nothing here is a code, and a card drawn with four cells for it submits
      // on the fourth character with no button to recover — so this page must
      // state no count at all.
      res.end(`<!doctype html><meta charset=utf-8><title>checkout</title>
<h1>Payment details</h1>
<form>
  <input name=card type=text inputmode=numeric maxlength=19 autocomplete="cc-number">
  <input name=exp type=text inputmode=numeric maxlength=5>
  <input name=cvc type=text inputmode=numeric maxlength=4>
  <input name=zip type=text inputmode=numeric maxlength=10>
</form>`);
      return;
    }
    if (url.pathname === "/quantities") {
      // The same count, uniform this time, and still not a code: nothing on the
      // page says one was sent, and no box claims to hold a single character.
      res.end(`<!doctype html><meta charset=utf-8><title>cart</title>
<h1>Your basket</h1>
<form>${Array.from(
        { length: 5 },
        (_, i) => `<input name=qty${i} type=number>`
      ).join("")}</form>`);
      return;
    }
    if (url.pathname === "/otp-boxes-unmarked-stubborn") {
      // Both halves of the reported failure at once: no `maxlength` anywhere AND
      // no script to advance the focus. Typing the code into the first box leaves
      // the whole of it sitting there, which a total-character count reads as a
      // filled row — one box full, five empty, and reported as landed.
      res.end(`<!doctype html><meta charset=utf-8><title>code</title>
<h1>Enter the code we sent you</h1>
<form>${Array.from(
        { length: 6 },
        (_, i) => `<input name=d${i} type=text inputmode=numeric>`
      ).join("")}</form>`);
      return;
    }
    if (url.pathname === "/masked-checkbox") {
      // The ordinary cookie banner: a dialog masking the page that carries an input
      // of its own. "The page asks for something else" is satisfied by that
      // checkbox, so the sign-in form below counted as staged.
      res.end(`<!doctype html><meta charset=utf-8><title>sign-in</title>
<div id=root aria-hidden="true">
  <form action="/done" method="get">
    <label for=u>Email address</label><input id=u name=username type=email autocomplete=username>
    <label for=p>Password</label><input id=p name=password type=password>
    <button type=submit>Sign in</button>
  </form>
</div>
<div role="dialog"><p>We use cookies</p><label for=an>Analytics</label><input id=an type=checkbox><button>Accept</button></div>`);
      return;
    }
    if (url.pathname === "/staged-with-search") {
      // A search box in the header is enough to make everything under `aria-hidden`
      // count as staged — and there is no dialog to dismiss to get it back.
      res.end(`<!doctype html><meta charset=utf-8><title>sign-in</title>
<form><input name=q type=search placeholder="Search"></form>
<div aria-hidden="true">
  <form action="/done" method="get">
    <label for=u>Email</label><input id=u name=username type=email autocomplete=username>
    <label for=p>Password</label><input id=p name=password type=password>
    <button type=submit>Sign in</button>
  </form>
</div>`);
      return;
    }
    if (url.pathname === "/newsletter") {
      res.end(`<!doctype html><meta charset=utf-8><title>home</title>
<h1>Our blog</h1>
<footer><form><label for=n>Get our newsletter</label><input id=n name=email type=email></form></footer>`);
      return;
    }
    if (url.pathname === "/masked") {
      // The other thing `aria-hidden` on an ancestor means: a dialog masking the
      // page behind it. Here the password IS what the page wants — it is covered,
      // not staged — and nothing else is being asked for.
      res.end(`<!doctype html><meta charset=utf-8><title>sign-in</title>
<div id=root aria-hidden="true">
  <h1>Welcome back</h1>
  <form action="/done" method="get">
    <label for=p>Password</label>
    <input id=p name=password type=password>
    <button type=submit>Sign in</button>
  </form>
</div>
<div role="dialog"><p>We use cookies</p><button>Accept</button></div>`);
      return;
    }
    if (url.pathname === "/password-step") {
      // The ordinary second-factor shape, and the one a live report was about:
      // identifier and password together, then a mailed code. Nothing about it is
      // passwordless, so the whole path — the stored password, the code screen
      // after it, the card raised for that code — has to work as a sequence.
      res.end(`<!doctype html><meta charset=utf-8><title>sign-in</title>
<h1>Sign in</h1>
<form action="/code" method="get">
  <label for=u>Username</label><input id=u name=username autocomplete=username>
  <label for=p>Password</label><input id=p name=password type=password autocomplete=current-password>
  <button type=submit>Sign in</button>
</form>`);
      return;
    }
    if (url.pathname === "/staged") {
      // Booking.com's shape: the password step is fully built and laid out on
      // the e-mail screen — sized, opaque, inside the viewport — and taken out
      // of the accessibility tree until it is the owner's turn to see it.
      res.end(`<!doctype html><meta charset=utf-8><title>sign-in</title>
<h1>Sign in or create an account</h1>
<form action="/code" method="get">
  <label for=u>Email address</label>
  <input id=u name=username type=email autocomplete=username>
  <div aria-hidden="true">
    <label for=p>Password</label>
    <input id=p name=password type=password style="width:162px;height:26px;opacity:1">
  </div>
  <button type=submit>Continue with email</button>
</form>`);
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
      resolve({ server, port: server.address().port })
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
    }
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

        await page.goto(`http://127.0.0.1:${port}/`, {
          waitUntil: "domcontentloaded",
        });
        const step1 = await detectPageState(page);
        assert.equal(step1.hasPasswordField, false);
        assert.equal(step1.hasIdentifierField, true, "the e-mail input must be seen");
        // The whole point: a screen with no password is not a finished login —
        // while we are still standing on it. `onLoginPage` is what the caller
        // knows and the snapshot does not; off the sign-in page the same e-mail
        // input is a newsletter box.
        assert.equal(classifyLogin({ ...step1, onLoginPage: true }), "unknown");
        assert.equal(classifyLogin({ ...step1, onLoginPage: false }), "logged-in");

        await page.goto(`http://127.0.0.1:${port}/code`, {
          waitUntil: "domcontentloaded",
        });
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
  }
);

test(
  "a code the site keeps refusing is asked for once, not once per round",
  { skip },
  async () => {
    // With one card per round this was ten consecutive 10-minute asks inside a
    // 16-minute host budget. `otp: interactive` cannot afford a second full-length
    // ask, so the run reports instead of looping.
    const { server, port } = await fixtureServer({
      submit: "button",
      acceptCode: false,
    });
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
      // Two attempts, not one per round. The second waits out the TOTP window so
      // it is a different code — which is the only retry that can succeed.
      assert.ok(asks <= 4, `asked ${asks} times; the budget is meant to stop it`);
    } finally {
      server.close();
    }
  }
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
  }
);

test(
  "a password the page has hidden from the accessibility tree is not a password it wants",
  { skip },
  async () => {
    const { server, port } = await fixtureServer();
    try {
      await withBrowser(async (context) => {
        const page = await context.newPage();
        await page.goto(`http://127.0.0.1:${port}/staged`, {
          waitUntil: "domcontentloaded",
        });

        // Every ordinary visibility test passes on this input: it has a box, it
        // is opaque, it is in the viewport. Only the accessibility tree says it
        // is not this step.
        const naive = await page.evaluate(() => {
          const el = document.querySelector('input[type="password"]');
          const r = el.getBoundingClientRect();
          const st = getComputedStyle(el);
          return {
            laidOut: r.width > 0 && r.height > 0,
            opacity: st.opacity,
            offsetParent: !!el.offsetParent,
          };
        });
        assert.deepEqual(naive, {
          laidOut: true,
          opacity: "1",
          offsetParent: true,
        });

        const state = await detectPageState(page);
        assert.equal(state.hasPasswordField, false, "a staged password is not being asked for");
        assert.equal(state.hasIdentifierField, true, "the identifier keeps the looser test");
        assert.equal(classifyLogin({ ...state, onLoginPage: true }), "unknown");

        // The same rule where the agent reads it. Seeing a password control here
        // is what made one store an ordinary login for a site that has none.
        const snapshot = await page.evaluate(formSnapshotInPage, {
          prefix: "",
          generation: 1,
        });
        assert.ok(
          !snapshot.controls.some((c) => c.type === "password"),
          "a staged control is not one of the fields on offer"
        );
        assert.ok(snapshot.controls.some((c) => c.type === "email"), "the identifier is");
        // The conclusion, not the evidence. Reporting the password flagged was tried
        // and read straight past: an agent said it saw "a technical password field in
        // the markup" and stored a credential the site has no use for.
        assert.deepEqual(snapshot.signIn, {
          identifier: true,
          passwordAsked: false,
        });
      });
    } finally {
      server.close();
    }
  }
);

test(
  "a page masked behind a dialog is covered, not staged — its password still counts",
  { skip },
  async () => {
    const { server, port } = await fixtureServer();
    try {
      await withBrowser(async (context) => {
        const page = await context.newPage();
        await page.goto(`http://127.0.0.1:${port}/masked`, {
          waitUntil: "domcontentloaded",
        });

        // Reading `aria-hidden` as "not asked for" without this distinction reported
        // no password and no identifier, which is the shape of a finished login: the
        // run sealed an unauthenticated profile and called it a success.
        const state = await detectPageState(page);
        assert.equal(state.hasPasswordField, true, "the page is asking for this password");
        assert.notEqual(
          classifyLogin({ ...state, onLoginPage: false }),
          "logged-in",
          "a masked sign-in page is not a finished one"
        );

        const snapshot = await page.evaluate(formSnapshotInPage, {
          prefix: "",
          generation: 1,
        });
        assert.ok(
          snapshot.controls.some((c) => c.type === "password"),
          "covered is not staged"
        );
        // Nothing here asks for an identifier, so no verdict is offered. Claiming one
        // on every page would make the field worthless where it matters.
        assert.equal(snapshot.signIn, undefined, "a page with no identifier gets no verdict");
      });
    } finally {
      server.close();
    }
  }
);

test(
  "a staged control leaves the fields on offer but stays reachable",
  { skip },
  async () => {
    const { server, port } = await fixtureServer();
    try {
      await withBrowser(async (context) => {
        const page = await context.newPage();

        // Dropping staged controls read "the page asks for something else" as ANY
        // live input on the page. A cookie banner's own checkbox satisfies that, and
        // took the sign-in form with it — with no ref left to fill it by.
        for (const route of ["/masked-checkbox", "/staged-with-search"]) {
          await page.goto(`http://127.0.0.1:${port}${route}`, {
            waitUntil: "domcontentloaded",
          });
          const snapshot = await page.evaluate(formSnapshotInPage, {
            prefix: "",
            generation: 1,
          });
          const staged = snapshot.staged ?? [];

          assert.ok(
            !snapshot.controls.some((c) => c.type === "password"),
            `${route}: a staged control is not one of the fields on offer`
          );
          assert.ok(
            staged.some((c) => c.type === "password") &&
              staged.some((c) => c.type === "email"),
            `${route}: the form must still be reachable, got ${JSON.stringify(
              staged.map((c) => c.type)
            )}`
          );
          assert.ok(staged.every((c) => c.ref), `${route}: reachable means it has a ref`);
        }
      });
    } finally {
      server.close();
    }
  }
);

test(
  "a page is only called a sign-in when something submits it",
  { skip },
  async () => {
    const { server, port } = await fixtureServer();
    try {
      await withBrowser(async (context) => {
        const page = await context.newPage();

        // A newsletter box answering `passwordAsked: false` tells the caller the site
        // has no password — the same wrong conclusion this file exists to prevent,
        // reached from the other end.
        await page.goto(`http://127.0.0.1:${port}/newsletter`, {
          waitUntil: "domcontentloaded",
        });
        const footer = await page.evaluate(formSnapshotInPage, {
          prefix: "",
          generation: 1,
        });
        assert.equal(
          footer.signIn,
          undefined,
          "an e-mail field alone is not a sign-in"
        );

        await page.goto(`http://127.0.0.1:${port}/staged`, {
          waitUntil: "domcontentloaded",
        });
        const signIn = await page.evaluate(formSnapshotInPage, {
          prefix: "",
          generation: 1,
        });
        assert.deepEqual(signIn.signIn, {
          identifier: true,
          passwordAsked: false,
        });
      });
    } finally {
      server.close();
    }
  }
);

test(
  "the page's own constraint is what says how many cells to draw",
  { skip },
  async () => {
    const { server, port } = await fixtureServer();
    try {
      await withBrowser(async (context) => {
        const page = await context.newPage();
        const lengthAt = async (route) => {
          await page.goto(`http://127.0.0.1:${port}${route}`, {
            waitUntil: "domcontentloaded",
          });
          return (await otpCardHints(page)).length;
        };

        // A row of one-character boxes IS the count.
        assert.equal(await lengthAt("/otp-boxes"), 6);
        // One field states it outright.
        assert.equal(
          await lengthAt("/otp-single"),
          null,
          "a maxlength is an upper bound, not the length of the code"
        );
        // And an unconstrained input states nothing — which must not be read as a
        // count, because the screen submits itself once the cells it drew are full.
        assert.equal(await lengthAt("/otp-unbounded"), null);
        // Four numeric inputs is what a checkout step looks like, and "four or
        // more inputs that could take a code" is satisfied by it. What rules it
        // out is that a row is uniform: 19, 5, 4 and 10 characters are four
        // different fields, not one code.
        assert.equal(
          await lengthAt("/checkout-numeric"),
          null,
          "a payment form must not be read as a four-cell code row"
        );
        // Uniform this time, so shape alone does not settle it — but nothing says
        // a code was sent and no box claims a single character, so the page is
        // taken at its word rather than counted.
        assert.equal(
          await lengthAt("/quantities"),
          null,
          "a row of quantity inputs is not a code row"
        );
      });
    } finally {
      server.close();
    }
  }
);

test(
  "both paths to a code card read the same hints off the page",
  { skip },
  async () => {
    const { server, port } = await fixtureServer();
    try {
      await withBrowser(async (context) => {
        const page = await context.newPage();
        const hintsAt = async (route) => {
          await page.goto(`http://127.0.0.1:${port}${route}`, {
            waitUntil: "domcontentloaded",
          });
          return otpCardHints(page);
        };

        // `fill_otp` raises the same card as auto-login and used to pass neither of
        // these, so a code screen driven by hand drew a plain field and told the
        // owner nothing about where to look.
        assert.deepEqual(await hintsAt("/otp-boxes"), {
          length: 6,
          destination: null,
        });
        assert.deepEqual(await hintsAt("/otp-boxes-unmarked"), {
          length: 6,
          destination: null,
        });
        assert.deepEqual(await hintsAt("/otp-boxes-wrapped"), {
          length: 6,
          destination: null,
        });
        assert.equal(
          (await hintsAt("/otp-not-a-code")).length,
          null,
          "several text inputs are a form, not a row of code boxes"
        );
        // `maxlength` says "no more than", not "exactly": a site may allow eight
        // for a six-character code. Cells drawn from it would submit on the eighth
        // and strand a correct six-character answer, so this states no count and
        // the request goes out as a plain field with a button.
        assert.deepEqual(await hintsAt("/otp-single"), {
          length: null,
          destination: null,
        });

        const unbounded = await hintsAt("/otp-unbounded");
        assert.equal(
          unbounded.length,
          null,
          "an unconstrained input states no count"
        );
      });
    } finally {
      server.close();
    }
  }
);

test(
  "a credential that claims the site has no codes is corrected when it asks for one",
  { skip },
  async () => {
    // `otp: "none"` is a claim about the site, and it used to end the run: the
    // owner had a password typed and a code mailed, and no card was ever raised
    // to type it into. The site asking IS the evidence that the claim is wrong.
    const { server, port } = await fixtureServer();
    try {
      const corrections = [];
      const result = await withBrowser(async (context) => {
        const page = await context.newPage();
        return autoLogin({
          page,
          cred: {
            name: "fixture",
            type: "login",
            username: IDENTIFIER,
            passwordless: true,
            otp: "none",
            loginUrl: `http://127.0.0.1:${port}/`,
            domains: ["127.0.0.1"],
            warmup: false,
          },
          settleMs: 400,
          resolveOtpFn: async () => "123456",
          onOtpModeCorrected: async (otp) => corrections.push(otp),
        });
      });

      assert.notEqual(
        result.outcome,
        "otp-unexpected",
        "asking is not a reason to give up"
      );
      assert.equal(result.ok, true, `auto-login failed: ${result.outcome}`);
      assert.deepEqual(
        corrections,
        ["interactive"],
        "and the record stops being wrong"
      );
    } finally {
      server.close();
    }
  }
);

test(
  "a credential that already answers codes is left alone",
  { skip },
  async () => {
    const { server, port } = await fixtureServer();
    try {
      const corrections = [];
      await withBrowser(async (context) => {
        const page = await context.newPage();
        return autoLogin({
          page,
          cred: {
            name: "fixture",
            type: "login",
            username: IDENTIFIER,
            passwordless: true,
            otp: "interactive",
            loginUrl: `http://127.0.0.1:${port}/`,
            domains: ["127.0.0.1"],
            warmup: false,
          },
          settleMs: 400,
          resolveOtpFn: async () => "123456",
          onOtpModeCorrected: async (otp) => corrections.push(otp),
        });
      });

      assert.deepEqual(corrections, [], "nothing to correct");
    } finally {
      server.close();
    }
  }
);

test(
  "an unmarked row that will not move the focus is filled, not merely counted",
  { skip },
  async () => {
    // Both halves of the reported failure together: no `maxlength` to truncate the
    // first box, and no script to advance the focus. Typing the code leaves all
    // six characters in box 0 — which a total-character count reads as a filled
    // row, so the repair loop never runs and `fill-otp` reports success over one
    // box full and five empty. Per-box comparison is what tells the two apart.
    const { server, port } = await fixtureServer();
    try {
      await withBrowser(async (context) => {
        const page = await context.newPage();
        await page.goto(
          `http://127.0.0.1:${port}/otp-boxes-unmarked-stubborn`,
          { waitUntil: "domcontentloaded" }
        );

        const boxes = await otpBoxes(page);
        assert.equal(boxes.length, 6, "the unmarked row is recognised");

        const typed = await typeCodeAcrossBoxes(page, boxes, "423124");
        assert.deepEqual(typed, { complete: true, submitted: false });

        const values = await page.evaluate(() =>
          Array.from(document.querySelectorAll("input")).map((i) => i.value)
        );
        assert.deepEqual(
          values,
          ["4", "2", "3", "1", "2", "4"],
          `one character per box, not all six in the first: got ${values.join("|")}`
        );
      });
    } finally {
      server.close();
    }
  }
);

test(
  "a row still holding a refused code is cleared, not spliced with the new one",
  { skip },
  async () => {
    // A retry arrives at a row the site re-rendered with the previous code in it.
    // Clearing only box 0 left five stale characters behind, and a total count
    // then passed on a hybrid of two codes — submitted, and reported as landed.
    const { server, port } = await fixtureServer();
    try {
      await withBrowser(async (context) => {
        const page = await context.newPage();
        await page.goto(
          `http://127.0.0.1:${port}/otp-boxes-unmarked-stubborn`,
          { waitUntil: "domcontentloaded" }
        );
        await page.evaluate(() =>
          Array.from(document.querySelectorAll("input")).forEach((input, i) => {
            input.value = "999999"[i];
          })
        );

        const boxes = await otpBoxes(page);
        const typed = await typeCodeAcrossBoxes(page, boxes, "423124");
        assert.deepEqual(typed, { complete: true, submitted: false });

        const values = await page.evaluate(() =>
          Array.from(document.querySelectorAll("input")).map((i) => i.value)
        );
        assert.deepEqual(
          values,
          ["4", "2", "3", "1", "2", "4"],
          `no digit of the refused code survives: got ${values.join("|")}`
        );
      });
    } finally {
      server.close();
    }
  }
);

test(
  "a code lands in every box, even when the page will not move the focus",
  { skip },
  async () => {
    const { server, port } = await fixtureServer();
    try {
      await withBrowser(async (context) => {
        const page = await context.newPage();
        await page.goto(`http://127.0.0.1:${port}/otp-boxes-stubborn`, {
          waitUntil: "domcontentloaded",
        });

        const boxes = await otpBoxes(page);
        assert.equal(boxes.length, 6, "the row is recognised");

        const typed = await typeCodeAcrossBoxes(page, boxes, "423124");
        assert.deepEqual(
          typed,
          { complete: true, submitted: false },
          "the row is filled, and this row is not one that submits itself"
        );

        const values = await page.evaluate(() =>
          Array.from(document.querySelectorAll("input")).map((i) => i.value)
        );
        assert.deepEqual(
          values,
          ["4", "2", "3", "1", "2", "4"],
          `got ${values.join("|")}`
        );
      });
    } finally {
      server.close();
    }
  }
);

test(
  "an ordinary single code field is not mistaken for a row",
  { skip },
  async () => {
    const { server, port } = await fixtureServer();
    try {
      await withBrowser(async (context) => {
        const page = await context.newPage();
        await page.goto(`http://127.0.0.1:${port}/otp-single`, {
          waitUntil: "domcontentloaded",
        });

        assert.deepEqual(
          await otpBoxes(page),
          [],
          "one field is not a row to spread across"
        );
      });
    } finally {
      server.close();
    }
  }
);

test(
  "a row that submits itself is not reported as a code that failed to land",
  { skip },
  async () => {
    const { server, port } = await fixtureServer();
    try {
      await withBrowser(async (context) => {
        const page = await context.newPage();
        await page.goto(`http://127.0.0.1:${port}/otp-boxes-self-submitting`, {
          waitUntil: "domcontentloaded",
        });

        const boxes = await otpBoxes(page);
        const typed = await typeCodeAcrossBoxes(page, boxes, "423124");

        assert.deepEqual(
          typed,
          { complete: true, submitted: true },
          "navigating away is the code landing, not losing it — and the caller is " +
            "told the row took the page with it, so it does not press Enter into " +
            "whatever screen came next"
        );
        await page.waitForURL(/code=423124/, { timeout: 5000 });
      });
    } finally {
      server.close();
    }
  }
);

test("a sign-in with a password AND a code runs end to end", { skip }, async () => {
  // Everything before this exercised passwordless sign-ins. The reported failure
  // was the other shape: username, password, and only then a code — where the
  // card for that code never appeared at all.
  const { server, port } = await fixtureServer();
  try {
    const cards = [];
    const result = await withBrowser(async (context) => {
      const page = await context.newPage();
      return autoLogin({
        page,
        cred: {
          name: "fixture-2fa",
          type: "login",
          username: IDENTIFIER,
          password: "hunter2",
          passwordless: false,
          otp: "interactive",
          loginUrl: `http://127.0.0.1:${port}/password-step`,
          domains: ["127.0.0.1"],
          warmup: false,
        },
        settleMs: 400,
        resolveOtpFn: async (cred, opts) => {
          cards.push({ length: opts?.length ?? null, destination: opts?.destination ?? null });
          return "423124";
        },
      });
    });

    assert.equal(result.ok, true, `auto-login failed: ${result.outcome}`);
    assert.match(result.finalUrl, /code=423124$/, "the code reached the site");
    assert.equal(cards.length, 1, "exactly one card, raised when the site asked");
    // The card the owner would have seen: six cells, and where the code went.
    assert.equal(cards[0].length, 6);
    assert.equal(cards[0].destination, IDENTIFIER);
  } finally {
    server.close();
  }
});

test("a field that declares itself a code field states its length", { skip }, async () => {
  const { server, port } = await fixtureServer();
  try {
    await withBrowser(async (context) => {
      const page = await context.newPage();
      const lengthAt = async (route) => {
        await page.goto(`http://127.0.0.1:${port}${route}`, { waitUntil: "domcontentloaded" });
        return (await otpCardHints(page)).length;
      };

      // `one-time-code` AND a maxlength: the field says what it is for and how
      // long that is. Every length the screen can draw.
      for (const len of [4, 5, 6, 7, 8]) {
        assert.equal(await lengthAt(`/otp-declared-field?len=${len}`), len, `len=${len}`);
      }

      // Neither half alone. A maxlength on an ordinary field is the upper bound
      // this refuses, and it is refused still.
      assert.equal(await lengthAt("/otp-single"), null, "a bare maxlength is a bound, not a length");
      assert.equal(
        await lengthAt("/otp-declared-twice"),
        null,
        "two code fields state two lengths, and neither is this code's",
      );
    });
  } finally {
    server.close();
  }
});
