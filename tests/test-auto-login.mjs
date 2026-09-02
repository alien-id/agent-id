#!/usr/bin/env node

// Unit tests for the auto-login engine's deterministic pieces (lib/auto-login.mjs):
// placeholder substitution, recipe-step → page-call mapping with lazy {otp}
// resolution, and stored-TOTP code resolution. No real browser is launched.
//
// Run: node --test tests/test-auto-login.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import os from "node:os";
import path from "node:path";

import {
  applyVars,
  stepNeedsOtp,
  runRecipe,
  autoLogin,
  otpPromptWording,
  millisToNextTotpWindow,
  CODE_SUBMIT_TEXT_RE,
  resolveOtp,
  isLoginishPath,
  stillOnLoginPage,
  originOf,
  isDeepLoginUrl,
  otpCardBudgetMs,
  otpCardSpec,
  fromAuthenticatorApp,
  maskedIdentifier,
  otpCardLength,
  otpModeCorrection,
} from "../plugins/agent-id-browser/lib/auto-login.mjs";
import { generateTotp } from "../plugins/agent-id-core/lib/totp.mjs";

test("applyVars substitutes username/password/otp; passes non-strings through", () => {
  assert.equal(
    applyVars("{username}:{password}:{otp}", {
      username: "u",
      password: "p",
      otp: "123",
    }),
    "u:p:123"
  );
  assert.equal(applyVars("nothing here", {}), "nothing here");
  assert.equal(applyVars(42, {}), 42);
});

test("stepNeedsOtp detects {otp} in a placeholder field", () => {
  assert.equal(stepNeedsOtp({ action: "fill", selector: "#code", value: "{otp}" }), true);
  assert.equal(stepNeedsOtp({ action: "fill", selector: "#pw", value: "{password}" }), false);
});

// A page stub that reports the origin it is "on" — the allowlist gate reads it
// live via page.url(), so a bare {} is no longer a usable stand-in.
function pageOn(url) {
  return { url: () => url };
}

// A recording driver stands in for the human-input driver so the recipe
// mapping / var-substitution / lazy-OTP logic is tested without a browser.
function recordingDriver(calls) {
  return {
    navigate: async (_p, url) => calls.push(["goto", url]),
    fill: async (_p, sel, val) => calls.push(["fill", sel, val]),
    type: async (_p, sel, val) => calls.push(["type", sel, val]),
    // Separate from `fill` on purpose: a code goes to the row-aware verb, and a
    // recipe that sent it through the ordinary one is the Booking.com failure.
    fillCode: async (_p, sel, val) => calls.push(["fillCode", sel, val]),
    click: async (_p, sel) => calls.push(["click", sel]),
    press: async (_p, sel, key) => calls.push(["press", sel, key]),
    wait: async (_p, ms) => calls.push(["wait", ms]),
  };
}

test("runRecipe maps steps to driver calls, substitutes vars, resolves {otp} once and lazily", async () => {
  const calls = [];
  let otpCalls = 0;
  const getOtp = async () => {
    otpCalls++;
    return "654321";
  };
  const steps = [
    { action: "navigate", url: "https://x/login" },
    { action: "fill", selector: "#user", value: "{username}" },
    { action: "fill", selector: "#pass", value: "{password}" },
    { action: "click", selector: "#submit" },
    { action: "fill", selector: "#otp", value: "{otp}" },
    { action: "press", selector: "#otp", key: "Enter" },
  ];
  await runRecipe(pageOn("https://x/login"), steps, {
    username: "alice",
    password: "s3cret",
    getOtp,
    domains: ["x"],
    driver: recordingDriver(calls),
  });
  assert.deepEqual(calls, [
    ["goto", "https://x/login"],
    ["fill", "#user", "alice"],
    ["fill", "#pass", "s3cret"],
    ["click", "#submit"],
    ["fillCode", "#otp", "654321"],
    ["press", "#otp", "Enter"],
  ]);
  assert.equal(otpCalls, 1);
});

test("runRecipe does not resolve OTP when no step needs it", async () => {
  let otpCalls = 0;
  await runRecipe(pageOn("https://x/login"), [{ action: "fill", selector: "#u", value: "{username}" }], {
    username: "u",
    password: "p",
    getOtp: async () => {
      otpCalls++;
      return "x";
    },
    domains: ["x"],
    driver: recordingDriver([]),
  });
  assert.equal(otpCalls, 0);
});

test("runRecipe rejects an unknown action", async () => {
  await assert.rejects(
    runRecipe(pageOn("https://x/login"), [{ action: "frobnicate" }], {
      username: "u",
      password: "p",
      getOtp: async () => "",
      domains: ["x"],
      driver: recordingDriver([]),
    }),
    /unknown recipe action/
  );
});

test("runRecipe requires the credential's domains allowlist", async () => {
  await assert.rejects(
    runRecipe(pageOn("https://x/login"), [{ action: "wait", ms: 1 }], {
      username: "u",
      password: "p",
      getOtp: async () => "",
      driver: recordingDriver([]),
    }),
    /requires the credential's `domains` allowlist/
  );
});

test("runRecipe refuses to navigate off the credential's allowlist", async () => {
  const calls = [];
  await assert.rejects(
    runRecipe(
      pageOn("https://x/login"),
      [{ action: "navigate", url: "https://evil.test/collect" }],
      {
        username: "u",
        password: "p",
        getOtp: async () => "",
        domains: ["x"],
        driver: recordingDriver(calls),
      }
    ),
    /not on the credential's domain allowlist/
  );
  assert.deepEqual(calls, [], "the navigation must not have happened");
});

test("runRecipe refuses a secret step on a foreign origin BEFORE resolving the code", async () => {
  const calls = [];
  let otpCalls = 0;
  await assert.rejects(
    runRecipe(
      pageOn("https://evil.test/phish"),
      [{ action: "fill", selector: "#code", value: "{otp}" }],
      {
        username: "u",
        password: "p",
        getOtp: async () => {
          otpCalls++;
          return "654321";
        },
        domains: ["x"],
        driver: recordingDriver(calls),
      }
    ),
    /not on the credential's domain allowlist/
  );
  assert.deepEqual(calls, [], "the fill must not have happened");
  assert.equal(otpCalls, 0, "the owner must not be asked for a code we were going to refuse");
});

test("runRecipe gates a secret hidden in a selector, not just in a value", async () => {
  const calls = [];
  await assert.rejects(
    runRecipe(
      pageOn("https://evil.test/phish"),
      [{ action: "click", selector: "#x-{password}" }],
      {
        username: "u",
        password: "p",
        getOtp: async () => "",
        domains: ["x"],
        driver: recordingDriver(calls),
      }
    ),
    /not on the credential's domain allowlist/
  );
  assert.deepEqual(calls, []);
});

test("runRecipe refuses a navigate URL carrying a secret placeholder", async () => {
  const calls = [];
  await assert.rejects(
    runRecipe(
      pageOn("https://x/login"),
      [{ action: "navigate", url: "https://x/c?v={otp}" }],
      {
        username: "u",
        password: "p",
        getOtp: async () => "654321",
        domains: ["x"],
        driver: recordingDriver(calls),
      }
    ),
    /must not carry \{password\} or \{otp\}/
  );
  assert.deepEqual(calls, []);
});

test("runRecipe fails closed when the page cannot report its origin", async () => {
  // A page object that cannot say where it is must stop the step, not skip the
  // check. What it throws is not the point — that nothing was typed is.
  const calls = [];
  await assert.rejects(
    runRecipe({}, [{ action: "fill", selector: "#code", value: "{otp}" }], {
      username: "u",
      password: "p",
      getOtp: async () => "654321",
      domains: ["x"],
      driver: recordingDriver(calls),
    })
  );
  assert.deepEqual(calls, []);
});

test("autoLogin refuses a loginUrl off the credential's allowlist, before opening anything", async () => {
  await assert.rejects(
    autoLogin({
      page: {},
      cred: {
        name: "c",
        username: "u",
        password: "p",
        loginUrl: "https://evil.test/login",
        domains: ["x"],
      },
    }),
    /not on the credential's domain allowlist/
  );
});

test("resolveOtp generates a code from a stored TOTP seed (RFC vector)", async () => {
  const cred = {
    name: "demo",
    otp: "totp",
    totpSecret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    period: 30,
    digits: 6,
  };
  const code = await resolveOtp(cred, { now: 59_000 });
  assert.equal(code, "287082");
  assert.equal(
    code,
    generateTotp({
      secret: cred.totpSecret,
      period: 30,
      digits: 6,
      now: 59_000,
    })
  );
});

// The hosted-harness protocol on a unix socket, as `test-secure-prompt.mjs` drives
// it — the one way to watch what `resolveOtp` puts in front of the owner.
async function withCardCapture(run) {
  const sock = path.join(os.tmpdir(), `agentid-otp-${process.pid}-${Date.now()}.sock`);
  const seen = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      seen.push(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ values: { otp: "123456" } }));
    });
  });
  await new Promise((resolve) => server.listen(sock, resolve));
  try {
    return { result: await run({ AGENT_ID_SECURE_PROMPT_SOCK: sock }), seen };
  } finally {
    server.close();
  }
}

test("a TOTP credential with no seed asks the owner instead of failing the sign-in", async () => {
  // It used to throw `otp=totp but no totpSecret stored` and fail the whole sign-in
  // while the owner sat there with the code already on their phone.
  const { result, seen } = await withCardCapture((env) =>
    resolveOtp(
      { name: "gh", otp: "totp", loginUrl: "https://github.example/login" },
      { env }
    )
  );

  assert.equal(result, "123456");
  assert.equal(seen.length, 1, "exactly one card");
  assert.match(seen[0].title, /2FA code for Github\.example/);
  assert.equal(seen[0].fields[0].name, "otp");
});

test("a TOTP credential that has its seed still never raises a card", async () => {
  const { result, seen } = await withCardCapture((env) =>
    resolveOtp(
      { name: "gh", otp: "totp", totpSecret: "JBSWY3DPEHPK3PXP" },
      { env }
    )
  );

  assert.equal(seen.length, 0, "a stored seed is answered without asking anyone");
  assert.match(result, /^\d{6}$/);
});

test("the card for an authenticator code sends nobody to a mailbox", () => {
  // The copy that was already there says "check your email or messages", which for
  // a code that was never sent anywhere is a wrong instruction, not a vague one.
  const spec = otpCardSpec({
    name: "gh",
    otp: "totp",
    loginUrl: "https://github.example/login",
  });

  assert.match(spec.description, /2FA app/i);
  assert.ok(!/email|messages|sent/i.test(spec.description), spec.description);
  assert.ok(fromAuthenticatorApp({ name: "gh", otp: "totp" }));
  assert.ok(
    !fromAuthenticatorApp({ name: "gh", otp: "totp", totpSecret: "x" }),
    "with a seed there is no card, so nothing to word"
  );
});

// ── Positive-confirmation helpers (the "logged-in" false-positive guard) ──────────

test("isLoginishPath matches whole login/auth segments, not substrings", () => {
  for (const p of [
    "/login",
    "/login/",
    "/account/signin",
    "/oauth2/authorize",
    "/auth/callback",
    "/challenge",
  ]) {
    assert.equal(isLoginishPath(p), true, `login-ish: ${p}`);
  }
  // "authors" must NOT match "auth"; app paths are not login-ish.
  for (const p of [
    "/",
    "/feed",
    "/authors/jane",
    "/r/test",
    "/user/me",
    "/settings",
  ]) {
    assert.equal(isLoginishPath(p), false, `app path: ${p}`);
  }
});

test("stillOnLoginPage: true only when stuck on the same-host login page", () => {
  const loginUrl = "https://www.reddit.com/login";
  // The exact Reddit failure: form gone but still on /login with a js_challenge.
  assert.equal(
    stillOnLoginPage(
      "https://www.reddit.com/login/?solution=abc&js_challenge=1",
      loginUrl
    ),
    true
  );
  // Real success leaves the login page (redirect to the feed) → confirmed.
  assert.equal(stillOnLoginPage("https://www.reddit.com/", loginUrl), false);
  assert.equal(stillOnLoginPage("https://www.reddit.com/r/programming/", loginUrl), false);
  // Left the auth host entirely → progressed.
  assert.equal(stillOnLoginPage("https://app.example.com/dashboard", loginUrl), false);
  // Garbage URLs don't wedge the caller into a false "stuck".
  assert.equal(stillOnLoginPage("not a url", loginUrl), false);
});

test("stillOnLoginPage: a modal login on the homepage isn't falsely flagged as stuck", () => {
  // loginUrl is the app homepage (login via modal, URL unchanged). After login we
  // are on "/" — NOT a login-ish path — so "logged-in" is confirmed, not rejected.
  assert.equal(stillOnLoginPage("https://app.example.com/", "https://app.example.com/"), false);
});

// ── Warmup helpers (the cold-deep-link block fix) ─────────────────────────────────

test("originOf returns scheme+host, null on garbage", () => {
  assert.equal(originOf("https://www.reddit.com/login/?x=1"), "https://www.reddit.com");
  assert.equal(originOf("http://host:8080/a/b"), "http://host:8080");
  assert.equal(originOf("not a url"), null);
});

test("isDeepLoginUrl: true for a real path, false for the bare origin root", () => {
  assert.equal(isDeepLoginUrl("https://www.reddit.com/login/"), true);
  assert.equal(isDeepLoginUrl("https://accounts.example.com/auth/signin"), true);
  // Bare root → nothing to warm up first.
  assert.equal(isDeepLoginUrl("https://www.reddit.com/"), false);
  assert.equal(isDeepLoginUrl("https://www.reddit.com"), false);
  assert.equal(isDeepLoginUrl("garbage"), false);
});

// ─── the code card's wording ──────────────────────────────────────────────────────

test("otpPromptWording: a passwordless code is not presented as a second factor", () => {
  const w = otpPromptWording({
    // A name that shares nothing with the host, so its absence is a real assertion:
    // "booking" would have been a substring of the site and passed either way.
    name: "record-key-not-a-site",
    passwordless: true,
    loginUrl: "https://account.booking.example/sign-in",
  });
  // The site, not the record: the owner is looking at a sign-in page, and the
  // name is a key the agent chose.
  // The same site name the vault card used when it collected the identifier —
  // both cards belong to one sign-in, so a service subdomain is dropped on both.
  assert.match(w.title, /Sign-in code for Booking\.example/);
  assert.ok(!JSON.stringify(w).includes("record-key-not-a-site"), "the credential name is not a title");
  assert.ok(!/2FA/i.test(w.title), "the only factor must not be called 2FA");
  assert.ok(!/2FA/i.test(w.label));
  assert.match(w.description, /Booking\.example/);
});

test("otpPromptWording: an ordinary second factor keeps the 2FA wording", () => {
  const w = otpPromptWording({
    name: "gh",
    loginUrl: "https://github.example/login",
  });
  assert.match(w.title, /2FA code for Github\.example/);
  assert.match(w.label, /2FA/);
});

test("the card names where to look when the page did not say", () => {
  // "check your email or messages" cost a real sign-in: the code went to a number
  // attached to the account years earlier, on a phone in another room, and the
  // owner spent the card's ten minutes searching a mailbox. The identifier they
  // signed in with is the one thing we always have.
  const cred = {
    name: "airbnb",
    passwordless: true,
    username: "daniel@eti.co",
    loginUrl: "https://www.airbnb.com/login",
  };
  const guessed = otpPromptWording(cred);

  assert.match(guessed.description, /d•••@eti\.co/);
  // A guess, and worded as one: the page said nothing, and a site can text a code
  // to an account opened with an address.
  assert.match(guessed.description, /should reach/);
  assert.ok(!/sent a code to/.test(guessed.description), guessed.description);

  // What the page itself printed outranks it, and gets the certain wording.
  const stated = otpPromptWording(cred, {
    destination: "your phone ending in 4817",
  });
  assert.match(stated.description, /sent a code to your phone ending in 4817/);
  assert.ok(!/d•••@eti\.co/.test(stated.description), stated.description);

  // A username that names no channel is not turned into one.
  const opaque = otpPromptWording({ ...cred, username: "daniel_smith" });
  assert.match(opaque.description, /check your email or messages/);
});

test("the card carries the cell count only when the page really stated one", () => {
  const cred = {
    name: "booking",
    passwordless: true,
    loginUrl: "https://booking.com/in",
  };
  const placeholderFor = (length) =>
    otpCardSpec(cred, { length }).fields[0].placeholder ?? null;

  // The screen draws one cell per placeholder character and submits itself when
  // they fill. That is why a guess is not a lesser version of silence: too few
  // cells truncate a correct code, too many leave it unsubmittable with no button.
  assert.equal(placeholderFor(6), "••••••");
  assert.equal(placeholderFor(4), "••••");
  assert.equal(placeholderFor(8), "••••••••");

  // An unconstrained text input (maxlength 32, or none at all) states nothing
  // about a code, and a three-character one is not a code either.
  for (const nonsense of [3, 12, 32, 0, null, undefined, 6.5, "6"]) {
    assert.equal(placeholderFor(nonsense), null, String(nonsense));
  }
  assert.equal(otpCardLength(6), 6);
  assert.equal(otpCardLength(32), null);
});

test("only a credential that denies codes is corrected, and it is corrected once", () => {
  // The record and the object the fill path works with are the same object for a
  // `login` credential, so asking "is it still none?" after setting it answered
  // no — and the correction was computed, applied in memory, and never saved.
  const denies = { name: "booking", otp: "none" };

  assert.equal(otpModeCorrection(denies), "interactive");
  denies.otp = otpModeCorrection(denies);
  assert.equal(otpModeCorrection(denies), null, "nothing left to correct");

  assert.equal(otpModeCorrection({ otp: "interactive" }), null);
  assert.equal(
    otpModeCorrection({ otp: "totp" }),
    null,
    "a seed is not a wrong answer"
  );
  assert.equal(otpModeCorrection(undefined), null);
});

test("an identifier is masked down to what the owner recognises", () => {
  assert.equal(maskedIdentifier("daniel@eti.co"), "d•••@eti.co");
  assert.equal(maskedIdentifier("+1 (415) 555-4817"), "••• 4817");
  // Neither an address nor a number: it names no place to look.
  assert.equal(maskedIdentifier("danielsmith"), null);
  assert.equal(maskedIdentifier(""), null);
  assert.equal(maskedIdentifier(null), null);
});

test("otpPromptWording: nothing to name the site by still says what to do", () => {
  // The description used to come out empty here, which told the owner nothing at
  // all in the one place they had to act. With no host to show, the record's own
  // name is the last thing left — worse than a site, better than silence.
  const passwordless = otpPromptWording({ name: "x", passwordless: true });
  assert.match(passwordless.description, /x sent you a code/);
  assert.match(passwordless.description, /email or messages/i);
  assert.match(otpPromptWording({ name: "x" }).description, /needs your current code/);
});

// ─── multi-host sign-ins refuse safely, not silently ──────────────────────────────

test("a sign-in that hops to an unlisted subdomain is refused BEFORE the owner is asked", async () => {
  // Sign-ins routinely redirect (www.example.com -> account.example.com). The
  // credential's domains default to the login-page host alone, so this is the
  // shape a model gets wrong most often. It must cost a clear error, never a code
  // the owner typed into a card and then had thrown away.
  const calls = [];
  let otpCalls = 0;
  await assert.rejects(
    runRecipe(
      pageOn("https://account.example.com/verify"),
      [{ action: "fill", selector: "#code", value: "{otp}" }],
      {
        username: "u",
        password: "p",
        getOtp: async () => {
          otpCalls++;
          return "654321";
        },
        domains: ["www.example.com"],
        driver: recordingDriver(calls),
      }
    ),
    /account\.example\.com.*not on the credential's domain allowlist/s
  );
  assert.equal(otpCalls, 0, "no card may be raised for a step we are going to refuse");
  assert.deepEqual(calls, []);
});

test("a wildcard covering the whole sign-in flow lets the hop through", async () => {
  const calls = [];
  await runRecipe(pageOn("https://account.example.com/verify"), [{ action: "fill", selector: "#code", value: "{otp}" }], {
    username: "u",
    password: "p",
    getOtp: async () => "654321",
    domains: ["*.example.com"],
    driver: recordingDriver(calls),
  });
  assert.deepEqual(calls, [["fillCode", "#code", "654321"]]);
});

test("the code-screen submit vocabulary never matches a control that discards the code", () => {
  for (const label of [
    "Verify",
    "Continue",
    "Submit",
    "Confirm",
    "Next",
    "Sign in",
    "Log in",
  ]) {
    assert.ok(
      CODE_SUBMIT_TEXT_RE.test(label),
      `"${label}" should advance the code screen`
    );
  }
  // Clicking any of these throws away a code the owner has just typed, and on a
  // mailed code that means waiting for a fresh one.
  for (const label of [
    "Resend code",
    "Send again",
    "Send a new code",
    "Use another method",
    "Back",
    "Cancel",
    "Try another way",
  ]) {
    assert.ok(!CODE_SUBMIT_TEXT_RE.test(label), `"${label}" must never be clicked`);
  }
});

// ─── the secret gate must hold across the human wait ──────────────────────────────

test("a page that navigates WHILE the owner types the code cannot receive it", async () => {
  // The pre-`sub` check passes on the right origin, then resolving {otp} blocks on
  // the owner for minutes. Without a second check immediately before the driver
  // call, the code lands on whatever the page navigated to in the meantime.
  const calls = [];
  let url = "https://account.example.com/verify";
  const page = { url: () => url };
  await assert.rejects(
    runRecipe(page, [{ action: "fill", selector: "#code", value: "{otp}" }], {
      username: "u",
      password: "p",
      getOtp: async () => {
        url = "https://evil.test/collect";
        return "654321";
      },
      domains: ["account.example.com"],
      driver: recordingDriver(calls),
    }),
    /evil\.test.*not on the credential's domain allowlist/s
  );
  assert.deepEqual(calls, [], "the code must not have been typed anywhere");
});

test("a step whose origin stays put is unaffected by the second check", async () => {
  const calls = [];
  await runRecipe(
    pageOn("https://account.example.com/verify"),
    [{ action: "fill", selector: "#code", value: "{otp}" }],
    {
      username: "u",
      password: "p",
      getOtp: async () => "654321",
      domains: ["account.example.com"],
      driver: recordingDriver(calls),
    }
  );
  assert.deepEqual(calls, [["fillCode", "#code", "654321"]]);
});

// ─── retrying a generated code only means something across a window ───────────────

test("the TOTP retry lands in the next period, not the one just refused", () => {
  // Within one period the seed produces the same digits, so a back-to-back retry
  // submits an identical code and only looks like diligence. The retry that can
  // succeed is the boundary race: generated at t+29s, validated at t+31s.
  const seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  const now = 1_000_000_000_000;
  const first = generateTotp({ secret: seed, now });
  const immediate = generateTotp({ secret: seed, now: now + 3000 });
  const afterWait = generateTotp({
    secret: seed,
    now: now + millisToNextTotpWindow({}, now),
  });

  assert.equal(immediate, first, "a retry three seconds later is the same code");
  assert.notEqual(afterWait, first, "a retry after the wait is a different one");
});

test("millisToNextTotpWindow respects the credential's own period", () => {
  assert.equal(millisToNextTotpWindow({}, 29_500), 1000);
  assert.equal(millisToNextTotpWindow({ period: 60 }, 59_500), 1000);
  // A beat past the boundary, so the new window is unambiguously current.
  assert.ok(millisToNextTotpWindow({}, 0) > 30_000);
});

// ─── a mistyped code gets one more chance, and the card says why ──────────────────

test("the retry card says the code was refused, so the owner reads a fresh one", () => {
  // Without it the owner sees the same prompt twice and cannot tell a refused
  // code from a lost one — and for a time-based code the right move is to read
  // the CURRENT one, not retype what they just sent.
  const cred = { name: "site", loginUrl: "https://x.example/login" };
  assert.ok(!otpPromptWording(cred).description.includes("not accepted"));
  assert.match(
    otpPromptWording(cred, { retry: true }).description,
    /not accepted/
  );
  assert.match(
    otpPromptWording({ ...cred, passwordless: true }, { retry: true })
      .description,
    /not accepted/
  );
});

// ── An unanswered code card ends the run as an outcome, not an exception ─────────

function formTimeout() {
  const err = new Error("timed out waiting for the secure form to be submitted");
  err.code = "FORM_TIMEOUT";
  return err;
}

function recipePage(url) {
  return {
    url: () => url,
    goto: async () => {},
    waitForTimeout: async () => {},
  };
}

const OTP_FIRST_RECIPE = [
  { action: "fill", selector: "#code", value: "{otp}" },
];
const PWLESS_CRED = {
  name: "booking",
  username: "u@example.test",
  passwordless: true,
  otp: "interactive",
  loginUrl: "https://x.test/sign-in",
  domains: ["x.test"],
  recipe: OTP_FIRST_RECIPE,
};

test("autoLogin reports an expired code card as an outcome, so the caller learns where it stopped", async () => {
  const result = await autoLogin({
    page: recipePage("https://x.test/otp"),
    cred: PWLESS_CRED,
    resolveOtpFn: async () => {
      throw formTimeout();
    },
  });
  assert.equal(result.ok, false);
  assert.equal(result.outcome, "otp-timeout");
  assert.equal(result.finalUrl, "https://x.test/otp");
});

test("a card closed for the browser asks for the browser, not for another card", async () => {
  const useBrowser = () => {
    const err = new Error("hosted secure prompt: the owner will sign in through the browser instead");
    err.code = "FORM_USE_BROWSER";
    return err;
  };
  const result = await autoLogin({
    page: recipePage("https://x.test/otp"),
    cred: PWLESS_CRED,
    resolveOtpFn: async () => {
      throw useBrowser();
    },
  });

  assert.equal(result.outcome, "owner-will-drive");
  assert.notEqual(result.outcome, "otp-declined", "they did not refuse, they took it over");
});

test("a card the owner dismissed is reported as their answer, not as a fault", async () => {
  // The hosted host answers 409 when the owner closes the card. Arriving as a
  // bare HTTP error it read as "something broke", and the sensible response to
  // that is a retry — which puts the card back in front of someone who has just
  // said no.
  const cancelled = () => {
    const err = new Error("hosted secure prompt: the owner dismissed the card");
    err.code = "FORM_CANCELLED";
    return err;
  };
  const result = await autoLogin({
    page: recipePage("https://x.test/otp"),
    cred: PWLESS_CRED,
    resolveOtpFn: async () => {
      throw cancelled();
    },
  });

  assert.equal(result.ok, false);
  assert.equal(result.outcome, "otp-declined");
  assert.notEqual(result.outcome, "otp-timeout", "nobody ran out of time");
});

test(
  "a real 409 from the hosted card reaches the declined outcome, end to end",
  async () => {
    // The test above fabricates the error, so it passes whether or not anything
    // ever sets that code. The code is set in agent-id-core and read in
    // agent-id-browser, and a release that bumps only the reader resolves a
    // published core that never sets it — the retry loop would be exactly as open
    // as before, with the whole suite green. So this one drives a real 409 all the
    // way: hosted socket, core's provider, no `resolveOtpFn` injected.
    const sock = path.join(
      os.tmpdir(),
      `agentid-al-${process.pid}-${Date.now()}.sock`
    );
    const server = http.createServer((_req, res) => {
      const payload = JSON.stringify({ error: "cancelled" });
      res.writeHead(409, {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(payload),
      });
      res.end(payload);
    });
    await new Promise((resolve) => server.listen(sock, resolve));

    const previous = process.env.AGENT_ID_SECURE_PROMPT_SOCK;
    process.env.AGENT_ID_SECURE_PROMPT_SOCK = sock;
    try {
      const result = await autoLogin({
        page: recipePage("https://x.test/otp"),
        cred: PWLESS_CRED,
      });

      assert.equal(result.ok, false);
      assert.equal(
        result.outcome,
        "otp-declined",
        "a dismissal must survive the trip across the package boundary"
      );
    } finally {
      if (previous === undefined) delete process.env.AGENT_ID_SECURE_PROMPT_SOCK;
      else process.env.AGENT_ID_SECURE_PROMPT_SOCK = previous;
      server.close();
    }
  }
);

test("autoLogin does not dress every OTP failure up as a timeout", async () => {
  // Only an unanswered card is an outcome. A credential that cannot produce a
  // code at all is a fault, and swallowing it would report "nobody typed it".
  await assert.rejects(
    autoLogin({
      page: recipePage("https://x.test/otp"),
      cred: PWLESS_CRED,
      resolveOtpFn: async () => {
        throw new Error("login 'booking': otp=totp but no totpSecret stored");
      },
    }),
    /totpSecret/
  );
});

test("the retry card is sized by where the code comes from, not by the fact of retrying", () => {
  const mailed = { name: "booking", otp: "interactive", passwordless: true };
  // The only `totp` credential a card is ever built for: one whose seed is missing.
  const fromApp = { name: "gh", otp: "totp" };

  // Not the same wait even the first time. A mailed code may not have arrived yet
  // and the owner has to go and fetch it; an authenticator is already in their
  // hand, so ten minutes of an agent blocked on a card buys nothing.
  assert.ok(
    otpCardBudgetMs(mailed) > otpCardBudgetMs(fromApp),
    "a mailbox trip must outlast a glance"
  );
  assert.ok(
    otpCardBudgetMs(mailed, { retry: true }) >
      otpCardBudgetMs(fromApp, { retry: true }),
    "and the same holds on the retry"
  );

  // Both retries stay under the caller's 16-minute ceiling once the first card
  // has spent its own budget — that ceiling covers the whole run, so a second
  // full-length card would be killed mid-answer.
  const CALLER_CEILING_MS = 16 * 60 * 1000;
  for (const cred of [mailed, fromApp]) {
    const total = otpCardBudgetMs(cred) + otpCardBudgetMs(cred, { retry: true });
    assert.ok(total < CALLER_CEILING_MS, `${cred.otp}: ${total}ms leaves nothing for the page`);
  }
});

test("the code card does not mask what it asks for", () => {
  const mailed = otpCardSpec({
    name: "booking",
    otp: "interactive",
    loginUrl: "https://x.test/in",
  });
  const generated = otpCardSpec(
    { name: "gh", otp: "interactive", loginUrl: "https://gh.test/in" },
    { retry: true }
  );

  // Every other value this vault collects is masked by default — the code is the
  // one that must opt out, and it has to hold on the retry card too, which is
  // where a mistyped code lands in the first place.
  for (const spec of [mailed, generated]) {
    assert.equal(spec.fields.length, 1);
    assert.equal(spec.fields[0].name, "otp");
    assert.equal(spec.fields[0].secret, false, "a single-use code is not a lasting secret");
  }
});

test("the code card never says '2FA' to someone who has no first factor", () => {
  const passwordless = otpCardSpec({
    name: "booking",
    otp: "interactive",
    passwordless: true,
    loginUrl: "https://x.test/in",
  });
  assert.ok(
    !/2fa|two-factor/i.test(JSON.stringify(passwordless)),
    "this code IS the sign-in, not a second step"
  );
  assert.match(passwordless.fields[0].label, /sign-in code/i);
});

test("the code card names the site and where the code went", () => {
  const cred = {
    name: "airbnb-passwordless-again",
    passwordless: true,
    otp: "interactive",
    loginUrl: "https://www.airbnb.com/login",
    domains: ["*.airbnb.com", "airbnb.com"],
  };

  const named = otpCardSpec(cred, { destination: "+1 ••• ••• 4817" });
  // The owner is looking at Airbnb, not at whatever the agent called its record.
  assert.ok(!JSON.stringify(named).includes("airbnb-passwordless-again"));
  assert.match(named.title, /Airbnb\.com/);
  assert.match(named.description, /\+1 ••• ••• 4817/);

  // With no destination the card must not pick a channel for the owner: the one
  // this came from texted a code while the copy implied a mailbox.
  const blind = otpCardSpec(cred, {});
  assert.match(blind.description, /email or messages/i);
  assert.ok(!/sent a code to/.test(blind.description));
});
