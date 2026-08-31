#!/usr/bin/env node

// Unit tests for the auto-login engine's deterministic pieces (lib/auto-login.mjs):
// placeholder substitution, recipe-step → page-call mapping with lazy {otp}
// resolution, and stored-TOTP code resolution. No real browser is launched.
//
// Run: node --test tests/test-auto-login.mjs

import { test } from "node:test";
import assert from "node:assert/strict";

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
} from "../plugins/agent-id-browser/lib/auto-login.mjs";
import { generateTotp } from "../plugins/agent-id-core/lib/totp.mjs";

test("applyVars substitutes username/password/otp; passes non-strings through", () => {
  assert.equal(applyVars("{username}:{password}:{otp}", { username: "u", password: "p", otp: "123" }), "u:p:123");
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
    ["fill", "#otp", "654321"],
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
    /unknown recipe action/,
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
    /requires the credential's `domains` allowlist/,
  );
});

test("runRecipe refuses to navigate off the credential's allowlist", async () => {
  const calls = [];
  await assert.rejects(
    runRecipe(pageOn("https://x/login"), [{ action: "navigate", url: "https://evil.test/collect" }], {
      username: "u",
      password: "p",
      getOtp: async () => "",
      domains: ["x"],
      driver: recordingDriver(calls),
    }),
    /not on the credential's domain allowlist/,
  );
  assert.deepEqual(calls, [], "the navigation must not have happened");
});

test("runRecipe refuses a secret step on a foreign origin BEFORE resolving the code", async () => {
  const calls = [];
  let otpCalls = 0;
  await assert.rejects(
    runRecipe(pageOn("https://evil.test/phish"), [{ action: "fill", selector: "#code", value: "{otp}" }], {
      username: "u",
      password: "p",
      getOtp: async () => {
        otpCalls++;
        return "654321";
      },
      domains: ["x"],
      driver: recordingDriver(calls),
    }),
    /not on the credential's domain allowlist/,
  );
  assert.deepEqual(calls, [], "the fill must not have happened");
  assert.equal(otpCalls, 0, "the owner must not be asked for a code we were going to refuse");
});

test("runRecipe gates a secret hidden in a selector, not just in a value", async () => {
  const calls = [];
  await assert.rejects(
    runRecipe(pageOn("https://evil.test/phish"), [{ action: "click", selector: "#x-{password}" }], {
      username: "u",
      password: "p",
      getOtp: async () => "",
      domains: ["x"],
      driver: recordingDriver(calls),
    }),
    /not on the credential's domain allowlist/,
  );
  assert.deepEqual(calls, []);
});

test("runRecipe refuses a navigate URL carrying a secret placeholder", async () => {
  const calls = [];
  await assert.rejects(
    runRecipe(pageOn("https://x/login"), [{ action: "navigate", url: "https://x/c?v={otp}" }], {
      username: "u",
      password: "p",
      getOtp: async () => "654321",
      domains: ["x"],
      driver: recordingDriver(calls),
    }),
    /must not carry \{password\} or \{otp\}/,
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
    }),
  );
  assert.deepEqual(calls, []);
});

test("autoLogin refuses a loginUrl off the credential's allowlist, before opening anything", async () => {
  await assert.rejects(
    autoLogin({
      page: {},
      cred: { name: "c", username: "u", password: "p", loginUrl: "https://evil.test/login", domains: ["x"] },
    }),
    /not on the credential's domain allowlist/,
  );
});

test("resolveOtp generates a code from a stored TOTP seed (RFC vector)", async () => {
  const cred = { name: "demo", otp: "totp", totpSecret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", period: 30, digits: 6 };
  const code = await resolveOtp(cred, { now: 59_000 });
  assert.equal(code, "287082");
  assert.equal(code, generateTotp({ secret: cred.totpSecret, period: 30, digits: 6, now: 59_000 }));
});

test("resolveOtp throws when otp=totp but no seed is stored", async () => {
  await assert.rejects(resolveOtp({ name: "x", otp: "totp" }, {}), /totpSecret/);
});

// ── Positive-confirmation helpers (the "logged-in" false-positive guard) ──────────

test("isLoginishPath matches whole login/auth segments, not substrings", () => {
  for (const p of ["/login", "/login/", "/account/signin", "/oauth2/authorize", "/auth/callback", "/challenge"]) {
    assert.equal(isLoginishPath(p), true, `login-ish: ${p}`);
  }
  // "authors" must NOT match "auth"; app paths are not login-ish.
  for (const p of ["/", "/feed", "/authors/jane", "/r/test", "/user/me", "/settings"]) {
    assert.equal(isLoginishPath(p), false, `app path: ${p}`);
  }
});

test("stillOnLoginPage: true only when stuck on the same-host login page", () => {
  const loginUrl = "https://www.reddit.com/login";
  // The exact Reddit failure: form gone but still on /login with a js_challenge.
  assert.equal(
    stillOnLoginPage("https://www.reddit.com/login/?solution=abc&js_challenge=1", loginUrl),
    true,
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
  const w = otpPromptWording({ name: "gh", loginUrl: "https://github.example/login" });
  assert.match(w.title, /2FA code for Github\.example/);
  assert.match(w.label, /2FA/);
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
    runRecipe(pageOn("https://account.example.com/verify"), [{ action: "fill", selector: "#code", value: "{otp}" }], {
      username: "u",
      password: "p",
      getOtp: async () => {
        otpCalls++;
        return "654321";
      },
      domains: ["www.example.com"],
      driver: recordingDriver(calls),
    }),
    /account\.example\.com.*not on the credential's domain allowlist/s,
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
  assert.deepEqual(calls, [["fill", "#code", "654321"]]);
});

test("the code-screen submit vocabulary never matches a control that discards the code", () => {
  for (const label of ["Verify", "Continue", "Submit", "Confirm", "Next", "Sign in", "Log in"]) {
    assert.ok(CODE_SUBMIT_TEXT_RE.test(label), `"${label}" should advance the code screen`);
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
    /evil\.test.*not on the credential's domain allowlist/s,
  );
  assert.deepEqual(calls, [], "the code must not have been typed anywhere");
});

test("a step whose origin stays put is unaffected by the second check", async () => {
  const calls = [];
  await runRecipe(pageOn("https://account.example.com/verify"), [
    { action: "fill", selector: "#code", value: "{otp}" },
  ], {
    username: "u",
    password: "p",
    getOtp: async () => "654321",
    domains: ["account.example.com"],
    driver: recordingDriver(calls),
  });
  assert.deepEqual(calls, [["fill", "#code", "654321"]]);
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
  const afterWait = generateTotp({ secret: seed, now: now + millisToNextTotpWindow({}, now) });

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
  assert.match(otpPromptWording(cred, { retry: true }).description, /not accepted/);
  assert.match(
    otpPromptWording({ ...cred, passwordless: true }, { retry: true }).description,
    /not accepted/,
  );
});

// ── An unanswered code card ends the run as an outcome, not an exception ─────────

function formTimeout() {
  const err = new Error("timed out waiting for the secure form to be submitted");
  err.code = "FORM_TIMEOUT";
  return err;
}

function recipePage(url) {
  return { url: () => url, goto: async () => {}, waitForTimeout: async () => {} };
}

const OTP_FIRST_RECIPE = [{ action: "fill", selector: "#code", value: "{otp}" }];
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
    /totpSecret/,
  );
});

test("the retry card is sized by where the code comes from, not by the fact of retrying", () => {
  const mailed = { name: "booking", otp: "interactive", passwordless: true };
  const generated = { name: "gh", otp: "totp", totpSecret: "x" };

  // A first card is the same either way: nobody knows whether the owner is there.
  assert.equal(otpCardBudgetMs(mailed), otpCardBudgetMs(generated));

  // A mailed code sends the owner back to the mailbox, so its retry cannot be
  // sized like a glance at an authenticator already in their hand.
  assert.ok(
    otpCardBudgetMs(mailed, { retry: true }) > otpCardBudgetMs(generated, { retry: true }),
    "a mailbox trip must outlast a glance",
  );

  // Both retries stay under the caller's 16-minute ceiling once the first card
  // has spent its own budget — that ceiling covers the whole run, so a second
  // full-length card would be killed mid-answer.
  const CALLER_CEILING_MS = 16 * 60 * 1000;
  for (const cred of [mailed, generated]) {
    const total = otpCardBudgetMs(cred) + otpCardBudgetMs(cred, { retry: true });
    assert.ok(total < CALLER_CEILING_MS, `${cred.otp}: ${total}ms leaves nothing for the page`);
  }
});

test("the code card does not mask what it asks for", () => {
  const mailed = otpCardSpec({ name: "booking", otp: "interactive", loginUrl: "https://x.test/in" });
  const generated = otpCardSpec({ name: "gh", otp: "interactive", loginUrl: "https://gh.test/in" }, { retry: true });

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
  const passwordless = otpCardSpec({ name: "booking", otp: "interactive", passwordless: true, loginUrl: "https://x.test/in" });
  assert.ok(!/2fa|two-factor/i.test(JSON.stringify(passwordless)), "this code IS the sign-in, not a second step");
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
