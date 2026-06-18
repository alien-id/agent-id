#!/usr/bin/env node

// Tests for the no-Cloud-Console Gmail cookie-capture bootstrap
// (examples/gmail-cookie-bootstrap.mjs).
//
// The bootstrap drives a real Chrome over CDP, which we can't do in CI — so we
// test the parts that don't need a browser:
//   1. The pure cookie logic: domain-matching, "session ready?" gate, and the
//      CDP-cookies → flat { name: value } jar reduction (incl. dedup by domain
//      specificity).
//   2. That a captured jar plugs into the real vault schema and round-trips
//      through encrypt → decrypt unchanged.
//   3. That the proxy's injector materializes the jar as a single Cookie header,
//      and that the read URL the bootstrap prints parses into the right
//      credential + host + path.
//
// Run: node --test tests/test-gmail-cookie-bootstrap.mjs

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { DatabaseSync } from "node:sqlite";
import {
  buildCookieJar,
  cookieAppliesToHost,
  isGoogleSessionReady,
  pickFirefoxProfile,
  readFirefoxCookies,
} from "../examples/gmail-cookie-bootstrap.mjs";
import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { injectCredential, parseRewritePath } from "../plugins/agent-id-proxy/lib/rewrite.mjs";

// A representative slice of what CDP's Storage.getCookies returns after a Gmail
// login: account cookies on .google.com, host-only cookies on mail.google.com,
// a same-named cookie on two domains, and an unrelated cookie that must NOT be
// captured.
const SAMPLE_CDP_COOKIES = [
  { name: "SID", value: "sid-value", domain: ".google.com" },
  { name: "HSID", value: "hsid-value", domain: ".google.com" },
  { name: "SSID", value: "ssid-value", domain: ".google.com" },
  { name: "__Secure-1PSID", value: "1psid-value", domain: ".google.com" },
  { name: "__Secure-3PSID", value: "3psid-value", domain: ".google.com" },
  { name: "OSID", value: "osid-mail", domain: "mail.google.com" },
  { name: "COMPASS", value: "compass-mail", domain: "mail.google.com" },
  // Same name on two scopes — the host-only (more specific) value must win.
  { name: "PREF", value: "pref-broad", domain: ".google.com" },
  { name: "PREF", value: "pref-mail", domain: "mail.google.com" },
  // Different Google host — not applicable to mail.google.com, must be dropped.
  { name: "DRIVE_ONLY", value: "nope", domain: "drive.google.com" },
  // Entirely unrelated site.
  { name: "evil", value: "nope", domain: ".example.com" },
];

describe("cookie domain matching", () => {
  it("matches host-only and dot-prefixed domains, rejects others", () => {
    assert.equal(cookieAppliesToHost(".google.com", "mail.google.com"), true);
    assert.equal(cookieAppliesToHost("mail.google.com", "mail.google.com"), true);
    assert.equal(cookieAppliesToHost("drive.google.com", "mail.google.com"), false);
    assert.equal(cookieAppliesToHost(".example.com", "mail.google.com"), false);
    assert.equal(cookieAppliesToHost("", "mail.google.com"), false);
    assert.equal(cookieAppliesToHost(undefined, "mail.google.com"), false);
    // Must not match on a bare suffix that isn't a domain boundary.
    assert.equal(cookieAppliesToHost("google.com", "notgoogle.com"), false);
  });
});

describe("session-ready gate", () => {
  it("requires the account session markers to be present and non-empty", () => {
    assert.equal(isGoogleSessionReady(SAMPLE_CDP_COOKIES), true);
    assert.equal(isGoogleSessionReady([{ name: "SID", value: "x" }]), false); // missing __Secure-1PSID
    assert.equal(
      isGoogleSessionReady([
        { name: "SID", value: "" }, // present but empty → not signed in
        { name: "__Secure-1PSID", value: "y" },
      ]),
      false,
    );
    assert.equal(isGoogleSessionReady([]), false);
    assert.equal(isGoogleSessionReady(null), false);
  });
});

describe("buildCookieJar", () => {
  const jar = buildCookieJar(SAMPLE_CDP_COOKIES, "mail.google.com");

  it("keeps only cookies the browser would send to mail.google.com", () => {
    assert.equal(jar.SID, "sid-value");
    assert.equal(jar.OSID, "osid-mail");
    assert.equal(jar.COMPASS, "compass-mail");
    assert.equal(jar["__Secure-1PSID"], "1psid-value");
    assert.equal("DRIVE_ONLY" in jar, false);
    assert.equal("evil" in jar, false);
  });

  it("dedupes same-named cookies, preferring the most specific domain", () => {
    assert.equal(jar.PREF, "pref-mail");
  });

  it("never captures empty or non-string values", () => {
    const j = buildCookieJar(
      [
        { name: "A", value: "ok", domain: "mail.google.com" },
        { name: "B", value: null, domain: "mail.google.com" },
        { name: "C", domain: "mail.google.com" },
      ],
      "mail.google.com",
    );
    assert.deepEqual(j, { A: "ok" });
  });
});

describe("firefox profiles.ini parsing", () => {
  it("prefers the [Install] section's Default path", () => {
    const ini = [
      "[Install4F96D1932A9F858E]",
      "Default=a49gx0ef.default-release",
      "Locked=1",
      "",
      "[Profile1]",
      "Name=default",
      "IsRelative=1",
      "Path=lfkqmwmw.default",
      "",
      "[Profile0]",
      "Name=default-release",
      "IsRelative=1",
      "Path=a49gx0ef.default-release",
      "Default=1",
    ].join("\n");
    assert.deepEqual(pickFirefoxProfile(ini), {
      path: "a49gx0ef.default-release",
      isRelative: true,
    });
  });

  it("falls back to the Default=1 profile when there is no Install section", () => {
    const ini = [
      "[Profile0]",
      "Name=dev",
      "IsRelative=1",
      "Path=aaaa.dev",
      "",
      "[Profile1]",
      "Name=default-release",
      "IsRelative=1",
      "Path=bbbb.default-release",
      "Default=1",
    ].join("\n");
    assert.deepEqual(pickFirefoxProfile(ini), { path: "bbbb.default-release", isRelative: true });
  });

  it("returns null when there are no profiles", () => {
    assert.equal(pickFirefoxProfile("[General]\nStartWithLastProfile=1\n"), null);
  });
});

describe("firefox cookies.sqlite read", () => {
  it("reads Google cookies out of a real moz_cookies table", async () => {
    const profileDir = await fs.mkdtemp(path.join(os.tmpdir(), "agent-id-ffprof-"));
    try {
      const db = new DatabaseSync(path.join(profileDir, "cookies.sqlite"));
      db.exec(
        "CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, name TEXT, value TEXT, host TEXT, path TEXT)",
      );
      const ins = db.prepare("INSERT INTO moz_cookies (name, value, host) VALUES (?, ?, ?)");
      ins.run("SID", "sid-value", ".google.com");
      ins.run("__Secure-1PSID", "1psid-value", ".google.com");
      ins.run("OSID", "osid-mail", "mail.google.com");
      ins.run("SOMETHING", "drive-only", "drive.google.com");
      ins.run("unrelated", "nope", ".example.com"); // excluded by SQL host filter
      db.close();

      const cookies = await readFirefoxCookies(profileDir);
      assert.equal(isGoogleSessionReady(cookies), true);

      const jar = buildCookieJar(cookies, "mail.google.com");
      assert.equal(jar.SID, "sid-value");
      assert.equal(jar["__Secure-1PSID"], "1psid-value");
      assert.equal(jar.OSID, "osid-mail");
      assert.equal("SOMETHING" in jar, false); // drive.google.com isn't sent to mail
      assert.equal("unrelated" in jar, false);
    } finally {
      await fs.rm(profileDir, { recursive: true, force: true });
    }
  });
});

describe("vault + proxy integration", () => {
  it("a captured jar round-trips through the encrypted vault unchanged", async () => {
    const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "agent-id-cookie-"));
    try {
      await initVault({ stateDir, passphrase: "demo-pass" });
      const vault = await openVault({ stateDir, passphrase: "demo-pass" });
      const cookies = buildCookieJar(SAMPLE_CDP_COOKIES, "mail.google.com");
      vault.add({
        name: "gmail",
        type: "cookie-jar",
        domains: ["mail.google.com"],
        cookies,
      });
      await vault.save();
      vault.lock();

      const reopened = await openVault({ stateDir, passphrase: "demo-pass" });
      const rec = reopened.get("gmail");
      assert.equal(rec.type, "cookie-jar");
      assert.deepEqual(rec.cookies, cookies);
    } finally {
      await fs.rm(stateDir, { recursive: true, force: true });
    }
  });

  it("the proxy injects the jar as one Cookie header, appended to any existing", () => {
    const cred = {
      type: "cookie-jar",
      cookies: { SID: "sid-value", OSID: "osid-mail" },
    };
    const { headers } = injectCredential({
      headers: { cookie: "existing=1" },
      search: new URLSearchParams(),
      cred,
    });
    assert.equal(headers.cookie, "existing=1; SID=sid-value; OSID=osid-mail");
  });

  it("the read URL the bootstrap prints parses into cred + host + Atom path", () => {
    const parsed = parseRewritePath("/gmail/mail.google.com/mail/u/0/feed/atom");
    assert.equal(parsed.credname, "gmail");
    assert.equal(parsed.host, "mail.google.com");
    assert.equal(parsed.restAndQuery, "/mail/u/0/feed/atom");
  });
});
