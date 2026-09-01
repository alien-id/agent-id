#!/usr/bin/env node

// Tests for stub parsing, materialization, and URL/header rewriting.

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  findStubsInString,
  hasStub,
  materializeCredential,
  replaceStubs,
  rewriteHeaders,
  rewriteUrl,
  StubError,
} from "../plugins/agent-id-proxy/lib/stub.mjs";

describe("stub parsing", () => {
  it("finds a single stub", () => {
    const r = findStubsInString("AgentVault github-pat");
    assert.equal(r.length, 1);
    assert.equal(r[0].name, "github-pat");
  });

  it("finds multiple stubs in the same string", () => {
    const r = findStubsInString("AgentVault a-1 then AgentVault b-2");
    assert.equal(r.length, 2);
    assert.equal(r[0].name, "a-1");
    assert.equal(r[1].name, "b-2");
  });

  it("ignores non-stub text", () => {
    assert.equal(hasStub("Bearer ghp_xxxx"), false);
    assert.equal(hasStub(""), false);
  });

  it("requires a name after `AgentVault `", () => {
    assert.equal(findStubsInString("AgentVault ").length, 0);
  });
});

describe("materialize", () => {
  it("bearer prepends Bearer", () => {
    assert.equal(
      materializeCredential({ type: "bearer", value: "ghp_xxx" }),
      "Bearer ghp_xxx",
    );
  });

  it("basic encodes user:pass in b64", () => {
    assert.equal(
      materializeCredential({ type: "basic", username: "u", password: "p" }),
      "Basic dTpw",
    );
  });

  it("header returns raw value", () => {
    assert.equal(
      materializeCredential({ type: "header", value: "raw-value" }),
      "raw-value",
    );
  });

  it("cookie produces name=value", () => {
    assert.equal(
      materializeCredential({ type: "cookie", cookieName: "sid", value: "abc" }),
      "sid=abc",
    );
  });

  it("cookie-jar joins all pairs", () => {
    assert.equal(
      materializeCredential({
        type: "cookie-jar",
        cookies: { a: "1", b: "2" },
      }),
      "a=1; b=2",
    );
  });
});

describe("replaceStubs", () => {
  const lookup = (name) => {
    if (name === "gh") {
      return {
        type: "bearer",
        value: "ghp_xxx",
        domains: ["api.github.com", "*.github.com"],
      };
    }
    return null;
  };

  it("replaces stub and reports use", () => {
    const r = replaceStubs("AgentVault gh", { lookup, host: "api.github.com" });
    assert.equal(r.value, "Bearer ghp_xxx");
    assert.deepEqual(r.used, [{ name: "gh", type: "bearer" }]);
  });

  it("throws StubError on unknown credential", () => {
    assert.throws(
      () => replaceStubs("AgentVault missing", { lookup, host: "api.github.com" }),
      (err) => err instanceof StubError && err.code === "credential_not_found",
    );
  });

  it("throws StubError on host not in allowlist", () => {
    assert.throws(
      () => replaceStubs("AgentVault gh", { lookup, host: "evil.example.com" }),
      (err) => err instanceof StubError && err.code === "host_not_allowed",
    );
  });

  it("wildcard domain matches subdomain", () => {
    const r = replaceStubs("AgentVault gh", { lookup, host: "x.api.github.com" });
    assert.equal(r.value, "Bearer ghp_xxx");
  });
});

describe("rewriteHeaders", () => {
  const lookup = (name) =>
    name === "api"
      ? { type: "header", value: "xyz", domains: ["api.example.com"] }
      : null;

  it("rewrites only stubbed headers", () => {
    const r = rewriteHeaders(
      { "X-Api-Key": "AgentVault api", Accept: "application/json" },
      { lookup, host: "api.example.com" },
    );
    assert.equal(r.headers["X-Api-Key"], "xyz");
    assert.equal(r.headers.Accept, "application/json");
  });
});

describe("injection-site enforcement (stub mode)", () => {
  const lookup = (name) => {
    const creds = {
      tok: { type: "bearer", value: "ghp_xxx", domains: ["api.example.com"] },
      jar: { type: "cookie-jar", cookies: { sid: "abc" }, domains: ["api.example.com"] },
      key: { type: "header", headerName: "X-Api-Key", value: "xyz", domains: ["api.example.com"] },
      q: { type: "query", paramName: "k", value: "v", domains: ["api.example.com"] },
    };
    return creds[name] || null;
  };
  const opts = { lookup, host: "api.example.com" };

  it("allows a bearer in the Authorization header", () => {
    const r = rewriteHeaders({ Authorization: "AgentVault tok" }, opts);
    assert.equal(r.headers.Authorization, "Bearer ghp_xxx");
  });

  it("refuses a bearer placed in some other (reflectable) header", () => {
    assert.throws(
      () => rewriteHeaders({ "X-Debug": "AgentVault tok" }, opts),
      (err) => err instanceof StubError && err.code === "injection_site_not_allowed",
    );
  });

  it("refuses a cookie-jar placed outside the Cookie header", () => {
    assert.throws(
      () => rewriteHeaders({ "X-Leak": "AgentVault jar" }, opts),
      (err) => err instanceof StubError && err.code === "injection_site_not_allowed",
    );
    const ok = rewriteHeaders({ Cookie: "AgentVault jar" }, opts);
    assert.equal(ok.headers.Cookie, "sid=abc");
  });

  it("pins a header credential to its declared headerName", () => {
    const ok = rewriteHeaders({ "X-Api-Key": "AgentVault key" }, opts);
    assert.equal(ok.headers["X-Api-Key"], "xyz");
    assert.throws(
      () => rewriteHeaders({ "X-Wrong": "AgentVault key" }, opts),
      (err) => err instanceof StubError && err.code === "injection_site_not_allowed",
    );
  });

  it("refuses a bearer smuggled into a query parameter", () => {
    assert.throws(
      () => rewriteUrl("http://api.example.com/x?leak=AgentVault%20tok", opts),
      (err) => err instanceof StubError && err.code === "injection_site_not_allowed",
    );
  });

  it("pins a query credential to its declared paramName", () => {
    const ok = rewriteUrl("http://api.example.com/x?k=AgentVault%20q", opts);
    assert.equal(new URL(ok.url).searchParams.get("k"), "v");
    assert.throws(
      () => rewriteUrl("http://api.example.com/x?other=AgentVault%20q", opts),
      (err) => err instanceof StubError && err.code === "injection_site_not_allowed",
    );
  });
});

describe("rewriteUrl", () => {
  const lookup = (name) =>
    name === "key"
      ? { type: "query", paramName: "k", value: "abc def", domains: ["api.example.com"] }
      : null;

  it("rewrites query parameter and URL-encodes spaces", () => {
    const r = rewriteUrl("http://api.example.com/foo?k=AgentVault%20key&z=plain", {
      lookup,
      host: "api.example.com",
    });
    const url = new URL(r.url);
    assert.equal(url.searchParams.get("k"), "abc def");
    assert.equal(url.searchParams.get("z"), "plain");
  });
});
