#!/usr/bin/env node

// Unit tests for per-credential access levels (vault access.mjs + store
// validation + the browser guard's pure pieces).
//
// Run: node --test tests/test-access-policy.mjs

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  ACCESS_LEVELS,
  classifyBodyRead,
  effectiveAccess,
  evaluateAccess,
  isAccessRelaxation,
  isAccessRestricted,
  pathMatchesGlob,
  strictestAccess,
} from "../plugins/agent-id-vault/lib/access.mjs";
import { validateRecord } from "../plugins/agent-id-vault/lib/store.mjs";
import {
  assertActionAllowed,
  guardDecision,
} from "../plugins/agent-id-browser/lib/access-guard.mjs";

const base = { name: "t", type: "bearer", value: "x", domains: ["api.example.com"] };

describe("schema validation", () => {
  it("accepts access ro/rw and rejects junk", () => {
    validateRecord({ ...base, access: "ro" });
    validateRecord({ ...base, access: "rw" });
    assert.throws(() => validateRecord({ ...base, access: "readonly" }), /access must be one of/);
    assert.deepEqual(ACCESS_LEVELS, ["ro", "rw"]);
  });

  it("validates accessRules shape", () => {
    validateRecord({
      ...base,
      access: "ro",
      accessRules: [
        { effect: "allow", methods: ["POST"], path: "/search/*" },
        { effect: "deny", hosts: ["*.example.com"] },
      ],
    });
    assert.throws(() => validateRecord({ ...base, accessRules: [] }), /non-empty array/);
    assert.throws(() => validateRecord({ ...base, accessRules: [{ effect: "block" }] }), /effect/);
    assert.throws(
      () => validateRecord({ ...base, accessRules: [{ effect: "allow", methods: [] }] }),
      /methods/,
    );
    assert.throws(
      () => validateRecord({ ...base, accessRules: [{ effect: "allow", path: "no-slash" }] }),
      /path/,
    );
  });
});

describe("evaluateAccess", () => {
  const req = (over = {}) => ({ method: "GET", host: "api.example.com", path: "/v1/x", ...over });

  it("rw (and absent) allows everything", () => {
    assert.equal(evaluateAccess(base, req({ method: "DELETE" })).allowed, true);
    assert.equal(evaluateAccess({ ...base, access: "rw" }, req({ method: "POST" })).allowed, true);
  });

  it("ro allows read methods, blocks writes", () => {
    const ro = { ...base, access: "ro" };
    for (const m of ["GET", "HEAD", "OPTIONS", "get"]) {
      assert.equal(evaluateAccess(ro, req({ method: m })).allowed, true, m);
    }
    for (const m of ["POST", "PUT", "PATCH", "DELETE"]) {
      const d = evaluateAccess(ro, req({ method: m, body: null }));
      assert.equal(d.allowed, false, m);
      assert.equal(d.reason, "write_blocked");
    }
  });

  it("a read-shaped body does NOT promote PUT/PATCH/DELETE (only POST tunnels reads)", () => {
    const ro = { ...base, access: "ro" };
    const readBody = '{"query":"{ __typename }"}';
    for (const m of ["DELETE", "PUT", "PATCH"]) {
      const d = evaluateAccess(ro, req({ method: m, body: readBody }));
      assert.equal(d.allowed, false, `${m} with read-shaped body must stay blocked`);
      assert.equal(d.needsBody, undefined, `${m} must not even ask for the body`);
    }
    // POST with the same read body is the only one that passes.
    assert.equal(evaluateAccess(ro, req({ method: "POST", body: readBody })).allowed, true);
  });

  it("asks for the body once, when only the body can decide", () => {
    const ro = { ...base, access: "ro" };
    const first = evaluateAccess(ro, req({ method: "POST" }));
    assert.equal(first.allowed, false);
    assert.equal(first.needsBody, true);
    const second = evaluateAccess(ro, req({ method: "POST", body: '{"query":"query { me }"}' }));
    assert.equal(second.allowed, true);
    assert.equal(second.reason, "read_classified");
  });

  it("rules run first, in order, and beat the level", () => {
    const rec = {
      ...base,
      access: "ro",
      accessRules: [
        { effect: "deny", methods: ["GET"], path: "/admin/*" },
        { effect: "allow", methods: ["POST"], path: "/search" },
      ],
    };
    assert.equal(evaluateAccess(rec, req({ path: "/admin/users" })).allowed, false);
    assert.equal(evaluateAccess(rec, req({ method: "POST", path: "/search" })).allowed, true);
    // unmatched POST falls through to the ro default
    assert.equal(evaluateAccess(rec, req({ method: "POST", path: "/other", body: null })).allowed, false);
  });

  it("rule hosts use the domains wildcard syntax", () => {
    const rec = {
      ...base,
      accessRules: [{ effect: "deny", hosts: ["*.internal.example.com"] }],
    };
    assert.equal(
      evaluateAccess(rec, req({ host: "db.internal.example.com" })).allowed,
      false,
    );
    assert.equal(evaluateAccess(rec, req()).allowed, true);
  });
});

describe("body classification (POST-tunneled reads)", () => {
  it("GraphQL: query reads, mutation writes", () => {
    assert.equal(classifyBodyRead('{"query":"query Q { me { id } }"}'), "read");
    assert.equal(classifyBodyRead('{"query":"{ me { id } }"}'), "read");
    assert.equal(classifyBodyRead('{"query":"mutation M { send }"}'), "write");
    assert.equal(classifyBodyRead('{"query":"subscription S { x }"}'), "write");
    // batched: one mutation poisons the batch
    assert.equal(
      classifyBodyRead('[{"query":"query{a}"},{"query":"mutation{b}"}]'),
      "write",
    );
    assert.equal(classifyBodyRead('[{"query":"query{a}"},{"query":"{b}"}]'), "read");
  });

  it("GraphQL: a multi-operation doc with a mutation is a write even if it leads with query", () => {
    // operationName could select the mutation — leading keyword is not enough.
    assert.equal(
      classifyBodyRead(
        JSON.stringify({
          query: "query GetMe { me { id } }\nmutation DoBad { sendMail }",
          operationName: "DoBad",
        }),
      ),
      "write",
    );
    // a `#`-comment must not hide a real mutation, nor fake a leading query
    assert.equal(classifyBodyRead('{"query":"# query\\nmutation { x }"}'), "write");
    assert.equal(classifyBodyRead('{"query":"query Foo { a }"}'), "read");
    // leading comment before a genuine query stays a read
    assert.equal(classifyBodyRead('{"query":"# hi\\nquery { a }"}'), "read");
  });

  it("JMAP: get/query read, set writes", () => {
    assert.equal(
      classifyBodyRead(
        '{"methodCalls":[["Email/query",{},"0"],["Email/get",{},"1"]]}',
      ),
      "read",
    );
    assert.equal(
      classifyBodyRead('{"methodCalls":[["Email/get",{},"0"],["EmailSubmission/set",{},"1"]]}'),
      "write",
    );
    // an empty batch is a no-op → unknown (blocked under ro), not vacuously read
    assert.equal(classifyBodyRead('{"methodCalls":[]}'), "unknown");
  });

  it("JSON-RPC: recognized reads pass, sends write", () => {
    assert.equal(classifyBodyRead('{"jsonrpc":"2.0","id":1,"method":"eth_getBalance"}'), "read");
    assert.equal(classifyBodyRead('{"jsonrpc":"2.0","id":1,"method":"eth_call"}'), "read");
    assert.equal(classifyBodyRead('{"jsonrpc":"2.0","id":1,"method":"getBalance"}'), "read");
    assert.equal(classifyBodyRead('{"jsonrpc":"2.0","id":1,"method":"simulateTransaction"}'), "read");
    assert.equal(
      classifyBodyRead('{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction"}'),
      "write",
    );
    assert.equal(classifyBodyRead('{"jsonrpc":"2.0","id":1,"method":"sendTransaction"}'), "write");
    assert.equal(classifyBodyRead('{"jsonrpc":"2.0","id":1,"method":"requestAirdrop"}'), "write");
  });

  it("JSON-RPC is default-DENY: unrecognized methods are unknown (blocked), not read", () => {
    // Writes on non-EVM/Solana RPC services that the old denylist let through as
    // reads — now unknown (→ blocked). `wallet_sendCalls` is explicitly a write.
    for (const method of ["deleteUser", "sendtoaddress", "starknet_addInvokeTransaction", "admin_addPeer"]) {
      assert.equal(
        classifyBodyRead(`{"jsonrpc":"2.0","id":1,"method":"${method}"}`),
        "unknown",
        `${method} must not classify as a read`,
      );
    }
    assert.equal(classifyBodyRead('{"jsonrpc":"2.0","id":1,"method":"wallet_sendCalls"}'), "write");
  });

  it("unknown shapes stay unknown (blocked under ro)", () => {
    assert.equal(classifyBodyRead("a=b&c=d"), "unknown");
    assert.equal(classifyBodyRead('{"hello":"world"}'), "unknown");
    assert.equal(classifyBodyRead(""), "unknown");
    assert.equal(classifyBodyRead(null), "unknown");
  });
});

describe("glob + level helpers", () => {
  it("pathMatchesGlob", () => {
    assert.equal(pathMatchesGlob("/v1/messages", "/v1/*"), true);
    assert.equal(pathMatchesGlob("/v1/messages/send", "/v1/*"), true); // * crosses /
    assert.equal(pathMatchesGlob("/v2/messages", "/v1/*"), false);
    assert.equal(pathMatchesGlob("/exact", "/exact"), true);
    assert.equal(pathMatchesGlob("/exact/no", "/exact"), false);
  });

  it("strictestAccess / effectiveAccess", () => {
    assert.equal(strictestAccess("ro", "rw"), "ro");
    assert.equal(strictestAccess("rw", "rw"), "rw");
    assert.equal(effectiveAccess({}), "rw");
    assert.equal(effectiveAccess({ access: "ro" }), "ro");
  });
});

describe("relaxation detection", () => {
  it("level changes", () => {
    assert.equal(isAccessRelaxation({ access: "ro" }, { access: "rw" }), true);
    assert.equal(isAccessRelaxation({ access: "ro" }, {}), true); // absent = rw
    assert.equal(isAccessRelaxation({ access: "rw" }, { access: "ro" }), false);
    assert.equal(isAccessRelaxation({}, { access: "ro" }), false);
  });

  it("rule changes", () => {
    const allow = { effect: "allow", methods: ["POST"], path: "/x" };
    const deny = { effect: "deny", hosts: ["a.com"] };
    // adding an allow rule = relax; adding a deny = tighten
    assert.equal(isAccessRelaxation({ access: "ro" }, { access: "ro", accessRules: [allow] }), true);
    assert.equal(isAccessRelaxation({ access: "ro" }, { access: "ro", accessRules: [deny] }), false);
    // dropping a deny rule = relax; dropping an allow = tighten
    assert.equal(
      isAccessRelaxation({ access: "ro", accessRules: [deny] }, { access: "ro" }),
      true,
    );
    assert.equal(
      isAccessRelaxation({ access: "ro", accessRules: [allow] }, { access: "ro" }),
      false,
    );
    // identical rules = no relax
    assert.equal(
      isAccessRelaxation(
        { access: "ro", accessRules: [allow, deny] },
        { access: "ro", accessRules: [allow, deny] },
      ),
      false,
    );
  });

  it("REORDERING an allow ahead of an overlapping deny is a relaxation (first-match-wins)", () => {
    const allow = { effect: "allow", methods: ["POST"], path: "/x" };
    const deny = { effect: "deny", methods: ["POST"], path: "/x" };
    // Same set, different order: [deny, allow] denies /x; [allow, deny] allows it.
    assert.equal(
      isAccessRelaxation(
        { access: "ro", accessRules: [deny, allow] },
        { access: "ro", accessRules: [allow, deny] },
      ),
      true,
    );
  });

  it("harmless reorders and tightenings do NOT require the ceremony", () => {
    const allow = { effect: "allow", methods: ["POST"], path: "/x" };
    const deny = { effect: "deny", methods: ["POST"], path: "/x" };
    const denyGet = { effect: "deny", methods: ["GET"], path: "/y" };
    const allowOpt = { effect: "allow", methods: ["OPTIONS"], path: "/z" };
    // moving a deny AHEAD of an allow is a tightening → not a relaxation
    assert.equal(
      isAccessRelaxation(
        { access: "ro", accessRules: [allow, deny] },
        { access: "ro", accessRules: [deny, allow] },
      ),
      false,
    );
    // reordering two denies among themselves → neutral
    assert.equal(
      isAccessRelaxation(
        { access: "ro", accessRules: [deny, denyGet] },
        { access: "ro", accessRules: [denyGet, deny] },
      ),
      false,
    );
    // reordering two allows among themselves → neutral
    assert.equal(
      isAccessRelaxation(
        { access: "ro", accessRules: [allow, allowOpt] },
        { access: "ro", accessRules: [allowOpt, allow] },
      ),
      false,
    );
    // an allow moving ahead of a NON-overlapping deny (different method) → neutral
    assert.equal(
      isAccessRelaxation(
        { access: "ro", accessRules: [denyGet, allow] },
        { access: "ro", accessRules: [allow, denyGet] },
      ),
      false,
    );
  });
});

describe("isAccessRestricted", () => {
  it("true for ro and for any accessRules, false for plain rw", () => {
    assert.equal(isAccessRestricted({ access: "ro" }), true);
    assert.equal(isAccessRestricted({ access: "rw", accessRules: [{ effect: "deny" }] }), true);
    assert.equal(isAccessRestricted({ accessRules: [{ effect: "deny" }] }), true);
    assert.equal(isAccessRestricted({ access: "rw" }), false);
    assert.equal(isAccessRestricted({}), false);
  });
});

describe("browser guard (pure pieces)", () => {
  const ro = { access: "ro" };

  it("assertActionAllowed refuses eval/fill-secret/fill-otp on ro only", () => {
    for (const action of ["eval", "fill-secret", "fill-otp"]) {
      assert.throws(() => assertActionAllowed(ro, action), /read-only session/);
      assertActionAllowed({ access: "rw" }, action); // no throw
      assertActionAllowed({}, action);
    }
    for (const action of ["navigate", "click", "type", "snapshot", "text", "screenshot"]) {
      assertActionAllowed(ro, action);
    }
  });

  it("guardDecision: reads pass, writes abort, non-http passes", () => {
    assert.equal(
      guardDecision(ro, { method: "GET", url: "https://x.com/home", postData: null }).allowed,
      true,
    );
    assert.equal(
      guardDecision(ro, {
        method: "POST",
        url: "https://x.com/i/api/graphql/abc/HomeTimeline",
        postData: '{"query":"query{home}"}',
      }).allowed,
      true,
    );
    assert.equal(
      guardDecision(ro, {
        method: "POST",
        url: "https://x.com/i/api/graphql/abc/CreateTweet",
        postData: '{"variables":{},"queryId":"abc"}',
      }).allowed,
      false,
    );
    assert.equal(
      guardDecision(ro, { method: "POST", url: "https://mail.google.com/sync", postData: "junk" })
        .allowed,
      false,
    );
    assert.equal(
      guardDecision(ro, { method: "GET", url: "data:text/plain,hi", postData: null }).allowed,
      true,
    );
  });
});
