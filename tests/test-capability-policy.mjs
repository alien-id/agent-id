#!/usr/bin/env node

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  capabilityPolicyHash,
  evaluateCapabilityAccess,
  evaluateCapabilityPolicy,
  validateCapabilityPolicy,
} from "../plugins/agent-id-vault/lib/capability.mjs";
import { validateRecord } from "../plugins/agent-id-vault/lib/store.mjs";

const principal = "agent:jkt:abcdefghijklmnopqrstuvwxyzABCDEFGH123456789";
const baseContext = (over = {}) => ({
  principal,
  credential: "mail",
  method: "POST",
  scheme: "https",
  host: "mail.example.com",
  path: "/v1/messages/send",
  query: "",
  headers: { "content-type": "application/json", "idempotency-key": "one" },
  body: JSON.stringify({ to: ["alice@alien.org"], subject: "Hello", amount: 20, currency: "CHF" }),
  nowMs: 1_000,
  nonce: "request-1",
  expiresAtMs: 61_000,
  ...over,
});

const policy = (over = {}) => ({
  version: 1,
  epoch: 3,
  onUnmatched: "deny",
  grants: [
    {
      id: "send-default",
      principal: "*",
      capability: "mail.send",
      label: "Send email",
      decision: "ask",
      match: { methods: ["POST"], hosts: ["mail.example.com"], path: "/v1/messages/send" },
      previewFields: ["/to", "/subject"],
    },
  ],
  ...over,
});

describe("capability policy validation", () => {
  it("accepts a closed v1 policy through the credential schema", () => {
    const p = policy();
    assert.equal(validateCapabilityPolicy(p), p);
    validateRecord({
      name: "mail",
      type: "bearer",
      domains: ["mail.example.com"],
      value: "secret",
      capabilityPolicyEpoch: p.epoch,
      capabilityPolicy: p,
    });
    assert.match(capabilityPolicyHash(p), /^sha256:[0-9a-f]{64}$/);
  });

  it("rejects unknown keys, duplicate ids, and malformed field rules", () => {
    assert.throws(() => validateCapabilityPolicy({ ...policy(), surprise: true }), /unknown key/);
    assert.throws(
      () => validateCapabilityPolicy({ ...policy(), grants: [policy().grants[0], policy().grants[0]] }),
      /duplicate id/,
    );
    assert.throws(
      () =>
        validateCapabilityPolicy({
          ...policy(),
          grants: [{ ...policy().grants[0], constraints: [{ path: "amount", op: "lte", value: 10 }] }],
        }),
      /pointer/,
    );
    assert.throws(
      () =>
        validateCapabilityPolicy({
          ...policy(),
          grants: [
            {
              ...policy().grants[0],
              constraints: [{ path: "/amount", op: "lte", value: "50" }],
            },
          ],
        }),
      /finite number/,
    );
  });
});

describe("capability decisions", () => {
  it("returns ask with an owner-legible preview and no raw body", () => {
    const out = evaluateCapabilityPolicy(policy(), baseContext());
    assert.equal(out.verdict, "ask");
    assert.equal(out.allowed, false);
    assert.equal(out.capability, "mail.send");
    assert.deepEqual(out.grants, [
      { id: "send-default", capability: "mail.send", label: "Send email" },
    ]);
    assert.deepEqual(out.preview.parameters["/to"], ["alice@alien.org"]);
    assert.equal(out.preview.parameters["/subject"], "Hello");
    assert.ok(!JSON.stringify(out.envelope).includes("secret"));
    assert.match(out.actionDigest, /^sha256:[0-9a-f]{64}$/);
    assert.deepEqual(out.envelope.grants, [
      { id: "send-default", capability: "mail.send" },
    ]);
  });

  it("uses explicit priority, then deny > ask > allow at equal priority", () => {
    const p = policy({
      grants: [
        policy().grants[0],
        {
          id: "internal-auto",
          principal,
          capability: "mail.send",
          decision: "allow",
          priority: 10,
          match: { methods: ["POST"], path: "/v1/messages/send" },
          constraints: [{ path: "/to", op: "domainIn", values: ["alien.org"] }],
        },
      ],
    });
    assert.equal(evaluateCapabilityPolicy(p, baseContext()).verdict, "allow");

    const tie = policy({
      grants: [
        { ...policy().grants[0], id: "allow", decision: "allow" },
        { ...policy().grants[0], id: "deny", decision: "deny" },
      ],
    });
    assert.equal(evaluateCapabilityPolicy(tie, baseContext()).verdict, "deny");
  });

  it("supports amount thresholds with an ask fallback", () => {
    const p = policy({
      grants: [
        {
          id: "purchase-small",
          principal,
          capability: "commerce.purchase",
          decision: "allow",
          priority: 10,
          match: { methods: ["POST"], path: "/v1/messages/send" },
          constraints: [
            { path: "/amount", op: "lte", value: 50 },
            { path: "/currency", op: "eq", value: "CHF" },
          ],
        },
        {
          id: "purchase-large",
          principal,
          capability: "commerce.purchase",
          decision: "ask",
          match: { methods: ["POST"], path: "/v1/messages/send" },
        },
      ],
    });
    assert.equal(evaluateCapabilityPolicy(p, baseContext()).verdict, "allow");
    assert.equal(
      evaluateCapabilityPolicy(
        p,
        baseContext({ body: JSON.stringify({ amount: 75, currency: "CHF" }) }),
      ).verdict,
      "ask",
    );
  });

  it("requires grants to opt in to non-default ports", () => {
    assert.equal(
      evaluateCapabilityPolicy(policy(), baseContext({ port: "4443" })).verdict,
      "deny",
    );
    const explicit = policy({
      grants: [
        {
          ...policy().grants[0],
          match: { ...policy().grants[0].match, ports: ["4443"] },
        },
      ],
    });
    const allowedPort = evaluateCapabilityPolicy(explicit, baseContext({ port: "4443" }));
    assert.equal(allowedPort.verdict, "ask");
    assert.equal(allowedPort.preview.origin, "https://mail.example.com:4443");
    assert.equal(allowedPort.preview.port, "4443");
    assert.throws(
      () =>
        validateCapabilityPolicy(
          policy({
            grants: [
              {
                ...policy().grants[0],
                match: { ...policy().grants[0].match, ports: ["70000"] },
              },
            ],
          }),
        ),
      /ports/,
    );
  });

  it("orders digest arrays by explicit UTF-8 byte order", () => {
    const p = policy({
      grants: [
        {
          ...policy().grants[0],
          id: "alpha",
          capability: "mail.send",
        },
        {
          ...policy().grants[0],
          id: "_under",
          capability: "form.submit",
        },
        {
          ...policy().grants[0],
          id: "Zed",
          capability: "commerce.purchase",
        },
      ],
    });
    const out = evaluateCapabilityPolicy(p, baseContext());
    assert.deepEqual(out.envelope.grants.map((grant) => grant.id), [
      "Zed",
      "_under",
      "alpha",
    ]);
    assert.deepEqual(out.envelope.capabilities, [
      "commerce.purchase",
      "form.submit",
      "mail.send",
    ]);
  });

  it("does not let a missing field satisfy a negative predicate", () => {
    const p = policy({
      grants: [
        {
          ...policy().grants[0],
          decision: "allow",
          constraints: [{ path: "/approved", op: "neq", value: false }],
        },
      ],
    });
    assert.equal(evaluateCapabilityPolicy(p, baseContext()).verdict, "deny");
    assert.equal(
      evaluateCapabilityPolicy(
        p,
        baseContext({ body: JSON.stringify({ approved: true }) }),
      ).verdict,
      "allow",
    );
  });

  it("denies duplicate-key and unsafe-number JSON before constraints or preview", () => {
    const p = policy({
      grants: [
        {
          ...policy().grants[0],
          decision: "allow",
          constraints: [{ path: "/amount", op: "lte", value: 50 }],
        },
      ],
    });
    for (const body of [
      '{"amount":25,"amount":5000}',
      '{"amount":1e400}',
      '{"amount":9007199254740993}',
    ]) {
      const out = evaluateCapabilityPolicy(p, baseContext({ body }));
      assert.equal(out.verdict, "deny");
      assert.equal(out.reason, "invalid_or_ambiguous_json");
    }
  });

  it("distinguishes an own __proto__ JSON member in structured equality", () => {
    const expected = JSON.parse('{"__proto__":{"admin":true}}');
    const p = policy({
      grants: [
        {
          ...policy().grants[0],
          decision: "allow",
          constraints: [{ path: "/target", op: "eq", value: expected }],
        },
      ],
    });
    assert.equal(
      evaluateCapabilityPolicy(p, baseContext({ body: '{"target":{}}' })).verdict,
      "deny",
    );
    assert.equal(
      evaluateCapabilityPolicy(
        p,
        baseContext({ body: '{"target":{"__proto__":{"admin":true}}}' }),
      ).verdict,
      "allow",
    );
  });

  it("uses the configured unmatched verdict and can fall back to legacy access", () => {
    const denied = evaluateCapabilityPolicy(policy(), baseContext({ method: "GET", path: "/inbox" }));
    assert.equal(denied.verdict, "deny");
    const rec = {
      name: "mail",
      access: "ro",
      capabilityPolicy: { ...policy(), onUnmatched: "legacy" },
    };
    const legacy = evaluateCapabilityAccess(rec, baseContext({ method: "GET", path: "/inbox", body: "" }));
    assert.equal(legacy.verdict, "allow");
    assert.equal(legacy.reason, "read_method");
  });

  it("keeps an explicit legacy deny as a hard outer guard", () => {
    const rec = {
      name: "mail",
      access: "rw",
      accessRules: [{ effect: "deny", methods: ["POST"], path: "/v1/messages/send" }],
      capabilityPolicy: policy({ grants: [{ ...policy().grants[0], decision: "allow" }] }),
    };
    const out = evaluateCapabilityAccess(rec, baseContext());
    assert.equal(out.verdict, "deny");
    assert.match(out.reason, /rule_0_deny/);
  });
});

describe("exact action commitment", () => {
  it("changes for body, query, headers, principal, epoch, and nonce", () => {
    const p = policy();
    const first = evaluateCapabilityPolicy(p, baseContext()).actionDigest;
    const mutations = [
      baseContext({ body: JSON.stringify({ to: ["mallory@example.com"] }) }),
      baseContext({ query: "draft=false" }),
      baseContext({ port: "8443" }),
      baseContext({ headers: { "content-type": "application/json", "idempotency-key": "two" } }),
      baseContext({ principal: "agent:jkt:different" }),
      baseContext({ nonce: "request-2" }),
    ];
    for (const changed of mutations) {
      assert.notEqual(evaluateCapabilityPolicy(p, changed).actionDigest, first);
    }
    assert.notEqual(evaluateCapabilityPolicy({ ...p, epoch: 4 }, baseContext()).actionDigest, first);
  });

  it("changes when a same-name credential's materialization config changes", () => {
    const firstRecord = {
      name: "mail",
      type: "bearer",
      domains: ["mail.example.com"],
      value: "token-one",
      updatedAt: 1,
      capabilityPolicy: policy(),
    };
    const first = evaluateCapabilityAccess(firstRecord, baseContext()).actionDigest;
    assert.notEqual(
      evaluateCapabilityAccess(
        { ...firstRecord, value: "token-two", updatedAt: 2 },
        baseContext(),
      ).actionDigest,
      first,
    );
    assert.notEqual(
      evaluateCapabilityAccess(
        {
          ...firstRecord,
          type: "query",
          paramName: "api_key",
          value: "token-one",
        },
        baseContext(),
      ).actionDigest,
      first,
    );
  });
});
