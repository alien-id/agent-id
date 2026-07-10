#!/usr/bin/env node

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  applyAccessGuard,
  assertActionAllowed,
  exactImmediateApproval,
  guardDecision,
  safePolicyFeedback,
} from "../plugins/agent-id-browser/lib/access-guard.mjs";
import {
  actionErrorPayload,
  createActionFeedbackTracker,
  policyFeedbackError,
} from "../plugins/agent-id-browser/lib/session-server.mjs";

const PRINCIPAL = "agent:jkt:browser-capability-test";

function record(decision = "ask") {
  return {
    name: "browser-mail",
    type: "browser-profile",
    domains: ["*"],
    capabilityPolicyEpoch: 2,
    capabilityPolicy: {
      version: 1,
      epoch: 2,
      onUnmatched: "deny",
      grants: [
        {
          id: "mail-send",
          principal: PRINCIPAL,
          capability: "mail.send",
          label: "Send email",
          decision,
          match: {
            methods: ["POST"],
            hosts: ["mail.example.com"],
            path: "/v1/messages/send",
          },
          previewFields: ["/to", "/subject"],
        },
      ],
    },
  };
}

const request = (over = {}) => ({
  method: "POST",
  url: "https://mail.example.com/v1/messages/send?mode=now",
  postData: JSON.stringify({ to: ["alice@alien.org"], subject: "Hello" }),
  headers: { "content-type": "application/json" },
  principal: PRINCIPAL,
  nonce: "browser-request-1",
  nowMs: 1_000,
  expiresAtMs: 60_000,
  ...over,
});

function fakeContext(requestSpec = request()) {
  let routeHandler = null;
  const events = [];
  let pages;
  const restoredPage = {
    async close() {
      events.push("restored-page-closed");
      pages = pages.filter((page) => page !== restoredPage);
    },
  };
  const guardedPage = {
    async goto(url) {
      assert.match(url, /^data:text\/html,/);
      events.push("guarded-navigation");
    },
    async title() {
      events.push("transport-check");
      return "agent-id-transports-blocked";
    },
  };
  pages = [restoredPage];
  const ctx = {
    async routeWebSocket() {
      events.push("websocket-route");
    },
    async addInitScript() {
      events.push("init-script");
    },
    pages() {
      return pages;
    },
    async newPage() {
      events.push("guarded-page-created");
      pages.push(guardedPage);
      return guardedPage;
    },
    async setOffline() {
      events.push("online");
    },
    async route(_pattern, handler) {
      routeHandler = handler;
      events.push("http-route");
    },
  };
  const calls = { continued: 0, aborted: 0 };
  const route = {
    request() {
      return {
        method: () => requestSpec.method,
        url: () => requestSpec.url,
        postData: () => requestSpec.postData,
        postDataBuffer: () => Buffer.from(requestSpec.postData || "", "utf8"),
        headers: () => requestSpec.headers || {},
      };
    },
    async continue() {
      calls.continued++;
    },
    async abort() {
      calls.aborted++;
    },
  };
  return {
    ctx,
    calls,
    events,
    async dispatch() {
      assert.equal(typeof routeHandler, "function");
      await routeHandler(route);
    },
  };
}

describe("browser capability decisions", () => {
  it("binds an ask to exact body, query, headers, principal, and nonce", () => {
    const first = guardDecision(record(), request());
    assert.equal(first.verdict, "ask");
    assert.equal(first.capability, "mail.send");
    assert.deepEqual(first.grants, [
      { id: "mail-send", capability: "mail.send", label: "Send email" },
    ]);
    assert.deepEqual(first.preview.parameters["/to"], ["alice@alien.org"]);
    for (const changed of [
      request({ postData: '{"to":["mallory@example.com"]}' }),
      request({ url: "https://mail.example.com/v1/messages/send?mode=later" }),
      request({ headers: { "content-type": "application/json", "x-mode": "two" } }),
      request({ principal: "agent:jkt:someone-else" }),
      request({ nonce: "browser-request-2" }),
    ]) {
      assert.notEqual(guardDecision(record(), changed).actionDigest, first.actionDigest);
    }
  });

  it("fails closed when the capability principal is unavailable", () => {
    const out = guardDecision(record(), request({ principal: null }));
    assert.equal(out.verdict, "deny");
    assert.equal(out.reason, "capability_evaluation_failed");
  });

  it("refuses eval and secret/exfiltration helpers for every restricted policy", () => {
    const capabilityOnly = record("allow");
    for (const action of ["eval", "fill-secret", "fill-otp", "upload"]) {
      assert.throws(() => assertActionAllowed(capabilityOnly, action), /access-restricted/);
    }
    assertActionAllowed({ access: "rw" }, "eval");
  });

  it("builds useful policy feedback without reflecting request secrets", () => {
    const input = request({
      url: "https://user:password@mail.example.com/v1/messages/send?token=query-secret",
      postData: JSON.stringify({
        to: ["body-secret@example.com"],
        subject: "private body secret",
      }),
      headers: {
        authorization: "Bearer header-secret",
        "content-type": "application/json",
      },
    });
    const decision = guardDecision(record(), input);
    const feedback = safePolicyFeedback(record(), decision, input.method, input.url);

    assert.equal(feedback.code, "BROWSER_APPROVAL_REQUIRED");
    assert.equal(feedback.verdict, "ask");
    assert.equal(feedback.reason, "capability_ask");
    assert.equal(feedback.capability, "mail.send");
    assert.deepEqual(feedback.grants, [
      { id: "mail-send", capability: "mail.send", label: "Send email" },
    ]);
    assert.deepEqual(feedback.request, {
      method: "POST",
      origin: "https://mail.example.com",
      path: "/v1/messages/send",
    });
    assert.equal(feedback.policy.kind, "capability");
    assert.equal(feedback.policy.version, 1);
    assert.equal(feedback.policy.epoch, 2);
    assert.match(feedback.policy.hash, /^sha256:/);

    const visible = JSON.stringify(feedback);
    for (const secret of [
      "password",
      "query-secret",
      "body-secret",
      "private body secret",
      "header-secret",
    ]) {
      assert.equal(visible.includes(secret), false, `feedback leaked ${secret}`);
    }
    for (const forbiddenKey of ["query", "body", "headers", "preview", "envelope", "nonce", "actionDigest"]) {
      assert.equal(Object.hasOwn(feedback, forbiddenKey), false);
    }
  });
});

describe("browser ask handling", () => {
  it("accepts only a synchronous, exact, one-shot approval", () => {
    const decision = guardDecision(record(), request({ expiresAtMs: Date.now() + 60_000 }));
    assert.equal(
      exactImmediateApproval(decision, (d) => ({
        approved: true,
        scope: "once",
        actionDigest: d.actionDigest,
      })),
      true,
    );
    assert.equal(exactImmediateApproval(decision, () => true), false);
    assert.equal(
      exactImmediateApproval(decision, () => ({ approved: true, scope: "once", actionDigest: "wrong" })),
      false,
    );
    assert.equal(
      exactImmediateApproval(decision, async (d) => ({ approved: true, scope: "once", actionDigest: d.actionDigest })),
      false,
    );
  });

  it("aborts ask without a simulator and continues exactly once with approval", async () => {
    const denied = fakeContext();
    await applyAccessGuard(denied.ctx, record(), { principal: PRINCIPAL });
    assert.ok(
      denied.events.indexOf("restored-page-closed") < denied.events.indexOf("online"),
      "restored page realms must be destroyed before networking is enabled",
    );
    await denied.dispatch();
    assert.deepEqual(denied.calls, { continued: 0, aborted: 1 });

    const approved = fakeContext();
    let prompts = 0;
    await applyAccessGuard(approved.ctx, record(), {
      principal: PRINCIPAL,
      onAsk(decision) {
        prompts++;
        return {
          approved: true,
          scope: "once",
          actionDigest: decision.actionDigest,
        };
      },
    });
    await approved.dispatch();
    assert.equal(prompts, 1);
    assert.deepEqual(approved.calls, { continued: 1, aborted: 0 });
  });

  it("aborts an explicit deny without invoking approval", async () => {
    const denied = fakeContext();
    let prompts = 0;
    await applyAccessGuard(denied.ctx, record("deny"), {
      principal: PRINCIPAL,
      onAsk() {
        prompts++;
        return null;
      },
    });
    await denied.dispatch();
    assert.equal(prompts, 0);
    assert.deepEqual(denied.calls, { continued: 0, aborted: 1 });
  });

  it("reports a sanitized ask after the request is aborted", async () => {
    const denied = fakeContext();
    let blocked = null;
    await applyAccessGuard(denied.ctx, record(), {
      principal: PRINCIPAL,
      onBlocked(feedback, browserRequest) {
        blocked = { feedback, browserRequest };
      },
    });
    await denied.dispatch();
    assert.equal(blocked.feedback.code, "BROWSER_APPROVAL_REQUIRED");
    assert.equal(blocked.feedback.request.origin, "https://mail.example.com");
    assert.equal(blocked.feedback.request.path, "/v1/messages/send");
    assert.equal(typeof blocked.browserRequest.method, "function");
    assert.deepEqual(denied.calls, { continued: 0, aborted: 1 });
  });
});

function trackedRequest(page, { navigation = false, resourceType = "fetch" } = {}) {
  return {
    frame: () => ({ page: () => page }),
    isNavigationRequest: () => navigation,
    resourceType: () => resourceType,
  };
}

function feedback(overrides = {}) {
  return {
    code: "BROWSER_POLICY_DENIED",
    verdict: "deny",
    reason: "capability_unmatched",
    explanation: "No capability grant matched this browser request.",
    capability: null,
    capabilities: [],
    grants: [],
    request: {
      method: "GET",
      origin: "https://social.example.com",
      path: "/background",
    },
    policy: { kind: "capability", version: 1, epoch: 7, hash: "sha256:policy" },
    ...overrides,
  };
}

describe("browser action policy feedback", () => {
  it("correlates a matched mutation to its action and ignores unrelated request noise", () => {
    const tracker = createActionFeedbackTracker();
    const actionPage = {};
    const otherPage = {};
    const token = tracker.begin("click", actionPage);

    tracker.record(
      feedback({ request: { method: "POST", origin: "https://ads.example", path: "/event" } }),
      trackedRequest(otherPage),
    );
    tracker.record(
      feedback({ request: { method: "GET", origin: "https://social.example.com", path: "/poll" } }),
      trackedRequest(actionPage),
    );
    tracker.record(
      feedback({ request: { method: "POST", origin: "https://social.example.com", path: "/pixel" } }),
      trackedRequest(actionPage, { resourceType: "image" }),
    );

    const likeDenied = feedback({
      reason: "capability_deny",
      explanation: "The request is denied by Like posts.",
      capability: "social.react",
      capabilities: ["social.react"],
      grants: [{ id: "react", capability: "social.react", label: "Like posts" }],
      request: { method: "POST", origin: "https://social.example.com", path: "/reactions" },
    });
    tracker.record(likeDenied, trackedRequest(actionPage));

    assert.deepEqual(tracker.end(token), likeDenied);
  });

  it("attributes direct navigation only to the document request", () => {
    const tracker = createActionFeedbackTracker();
    const page = {};
    const token = tracker.begin("navigate", page);
    tracker.record(
      feedback({ request: { method: "POST", origin: "https://social.example.com", path: "/telemetry" } }),
      trackedRequest(page),
    );
    const navigationDenied = feedback({
      request: { method: "GET", origin: "https://blocked.example.com", path: "/profile" },
    });
    tracker.record(navigationDenied, trackedRequest(page, { navigation: true, resourceType: "document" }));
    assert.deepEqual(tracker.end(token), navigationDenied);
  });

  it("turns feedback into a structured agent-visible error", () => {
    const denied = feedback({
      code: "BROWSER_APPROVAL_REQUIRED",
      verdict: "ask",
      reason: "capability_ask",
      explanation: "Owner approval is required by Like posts.",
      capability: "social.react",
      capabilities: ["social.react"],
      grants: [{ id: "react", capability: "social.react", label: "Like posts" }],
      request: { method: "POST", origin: "https://social.example.com", path: "/reactions" },
    });
    const payload = actionErrorPayload(policyFeedbackError(denied));
    assert.equal(payload.error, "BROWSER_APPROVAL_REQUIRED");
    assert.match(payload.message, /requires owner approval/);
    assert.match(payload.message, /POST https:\/\/social\.example\.com\/reactions/);
    assert.deepEqual(payload.policyDecision, denied);
  });
});
