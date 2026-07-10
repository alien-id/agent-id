#!/usr/bin/env node

// LIVE real-browser proof of read-only enforcement (the "read my Reddit, don't
// write it" story). Launches actual Chrome via the browser plugin's
// launchContext + applyAccessGuard with access:"ro", points it at a local
// server standing in for reddit.com, and asserts that a page-issued READ
// reaches the server while a WRITE is aborted at the network layer.
//
// SKIPS automatically when patchright / Chrome are not installed (e.g. CI
// without the on-demand browser install), so it never breaks the suite.
//
// Run: node --test tests/test-browser-ro-live.mjs

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { resolvePatchright, launchContext } from "../plugins/agent-id-browser/lib/launch.mjs";
import {
  applyAccessGuard,
  contextOptionsForAccess,
} from "../plugins/agent-id-browser/lib/access-guard.mjs";
import { createActionFeedbackTracker } from "../plugins/agent-id-browser/lib/session-server.mjs";

const patchrightAvailable = !!resolvePatchright();

let server;
let base;
const seen = [];

function startServer() {
  return new Promise((resolve) => {
    server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        seen.push({ method: req.method, url: req.url, body });
        if (req.url === "/") {
          res.writeHead(200, { "Content-Type": "text/html" });
          res.end(`<!doctype html><title>fake-reddit</title><h1>Inbox</h1>
            <button id="compose" onclick="fetch('/api/compose', {
              method: 'POST', body: 'to=x&text=private-body'
            }).catch(() => {})">Send</button>
            <script>
              document.documentElement.dataset.transportTypes = [
                "WebSocket", "WebTransport", "RTCPeerConnection",
                "webkitRTCPeerConnection", "Worker", "SharedWorker"
              ].map((name) => typeof globalThis[name]).join(",");
            </script>`);
        } else {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ ok: true }));
        }
      });
    });
    server.listen(0, "127.0.0.1", () => {
      base = `http://127.0.0.1:${server.address().port}`;
      resolve();
    });
  });
}

before(async () => {
  if (patchrightAvailable) await startServer();
});
after(async () => {
  if (server) await new Promise((r) => server.close(r));
});

test(
  "an access:'ro' sealed browser session reads but cannot write (real Chrome)",
  { skip: patchrightAvailable ? false : "patchright/Chrome not installed" },
  async () => {
    const roProfile = { type: "browser-profile", access: "ro", domains: ["*"] };
    const feedbackTracker = createActionFeedbackTracker();
    const workDir = await fs.mkdtemp(path.join(os.tmpdir(), "ro-live-"));
    let ctx;
    try {
      ctx = await launchContext({
        profileDir: workDir,
        headless: true,
        contextOptions: contextOptionsForAccess(roProfile),
      });
      const restoredPage = ctx.pages()[0] || (await ctx.newPage());
      await restoredPage.goto(
        "data:text/html,<script>globalThis.__capturedWorker=globalThis.Worker</script>",
      );
      const active = await applyAccessGuard(ctx, roProfile, {
        log: () => {},
        onBlocked: (feedback, request) => feedbackTracker.record(feedback, request),
      });
      assert.equal(active, true, "the access guard should be active for a ro profile");
      assert.equal(restoredPage.isClosed(), true, "the pre-guard realm must be destroyed");

      const page = ctx.pages()[0] || (await ctx.newPage());
      await page.goto(`${base}/`, { waitUntil: "domcontentloaded" });
      assert.equal(
        await page.getAttribute("html", "data-transport-types"),
        "undefined,undefined,undefined,undefined,undefined,undefined",
        "main-world page code must see every bypass transport disabled",
      );

      // The same route decision is correlated back to the agent action without
      // exposing the POST body. This is the live counterpart to the pure
      // session-server attribution tests.
      const clickToken = feedbackTracker.begin("click", page);
      await page.click("#compose");
      await page.waitForTimeout(100);
      const clickFeedback = feedbackTracker.end(clickToken);
      assert.equal(clickFeedback.code, "BROWSER_POLICY_DENIED");
      assert.equal(clickFeedback.verdict, "deny");
      assert.equal(clickFeedback.reason, "write_blocked");
      assert.deepEqual(clickFeedback.request, {
        method: "POST",
        origin: base,
        path: "/api/compose",
      });
      assert.equal(JSON.stringify(clickFeedback).includes("private-body"), false);

      // Drive exactly what an agent on reddit.com would: a read, a write, a
      // GraphQL query (read), and a GraphQL mutation (write).
      const results = await page.evaluate(async (b) => {
        const out = {};
        const tryFetch = async (label, url, opts) => {
          try {
            const r = await fetch(url, opts);
            out[label] = "reached:" + r.status;
          } catch (e) {
            out[label] = "BLOCKED:" + e.name;
          }
        };
        await tryFetch("read", b + "/message/inbox", {});
        await tryFetch("write", b + "/api/compose", { method: "POST", body: "to=x&text=hi" });
        await tryFetch("gqlQuery", b + "/svc/gql", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ query: "query { inbox }" }),
        });
        await tryFetch("gqlMutation", b + "/svc/gql", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ query: "mutation { sendMessage }" }),
        });
        return out;
      }, base);

      const hit = (m, u) => seen.some((s) => s.method === m && s.url === u);

      // Reads pass and actually reach the server.
      assert.match(results.read, /^reached:200/, "read GET should succeed");
      assert.ok(hit("GET", "/message/inbox"), "read GET should reach the server");
      assert.match(results.gqlQuery, /^reached:200/, "GraphQL query POST should succeed");

      // Writes are aborted at the wire and NEVER reach the server.
      assert.match(results.write, /^BLOCKED/, "write POST should be blocked in the page");
      assert.ok(!hit("POST", "/api/compose"), "write POST must never reach the server");
      assert.match(results.gqlMutation, /^BLOCKED/, "GraphQL mutation should be blocked");
      assert.ok(
        !seen.some((s) => s.body && s.body.includes("mutation")),
        "no mutation body may reach the server",
      );
    } finally {
      if (ctx) await ctx.close().catch(() => {});
      await fs.rm(workDir, { recursive: true, force: true }).catch(() => {});
    }
  },
);

test(
  "a capability ask blocks without approval and releases one exact request with approval (real Chrome)",
  { skip: patchrightAvailable ? false : "patchright/Chrome not installed" },
  async () => {
    const target = new URL(base);
    const principal = "agent:jkt:browser-live-capability-test";
    const profile = {
      name: "local-social",
      type: "browser-profile",
      domains: ["127.0.0.1"],
      capabilityPolicyEpoch: 1,
      capabilityPolicy: {
        version: 1,
        epoch: 1,
        onUnmatched: "deny",
        grants: [
          {
            id: "local-read",
            principal,
            capability: "social.read",
            decision: "allow",
            match: {
              methods: ["GET"],
              hosts: ["127.0.0.1"],
              ports: [target.port],
              path: "/*",
            },
          },
          {
            id: "local-publish",
            principal,
            capability: "social.publish",
            label: "Publish the local test post",
            decision: "ask",
            match: {
              methods: ["POST"],
              hosts: ["127.0.0.1"],
              ports: [target.port],
              path: "/api/compose",
            },
          },
        ],
      },
    };
    const feedbackTracker = createActionFeedbackTracker();
    const workDir = await fs.mkdtemp(path.join(os.tmpdir(), "capability-live-"));
    let ctx;
    let approve = false;
    let approvalCalls = 0;
    try {
      ctx = await launchContext({
        profileDir: workDir,
        headless: true,
        contextOptions: contextOptionsForAccess(profile),
      });
      await applyAccessGuard(ctx, profile, {
        principal,
        log: () => {},
        onAsk(decision) {
          approvalCalls++;
          return {
            approved: approve,
            scope: "once",
            actionDigest: decision.actionDigest,
          };
        },
        onBlocked: (feedback, request) => feedbackTracker.record(feedback, request),
      });

      const page = ctx.pages()[0] || (await ctx.newPage());
      await page.goto(`${base}/`, { waitUntil: "domcontentloaded" });
      const before = seen.filter((entry) => entry.method === "POST" && entry.url === "/api/compose").length;

      const deniedToken = feedbackTracker.begin("click", page);
      await page.click("#compose");
      await page.waitForTimeout(100);
      const denied = feedbackTracker.end(deniedToken);
      assert.equal(denied.code, "BROWSER_APPROVAL_REQUIRED");
      assert.equal(denied.capability, "social.publish");
      assert.equal(denied.grants[0].label, "Publish the local test post");
      assert.equal(
        seen.filter((entry) => entry.method === "POST" && entry.url === "/api/compose").length,
        before,
        "an unapproved exact request must not reach the server",
      );

      approve = true;
      const approvedToken = feedbackTracker.begin("click", page);
      await page.click("#compose");
      await page.waitForTimeout(100);
      assert.equal(feedbackTracker.end(approvedToken), null);
      assert.equal(
        seen.filter((entry) => entry.method === "POST" && entry.url === "/api/compose").length,
        before + 1,
        "one exact approval should release one request",
      );
      assert.equal(approvalCalls, 2);
    } finally {
      if (ctx) await ctx.close().catch(() => {});
      await fs.rm(workDir, { recursive: true, force: true }).catch(() => {});
    }
  },
);
