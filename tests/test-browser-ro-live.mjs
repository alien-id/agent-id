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

import {
  resolvePatchright,
  launchContext,
} from "../plugins/agent-id-browser/lib/launch.mjs";
import {
  applyAccessGuard,
  contextOptionsForAccess,
} from "../plugins/agent-id-browser/lib/access-guard.mjs";

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
          res.end("<!doctype html><title>fake-reddit</title><h1>Inbox</h1>");
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
    const workDir = await fs.mkdtemp(path.join(os.tmpdir(), "ro-live-"));
    let ctx;
    try {
      ctx = await launchContext({
        profileDir: workDir,
        headless: true,
        contextOptions: contextOptionsForAccess(roProfile),
      });
      const active = await applyAccessGuard(ctx, roProfile, { log: () => {} });
      assert.equal(
        active,
        true,
        "the access guard should be active for a ro profile"
      );

      const page = ctx.pages()[0] || (await ctx.newPage());
      await page.goto(`${base}/`, { waitUntil: "domcontentloaded" });

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
        await tryFetch("write", b + "/api/compose", {
          method: "POST",
          body: "to=x&text=hi",
        });
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
      assert.ok(
        hit("GET", "/message/inbox"),
        "read GET should reach the server"
      );
      assert.match(
        results.gqlQuery,
        /^reached:200/,
        "GraphQL query POST should succeed"
      );

      // Writes are aborted at the wire and NEVER reach the server.
      assert.match(
        results.write,
        /^BLOCKED/,
        "write POST should be blocked in the page"
      );
      assert.ok(
        !hit("POST", "/api/compose"),
        "write POST must never reach the server"
      );
      assert.match(
        results.gqlMutation,
        /^BLOCKED/,
        "GraphQL mutation should be blocked"
      );
      assert.ok(
        !seen.some((s) => s.body && s.body.includes("mutation")),
        "no mutation body may reach the server"
      );
    } finally {
      if (ctx) await ctx.close().catch(() => {});
      await fs.rm(workDir, { recursive: true, force: true }).catch(() => {});
    }
  }
);
