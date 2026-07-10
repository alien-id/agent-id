#!/usr/bin/env node

import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";

import { createProxy } from "../plugins/agent-id-proxy/lib/proxy.mjs";
import { startDevPhoneSimulator } from "../plugins/agent-id-proxy/lib/dev-phone.mjs";
import {
  SignatureEngine,
  verifyState,
} from "../plugins/agent-id-core/lib/signature-engine.mjs";
import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";

const PRINCIPAL = "agent:jkt:test-capability-principal";

function startUpstream(seen) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const chunks = [];
      req.on("data", (chunk) => chunks.push(chunk));
      req.on("end", () => {
        seen.push({
          method: req.method,
          url: req.url,
          auth: req.headers.authorization,
          body: Buffer.concat(chunks).toString("utf8"),
        });
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end('{"ok":true,"messageId":"m-1"}');
      });
    });
    server.listen(0, "127.0.0.1", () =>
      resolve({ server, host: "127.0.0.1", port: server.address().port }),
    );
  });
}

function requestProxy({ proxyPort, upstream, body, cred = "mail", query = "mode=now" }) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port: proxyPort,
        method: "POST",
        path: `/${cred}/${upstream.host}:${upstream.port}/v1/messages/send?${query}`,
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
          "Idempotency-Key": JSON.parse(body).id,
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () =>
          resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString("utf8") }),
        );
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

function startAbortableProxyRequest({ proxyPort, upstream, body, cred = "mail" }) {
  let req;
  const finished = new Promise((resolve) => {
    req = http.request({
      host: "127.0.0.1",
      port: proxyPort,
      method: "POST",
      path: `/${cred}/${upstream.host}:${upstream.port}/v1/messages/send?mode=now`,
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(body),
        "Idempotency-Key": JSON.parse(body).id,
      },
    });
    req.on("response", (res) => {
      res.resume();
      res.on("end", resolve);
    });
    req.on("error", resolve);
    req.end(body);
  });
  return { abort: () => req.destroy(), finished };
}

function controlJson({ port, token, method = "GET", route, body = null }) {
  return new Promise((resolve, reject) => {
    const payload = body == null ? null : JSON.stringify(body);
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        method,
        path: route,
        headers: {
          Authorization: `Bearer ${token}`,
          ...(payload
            ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) }
            : {}),
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () =>
          resolve({ status: res.statusCode, json: JSON.parse(Buffer.concat(chunks).toString("utf8")) }),
        );
      },
    );
    req.on("error", reject);
    req.end(payload || undefined);
  });
}

async function waitPending(controlPort, token, count = 1) {
  for (let i = 0; i < 400; i++) {
    const out = await controlJson({ port: controlPort, token, route: "/pending" });
    if ((out.json.pending || []).length >= count) return out.json.pending;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.fail("capability request did not enter the pending registry");
}

describe("proxy semantic capability broker", () => {
  let dir;
  let upstream;
  let proxy;
  let proxyPort;
  let controlPort;
  let token;
  let logPath;
  const seen = [];
  const signedEvents = [];
  let auditEngine;

  before(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "capability-proxy-"));
    await initVault({ stateDir: dir, passphrase: "dev-pass" });
    auditEngine = new SignatureEngine({ baseDir: dir });
    await auditEngine.init();
    const vault = await openVault({ stateDir: dir, passphrase: "dev-pass" });
    upstream = await startUpstream(seen);
    vault.add({
      name: "mail",
      type: "bearer",
      domains: [upstream.host],
      upstreamScheme: "http",
      value: "TOP_SECRET_TOKEN",
      capabilityPolicyEpoch: 7,
      capabilityPolicy: {
        version: 1,
        epoch: 7,
        onUnmatched: "deny",
        grants: [
          {
            id: "mail-send",
            principal: PRINCIPAL,
            capability: "mail.send",
            label: "Send email",
            decision: "ask",
            match: {
              methods: ["POST"],
              ports: [String(upstream.port)],
              path: "/v1/messages/send",
            },
            previewFields: ["/to", "/subject"],
          },
        ],
      },
    });
    vault.add({
      name: "mail-deny",
      type: "bearer",
      domains: [upstream.host],
      upstreamScheme: "http",
      value: "DENY_SECRET",
      capabilityPolicyEpoch: 1,
      capabilityPolicy: {
        version: 1,
        epoch: 1,
        onUnmatched: "deny",
        grants: [
          {
            id: "never-send",
            principal: "*",
            capability: "mail.send",
            decision: "deny",
            match: {
              methods: ["POST"],
              ports: [String(upstream.port)],
              path: "/v1/messages/send",
            },
          },
        ],
      },
    });
    await vault.save();

    logPath = path.join(dir, "proxy.log");
    proxy = createProxy({
      vault,
      stateDir: dir,
      logPath,
      principal: PRINCIPAL,
      idleTimeoutMs: Infinity,
      control: { listen: { port: 0, host: "127.0.0.1" }, approvalTimeoutMs: 10_000 },
      capabilityAudit: async (event) => {
        signedEvents.push(event);
        await auditEngine.appendOperation({
          operationType: "capability",
          action: event.event,
          payload: event,
          ctx: { agentId: "main" },
        });
      },
    });
    const addr = await proxy.listen();
    proxyPort = addr.port;
    controlPort = proxy.controlAddress.port;
    token = proxy.controlToken;
  });

  after(async () => {
    if (proxy) await proxy.close();
    if (upstream?.server) await new Promise((resolve) => upstream.server.close(resolve));
    if (dir) await fs.rm(dir, { recursive: true, force: true });
  });

  it("parks, rejects a wrong digest, then forwards the exact request once", async () => {
    const body = JSON.stringify({ id: "one", to: ["alice@alien.org"], subject: "Launch" });
    const pendingResponse = requestProxy({ proxyPort, upstream, body });
    const [entry] = await waitPending(controlPort, token);
    assert.equal(entry.action, "capability");
    assert.equal(entry.principal, PRINCIPAL);
    assert.equal(entry.capability, "mail.send");
    assert.deepEqual(entry.grants, [
      { id: "mail-send", capability: "mail.send", label: "Send email" },
    ]);
    assert.deepEqual(entry.preview.parameters["/to"], ["alice@alien.org"]);
    assert.equal(seen.length, 0, "upstream was reached before approval");
    assert.ok(!JSON.stringify(entry).includes("TOP_SECRET_TOKEN"));
    assert.ok(!JSON.stringify(entry).includes(body));

    const wrong = await controlJson({
      port: controlPort,
      token,
      method: "POST",
      route: "/approve",
      body: { id: entry.id, actionDigest: "sha256:wrong", scope: "once" },
    });
    assert.equal(wrong.status, 409);
    assert.equal(seen.length, 0);

    const approved = await controlJson({
      port: controlPort,
      token,
      method: "POST",
      route: "/approve",
      body: { id: entry.id, actionDigest: entry.actionDigest, scope: "once" },
    });
    assert.equal(approved.status, 200);
    const response = await pendingResponse;
    assert.equal(response.status, 200);
    assert.equal(seen.length, 1);
    assert.equal(seen[0].auth, "Bearer TOP_SECRET_TOKEN");
    assert.equal(seen[0].body, body);
    assert.ok(signedEvents.some((event) => event.event === "capability_requested"));
    assert.ok(signedEvents.some((event) => event.event === "capability_approved"));
  });

  it("creates independent digests/approvals for concurrent writes", async () => {
    const a = requestProxy({
      proxyPort,
      upstream,
      body: JSON.stringify({ id: "a", to: ["a@alien.org"], subject: "A" }),
    });
    const b = requestProxy({
      proxyPort,
      upstream,
      body: JSON.stringify({ id: "b", to: ["b@alien.org"], subject: "B" }),
    });
    const pending = await waitPending(controlPort, token, 2);
    assert.equal(new Set(pending.map((entry) => entry.actionDigest)).size, 2);
    for (const entry of pending) {
      const denied = await controlJson({
        port: controlPort,
        token,
        method: "POST",
        route: "/deny",
        body: { id: entry.id, actionDigest: entry.actionDigest, scope: "once", reason: "dev_denied" },
      });
      assert.equal(denied.status, 200);
    }
    const results = await Promise.all([a, b]);
    assert.deepEqual(results.map((result) => result.status), [403, 403]);
    assert.equal(seen.length, 1, "denied concurrent writes reached upstream");
  });

  it("cancels a parked action when the calling client disconnects", async () => {
    const before = seen.length;
    const pendingRequest = startAbortableProxyRequest({
      proxyPort,
      upstream,
      body: JSON.stringify({ id: "aborted", to: ["a@alien.org"], subject: "Abort" }),
    });
    const [entry] = await waitPending(controlPort, token);
    pendingRequest.abort();
    await pendingRequest.finished;
    for (let i = 0; i < 100 && proxy.pendingCount !== 0; i++) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    assert.equal(proxy.pendingCount, 0);
    const lateApproval = await controlJson({
      port: controlPort,
      token,
      method: "POST",
      route: "/approve",
      body: { id: entry.id, actionDigest: entry.actionDigest, scope: "once" },
    });
    assert.equal(lateApproval.status, 404);
    assert.equal(seen.length, before);
  });

  it("releases an exact ask through the development phone simulator", async () => {
    const simulator = startDevPhoneSimulator({
      controlPort,
      controlToken: token,
      decision: "approve",
      pollIntervalMs: 5,
    });
    try {
      const body = JSON.stringify({
        id: "dev-phone",
        to: ["dev@alien.org"],
        subject: "Simulator",
      });
      const response = await requestProxy({ proxyPort, upstream, body });
      assert.equal(response.status, 200);
      assert.equal(seen.at(-1).body, body);
      assert.equal(simulator.handledCount, 1);
    } finally {
      await simulator.stop();
    }
  });

  it("invalidates a parked approval when policy changes on disk", async () => {
    const before = seen.length;
    const body = JSON.stringify({
      id: "revoked",
      to: ["revoked@alien.org"],
      subject: "Must not send",
    });
    const pendingResponse = requestProxy({ proxyPort, upstream, body });
    const [entry] = await waitPending(controlPort, token);

    const editor = await openVault({ stateDir: dir, passphrase: "dev-pass" });
    const rec = editor.get("mail");
    editor.add({
      ...rec,
      capabilityPolicyEpoch: 8,
      capabilityPolicy: {
        ...rec.capabilityPolicy,
        epoch: 8,
        grants: rec.capabilityPolicy.grants.map((grant) => ({
          ...grant,
          decision: "deny",
        })),
      },
    });
    await editor.save();
    editor.lock();

    const approved = await controlJson({
      port: controlPort,
      token,
      method: "POST",
      route: "/approve",
      body: { id: entry.id, actionDigest: entry.actionDigest, scope: "once" },
    });
    assert.equal(approved.status, 200, "the phone response itself was exact");
    const response = await pendingResponse;
    assert.equal(response.status, 409);
    assert.equal(JSON.parse(response.body).error, "approval_stale_policy");
    assert.equal(seen.length, before);

    // Restore an ask policy at a newer generation for the remaining fixtures.
    const restore = await openVault({ stateDir: dir, passphrase: "dev-pass" });
    const denied = restore.get("mail");
    restore.add({
      ...denied,
      capabilityPolicyEpoch: 9,
      capabilityPolicy: {
        ...denied.capabilityPolicy,
        epoch: 9,
        grants: denied.capabilityPolicy.grants.map((grant) => ({
          ...grant,
          decision: "ask",
        })),
      },
    });
    await restore.save();
    restore.lock();
  });

  it("invalidates approval when same-name materialization config is swapped", async () => {
    const before = seen.length;
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id: "config-swap",
      method: "eth_sendTransaction",
      params: [
        {
          from: "0x0000000000000000000000000000000000000000",
          to: "0x0000000000000000000000000000000000000001",
        },
      ],
    });
    const pendingResponse = requestProxy({ proxyPort, upstream, body });
    const [entry] = await waitPending(controlPort, token);

    const editor = await openVault({ stateDir: dir, passphrase: "dev-pass" });
    const rec = editor.get("mail");
    editor.add({
      ...rec,
      type: "evm-keypair",
      privateKey: "1".padStart(64, "0"),
      address: "0x0000000000000000000000000000000000000000",
    });
    await editor.save();
    editor.lock();

    const approved = await controlJson({
      port: controlPort,
      token,
      method: "POST",
      route: "/approve",
      body: { id: entry.id, actionDigest: entry.actionDigest, scope: "once" },
    });
    assert.equal(approved.status, 200);
    const response = await pendingResponse;
    assert.equal(response.status, 409);
    assert.equal(JSON.parse(response.body).error, "approval_stale_policy");
    assert.equal(seen.length, before);

    const restore = await openVault({ stateDir: dir, passphrase: "dev-pass" });
    const swapped = restore.get("mail");
    const { privateKey, address, ...base } = swapped;
    void privateKey;
    void address;
    restore.add({ ...base, type: "bearer", value: "TOP_SECRET_TOKEN" });
    await restore.save();
    restore.lock();
  });

  it("fails a denied semantic capability closed without creating a prompt", async () => {
    const beforePending = proxy.pendingCount;
    const response = await requestProxy({
      proxyPort,
      upstream,
      cred: "mail-deny",
      body: JSON.stringify({ id: "deny", to: ["x@example.com"] }),
    });
    assert.equal(response.status, 403);
    assert.equal(JSON.parse(response.body).error, "capability_denied");
    assert.equal(proxy.pendingCount, beforePending);
    assert.equal(seen.length, 2);
  });

  it("commits the same normalized agent query bytes that are forwarded", async () => {
    const body = JSON.stringify({
      id: "encoded-query",
      to: ["query@alien.org"],
      subject: "Query",
    });
    const pendingResponse = requestProxy({
      proxyPort,
      upstream,
      body,
      query: "q=a%20b&tilde=~",
    });
    const [entry] = await waitPending(controlPort, token);
    const approved = await controlJson({
      port: controlPort,
      token,
      method: "POST",
      route: "/approve",
      body: { id: entry.id, actionDigest: entry.actionDigest, scope: "once" },
    });
    assert.equal(approved.status, 200);
    assert.equal((await pendingResponse).status, 200);
    assert.equal(seen.at(-1).url, "/v1/messages/send?q=a+b&tilde=%7E");
  });

  it("audit/log metadata contains digests but no credential or request secret", async () => {
    const log = await fs.readFile(logPath, "utf8");
    assert.match(log, /capability_requested/);
    assert.match(log, /actionDigest/);
    assert.ok(!log.includes("TOP_SECRET_TOKEN"));
    assert.ok(!log.includes("Launch"));
    const verified = await verifyState(dir);
    assert.equal(verified.ok, true, JSON.stringify(verified.errors));
    assert.ok(verified.operations >= signedEvents.length);
  });
});
