#!/usr/bin/env node

// RFC 9207 §2.4: when the AS surfaces the `iss` parameter on the
// authorization response, the client MUST compare it to the AS's
// discovered issuer and reject mismatches. This defeats the OAuth
// mix-up class of attacks. Tolerated when the AS does not surface the
// value (older AS / response shapes that do not carry `iss`).
//
// Run: node --test tests/test-rfc9207-iss.mjs

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import {
  beginOidcAuthorization,
  pollForAuthorizationCode,
} from "../bin/lib.mjs";

function startMock({ issuer, authorize, poll }) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      if (req.url === "/.well-known/openid-configuration") {
        res.writeHead(200, { "Content-Type": "application/json" });
        const port = server.address().port;
        res.end(
          JSON.stringify({
            issuer: issuer === undefined ? `http://127.0.0.1:${port}` : issuer,
            jwks_uri: `http://127.0.0.1:${port}/jwks`,
          }),
        );
        return;
      }
      if (req.url.startsWith("/oauth/authorize")) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(authorize(server)));
        return;
      }
      if (req.url === "/oauth/poll") {
        let body = "";
        req.on("data", (chunk) => (body += chunk));
        req.on("end", () => {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(poll(server, body)));
        });
        return;
      }
      res.writeHead(404).end();
    });
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ server, baseUrl: `http://127.0.0.1:${port}` });
    });
  });
}

describe("RFC 9207 §2.4 — iss check on authorize response", () => {
  it("rejects when authorize response carries iss that does not match discovery.issuer", async () => {
    const mock = await startMock({
      authorize: (server) => ({
        deep_link: "alien://demo",
        polling_code: "p1",
        expired_at: Date.now() + 60_000,
        iss: "https://attacker.example",
      }),
      poll: () => ({ status: "pending" }),
    });
    try {
      await assert.rejects(
        () =>
          beginOidcAuthorization({
            ssoBaseUrl: mock.baseUrl,
            providerAddress: "0xprovider",
          }),
        /Authorize response issuer mismatch/,
      );
    } finally {
      mock.server.close();
    }
  });

  it("accepts when authorize response carries matching iss", async () => {
    const mock = await startMock({
      authorize: (server) => ({
        deep_link: "alien://demo",
        polling_code: "p1",
        expired_at: Date.now() + 60_000,
        iss: `http://127.0.0.1:${server.address().port}`,
      }),
      poll: () => ({ status: "pending" }),
    });
    try {
      const out = await beginOidcAuthorization({
        ssoBaseUrl: mock.baseUrl,
        providerAddress: "0xprovider",
      });
      assert.equal(out.issuer, mock.baseUrl);
      assert.equal(out.pollingCode, "p1");
    } finally {
      mock.server.close();
    }
  });

  it("tolerates legacy authorize response that omits iss", async () => {
    const mock = await startMock({
      authorize: () => ({
        deep_link: "alien://demo",
        polling_code: "p1",
        expired_at: Date.now() + 60_000,
      }),
      poll: () => ({ status: "pending" }),
    });
    try {
      const out = await beginOidcAuthorization({
        ssoBaseUrl: mock.baseUrl,
        providerAddress: "0xprovider",
      });
      assert.equal(out.issuer, mock.baseUrl);
    } finally {
      mock.server.close();
    }
  });
});

describe("RFC 9207 §2.4 — iss check on poll response", () => {
  it("rejects when poll authorized response carries iss that does not match expectedIssuer", async () => {
    const mock = await startMock({
      authorize: () => ({
        deep_link: "alien://demo",
        polling_code: "p1",
        expired_at: Date.now() + 60_000,
      }),
      poll: () => ({
        status: "authorized",
        authorization_code: "auth-123",
        iss: "https://attacker.example",
      }),
    });
    try {
      await assert.rejects(
        () =>
          pollForAuthorizationCode({
            ssoBaseUrl: mock.baseUrl,
            pollingCode: "p1",
            expectedIssuer: mock.baseUrl,
            pollIntervalMs: 5,
            timeoutSec: 1,
          }),
        /Authorization response issuer mismatch/,
      );
    } finally {
      mock.server.close();
    }
  });

  it("accepts when poll authorized response carries matching iss", async () => {
    const mock = await startMock({
      authorize: () => ({
        deep_link: "alien://demo",
        polling_code: "p1",
        expired_at: Date.now() + 60_000,
      }),
      poll: (server) => ({
        status: "authorized",
        authorization_code: "auth-123",
        iss: `http://127.0.0.1:${server.address().port}`,
      }),
    });
    try {
      const out = await pollForAuthorizationCode({
        ssoBaseUrl: mock.baseUrl,
        pollingCode: "p1",
        expectedIssuer: mock.baseUrl,
        pollIntervalMs: 5,
        timeoutSec: 1,
      });
      assert.equal(out.authorizationCode, "auth-123");
    } finally {
      mock.server.close();
    }
  });

  it("tolerates legacy poll response without iss when expectedIssuer is supplied", async () => {
    const mock = await startMock({
      authorize: () => ({
        deep_link: "alien://demo",
        polling_code: "p1",
        expired_at: Date.now() + 60_000,
      }),
      poll: () => ({
        status: "authorized",
        authorization_code: "auth-123",
      }),
    });
    try {
      const out = await pollForAuthorizationCode({
        ssoBaseUrl: mock.baseUrl,
        pollingCode: "p1",
        expectedIssuer: mock.baseUrl,
        pollIntervalMs: 5,
        timeoutSec: 1,
      });
      assert.equal(out.authorizationCode, "auth-123");
    } finally {
      mock.server.close();
    }
  });

  it("skips iss check when expectedIssuer is null (legacy callers)", async () => {
    const mock = await startMock({
      authorize: () => ({
        deep_link: "alien://demo",
        polling_code: "p1",
        expired_at: Date.now() + 60_000,
      }),
      poll: () => ({
        status: "authorized",
        authorization_code: "auth-123",
        iss: "https://attacker.example",
      }),
    });
    try {
      const out = await pollForAuthorizationCode({
        ssoBaseUrl: mock.baseUrl,
        pollingCode: "p1",
        expectedIssuer: null,
        pollIntervalMs: 5,
        timeoutSec: 1,
      });
      assert.equal(out.authorizationCode, "auth-123");
    } finally {
      mock.server.close();
    }
  });
});
