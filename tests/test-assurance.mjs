#!/usr/bin/env node

// Tests for the identity assurance ladder (L0 self-asserted → L1 anonymous →
// L2 linked):
//
//   - classifyAssurance: claim → level
//   - buildV3Bundle / verifyBundle: an L0 (no id_token) bundle verifies without
//     an SSO call; L1/L2 bundles classify from claims
//   - SignatureEngine: an UNBOUND agent can sign into its own audit trail, and
//     verifyState reports that as a valid level-0 state (not an error)
//
// Run: node --test tests/test-assurance.mjs

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm } from "node:fs/promises";

import {
  ASSURANCE,
  classifyAssurance,
  describeAssurance,
  nextAssuranceStep,
} from "../plugins/agent-id-core/lib/assurance.mjs";
import {
  buildV3Bundle,
  verifyBundle,
} from "../plugins/agent-id-core/lib/bundle.mjs";
import {
  ed25519PublicKeyToJwk,
  generateEd25519PemPair,
  jwkThumbprint,
} from "../plugins/agent-id-core/lib/crypto.mjs";
import {
  SignatureEngine,
  verifyState,
} from "../plugins/agent-id-core/lib/signature-engine.mjs";

function tmp() {
  return mkdtemp(path.join(os.tmpdir(), "assurance-"));
}

// An agent key + the JWK/JKT a bundle's cnf.jkt must match.
function agentIdentity() {
  const pair = generateEd25519PemPair();
  const jwk = ed25519PublicKeyToJwk(pair.publicKeyPem);
  return { pair, jwk, jkt: jwkThumbprint(jwk) };
}

describe("classifyAssurance", () => {
  it("no token → L0 self-asserted", () => {
    assert.equal(classifyAssurance(null), ASSURANCE.SELF);
    assert.equal(classifyAssurance(undefined), ASSURANCE.SELF);
    assert.equal(classifyAssurance("nope"), ASSURANCE.SELF);
  });

  it("token without cnf.jkt cannot anchor → L0", () => {
    assert.equal(classifyAssurance({ sub: "0xAlice" }), ASSURANCE.SELF);
  });

  it("token without sub → L0", () => {
    assert.equal(classifyAssurance({ cnf: { jkt: "abc" } }), ASSURANCE.SELF);
  });

  it("cnf.jkt + canonical sub → L2 linked", () => {
    assert.equal(
      classifyAssurance({ sub: "0xAlice", cnf: { jkt: "abc" } }),
      ASSURANCE.LINKED
    );
  });

  it("alien_assurance:anonymous + pairwise sub → L1 anonymous", () => {
    assert.equal(
      classifyAssurance({
        sub: "ppid-xyz",
        cnf: { jkt: "abc" },
        alien_assurance: "anonymous",
      }),
      ASSURANCE.ANONYMOUS
    );
  });

  it("describeAssurance + nextAssuranceStep are coherent", () => {
    assert.equal(describeAssurance(ASSURANCE.SELF), "self-asserted");
    assert.equal(describeAssurance(ASSURANCE.LINKED), "linked");
    assert.match(nextAssuranceStep(ASSURANCE.SELF), /auth/);
    assert.equal(nextAssuranceStep(ASSURANCE.LINKED), null);
  });
});

describe("verifyBundle assurance levels", () => {
  it("an L0 bundle (no id_token) verifies without an SSO call", async () => {
    const { jwk, jkt } = agentIdentity();
    const bundle = buildV3Bundle({ agentJwk: jwk });
    assert.equal("id_token" in bundle, false, "L0 bundle carries no id_token");

    // No verifyIdToken callback passed — L0 must not need one.
    const res = await verifyBundle(bundle);
    assert.equal(res.ok, true);
    assert.equal(res.level, ASSURANCE.SELF);
    assert.equal(res.assurance, "self-asserted");
    assert.equal(res.jkt, jkt);
    assert.equal(res.ownerSub, null);
    assert.equal(res.idTokenPayload, null);
  });

  it("classifies a linked token as L2 and an anonymous token as L1", async () => {
    const { jwk, jkt } = agentIdentity();
    const issuer = "https://sso.example";

    const verifyWith = (payload) => ({
      verifyIdToken: async ({ ssoBaseUrl }) => ({
        payload,
        issuer: ssoBaseUrl,
      }),
      ssoBaseUrl: issuer,
    });

    const linked = await verifyBundle(
      buildV3Bundle({ idToken: "a.b.c", agentJwk: jwk }),
      verifyWith({
        sub: "0xAlice",
        cnf: { jkt },
        iss: issuer,
        aud: "0xprov",
        iat: 1,
      })
    );
    assert.equal(linked.level, ASSURANCE.LINKED);
    assert.equal(linked.assurance, "linked");
    assert.equal(linked.ownerSub, "0xAlice");

    const anon = await verifyBundle(
      buildV3Bundle({ idToken: "a.b.c", agentJwk: jwk }),
      verifyWith({
        sub: "ppid-xyz",
        cnf: { jkt },
        alien_assurance: "anonymous",
        iss: issuer,
        aud: "0xprov",
        iat: 1,
      })
    );
    assert.equal(anon.level, ASSURANCE.ANONYMOUS);
    assert.equal(anon.assurance, "anonymous-human");
    assert.equal(anon.ownerSub, "ppid-xyz"); // a pairwise pseudonym, not the AlienID
  });

  it("still rejects a bound bundle whose agent_jwk ≠ cnf.jkt", async () => {
    const { jwk } = agentIdentity();
    const other = agentIdentity(); // different key → different thumbprint
    await assert.rejects(
      verifyBundle(buildV3Bundle({ idToken: "a.b.c", agentJwk: jwk }), {
        ssoBaseUrl: "https://sso.example",
        verifyIdToken: async () => ({
          payload: {
            sub: "0xAlice",
            cnf: { jkt: other.jkt },
            iss: "https://sso.example",
          },
          issuer: "https://sso.example",
        }),
      }),
      /does not match id_token cnf\.jkt/
    );
  });
});

describe("SignatureEngine: level-0 (unbound) usability", () => {
  it("an unbound agent signs into its own audit trail; verifyState reports L0, ok", async () => {
    const dir = await tmp();
    try {
      const engine = new SignatureEngine({ baseDir: dir });
      await engine.init(); // generates the main key; NO owner-session

      assert.equal(engine.isOwnerBound(), false);

      // Previously this threw "Owner session missing"; now it must succeed.
      const rec = await engine.appendOperation({
        operationType: "TEST_OP",
        action: "test.action",
        payload: { hello: "world" },
        ctx: { agentId: "main" },
      });
      assert.equal(rec.seq, 1);
      assert.ok(rec.signatureShort);

      const state = await verifyState(dir);
      assert.equal(state.ok, true, `errors: ${JSON.stringify(state.errors)}`);
      assert.equal(state.level, ASSURANCE.SELF);
      assert.equal(state.assurance, "self-asserted");
      assert.equal(state.ownerSessionSub, null);
      assert.equal(state.operations, 1);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
