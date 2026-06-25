// Alien Agent ID — v3 proof bundle: construction, parsing, universal verifier.
//
// The bundle is the unit of provenance attestation. A v3 bundle binds a
// payload (currently: a signed git commit) to the agent that produced it,
// and through the agent to a verified human owner via Alien Network SSO:
//
//     bundle.id_token       — SSO-issued OIDC id_token (RS256), base64url-encoded
//     bundle.agent_jwk      — agent's Ed25519 public key, OKP JWK
//     bundle.version        — protocol version, currently 3
//
// The chain is anchored by id_token.cnf.jkt (RFC 7800 §3.1) — the SSO
// computes the JWK thumbprint at binding time, so jwkThumbprint(agent_jwk)
// must equal cnf.jkt. The payload (e.g., commit) is signed with the
// matching private key and verified separately by transport-specific code
// in the consuming plugin (e.g., agent-id-git verifies the SSH signature
// against agent_jwk after this verifier returns).

import { createPublicKey } from "node:crypto";

import { jwkThumbprint } from "./crypto.mjs";
import { ASSURANCE, classifyAssurance, describeAssurance } from "./assurance.mjs";
import { errorMessage, BundleFormatError, BundleVerifyError } from "./errors.mjs";

export const BUNDLE_VERSION = 3;

/**
 * Build a v3 proof bundle from a signed-in agent's runtime state.
 *
 *   idToken    — the SSO-issued id_token (compact JWS). OPTIONAL: omit it for a
 *                self-asserted (L0) bundle that proves only the agent key, with
 *                no human attestation.
 *   agentJwk   — the agent's Ed25519 OKP JWK (kty=OKP, crv=Ed25519, x=...)
 *
 * Returns a plain JSON-serializable object. Consumers serialize and attach
 * it to a transport (git note, exported file, future signed-tool-call
 * attestation) however they like.
 */
export function buildV3Bundle({ idToken = null, agentJwk }) {
  if (!agentJwk || typeof agentJwk !== "object") {
    throw new Error("buildV3Bundle: agentJwk is required");
  }
  const bundle = { version: BUNDLE_VERSION, agent_jwk: agentJwk };
  // A bound (L1/L2) bundle carries the SSO id_token; an L0 bundle omits it.
  if (idToken != null) {
    if (typeof idToken !== "string" || !idToken) {
      throw new Error("buildV3Bundle: idToken must be a non-empty string when present");
    }
    bundle.id_token = Buffer.from(idToken).toString("base64url");
  }
  return bundle;
}

/**
 * Parse a serialized bundle (string or already-parsed object) and validate
 * its shape. Throws BundleFormatError on any structural problem; callers
 * receive a guaranteed-shape object on success.
 */
export function parseBundle(raw) {
  let bundle = raw;
  if (typeof raw === "string") {
    try {
      bundle = JSON.parse(raw);
    } catch (err) {
      throw new BundleFormatError(
        `bundle is not valid JSON: ${errorMessage(err)}`,
      );
    }
  }
  if (!bundle || typeof bundle !== "object") {
    throw new BundleFormatError("bundle must be a JSON object");
  }
  if (bundle.version !== BUNDLE_VERSION) {
    throw new BundleFormatError(
      `unsupported bundle version ${String(bundle.version)} (only v${BUNDLE_VERSION} is supported)`,
    );
  }
  // agent_jwk is always required — it IS the identity. id_token is optional:
  // present for a bound (L1/L2) bundle, absent for a self-asserted (L0) one.
  if (!bundle.agent_jwk || typeof bundle.agent_jwk !== "object") {
    throw new BundleFormatError("bundle missing agent_jwk");
  }
  if ("id_token" in bundle && (typeof bundle.id_token !== "string" || !bundle.id_token)) {
    throw new BundleFormatError("bundle id_token, when present, must be a non-empty string");
  }
  return bundle;
}

/**
 * Decode the id_token field of a v3 bundle back to its compact JWS string.
 * Bundles store the id_token base64url-encoded so they survive JSON
 * transports that may not preserve the dot-separated form unchanged.
 */
export function decodeBundleIdToken(bundle) {
  try {
    return Buffer.from(bundle.id_token, "base64url").toString("utf8");
  } catch (err) {
    throw new BundleFormatError(
      `bundle.id_token is not valid base64url: ${errorMessage(err)}`,
    );
  }
}

/**
 * Universal v3 bundle verifier.
 *
 * Validates everything that does not depend on the transport: bundle shape,
 * id_token SSO signature, agent_jwk ↔ cnf.jkt binding. The caller is
 * responsible for any transport-specific binding (e.g., agent-id-git
 * additionally verifies the SSH commit signature against agent_jwk; a
 * signed-tool-call attestation would verify the payload signature).
 *
 *   bundle              — already-parsed bundle (use parseBundle if raw)
 *   ssoBaseUrl          — override for id_token issuer discovery; defaults
 *                         to bundle's id_token.iss. Required when iss is
 *                         absent or untrustworthy in the caller's context.
 *   verifyIdToken       — async function that performs the SSO signature
 *                         check. Injected so this module stays free of
 *                         OIDC-stack dependencies. Signature:
 *                           ({ idToken, ssoBaseUrl }) => { payload, issuer }
 *
 * Returns:
 *
 *   { ok: true,
 *     level,            // assurance level: 0 self-asserted / 1 anonymous / 2 linked
 *     assurance,        // human-readable level name
 *     jkt,              // jwkThumbprint(bundle.agent_jwk)
 *     ownerSub,         // id_token.sub (pairwise pseudonym at L1) or null at L0
 *     issuer,           // discovery-resolved issuer of the id_token (null at L0)
 *     aud,              // id_token.aud (or null)
 *     iat,              // id_token.iat (or null)
 *     agentJwk,         // pass-through for transport-specific binding
 *     idTokenPayload,   // full id_token claims (null at L0)
 *   }
 *
 * A bundle with no id_token verifies as L0 (self-asserted) without calling
 * verifyIdToken. On any failure, throws BundleVerifyError with a `.code`.
 */
export async function verifyBundle(bundle, { ssoBaseUrl, verifyIdToken } = {}) {
  // Accept either an already-parsed bundle or a raw JSON-shaped object.
  // parseBundle is idempotent on the latter.
  const parsed = parseBundle(bundle);

  // Validate agent_jwk parses as an Ed25519 public key before thumbprinting —
  // jwkThumbprint enforces the OKP/Ed25519 shape on its inputs, but a malformed
  // JWK would surface a less actionable error. Needed for both L0 and L1/L2.
  try {
    createPublicKey({ key: parsed.agent_jwk, format: "jwk" });
  } catch (err) {
    throw new BundleVerifyError(
      `agent_jwk is not a valid Ed25519 JWK: ${errorMessage(err)}`,
      "agent-jwk-invalid",
    );
  }
  const computedJkt = jwkThumbprint(parsed.agent_jwk);

  // L0 (self-asserted): no id_token. The bundle proves only the agent key; the
  // transport layer (e.g. the SSH commit signature) binds the payload to it.
  if (!("id_token" in parsed)) {
    return {
      ok: true,
      level: ASSURANCE.SELF,
      assurance: describeAssurance(ASSURANCE.SELF),
      jkt: computedJkt,
      ownerSub: null,
      issuer: null,
      aud: null,
      iat: null,
      agentJwk: parsed.agent_jwk,
      idTokenPayload: null,
    };
  }

  if (typeof verifyIdToken !== "function") {
    throw new TypeError("verifyBundle: verifyIdToken callback is required for a bound bundle");
  }
  const idTokenStr = decodeBundleIdToken(parsed);

  let resolvedSsoBaseUrl = ssoBaseUrl || null;
  if (!resolvedSsoBaseUrl) {
    // Extract iss from the id_token without trusting it yet — verifyIdToken
    // will fetch its discovery doc and confirm the signature. Best-effort
    // parse; verifyIdToken surfaces real errors.
    try {
      const payload = JSON.parse(
        Buffer.from(idTokenStr.split(".")[1], "base64url").toString("utf8"),
      );
      if (typeof payload?.iss === "string" && payload.iss) {
        resolvedSsoBaseUrl = payload.iss;
      }
    } catch {
      // fall through
    }
  }
  if (!resolvedSsoBaseUrl) {
    throw new BundleVerifyError(
      "could not determine SSO base URL (no ssoBaseUrl passed and id_token.iss missing)",
      "no-issuer",
    );
  }

  let tokenResult;
  try {
    tokenResult = await verifyIdToken({ idToken: idTokenStr, ssoBaseUrl: resolvedSsoBaseUrl });
  } catch (err) {
    throw new BundleVerifyError(
      `id_token SSO signature verification failed: ${errorMessage(err)}`,
      "id-token-invalid",
    );
  }
  const idPayload = tokenResult?.payload;

  if (typeof idPayload?.sub !== "string" || !idPayload.sub) {
    throw new BundleVerifyError("id_token missing sub claim", "missing-sub");
  }
  const cnfJkt = idPayload?.cnf?.jkt;
  if (typeof cnfJkt !== "string" || !cnfJkt) {
    throw new BundleVerifyError(
      "id_token missing cnf.jkt (RFC 7800 §3.1 confirmation claim required)",
      "missing-cnf-jkt",
    );
  }

  // agent_jwk was validated + thumbprinted up front; the bound branch only adds
  // the cnf.jkt anchor check.
  if (computedJkt !== cnfJkt) {
    throw new BundleVerifyError(
      `agent_jwk thumbprint ${computedJkt} does not match id_token cnf.jkt ${cnfJkt}`,
      "jkt-mismatch",
    );
  }

  const level = classifyAssurance(idPayload);
  return {
    ok: true,
    level,
    assurance: describeAssurance(level),
    jkt: computedJkt,
    ownerSub: idPayload.sub,
    issuer: tokenResult.issuer,
    aud: idPayload.aud ?? null,
    iat: idPayload.iat ?? null,
    agentJwk: parsed.agent_jwk,
    idTokenPayload: idPayload,
  };
}

// Re-export for backwards compatibility — canonical definitions are in errors.mjs.
export { BundleFormatError, BundleVerifyError } from "./errors.mjs";
