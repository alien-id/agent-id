// Alien Agent ID — Portable library for agent identity management.
// Zero npm dependencies. Requires Node.js 18+ (built-in crypto, fetch, fs).
//
// Consolidated from openclaw-alienid-signature-demo/src/{canonical,crypto,state,oidc,signer,verify}.js

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  hkdfSync,
  randomBytes,
} from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

// Re-export crypto primitives from agent-id-core. During the split refactor
// the canonical home is plugins/agent-id-core/lib/crypto.mjs; this re-export
// keeps existing imports from skills/alien-agent-id/lib.mjs working.
export * from "../../plugins/agent-id-core/lib/crypto.mjs";

// Re-export the v3 bundle module from agent-id-core. Bundles are the
// universal provenance unit — git commits today, signed tool calls
// tomorrow — so the constructor + parser + universal verifier live in
// core, not in the git plugin.
export * from "../../plugins/agent-id-core/lib/bundle.mjs";

// Re-export state I/O helpers from agent-id-core.
export * from "../../plugins/agent-id-core/lib/state.mjs";

import {
  appendJsonl,
  ensureDir,
  readJsonFile,
  readJsonl,
  setPrivateFilePermissions,
  statePaths,
  writeJsonFile,
} from "../../plugins/agent-id-core/lib/state.mjs";

// Re-export typed error classes from agent-id-core.
export * from "../../plugins/agent-id-core/lib/errors.mjs";

import {
  AuthRevokedError,
  SubjectMismatchError,
} from "../../plugins/agent-id-core/lib/errors.mjs";

// Re-export the OIDC stack: discovery, authorize/poll/exchange, refresh,
// userinfo, JWKS, id_token verifiers (verifyIdToken / verifyIdTokenSignatureOnly).
export * from "../../plugins/agent-id-core/lib/oidc.mjs";

import {
  parseJwt,
  refreshSession,
  verifyIdToken,
} from "../../plugins/agent-id-core/lib/oidc.mjs";

// Re-export the universal signer + audit-trail verifier: SignatureEngine
// (appendOperation, ensureValidSession, …), verifyState, resolveAgentId.
export * from "../../plugins/agent-id-core/lib/signature-engine.mjs";

// Re-export vault crypto from the agent-id-vault plugin. Plugin-private —
// no other plugin needs these — so it lives in the vault plugin's own lib,
// not in core. Stays surfaced from lib.mjs for now so the legacy
// skills/alien-agent-id/cli.mjs keeps working until per-plugin CLIs land.
export * from "../../plugins/agent-id-vault/lib/vault.mjs";

// Re-export service-manifest discovery + validation from the agent-id-auth
// plugin. Same rationale as vault: plugin-private surface, legacy cli.mjs
// still needs to see the symbols, so we re-export through here.
export * from "../../plugins/agent-id-auth/lib/manifest.mjs";

import {
  b64url,
  canonicalJSONString,
  createDPoPProof,
  ed25519PublicKeyToJwk,
  fingerprintPublicKeyPem,
  fromB64url,
  generateEd25519PemPair,
  jwkThumbprint,
  newOperationId,
  nowMs,
  sha256B64url,
  sha256Hex,
  sha256HexCanonical,
  signEd25519Base64Url,
  verifyEd25519Base64Url,
  verifyJwtEdDsaSignature,
  verifyJwtRs256Signature,
} from "../../plugins/agent-id-core/lib/crypto.mjs";


