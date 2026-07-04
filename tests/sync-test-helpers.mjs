#!/usr/bin/env node

// Shared fixture builders for the sync test suite: in-memory identities
// (test-sync-trust.mjs, test-sync-channel.mjs) and on-disk devices
// (test-sync-protocol.mjs, test-sync-e2e.mjs).
//
// NOT used by test-sync-oplog.mjs (its device()/rec() helpers are a
// different, pure keygen + record-builder shape — no id_token) or
// test-sync-cli.mjs (owned by a sibling agent).

import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import {
  ed25519PublicKeyToJwk,
  generateEd25519PemPair,
  jwkThumbprint,
} from "../plugins/agent-id-core/lib/crypto.mjs";
import { ensureDir, statePaths, writeJsonFile } from "../plugins/agent-id-core/lib/state.mjs";
import { initVault, openVault } from "../plugins/agent-id-vault/lib/vault.mjs";
import { loadSyncIdentity } from "../plugins/agent-id-vault/lib/sync/trust.mjs";

// Injected verifier: trusts the token body (signature is out of scope here —
// verifyBundle's structural checks + cnf.jkt binding still run for real).
export const fakeVerifyIdToken = async ({ idToken }) => {
  const payload = JSON.parse(Buffer.from(idToken.split(".")[1], "base64url").toString("utf8"));
  return { signatureValid: true, issuer: payload.iss, payload, header: {} };
};

// A "bound" in-memory test identity: fake id_token whose payload carries
// sub + cnf.jkt. verifyBundle receives our injected verifyIdToken, so no
// real SSO/JWKS is hit. `extraClaims` merges into the token payload (e.g.
// to inject an `exp` for expiry tests). `label` defaults to "t" to match
// callers that don't care about it.
export function makeIdentity(sub, label = "t", extraClaims = {}) {
  const pair = generateEd25519PemPair();
  const agentJwk = ed25519PublicKeyToJwk(pair.publicKeyPem);
  const jkt = jwkThumbprint(agentJwk);
  const payload = { iss: "https://sso.test", sub, cnf: { jkt }, ...extraClaims };
  const idToken = ["e30", Buffer.from(JSON.stringify(payload)).toString("base64url"), "sig"].join(".");
  return { privateKeyPem: pair.privateKeyPem, agentJwk, jkt, idToken, ownerSub: sub, label };
}

// A full simulated on-disk device: stateDir + agent key + owner session + vault.
export async function makeDevice(sub, label) {
  const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), `sync-${label}-`));
  const pair = generateEd25519PemPair();
  const agentJwk = ed25519PublicKeyToJwk(pair.publicKeyPem);
  const jkt = jwkThumbprint(agentJwk);
  const paths = statePaths(stateDir);
  await ensureDir(path.dirname(paths.mainKey));
  await writeJsonFile(paths.mainKey, { agentId: "main", ...pair });
  const idPayload = { iss: "https://sso.test", sub, cnf: { jkt } };
  const idToken = ["e30", Buffer.from(JSON.stringify(idPayload)).toString("base64url"), "sig"].join(".");
  await writeJsonFile(paths.ownerSession, { idToken });
  await initVault({ stateDir, privateKeyPem: pair.privateKeyPem, agentId: "main" });
  return { stateDir, pair, label, jkt };
}

// Opens a previously-made device: vault + sync identity. `label` defaults to
// the device's own label (test-sync-protocol.mjs's openDevice(device) shape);
// pass it explicitly to override (test-sync-e2e.mjs's open(device) shape).
export async function openDevice(device, label = device.label) {
  const vault = await openVault({ stateDir: device.stateDir, privateKeyPem: device.pair.privateKeyPem });
  const identity = await loadSyncIdentity(device.stateDir, { label });
  return { vault, identity };
}
