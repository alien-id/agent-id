// Alien Agent ID — Signature engine and audit-trail verifier.
//
// The SignatureEngine is the universal signer: every operation that
// produces a v3 attestation (git commits, future signed tool calls,
// arbitrary audit-trail entries) goes through appendOperation, which
// builds the canonical envelope, signs it with the agent's Ed25519 key,
// and writes a hash-chained audit-log entry.
//
// verifyState walks an existing audit log end-to-end and reports any
// chain-integrity or signature failures. Bundle-level verification of a
// single attestation lives in ./bundle.mjs.

import fs from "node:fs/promises";
import path from "node:path";

import {
  canonicalJSONString,
  fingerprintPublicKeyPem,
  generateEd25519PemPair,
  newOperationId,
  nowMs,
  sha256Hex,
  sha256HexCanonical,
  signEd25519Base64Url,
  verifyEd25519Base64Url,
} from "./crypto.mjs";

import {
  appendJsonl,
  ensureDir,
  readJsonFile,
  readJsonl,
  setPrivateFilePermissions,
  statePaths,
  writeJsonFile,
} from "./state.mjs";

import {
  parseJwt,
  refreshSession,
  verifyIdToken,
} from "./oidc.mjs";

import { SubjectMismatchError, errorMessage } from "./errors.mjs";

// ─── Private helpers ────────────────────────────────────────────────────────────

function summarizePayload(payload, max = 220) {
  const raw = typeof payload === "string" ? payload : canonicalJSONString(payload);
  if (raw.length <= max) {
    return raw;
  }
  return `${raw.slice(0, max)}...`;
}

function safeName(input) {
  return (input || "unknown").replace(/[^a-zA-Z0-9._-]/g, "_");
}

function agentKeyFile(baseDir, agentId) {
  if (agentId === "main") {
    return path.join(baseDir, "keys", "main.json");
  }
  return path.join(baseDir, "keys", "subagents", `${safeName(agentId)}.json`);
}

function delegationFile(baseDir, childAgentId) {
  return path.join(baseDir, "delegations", `${safeName(childAgentId)}.json`);
}

export function resolveAgentId(ctx = {}) {
  if (ctx.agentId && typeof ctx.agentId === "string") {
    return ctx.agentId;
  }
  return "main";
}

// ─── SignatureEngine ────────────────────────────────────────────────────────────

export class SignatureEngine {
  constructor(params) {
    this.baseDir = params.baseDir;
    this.ownerProfileUrl = params.ownerProfileUrl || null;
    this.paths = statePaths(this.baseDir);
    this.keys = new Map();
    this.delegations = new Map();
    this.nonces = null;
    this.sequence = null;
    this.idTokenJti = null;
    this.idTokenSub = null;
    this.writeQueue = Promise.resolve();
  }

  async init() {
    await ensureDir(this.baseDir);
    await ensureDir(path.dirname(this.paths.auditJsonl));

    this.nonces = (await readJsonFile(this.paths.nonces, { byAgent: {} })) || { byAgent: {} };
    this.sequence =
      (await readJsonFile(this.paths.seq, {
        nextSeq: 1,
        lastHash: null,
      })) || { nextSeq: 1, lastHash: null };

    // Parse the cached id_token (if any) for the audit-log anchor. The jti
    // (RFC 7519 §4.1.7) replaces the legacy ownerBindingId; sub is captured
    // for envelope fields that previously read it off the binding.
    const session = await readJsonFile(this.paths.ownerSession, null);
    if (session?.idToken) {
      try {
        const payload = parseJwt(session.idToken).payload;
        if (typeof payload?.jti === "string" && payload.jti) {
          this.idTokenJti = payload.jti;
        }
        if (typeof payload?.sub === "string" && payload.sub) {
          this.idTokenSub = payload.sub;
        }
      } catch (err) {
        if (typeof process !== "undefined" && process.stderr) {
          process.stderr.write(`Warning: could not parse cached id_token: ${errorMessage(err)}\n`);
        }
      }
    }

    await this.ensureMainKey();
  }

  isOwnerBound() {
    return Boolean(this.idTokenJti);
  }

  async ensureMainKey() {
    return await this.ensureAgentKey("main");
  }

  async ensureAgentKey(agentId) {
    const normalized = agentId || "main";
    if (this.keys.has(normalized)) {
      return this.keys.get(normalized);
    }

    const keyPath = agentKeyFile(this.baseDir, normalized);
    let key = await readJsonFile(keyPath, null);

    if (!key) {
      const pair = generateEd25519PemPair();
      key = {
        version: 1,
        agentId: normalized,
        keyNonce: 0,
        createdAt: nowMs(),
        publicKeyPem: pair.publicKeyPem,
        privateKeyPem: pair.privateKeyPem,
        fingerprint: fingerprintPublicKeyPem(pair.publicKeyPem),
      };
      await writeJsonFile(keyPath, key);
      await setPrivateFilePermissions(keyPath);
    }

    this.keys.set(normalized, key);

    if (normalized !== "main") {
      await this.ensureDelegation(normalized);
    }

    return key;
  }

  async ensureDelegation(childAgentId) {
    if (childAgentId === "main") {
      return null;
    }
    if (this.delegations.has(childAgentId)) {
      return this.delegations.get(childAgentId);
    }

    const filePath = delegationFile(this.baseDir, childAgentId);
    let cert = await readJsonFile(filePath, null);
    if (!cert) {
      const main = await this.ensureMainKey();
      const child = await this.ensureAgentKey(childAgentId);
      const payload = {
        version: 1,
        parentAgentId: "main",
        childAgentId,
        childPublicKeyPem: child.publicKeyPem,
        issuedAt: nowMs(),
      };
      const payloadCanonical = canonicalJSONString(payload);
      cert = {
        version: 1,
        payload,
        payloadHash: sha256Hex(payloadCanonical),
        signature: signEd25519Base64Url(payloadCanonical, main.privateKeyPem),
      };
      await writeJsonFile(filePath, cert);
      await setPrivateFilePermissions(filePath);
    }

    this.delegations.set(childAgentId, cert);
    return cert;
  }

  async bindOwnerSession(params) {
    await this.ensureMainKey();

    // v3 model: the SSO-signed id_token IS the binding (no agent-self-signed
    // ownerBinding envelope). Persist only the session; future operations
    // read the id_token directly and parse claims (sub, jti, cnf.jkt) at use.
    const ownerSessionRecord = {
      version: 1,
      issuer: params.issuer,
      ssoBaseUrl: params.ssoBaseUrl || params.issuer,
      providerAddress: params.providerAddress,
      ownerSessionSub: params.ownerSessionSub,
      idToken: params.idToken,
      accessToken: params.accessToken,
      refreshToken: params.refreshToken,
      savedAt: nowMs(),
    };
    await writeJsonFile(this.paths.ownerSession, ownerSessionRecord);
    await setPrivateFilePermissions(this.paths.ownerSession);

    // Refresh cached anchors so subsequent appendOperation calls work.
    try {
      const payload = parseJwt(params.idToken).payload;
      this.idTokenJti = typeof payload?.jti === "string" ? payload.jti : null;
      this.idTokenSub = typeof payload?.sub === "string" ? payload.sub : null;
    } catch {
      this.idTokenJti = null;
      this.idTokenSub = null;
    }

    return {
      ownerSessionSub: params.ownerSessionSub,
      issuer: params.issuer,
      providerAddress: params.providerAddress,
      idTokenJti: this.idTokenJti,
    };
  }

  async ensureValidSession(opts = {}) {
    const session = await readJsonFile(this.paths.ownerSession, null);
    if (!session?.accessToken) return null;

    const bufferSec = opts.bufferSec ?? 60;

    // Decode the access_token JWT to check expiry (no signature verification —
    // we just need to know if it's still fresh).
    let expired = false;
    try {
      const payload = parseJwt(session.accessToken).payload;
      const nowSec = Math.floor(Date.now() / 1000);
      expired = typeof payload.exp === "number" && payload.exp - bufferSec <= nowSec;
    } catch {
      // If the access_token isn't a JWT (opaque token), treat it as expired
      // so we attempt a refresh.
      expired = true;
    }

    if (!expired) return session;

    // No refresh_token — can't renew.
    if (!session.refreshToken) return null;

    // Resolve SSO base URL: explicit field, fall back to issuer.
    const ssoBaseUrl = session.ssoBaseUrl || session.issuer;
    if (!ssoBaseUrl) return null;

    // Forward the agent's main keypair so the refresh request carries a DPoP
    // proof bound to the same key the SSO advertises in `cnf.jkt`.
    const main = await this.ensureMainKey();

    const fresh = await refreshSession({
      ssoBaseUrl,
      refreshToken: session.refreshToken,
      providerAddress: session.providerAddress,
      agentPrivateKeyPem: main.privateKeyPem,
    });

    // Verify the refreshed token still belongs to the same owner.
    if (session.ownerSessionSub) {
      try {
        const freshPayload = parseJwt(fresh.access_token).payload;
        if (freshPayload.sub && freshPayload.sub !== session.ownerSessionSub) {
          throw new SubjectMismatchError(
            `Refreshed token subject mismatch: expected ${session.ownerSessionSub}, got ${freshPayload.sub}`,
          );
        }
      } catch (err) {
        if (err instanceof SubjectMismatchError) throw err;
        // Non-JWT or unparseable — skip subject check (opaque tokens have no sub).
      }
    }

    // RFC 9449 §6.1 + RFC 6749 §6: when the AS rotates the id_token, re-run
    // the full claim+signature+cnf.jkt check before persistence. A
    // compromised or buggy AS that rotates `sub` or `cnf.jkt` is caught
    // here rather than at the next chain verification.
    if (fresh.id_token) {
      const verified = await verifyIdToken({
        ssoBaseUrl,
        providerAddress: session.providerAddress,
        idToken: fresh.id_token,
        agentPublicKeyPem: main.publicKeyPem,
      });
      if (session.ownerSessionSub && verified.payload.sub !== session.ownerSessionSub) {
        throw new SubjectMismatchError(
          `Refreshed id_token sub mismatch: expected ${session.ownerSessionSub}, got ${verified.payload.sub}`,
        );
      }
    }

    session.accessToken = fresh.access_token;
    if (fresh.refresh_token) session.refreshToken = fresh.refresh_token;
    if (fresh.id_token) session.idToken = fresh.id_token;
    session.refreshedAt = nowMs();

    await writeJsonFile(this.paths.ownerSession, session);
    await setPrivateFilePermissions(this.paths.ownerSession);

    return session;
  }

  async nextNonce(agentId) {
    const key = agentId || "main";
    const current = Number(this.nonces.byAgent[key] || 0);
    const next = current + 1;
    this.nonces.byAgent[key] = next;
    await writeJsonFile(this.paths.nonces, this.nonces);
    return next;
  }

  async nextSequence() {
    const seq = Number(this.sequence.nextSeq || 1);
    this.sequence.nextSeq = seq + 1;
    await writeJsonFile(this.paths.seq, this.sequence);
    return seq;
  }

  async appendOperation(params) {
    this.writeQueue = this.writeQueue.then(async () => {
      if (!this.idTokenJti) {
        throw new Error("Owner session missing or id_token has no jti. Run `auth` and `bind` first.");
      }

      const agentId = resolveAgentId(params.ctx);
      const key = await this.ensureAgentKey(agentId);
      const delegation = agentId === "main" ? null : await this.ensureDelegation(agentId);

      const nonce = await this.nextNonce(agentId);
      const seq = await this.nextSequence();
      const payloadSummary = summarizePayload(params.payload);
      const payloadHash = sha256HexCanonical(params.payload);

      const unsignedEnvelope = {
        version: 1,
        operationId: newOperationId(),
        seq,
        hook: params.hook || null,
        operationType: params.operationType,
        action: params.action,
        timestamp: nowMs(),
        agentId,
        keyNonce: Number(key.keyNonce || 0),
        nonce,
        sessionKey: params.ctx?.sessionKey || null,
        idTokenJti: this.idTokenJti,
        ownerSessionSub: this.idTokenSub,
        agentPublicKeyPem: key.publicKeyPem,
        parentAgentId: delegation ? delegation.payload.parentAgentId : null,
        delegationPayloadHash: delegation ? delegation.payloadHash : null,
        delegationSignature: delegation ? delegation.signature : null,
        payloadHash,
        payloadSummary,
        meta: params.meta || null,
      };

      const canonicalUnsigned = canonicalJSONString(unsignedEnvelope);
      const envelope = {
        ...unsignedEnvelope,
        signature: signEd25519Base64Url(canonicalUnsigned, key.privateKeyPem),
      };

      const envelopeHash = sha256HexCanonical(canonicalJSONString(envelope));
      const auditEntry = {
        version: 1,
        prevHash: this.sequence.lastHash || null,
        envelopeHash,
        envelope,
        persistedAt: nowMs(),
      };

      this.sequence.lastHash = envelopeHash;
      await writeJsonFile(this.paths.seq, this.sequence);
      await appendJsonl(this.paths.auditJsonl, auditEntry);

      return {
        auditEntry,
        signatureShort: envelope.signature.slice(0, 18),
        envelopeHashShort: envelopeHash.slice(0, 16),
        agentId,
        nonce,
        seq,
      };
    });

    return await this.writeQueue;
  }
}

// ─── verifyState: audit-trail integrity check ───────────────────────────────────

async function readAllKeyRecords(paths) {
  const map = new Map();

  const main = await readJsonFile(paths.mainKey, null);
  if (main?.agentId && main?.publicKeyPem) {
    map.set(main.agentId, main);
  }

  try {
    const files = await fs.readdir(paths.subagentKeysDir);
    for (const file of files) {
      if (!file.endsWith(".json")) {
        continue;
      }
      const rec = await readJsonFile(path.join(paths.subagentKeysDir, file), null);
      if (rec?.agentId && rec?.publicKeyPem) {
        map.set(rec.agentId, rec);
      }
    }
  } catch {
    // No subagent dir yet.
  }

  return map;
}

async function readAllDelegations(paths) {
  const map = new Map();
  try {
    const files = await fs.readdir(paths.delegationsDir);
    for (const file of files) {
      if (!file.endsWith(".json")) {
        continue;
      }
      const rec = await readJsonFile(path.join(paths.delegationsDir, file), null);
      if (rec?.payload?.childAgentId) {
        map.set(rec.payload.childAgentId, rec);
      }
    }
  } catch {
    // No delegations yet.
  }
  return map;
}

function verifyDelegation(childAgentId, delegation, keyByAgent, errors) {
  if (!delegation) {
    errors.push(`missing delegation certificate for subagent ${childAgentId}`);
    return;
  }

  const main = keyByAgent.get("main");
  if (!main?.publicKeyPem) {
    errors.push("main key missing while verifying delegation");
    return;
  }

  const payloadCanonical = canonicalJSONString(delegation.payload);
  const payloadHash = sha256HexCanonical(payloadCanonical);
  if (payloadHash !== delegation.payloadHash) {
    errors.push(`delegation payload hash mismatch for ${childAgentId}`);
  }

  const sigOk = verifyEd25519Base64Url(payloadCanonical, delegation.signature, main.publicKeyPem);
  if (!sigOk) {
    errors.push(`delegation signature invalid for ${childAgentId}`);
  }
}

function verifyAuditRecord(record, prevHash, keyByAgent, delegationsByChild, idTokenJti, errors) {
  if ((record.prevHash || null) !== (prevHash || null)) {
    errors.push(`prevHash mismatch at seq=${record?.envelope?.seq ?? "?"}`);
  }

  if (!record?.envelope) {
    errors.push("audit record missing envelope");
    return prevHash;
  }

  const envelopeCanonical = canonicalJSONString(record.envelope);
  const expectedEnvelopeHash = sha256HexCanonical(envelopeCanonical);
  if (expectedEnvelopeHash !== record.envelopeHash) {
    errors.push(`envelopeHash mismatch at seq=${record.envelope.seq}`);
  }

  const { signature, ...unsignedEnvelope } = record.envelope;
  const unsignedCanonical = canonicalJSONString(unsignedEnvelope);

  const keyRecord = keyByAgent.get(record.envelope.agentId);
  if (!keyRecord?.publicKeyPem) {
    errors.push(`unknown agent key for ${record.envelope.agentId}`);
  } else {
    const ok = verifyEd25519Base64Url(unsignedCanonical, signature, keyRecord.publicKeyPem);
    if (!ok) {
      errors.push(`operation signature invalid at seq=${record.envelope.seq}`);
    }
  }

  // idTokenJti is the v3 audit-log anchor (RFC 7519 §4.1.7) — the audit chain
  // is consistent with whichever id_token was current at append time. Older
  // entries with a different jti just mean the session refreshed; that's not
  // a tamper signal, so only assert equality when both sides have a value.
  if (idTokenJti && record.envelope.idTokenJti && record.envelope.idTokenJti !== idTokenJti) {
    // Entries from a previous session — accept; verifyState only enforces
    // the chain-integrity (prevHash + envelopeHash + signature) invariants.
  }

  if (record.envelope.agentId !== "main") {
    const child = record.envelope.agentId;
    const cert = delegationsByChild.get(child);
    verifyDelegation(child, cert, keyByAgent, errors);

    if (cert && record.envelope.delegationPayloadHash !== cert.payloadHash) {
      errors.push(`delegationPayloadHash mismatch at seq=${record.envelope.seq}`);
    }
    if (cert && record.envelope.delegationSignature !== cert.signature) {
      errors.push(`delegationSignature mismatch at seq=${record.envelope.seq}`);
    }
  }

  return expectedEnvelopeHash;
}

export async function verifyState(baseDir) {
  const paths = statePaths(baseDir);
  const errors = [];

  const session = await readJsonFile(paths.ownerSession, null);
  const keyByAgent = await readAllKeyRecords(paths);
  const delegationsByChild = await readAllDelegations(paths);
  const auditRecords = await readJsonl(paths.auditJsonl);

  let currentJti = null;
  let ownerSub = null;
  if (session?.idToken) {
    try {
      const payload = parseJwt(session.idToken).payload;
      currentJti = typeof payload?.jti === "string" ? payload.jti : null;
      ownerSub = typeof payload?.sub === "string" ? payload.sub : null;
    } catch {
      errors.push("owner-session.json id_token is unparseable");
    }
  } else {
    errors.push("owner-session.json is missing");
  }

  let prevHash = null;
  for (const record of auditRecords) {
    prevHash = verifyAuditRecord(
      record,
      prevHash,
      keyByAgent,
      delegationsByChild,
      currentJti,
      errors,
    );
  }

  return {
    ok: errors.length === 0,
    errorCount: errors.length,
    errors,
    ownerSessionSub: ownerSub,
    operations: auditRecords.length,
    agents: Array.from(keyByAgent.keys()).sort(),
    subagentDelegations: Array.from(delegationsByChild.keys()).sort(),
  };
}
