#!/usr/bin/env node

// Unit tests for the zero-dependency Solana primitives:
//   - base58 round-trips + known vectors
//   - compact-u16 (shortvec) edge cases
//   - in-vault keypair generation (pubkey derivation from seed)
//   - transaction signing: legacy + v0 messages, partial multi-sig,
//     signature normalization, wrong-signer rejection
//   - JSON-RPC body transform (sendTransaction signed, other methods untouched)
//
// Run: node --test tests/test-solana-lib.mjs

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  base58Decode,
  base58Encode,
  buildSolanaTransferTx,
  decodeCompactU16,
  encodeCompactU16,
  generateSolanaKeypair,
  signSolanaRpcBody,
  signSolanaTransactionWire,
  solanaPublicKeyBytesFromSeed,
} from "../plugins/agent-id-core/lib/solana.mjs";

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function verifySignature(messageBytes, signatureBytes, rawPubkey32) {
  const pub = crypto.createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, rawPubkey32]),
    format: "der",
    type: "spki",
  });
  return crypto.verify(null, messageBytes, pub, signatureBytes);
}

// Extract the message bytes (after the signature section) from a wire tx.
function messageOf(wire) {
  const [numSigs, n] = decodeCompactU16(wire, 0);
  return wire.subarray(n + numSigs * 64);
}

describe("base58", () => {
  it("round-trips random buffers", () => {
    for (const len of [0, 1, 31, 32, 33, 64]) {
      const buf = crypto.randomBytes(len);
      assert.deepEqual(base58Decode(base58Encode(buf)), buf);
    }
  });

  it("preserves leading zeros", () => {
    const buf = Buffer.concat([Buffer.alloc(3), crypto.randomBytes(5)]);
    const enc = base58Encode(buf);
    assert.ok(enc.startsWith("111"));
    assert.deepEqual(base58Decode(enc), buf);
  });

  it("known vector: system program id", () => {
    assert.equal(base58Encode(Buffer.alloc(32)), "1".repeat(32));
    assert.deepEqual(base58Decode("11111111111111111111111111111111"), Buffer.alloc(32));
  });

  it("known vector: 'hello world'", () => {
    assert.equal(base58Encode(Buffer.from("hello world")), "StV1DL6CwTryKyV");
    assert.equal(base58Decode("StV1DL6CwTryKyV").toString(), "hello world");
  });

  it("rejects invalid characters", () => {
    assert.throws(() => base58Decode("0OIl"), /invalid character/);
  });
});

describe("compact-u16", () => {
  it("round-trips boundary values", () => {
    for (const v of [0, 1, 127, 128, 16383, 16384, 65535]) {
      const enc = encodeCompactU16(v);
      const [dec, size] = decodeCompactU16(enc, 0);
      assert.equal(dec, v);
      assert.equal(size, enc.length);
    }
  });

  it("rejects out-of-range", () => {
    assert.throws(() => encodeCompactU16(65536), RangeError);
    assert.throws(() => encodeCompactU16(-1), RangeError);
  });

  it("rejects truncated input", () => {
    assert.throws(() => decodeCompactU16(Buffer.from([0x80]), 0), /underrun/);
  });
});

describe("keypair generation", () => {
  it("produces a 32-byte base58 pubkey derivable from the seed", () => {
    const { publicKey, secretSeedHex } = generateSolanaKeypair();
    assert.match(secretSeedHex, /^[0-9a-f]{64}$/);
    const raw = base58Decode(publicKey);
    assert.equal(raw.length, 32);
    assert.deepEqual(solanaPublicKeyBytesFromSeed(Buffer.from(secretSeedHex, "hex")), raw);
  });

  it("generates distinct keys", () => {
    assert.notEqual(generateSolanaKeypair().publicKey, generateSolanaKeypair().publicKey);
  });
});

describe("transaction signing (legacy message)", () => {
  const { publicKey, secretSeedHex } = generateSolanaKeypair();
  const seed = Buffer.from(secretSeedHex, "hex");
  const other = generateSolanaKeypair();
  const blockhash = base58Encode(crypto.randomBytes(32));

  it("signs an unsigned transfer and the signature verifies", () => {
    const unsigned = buildSolanaTransferTx({
      from: publicKey,
      to: other.publicKey,
      lamports: 1_000_000,
      recentBlockhash: blockhash,
    });
    const { wire, signature } = signSolanaTransactionWire(unsigned, seed);

    const [numSigs, n] = decodeCompactU16(wire, 0);
    assert.equal(numSigs, 1);
    const sig = wire.subarray(n, n + 64);
    assert.equal(base58Encode(sig), signature);
    assert.ok(verifySignature(messageOf(wire), sig, base58Decode(publicKey)));
    // Message bytes are unchanged by signing.
    assert.deepEqual(messageOf(wire), messageOf(unsigned));
  });

  it("normalizes a sig-count-0 transaction to the required slot count", () => {
    const unsigned = buildSolanaTransferTx({
      from: publicKey,
      to: other.publicKey,
      lamports: 5,
      recentBlockhash: blockhash,
    });
    // Rebuild with an empty signature section (compact-u16 0, no slots).
    const msg = messageOf(unsigned);
    const noSigs = Buffer.concat([encodeCompactU16(0), msg]);
    const { wire } = signSolanaTransactionWire(noSigs, seed);
    const [numSigs] = decodeCompactU16(wire, 0);
    assert.equal(numSigs, 1);
    assert.ok(verifySignature(messageOf(wire), wire.subarray(1, 65), base58Decode(publicKey)));
  });

  it("rejects a transaction the credential cannot sign", () => {
    const unsigned = buildSolanaTransferTx({
      from: other.publicKey, // signer is NOT our key
      to: publicKey,
      lamports: 5,
      recentBlockhash: blockhash,
    });
    assert.throws(() => signSolanaTransactionWire(unsigned, seed), /not among the required signers/);
  });

  it("preserves co-signatures in a 2-of-2 (partial signing)", () => {
    // Hand-build a message with 2 required signers: [other, us].
    const data = Buffer.from([0, 0, 0, 0]);
    const message = Buffer.concat([
      Buffer.from([2, 0, 1]), // 2 required sigs, 0 ro-signed, 1 ro-unsigned
      encodeCompactU16(3),
      base58Decode(other.publicKey),
      base58Decode(publicKey),
      Buffer.alloc(32), // "program"
      crypto.randomBytes(32), // blockhash
      encodeCompactU16(1),
      Buffer.from([2]),
      encodeCompactU16(2),
      Buffer.from([0, 1]),
      encodeCompactU16(data.length),
      data,
    ]);
    const coSig = crypto.randomBytes(64); // pretend the other party already signed
    const tx = Buffer.concat([encodeCompactU16(2), coSig, Buffer.alloc(64), message]);

    const { wire } = signSolanaTransactionWire(tx, seed);
    const [numSigs, n] = decodeCompactU16(wire, 0);
    assert.equal(numSigs, 2);
    assert.deepEqual(wire.subarray(n, n + 64), coSig, "co-signature preserved");
    assert.ok(
      verifySignature(messageOf(wire), wire.subarray(n + 64, n + 128), base58Decode(publicKey)),
      "our slot signed",
    );
  });

  it("signs a v0 (versioned) message", () => {
    const legacy = buildSolanaTransferTx({
      from: publicKey,
      to: other.publicKey,
      lamports: 7,
      recentBlockhash: blockhash,
    });
    const legacyMsg = messageOf(legacy);
    // v0 = 0x80 prefix + same static layout + empty address-table lookups.
    const v0msg = Buffer.concat([Buffer.from([0x80]), legacyMsg, encodeCompactU16(0)]);
    const tx = Buffer.concat([encodeCompactU16(1), Buffer.alloc(64), v0msg]);
    const { wire } = signSolanaTransactionWire(tx, seed);
    assert.ok(verifySignature(messageOf(wire), wire.subarray(1, 65), base58Decode(publicKey)));
  });

  it("rejects unsupported message versions", () => {
    const legacy = buildSolanaTransferTx({
      from: publicKey,
      to: other.publicKey,
      lamports: 7,
      recentBlockhash: blockhash,
    });
    const v1msg = Buffer.concat([Buffer.from([0x81]), messageOf(legacy)]);
    const tx = Buffer.concat([encodeCompactU16(1), Buffer.alloc(64), v1msg]);
    assert.throws(() => signSolanaTransactionWire(tx, seed), /unsupported message version/);
  });
});

describe("JSON-RPC body transform", () => {
  const { publicKey, secretSeedHex } = generateSolanaKeypair();
  const to = generateSolanaKeypair().publicKey;
  const blockhash = base58Encode(crypto.randomBytes(32));
  const unsigned = buildSolanaTransferTx({
    from: publicKey,
    to,
    lamports: 42,
    recentBlockhash: blockhash,
  });

  it("signs sendTransaction (base64 encoding)", () => {
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "sendTransaction",
      params: [unsigned.toString("base64"), { encoding: "base64", skipPreflight: false }],
    });
    const { body: out, signed, signatures } = signSolanaRpcBody(body, secretSeedHex);
    assert.ok(signed);
    assert.equal(signatures.length, 1);
    const parsed = JSON.parse(out);
    const wire = Buffer.from(parsed.params[0], "base64");
    assert.equal(base58Encode(wire.subarray(1, 65)), signatures[0]);
    assert.deepEqual(parsed.params[1], { encoding: "base64", skipPreflight: false });
  });

  it("signs sendTransaction (default base58 encoding)", () => {
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id: 7,
      method: "sendTransaction",
      params: [base58Encode(unsigned)],
    });
    const { body: out, signed } = signSolanaRpcBody(body, secretSeedHex);
    assert.ok(signed);
    const wire = base58Decode(JSON.parse(out).params[0]);
    assert.notDeepEqual(wire.subarray(1, 65), Buffer.alloc(64), "signature slot filled");
  });

  it("passes other methods through byte-identical", () => {
    const body = JSON.stringify({ jsonrpc: "2.0", id: 2, method: "getLatestBlockhash", params: [] });
    const r = signSolanaRpcBody(body, secretSeedHex);
    assert.equal(r.signed, false);
    assert.deepEqual(JSON.parse(r.body), JSON.parse(body));
  });

  it("passes non-JSON bodies through untouched", () => {
    const r = signSolanaRpcBody("not json at all", secretSeedHex);
    assert.equal(r.signed, false);
    assert.equal(r.body, "not json at all");
  });

  it("handles batched requests, signing only sendTransaction entries", () => {
    const body = JSON.stringify([
      { jsonrpc: "2.0", id: 1, method: "getBalance", params: [publicKey] },
      {
        jsonrpc: "2.0",
        id: 2,
        method: "sendTransaction",
        params: [unsigned.toString("base64"), { encoding: "base64" }],
      },
    ]);
    const { body: out, signatures } = signSolanaRpcBody(body, secretSeedHex);
    assert.equal(signatures.length, 1);
    const parsed = JSON.parse(out);
    assert.equal(parsed[0].params[0], publicKey, "getBalance untouched");
    assert.notEqual(parsed[1].params[0], unsigned.toString("base64"), "sendTransaction signed");
  });

  it("surfaces malformed transactions as errors", () => {
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id: 3,
      method: "sendTransaction",
      params: [Buffer.from("garbage").toString("base64"), { encoding: "base64" }],
    });
    assert.throws(() => signSolanaRpcBody(body, secretSeedHex));
  });
});
