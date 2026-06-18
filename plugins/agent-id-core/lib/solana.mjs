// Alien Agent ID — Solana primitives (zero-dependency).
//
// Used by:
//   - agent-id-vault: `generate` creates an ed25519 keypair INSIDE the vault
//     process; only the base58 public key (the wallet address) ever leaves.
//   - agent-id-proxy: signs Solana transactions at injection time. The agent
//     POSTs a normal JSON-RPC `sendTransaction` with an UNSIGNED transaction
//     through the proxy; the proxy fills in the signature(s) for the vaulted
//     key and forwards. The agent never sees the private key — only the
//     resulting signature, which is public information once on chain.
//
// Wire-format notes (https://solana.com/docs/core/transactions):
//   tx      = compact-u16 sig-count || sig-count * 64-byte sigs || message
//   message = [0x80|version byte (v0 only)] || header(3 bytes) ||
//             compact-u16 key-count || key-count * 32-byte keys ||
//             recent-blockhash(32) || instructions…
//   The first `numRequiredSignatures` account keys are the signers; signature
//   slot i belongs to account key i. Signatures sign the message bytes.

import crypto from "node:crypto";

// ─── base58 (Bitcoin alphabet) ─────────────────────────────────────────────────

const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const B58_MAP = new Map([...B58_ALPHABET].map((c, i) => [c, BigInt(i)]));

export function base58Encode(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError("base58Encode: bytes required");
  if (bytes.length === 0) return "";
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  let n = BigInt("0x" + ("0" + Buffer.from(bytes).toString("hex")));
  let out = "";
  while (n > 0n) {
    out = B58_ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  return "1".repeat(zeros) + out;
}

export function base58Decode(str) {
  if (typeof str !== "string") throw new TypeError("base58Decode: string required");
  let zeros = 0;
  while (zeros < str.length && str[zeros] === "1") zeros++;
  let n = 0n;
  for (const c of str) {
    const v = B58_MAP.get(c);
    if (v === undefined) throw new Error(`base58: invalid character '${c}'`);
    n = n * 58n + v;
  }
  let hex = n.toString(16);
  if (hex === "0") hex = "";
  if (hex.length % 2) hex = "0" + hex;
  return Buffer.concat([Buffer.alloc(zeros), Buffer.from(hex, "hex")]);
}

// ─── compact-u16 ("shortvec") ──────────────────────────────────────────────────

export function encodeCompactU16(n) {
  if (!Number.isInteger(n) || n < 0 || n > 0xffff) {
    throw new RangeError(`compact-u16 out of range: ${n}`);
  }
  const out = [];
  let rem = n;
  for (;;) {
    const elem = rem & 0x7f;
    rem >>= 7;
    if (rem === 0) {
      out.push(elem);
      break;
    }
    out.push(elem | 0x80);
  }
  return Buffer.from(out);
}

export function decodeCompactU16(bytes, offset = 0) {
  let value = 0;
  let size = 0;
  for (;;) {
    if (offset + size >= bytes.length) throw new Error("compact-u16: buffer underrun");
    const elem = bytes[offset + size];
    value |= (elem & 0x7f) << (size * 7);
    size += 1;
    if ((elem & 0x80) === 0) break;
    if (size > 3) throw new Error("compact-u16: encoding too long");
  }
  if (value > 0xffff) throw new Error("compact-u16: value out of range");
  return [value, size];
}

// ─── ed25519 keys from a raw 32-byte seed ──────────────────────────────────────

// PKCS#8 DER prefix for a raw ed25519 private key (RFC 8410).
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function ed25519PrivateKeyFromSeed(seed) {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) {
    throw new Error("ed25519 seed must be 32 bytes");
  }
  return crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
}

export function solanaPublicKeyBytesFromSeed(seed) {
  const pub = crypto.createPublicKey(ed25519PrivateKeyFromSeed(seed));
  const spki = pub.export({ format: "der", type: "spki" });
  return Buffer.from(spki.subarray(spki.length - 32)); // raw key = last 32 bytes of SPKI
}

/**
 * Generate a Solana keypair. Returns the base58 address (public) and the
 * 32-byte seed as hex (SECRET — store only inside the vault payload).
 */
export function generateSolanaKeypair() {
  const seed = crypto.randomBytes(32);
  const publicKey = base58Encode(solanaPublicKeyBytesFromSeed(seed));
  return { publicKey, secretSeedHex: seed.toString("hex") };
}

// ─── Transaction signing ───────────────────────────────────────────────────────

/**
 * Sign a serialized Solana transaction (legacy or v0) with the given seed.
 * Fills every signature slot whose account key matches the seed's public key.
 * Other signature slots are preserved (partial signing is allowed — e.g. a
 * fee-payer co-signature added later by an x402 facilitator).
 *
 * The incoming transaction may declare fewer signatures than the message
 * requires (e.g. an entirely unsigned tx with sig-count 0); the signature
 * section is normalized to `numRequiredSignatures` slots.
 *
 * Returns { wire, signature, publicKey }.
 */
export function signSolanaTransactionWire(wire, seed) {
  if (!(wire instanceof Uint8Array) || wire.length === 0) {
    throw new Error("solana tx: empty buffer");
  }
  wire = Buffer.from(wire);
  const [numSigs, sigCountLen] = decodeCompactU16(wire, 0);
  const msgStart = sigCountLen + numSigs * 64;
  if (msgStart >= wire.length) throw new Error("solana tx: truncated signature section");
  const message = wire.subarray(msgStart);

  // Message header. A v0 message is prefixed with 0x80|version.
  let idx = 0;
  if (message[0] & 0x80) {
    const version = message[0] & 0x7f;
    if (version !== 0) throw new Error(`solana tx: unsupported message version ${version}`);
    idx = 1;
  }
  if (message.length < idx + 4) throw new Error("solana tx: truncated message header");
  const numRequired = message[idx];
  if (numRequired === 0) throw new Error("solana tx: message requires no signatures");
  const [numKeys, keyCountLen] = decodeCompactU16(message, idx + 3);
  const keysOff = idx + 3 + keyCountLen;
  if (numKeys < numRequired) throw new Error("solana tx: fewer account keys than signers");
  if (keysOff + numKeys * 32 + 32 > message.length) {
    throw new Error("solana tx: truncated account keys");
  }

  const pub = solanaPublicKeyBytesFromSeed(seed);
  const signerIndices = [];
  for (let i = 0; i < numRequired; i++) {
    if (message.subarray(keysOff + i * 32, keysOff + (i + 1) * 32).equals(pub)) {
      signerIndices.push(i);
    }
  }
  if (signerIndices.length === 0) {
    throw new Error(
      `solana tx: credential key ${base58Encode(pub)} is not among the required signers`,
    );
  }

  // Normalize the signature section to numRequired slots, preserving any
  // co-signatures already present.
  const sigs = [];
  for (let i = 0; i < numRequired; i++) {
    sigs.push(
      i < numSigs
        ? Buffer.from(wire.subarray(sigCountLen + i * 64, sigCountLen + (i + 1) * 64))
        : Buffer.alloc(64),
    );
  }

  const signature = crypto.sign(null, message, ed25519PrivateKeyFromSeed(seed));
  for (const i of signerIndices) sigs[i] = signature;

  return {
    wire: Buffer.concat([encodeCompactU16(numRequired), ...sigs, Buffer.from(message)]),
    signature: base58Encode(signature),
    publicKey: base58Encode(pub),
  };
}

/**
 * Decode the base58 program id of every instruction in a (signed or unsigned)
 * transaction wire buffer. Program ids always index into the static account
 * keys, so this does not need to resolve v0 address-table lookups. Used to
 * enforce a credential's optional programAllowlist before signing.
 */
export function solanaProgramIds(wire) {
  wire = Buffer.from(wire);
  const [numSigs, sigCountLen] = decodeCompactU16(wire, 0);
  const message = wire.subarray(sigCountLen + numSigs * 64);

  let idx = 0;
  if (message[0] & 0x80) {
    if ((message[0] & 0x7f) !== 0) throw new Error("solana tx: unsupported message version");
    idx = 1;
  }
  if (message.length < idx + 4) throw new Error("solana tx: truncated message header");
  const [numKeys, keyCountLen] = decodeCompactU16(message, idx + 3);
  const keysOff = idx + 3 + keyCountLen;
  if (keysOff + numKeys * 32 + 32 > message.length) {
    throw new Error("solana tx: truncated account keys");
  }
  const keyAt = (i) => message.subarray(keysOff + i * 32, keysOff + (i + 1) * 32);

  let off = keysOff + numKeys * 32 + 32; // skip the recent blockhash
  const [numIx, ixCountLen] = decodeCompactU16(message, off);
  off += ixCountLen;
  const programIds = [];
  for (let i = 0; i < numIx; i++) {
    if (off >= message.length) throw new Error("solana tx: truncated instructions");
    const programIdIndex = message[off];
    off += 1;
    const [numAcc, accLen] = decodeCompactU16(message, off);
    off += accLen + numAcc;
    const [dataLen, dataLenLen] = decodeCompactU16(message, off);
    off += dataLenLen + dataLen;
    if (programIdIndex >= numKeys) {
      throw new Error("solana tx: instruction program id index out of range");
    }
    programIds.push(base58Encode(keyAt(programIdIndex)));
  }
  return programIds;
}

/**
 * Transform a Solana JSON-RPC request body: any `sendTransaction` call has its
 * transaction parameter signed with the vaulted seed (base58 or base64 param
 * encoding, per the request's own config). Every other method — getBalance,
 * getLatestBlockhash, simulateTransaction, … — passes through untouched.
 * Batched (array) requests are handled element-wise.
 *
 * `constraints.programAllowlist` (optional): when set, every instruction's
 * program id must be on the list or signing is refused.
 *
 * Returns { body, signed, signatures } — `body` is the JSON to forward.
 * Throws on a malformed transaction inside a sendTransaction call.
 */
export function signSolanaRpcBody(bodyText, secretSeedHex, constraints = {}) {
  let parsed;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    return { body: bodyText, signed: false, signatures: [] }; // not JSON-RPC; forward as-is
  }
  if (!/^[0-9a-fA-F]{64}$/.test(secretSeedHex || "")) {
    throw new Error("solana credential: secretSeed must be 32 bytes of hex");
  }
  const seed = Buffer.from(secretSeedHex, "hex");
  const signatures = [];
  const programAllowlist = Array.isArray(constraints.programAllowlist)
    ? constraints.programAllowlist
    : null;

  const signOne = (msg) => {
    if (!msg || typeof msg !== "object" || msg.method !== "sendTransaction") return msg;
    if (!Array.isArray(msg.params) || typeof msg.params[0] !== "string") return msg;
    const cfg = msg.params[1];
    const encoding =
      (cfg && typeof cfg === "object" && cfg.encoding) || "base58"; // RPC default
    if (encoding !== "base58" && encoding !== "base64") {
      throw new Error(`sendTransaction: unsupported encoding '${encoding}'`);
    }
    const txBytes =
      encoding === "base64"
        ? Buffer.from(msg.params[0], "base64")
        : base58Decode(msg.params[0]);
    if (programAllowlist) {
      for (const pid of solanaProgramIds(txBytes)) {
        if (!programAllowlist.includes(pid)) {
          throw new Error(`sendTransaction: program ${pid} not in this credential's programAllowlist`);
        }
      }
    }
    const { wire, signature } = signSolanaTransactionWire(txBytes, seed);
    signatures.push(signature);
    const out =
      encoding === "base64" ? wire.toString("base64") : base58Encode(wire);
    return { ...msg, params: [out, ...msg.params.slice(1)] };
  };

  const transformed = Array.isArray(parsed) ? parsed.map(signOne) : signOne(parsed);
  return {
    body: JSON.stringify(transformed),
    signed: signatures.length > 0,
    signatures,
  };
}

// ─── Agent-side helper: build an UNSIGNED System Program transfer ──────────────
// Pure public-key plumbing — no secrets involved. The agent uses this to
// construct the transaction it submits through the proxy for signing.

const SYSTEM_PROGRAM_ID = Buffer.alloc(32); // base58 "11111111111111111111111111111111"

export function buildSolanaTransferTx({ from, to, lamports, recentBlockhash }) {
  const fromKey = base58Decode(from);
  const toKey = base58Decode(to);
  const blockhash = base58Decode(recentBlockhash);
  if (fromKey.length !== 32 || toKey.length !== 32) throw new Error("bad pubkey length");
  if (blockhash.length !== 32) throw new Error("bad blockhash length");
  if (fromKey.equals(toKey)) throw new Error("transfer to self not supported here");
  if (!Number.isSafeInteger(lamports) || lamports <= 0) throw new Error("bad lamports");

  // SystemProgram::Transfer = instruction index 2 (u32 LE) + lamports (u64 LE)
  const data = Buffer.alloc(12);
  data.writeUInt32LE(2, 0);
  data.writeBigUInt64LE(BigInt(lamports), 4);

  const message = Buffer.concat([
    Buffer.from([1, 0, 1]), // 1 required signature, 0 readonly-signed, 1 readonly-unsigned
    encodeCompactU16(3),
    fromKey, // signer, writable
    toKey, // writable
    SYSTEM_PROGRAM_ID, // readonly, program
    blockhash,
    encodeCompactU16(1), // one instruction
    Buffer.from([2]), // program id index
    encodeCompactU16(2),
    Buffer.from([0, 1]), // account indices
    encodeCompactU16(data.length),
    data,
  ]);

  // Unsigned: one all-zero signature slot for the proxy to fill.
  return Buffer.concat([encodeCompactU16(1), Buffer.alloc(64), message]);
}
