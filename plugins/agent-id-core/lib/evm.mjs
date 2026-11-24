// Alien Agent ID — EVM (Ethereum / Polygon / any EIP-1559 chain) primitives.
// Zero-dependency: keccak-256, RLP, and secp256k1 ECDSA (RFC 6979
// deterministic nonces) are implemented here in pure JS/BigInt because
// OpenSSL exposes neither keccak nor public-key recovery parity.
//
// Used by:
//   - agent-id-vault: `generate --type evm-keypair` creates the key INSIDE the
//     vault; only the EIP-55 address ever leaves.
//   - agent-id-proxy: rewrites `eth_sendTransaction` (unsigned tx object from
//     the agent) into `eth_sendRawTransaction` (signed EIP-1559 raw tx) at
//     injection time. The agent never sees the private key.
//
// Volume is interactive (a few signatures per session), so clarity beats
// speed throughout.

import crypto from "node:crypto";

// ─── keccak-256 (original Keccak padding, NOT NIST SHA-3) ──────────────────────

const KECCAK_RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
// Rotation offsets r[x][y] (x = column, y = row).
const KECCAK_ROT = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];
const U64_MASK = (1n << 64n) - 1n;

function rotl64(v, bits) {
  const b = BigInt(bits);
  return ((v << b) | (v >> (64n - b))) & U64_MASK;
}

function keccakF(s) {
  for (let round = 0; round < 24; round++) {
    // θ
    const c = new Array(5);
    for (let x = 0; x < 5; x++) c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
    for (let x = 0; x < 5; x++) {
      const d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
      for (let y = 0; y < 5; y++) s[x + 5 * y] ^= d;
    }
    // ρ + π
    const b = new Array(25);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(s[x + 5 * y], KECCAK_ROT[x][y]);
      }
    }
    // χ
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        s[x + 5 * y] = b[x + 5 * y] ^ (~b[((x + 1) % 5) + 5 * y] & U64_MASK & b[((x + 2) % 5) + 5 * y]);
      }
    }
    // ι
    s[0] ^= KECCAK_RC[round];
  }
}

export function keccak256(input) {
  const data = Buffer.isBuffer(input) ? input : Buffer.from(input);
  const RATE = 136; // 1088-bit rate for 256-bit output
  const state = new Array(25).fill(0n);

  // Pad: 0x01 … 0x80 (multi-rate keccak padding).
  const padLen = RATE - (data.length % RATE);
  const padded = Buffer.concat([data, Buffer.alloc(padLen)]);
  padded[data.length] = 0x01;
  padded[padded.length - 1] |= 0x80;

  for (let off = 0; off < padded.length; off += RATE) {
    for (let i = 0; i < RATE / 8; i++) {
      state[i] ^= padded.readBigUInt64LE(off + i * 8);
    }
    keccakF(state);
  }

  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) out.writeBigUInt64LE(state[i], i * 8);
  return out;
}

// ─── RLP encoding ───────────────────────────────────────────────────────────────

function rlpEncodeLength(len, offset) {
  if (len < 56) return Buffer.from([offset + len]);
  let hex = len.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  const lenBytes = Buffer.from(hex, "hex");
  return Buffer.concat([Buffer.from([offset + 55 + lenBytes.length]), lenBytes]);
}

/** item: Buffer (string item) or Array of items (list). */
export function rlpEncode(item) {
  if (Array.isArray(item)) {
    const body = Buffer.concat(item.map(rlpEncode));
    return Buffer.concat([rlpEncodeLength(body.length, 0xc0), body]);
  }
  if (!Buffer.isBuffer(item)) throw new TypeError("rlpEncode: Buffer or Array required");
  if (item.length === 1 && item[0] < 0x80) return item;
  return Buffer.concat([rlpEncodeLength(item.length, 0x80), item]);
}

/** Minimal big-endian buffer for a non-negative bigint/number (empty for 0). */
export function rlpIntBuf(v) {
  const n = BigInt(v);
  if (n < 0n) throw new RangeError("rlpIntBuf: negative");
  if (n === 0n) return Buffer.alloc(0);
  let hex = n.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  return Buffer.from(hex, "hex");
}

// ─── secp256k1 ─────────────────────────────────────────────────────────────────

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

function mod(a, m) {
  const r = a % m;
  return r < 0n ? r + m : r;
}

function modInv(a, m) {
  // extended Euclid
  let [old_r, r] = [mod(a, m), m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== 1n) throw new Error("modInv: not invertible");
  return mod(old_s, m);
}

function modPow(base, exp, m) {
  let result = 1n;
  base = mod(base, m);
  while (exp > 0n) {
    if (exp & 1n) result = mod(result * base, m);
    base = mod(base * base, m);
    exp >>= 1n;
  }
  return result;
}

// Jacobian coordinates: [X, Y, Z]; affine (x, y) = (X/Z², Y/Z³). null = ∞.
function jDouble(p) {
  if (!p) return null;
  const [X, Y, Z] = p;
  if (Y === 0n) return null;
  const S = mod(4n * X * Y * Y, P);
  const M = mod(3n * X * X, P); // a = 0 for secp256k1
  const X2 = mod(M * M - 2n * S, P);
  const Y2 = mod(M * (S - X2) - 8n * Y * Y * Y * Y, P);
  const Z2 = mod(2n * Y * Z, P);
  return [X2, Y2, Z2];
}

function jAdd(p, q) {
  if (!p) return q;
  if (!q) return p;
  const [X1, Y1, Z1] = p;
  const [X2, Y2, Z2] = q;
  const Z1Z1 = mod(Z1 * Z1, P);
  const Z2Z2 = mod(Z2 * Z2, P);
  const U1 = mod(X1 * Z2Z2, P);
  const U2 = mod(X2 * Z1Z1, P);
  const S1 = mod(Y1 * Z2 * Z2Z2, P);
  const S2 = mod(Y2 * Z1 * Z1Z1, P);
  if (U1 === U2) {
    if (S1 !== S2) return null; // p + (−p) = ∞
    return jDouble(p);
  }
  const H = mod(U2 - U1, P);
  const R = mod(S2 - S1, P);
  const H2 = mod(H * H, P);
  const H3 = mod(H * H2, P);
  const X3 = mod(R * R - H3 - 2n * U1 * H2, P);
  const Y3 = mod(R * (U1 * H2 - X3) - S1 * H3, P);
  const Z3 = mod(H * Z1 * Z2, P);
  return [X3, Y3, Z3];
}

function jMul(point, k) {
  let result = null;
  let addend = point;
  while (k > 0n) {
    if (k & 1n) result = jAdd(result, addend);
    addend = jDouble(addend);
    k >>= 1n;
  }
  return result;
}

function toAffine(p) {
  if (!p) throw new Error("secp256k1: point at infinity");
  const [X, Y, Z] = p;
  const zInv = modInv(Z, P);
  const zInv2 = mod(zInv * zInv, P);
  return [mod(X * zInv2, P), mod(Y * zInv2 * zInv, P)];
}

const G = [Gx, Gy, 1n];

function bufToBig(buf) {
  return buf.length ? BigInt("0x" + buf.toString("hex")) : 0n;
}

function bigTo32(n) {
  return Buffer.from(n.toString(16).padStart(64, "0"), "hex");
}

/** Uncompressed public key (64 bytes, no 0x04 prefix) from a 32-byte private key. */
export function evmPublicKeyFromPrivate(privKey32) {
  const d = bufToBig(privKey32);
  if (d <= 0n || d >= N) throw new Error("secp256k1: private key out of range");
  const [x, y] = toAffine(jMul(G, d));
  return Buffer.concat([bigTo32(x), bigTo32(y)]);
}

/** EIP-55 checksummed address from a 32-byte private key. */
export function evmAddressFromPrivate(privKey32) {
  const pub = evmPublicKeyFromPrivate(privKey32);
  const addr = keccak256(pub).subarray(12).toString("hex");
  return toChecksumAddress(addr);
}

export function toChecksumAddress(addrHex) {
  const lower = addrHex.toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{40}$/.test(lower)) throw new Error("bad address");
  const hash = keccak256(Buffer.from(lower, "ascii")).toString("hex");
  let out = "0x";
  for (let i = 0; i < 40; i++) {
    out += parseInt(hash[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i];
  }
  return out;
}

/** Generate an EVM keypair. The private key is SECRET — vault payload only. */
export function generateEvmKeypair() {
  let priv;
  do {
    priv = crypto.randomBytes(32);
  } while (bufToBig(priv) === 0n || bufToBig(priv) >= N);
  return { address: evmAddressFromPrivate(priv), privateKeyHex: priv.toString("hex") };
}

// RFC 6979 deterministic nonce (SHA-256, qlen = hlen = 256 → no bit shifting).
function rfc6979Nonce(privKey32, msgHash32) {
  const x = privKey32;
  const h = bigTo32(mod(bufToBig(msgHash32), N));
  let V = Buffer.alloc(32, 0x01);
  let K = Buffer.alloc(32, 0x00);
  const hmac = (key, ...parts) =>
    crypto.createHmac("sha256", key).update(Buffer.concat(parts)).digest();
  K = hmac(K, V, Buffer.from([0x00]), x, h);
  V = hmac(K, V);
  K = hmac(K, V, Buffer.from([0x01]), x, h);
  V = hmac(K, V);
  for (;;) {
    V = hmac(K, V);
    const k = bufToBig(V);
    if (k >= 1n && k < N) return k;
    K = hmac(K, V, Buffer.from([0x00]));
    V = hmac(K, V);
  }
}

/**
 * ECDSA-sign a 32-byte hash. Returns { r, s, yParity } with low-s (EIP-2)
 * normalization. Deterministic per RFC 6979.
 */
export function ecdsaSignHash(msgHash32, privKey32) {
  const d = bufToBig(privKey32);
  const e = mod(bufToBig(msgHash32), N);
  let k = rfc6979Nonce(privKey32, msgHash32);
  for (;;) {
    const [rx, ry] = toAffine(jMul(G, k));
    const r = mod(rx, N);
    if (r === 0n || rx >= N) {
      k = mod(k + 1n, N); // astronomically unlikely; keep deterministic-ish
      continue;
    }
    let s = mod(modInv(k, N) * (e + r * d), N);
    if (s === 0n) {
      k = mod(k + 1n, N);
      continue;
    }
    let yParity = Number(ry & 1n);
    if (s > N / 2n) {
      s = N - s;
      yParity ^= 1;
    }
    return { r, s, yParity };
  }
}

// ─── EIP-1559 transaction signing ───────────────────────────────────────────────

function hexToBuf(hex, what) {
  if (hex == null || hex === "" || hex === "0x") return Buffer.alloc(0);
  const h = String(hex).replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]*$/.test(h) || h.length % 2) throw new Error(`bad hex in ${what}: ${hex}`);
  return Buffer.from(h, "hex");
}

function qty(v, what) {
  if (v == null) throw new Error(`eth_sendTransaction: '${what}' is required`);
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v) || v < 0) throw new Error(`bad quantity ${what}`);
    return BigInt(v);
  }
  const s = String(v);
  const n = s.startsWith("0x") || s.startsWith("0X") ? BigInt(s) : BigInt(s);
  if (n < 0n) throw new Error(`bad quantity ${what}`);
  return n;
}

/**
 * Sign an EIP-1559 (type 2) transaction object with a 32-byte private key.
 * Required fields: chainId, nonce, gas, maxFeePerGas, maxPriorityFeePerGas.
 * Optional: to (null → contract creation), value, data, accessList ([]).
 * The proxy does not fill defaults from the chain — the agent supplies them
 * explicitly (it can read nonce/fees through the proxy's passthrough).
 *
 * Returns { raw: "0x02…", hash: "0x…", from } — all public material.
 */
export function signEip1559Transaction(tx, privKey32) {
  const chainId = qty(tx.chainId, "chainId");
  const nonce = qty(tx.nonce, "nonce");
  const maxPriorityFeePerGas = qty(tx.maxPriorityFeePerGas, "maxPriorityFeePerGas");
  const maxFeePerGas = qty(tx.maxFeePerGas, "maxFeePerGas");
  const gas = qty(tx.gas ?? tx.gasLimit, "gas");
  const to = tx.to == null || tx.to === "" ? Buffer.alloc(0) : hexToBuf(tx.to, "to");
  if (to.length !== 0 && to.length !== 20) throw new Error("eth_sendTransaction: 'to' must be a 20-byte address");
  const value = tx.value == null ? 0n : qty(tx.value, "value");
  const data = hexToBuf(tx.data ?? tx.input, "data");
  if (tx.accessList != null && !(Array.isArray(tx.accessList) && tx.accessList.length === 0)) {
    throw new Error("eth_sendTransaction: non-empty accessList not supported");
  }

  const payload = [
    rlpIntBuf(chainId),
    rlpIntBuf(nonce),
    rlpIntBuf(maxPriorityFeePerGas),
    rlpIntBuf(maxFeePerGas),
    rlpIntBuf(gas),
    to,
    rlpIntBuf(value),
    data,
    [], // accessList
  ];

  const signingData = Buffer.concat([Buffer.from([0x02]), rlpEncode(payload)]);
  const msgHash = keccak256(signingData);
  const { r, s, yParity } = ecdsaSignHash(msgHash, privKey32);

  const signed = Buffer.concat([
    Buffer.from([0x02]),
    rlpEncode([...payload, rlpIntBuf(BigInt(yParity)), rlpIntBuf(r), rlpIntBuf(s)]),
  ]);

  return {
    raw: "0x" + signed.toString("hex"),
    hash: "0x" + keccak256(signed).toString("hex"),
    from: evmAddressFromPrivate(privKey32),
  };
}

// ─── EIP-712 typed structured data ──────────────────────────────────────────────
// What an exchange or a prediction market asks a wallet to sign in place of a
// transaction: an order, an API-key request. The digest is
//   keccak256(0x19 0x01 ‖ hashStruct(domain) ‖ hashStruct(message))
// and the signature authorizes whatever the verifying contract reads into the
// message, with no chain, gas or recipient of its own to bound it. So the
// encoder is strict where a wallet UI would be lenient: a field the type does
// not declare, a missing value, a number out of range or a type nobody defined
// is refused rather than encoded as something the signer did not mean.

const TYPED_IDENT_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
// A struct's name may be namespaced, identifiers joined by colons: Hyperliquid
// signs its user actions as `HyperliquidTransaction:ApproveAgent`, and every
// wallet hashes that name into the type string as written. A field's name is
// a plain identifier.
export const TYPED_STRUCT_RE = /^[A-Za-z_][A-Za-z0-9_]*(?::[A-Za-z_][A-Za-z0-9_]*)*$/;
const TYPED_ARRAY_RE = /^(.*)\[(\d*)\]$/;
const TYPED_DOMAIN_FIELDS = [
  ["name", "string"],
  ["version", "string"],
  ["chainId", "uint256"],
  ["verifyingContract", "address"],
  ["salt", "bytes32"],
];

function typedBaseType(type) {
  let base = type;
  for (let m = TYPED_ARRAY_RE.exec(base); m; m = TYPED_ARRAY_RE.exec(base)) base = m[1];
  return base;
}

function isTypedAtomic(type) {
  if (type === "bool" || type === "address" || type === "string" || type === "bytes") return true;
  let m = /^u?int(\d+)$/.exec(type);
  if (m) {
    const bits = Number(m[1]);
    return bits >= 8 && bits <= 256 && bits % 8 === 0;
  }
  m = /^bytes(\d+)$/.exec(type);
  if (m) {
    const len = Number(m[1]);
    return len >= 1 && len <= 32;
  }
  return false;
}

function validateTypedTypes(types) {
  if (!types || typeof types !== "object" || Array.isArray(types)) {
    throw new Error("typed data: `types` must be an object");
  }
  for (const [name, fields] of Object.entries(types)) {
    if (!TYPED_STRUCT_RE.test(name) || isTypedAtomic(name)) {
      throw new Error(`typed data: bad struct name '${name}'`);
    }
    if (!Array.isArray(fields)) throw new Error(`typed data: type '${name}' must list its fields`);
    const seen = new Set();
    for (const field of fields) {
      if (
        !field ||
        typeof field !== "object" ||
        typeof field.name !== "string" ||
        typeof field.type !== "string" ||
        !TYPED_IDENT_RE.test(field.name)
      ) {
        throw new Error(`typed data: type '${name}' has a malformed field`);
      }
      if (seen.has(field.name)) {
        throw new Error(`typed data: type '${name}' declares '${field.name}' twice`);
      }
      seen.add(field.name);
      const base = typedBaseType(field.type);
      if (!isTypedAtomic(base) && !Object.hasOwn(types, base)) {
        throw new Error(`typed data: field '${name}.${field.name}' has unknown type '${field.type}'`);
      }
    }
  }
}

function typedDependencies(type, types, found = new Set()) {
  const base = typedBaseType(type);
  if (found.has(base) || !Object.hasOwn(types, base)) return found;
  found.add(base);
  for (const field of types[base]) typedDependencies(field.type, types, found);
  return found;
}

/** The EIP-712 type string: the primary type, then what it refers to, sorted. */
export function encodeTypedType(primaryType, types) {
  if (!Object.hasOwn(types, primaryType)) {
    throw new Error(`typed data: type '${primaryType}' is not defined`);
  }
  const deps = [...typedDependencies(primaryType, types)].filter((t) => t !== primaryType).sort();
  return [primaryType, ...deps]
    .map((t) => `${t}(${types[t].map((f) => `${f.type} ${f.name}`).join(",")})`)
    .join("");
}

function typedInteger(value, what) {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error(`typed data: ${what} is not a safe integer`);
    return BigInt(value);
  }
  if (typeof value === "string" && /^(-?(0|[1-9]\d*)|0[xX][0-9a-fA-F]+)$/.test(value)) {
    return BigInt(value);
  }
  throw new Error(`typed data: ${what} is not an integer`);
}

function typedHexBytes(value, what) {
  if (typeof value !== "string" || !/^0[xX]([0-9a-fA-F]{2})*$/.test(value)) {
    throw new Error(`typed data: ${what} must be 0x-prefixed hex bytes`);
  }
  return Buffer.from(value.slice(2), "hex");
}

function encodeTypedValue(type, value, types, what) {
  if (value === undefined || value === null) {
    throw new Error(`typed data: ${what} is missing`);
  }
  const array = TYPED_ARRAY_RE.exec(type);
  if (array) {
    if (!Array.isArray(value)) throw new Error(`typed data: ${what} must be an array`);
    if (array[2] !== "" && value.length !== Number(array[2])) {
      throw new Error(`typed data: ${what} must hold ${array[2]} items`);
    }
    return keccak256(
      Buffer.concat(value.map((item, i) => encodeTypedValue(array[1], item, types, `${what}[${i}]`))),
    );
  }
  if (Object.hasOwn(types, type)) return hashTypedStruct(type, value, types, what);
  if (type === "string") {
    if (typeof value !== "string") throw new Error(`typed data: ${what} must be a string`);
    return keccak256(Buffer.from(value, "utf8"));
  }
  if (type === "bytes") return keccak256(typedHexBytes(value, what));
  if (type === "bool") {
    if (typeof value !== "boolean") throw new Error(`typed data: ${what} must be true or false`);
    return bigTo32(value ? 1n : 0n);
  }
  if (type === "address") {
    if (typeof value !== "string" || !/^0[xX][0-9a-fA-F]{40}$/.test(value)) {
      throw new Error(`typed data: ${what} must be a 20-byte address`);
    }
    return Buffer.concat([Buffer.alloc(12), Buffer.from(value.slice(2), "hex")]);
  }
  let m = /^(u?)int(\d+)$/.exec(type);
  if (m && isTypedAtomic(type)) {
    const bits = BigInt(m[2]);
    const n = typedInteger(value, what);
    if (m[1] === "u") {
      if (n < 0n || n >= 1n << bits) throw new Error(`typed data: ${what} is out of range for ${type}`);
      return bigTo32(n);
    }
    const half = 1n << (bits - 1n);
    if (n < -half || n >= half) throw new Error(`typed data: ${what} is out of range for ${type}`);
    return bigTo32(n < 0n ? n + (1n << 256n) : n);
  }
  m = /^bytes(\d+)$/.exec(type);
  if (m && isTypedAtomic(type)) {
    const bytes = typedHexBytes(value, what);
    if (bytes.length !== Number(m[1])) {
      throw new Error(`typed data: ${what} must be exactly ${m[1]} bytes`);
    }
    return Buffer.concat([bytes, Buffer.alloc(32 - bytes.length)]);
  }
  throw new Error(`typed data: ${what} has unknown type '${type}'`);
}

function hashTypedStruct(type, value, types, what = type) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`typed data: ${what} must be an object`);
  }
  const fields = types[type];
  const declared = new Set(fields.map((f) => f.name));
  for (const key of Object.keys(value)) {
    if (!declared.has(key)) {
      throw new Error(`typed data: ${what} carries '${key}', which type ${type} does not declare`);
    }
  }
  const parts = [keccak256(Buffer.from(encodeTypedType(type, types), "utf8"))];
  for (const field of fields) {
    parts.push(encodeTypedValue(field.type, value[field.name], types, `${what}.${field.name}`));
  }
  return keccak256(Buffer.concat(parts));
}

// The domain's type is what the domain object holds, in the EIP's own order.
// A payload that also spells it out under `types.EIP712Domain` must spell out
// exactly that: a declared field the object lacks (or the reverse) would sign
// under a separator the reader of the object never saw.
function typedDomainType(domain, declared) {
  if (!domain || typeof domain !== "object" || Array.isArray(domain)) {
    throw new Error("typed data: `domain` must be an object");
  }
  const known = new Map(TYPED_DOMAIN_FIELDS);
  for (const key of Object.keys(domain)) {
    if (!known.has(key)) throw new Error(`typed data: domain carries unknown field '${key}'`);
  }
  const derived = TYPED_DOMAIN_FIELDS.filter(([name]) => domain[name] !== undefined).map(
    ([name, type]) => ({ name, type }),
  );
  if (derived.length === 0) throw new Error("typed data: domain is empty");
  if (declared !== undefined) {
    const same =
      Array.isArray(declared) &&
      declared.length === derived.length &&
      declared.every((f, i) => f && f.name === derived[i].name && f.type === derived[i].type);
    if (!same) {
      throw new Error("typed data: types.EIP712Domain does not match the fields of `domain`");
    }
  }
  return derived;
}

/**
 * The EIP-712 digest of a typed-data payload `{types, primaryType, domain,
 * message}` (the `eth_signTypedData_v4` shape). Returns the 32-byte digest and
 * its two halves, all public.
 */
export function hashTypedData(typedData) {
  if (!typedData || typeof typedData !== "object" || Array.isArray(typedData)) {
    throw new Error("typed data: payload must be an object");
  }
  const { types, primaryType, domain, message } = typedData;
  if (typeof primaryType !== "string" || primaryType === "EIP712Domain") {
    throw new Error("typed data: `primaryType` must name a message type");
  }
  validateTypedTypes(types);
  const domainFields = typedDomainType(domain, types.EIP712Domain);
  const all = { ...types, EIP712Domain: domainFields };
  if (!Object.hasOwn(types, primaryType)) {
    throw new Error(`typed data: primaryType '${primaryType}' is not defined in types`);
  }
  const domainSeparator = hashTypedStruct("EIP712Domain", domain, all, "domain");
  const messageHash = hashTypedStruct(primaryType, message, all, "message");
  const digest = keccak256(Buffer.concat([Buffer.from([0x19, 0x01]), domainSeparator, messageHash]));
  return { digest, domainSeparator, messageHash };
}

/**
 * Sign a typed-data payload with a 32-byte private key. Returns the 65-byte
 * `r ‖ s ‖ v` signature (v = 27 | 28) as 0x hex, plus the digest — public
 * material only.
 */
export function signTypedData(typedData, privKey32) {
  const { digest } = hashTypedData(typedData);
  const { r, s, yParity } = ecdsaSignHash(digest, privKey32);
  const signature = Buffer.concat([bigTo32(r), bigTo32(s), Buffer.from([27 + yParity])]);
  return { signature: "0x" + signature.toString("hex"), digest: "0x" + digest.toString("hex") };
}

// ─── Typed-data signing rules ───────────────────────────────────────────────────
// A wallet record's `typedDataAllowlist` names what the key may sign off chain:
//
//   [{ primaryType: "Order",
//      domain: { name: "…", version: "1", chainId: 137, verifyingContract: "0x…" } }]
//
// Default-DENY, unlike the transaction constraints: a record without the list
// signs no typed data at all. A transaction is bounded by its chain, its gas
// and the RPC-host allowlist; a typed-data signature is bounded by nothing but
// the contract that reads it, and the best-known ones (ERC-2612 permits,
// Permit2) hand a token balance to whoever holds the signature.
//
// A rule matches on the primary type and on the WHOLE domain: every field the
// rule lists must be equal, and the payload's domain may carry no field the
// rule does not. That pins the domain separator, so a contract that borrows a
// trusted name cannot have its messages signed under the trusted rule.

function sameDomainValue(field, a, b) {
  if (field === "chainId") {
    try {
      return typedInteger(a, "chainId") === typedInteger(b, "chainId");
    } catch {
      return false;
    }
  }
  if (field === "verifyingContract" || field === "salt") {
    return typeof a === "string" && typeof b === "string" && a.toLowerCase() === b.toLowerCase();
  }
  return a === b;
}

export function typedDataRuleMatches(rule, typedData) {
  if (!rule || typeof rule !== "object" || !rule.domain || typeof rule.domain !== "object") {
    return false;
  }
  if (!typedData || typeof typedData !== "object" || typedData.primaryType !== rule.primaryType) {
    return false;
  }
  const domain = typedData.domain;
  if (!domain || typeof domain !== "object" || Array.isArray(domain)) return false;
  const ruleKeys = Object.keys(rule.domain).filter((k) => rule.domain[k] !== undefined);
  const dataKeys = Object.keys(domain).filter((k) => domain[k] !== undefined);
  if (ruleKeys.length !== dataKeys.length) return false;
  return ruleKeys.every(
    (key) => Object.hasOwn(domain, key) && sameDomainValue(key, rule.domain[key], domain[key]),
  );
}

// JSON-RPC methods a wallet answers itself, without a node.
const EVM_SIGN_TYPED_DATA = "eth_signTypedData_v4";
const EVM_ACCOUNT_METHODS = new Set(["eth_accounts", "eth_requestAccounts"]);
// Signing methods this wallet never serves. `eth_sign` and `personal_sign` put
// the key under bytes nobody can read back; the older typed-data versions hash
// differently from what a reviewer of v4 expects. Left to pass through they
// would reach a node that holds no account, so the refusal is said here.
const EVM_REFUSED_SIGN_METHODS = new Set([
  "eth_sign",
  "personal_sign",
  "eth_signTransaction",
  "eth_signTypedData",
  "eth_signTypedData_v1",
  "eth_signTypedData_v3",
]);

/**
 * Answer the JSON-RPC calls an EVM wallet serves by itself: `eth_accounts`
 * (the credential's address) and `eth_signTypedData_v4` (an EIP-712 signature
 * under the record's `typedDataAllowlist`). Returns `null` for everything
 * else, which the caller forwards as before; `{ body, signed, digests }` when
 * the answer is made here and nothing is to reach the upstream.
 *
 * Throws for a typed-data request the record does not allow, for a malformed
 * one, for a signing method this wallet never serves, and for any of these
 * inside a batch — a batch is forwarded whole, and a signature has no place
 * in a request that leaves this process.
 */
export function answerEvmWalletRpc(bodyText, privateKeyHex, credAddress, constraints = {}) {
  let parsed;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    return null;
  }
  const isLocal = (msg) =>
    msg &&
    typeof msg === "object" &&
    (msg.method === EVM_SIGN_TYPED_DATA ||
      EVM_ACCOUNT_METHODS.has(msg.method) ||
      EVM_REFUSED_SIGN_METHODS.has(msg.method));
  if (Array.isArray(parsed)) {
    const local = parsed.find(isLocal);
    if (local) throw new Error(`${local.method}: not served inside a batch — send it on its own`);
    return null;
  }
  if (!isLocal(parsed)) return null;
  const reply = (result) => ({
    body: JSON.stringify({ jsonrpc: "2.0", id: parsed.id ?? null, result }),
  });

  if (EVM_ACCOUNT_METHODS.has(parsed.method)) {
    return { ...reply([credAddress]), signed: false, digests: [] };
  }
  if (EVM_REFUSED_SIGN_METHODS.has(parsed.method)) {
    throw new Error(
      `${parsed.method}: this wallet signs transactions (eth_sendTransaction) and allowlisted ` +
        "EIP-712 typed data (eth_signTypedData_v4) only",
    );
  }

  if (!/^[0-9a-fA-F]{64}$/.test(privateKeyHex || "")) {
    throw new Error("evm credential: privateKey must be 32 bytes of hex");
  }
  if (!Array.isArray(parsed.params) || parsed.params.length < 2) {
    throw new Error(`${EVM_SIGN_TYPED_DATA}: params must be [address, typedData]`);
  }
  const [from, raw] = parsed.params;
  if (typeof from !== "string" || from.toLowerCase() !== credAddress.toLowerCase()) {
    throw new Error(
      `${EVM_SIGN_TYPED_DATA}: signer (${from}) does not match the credential address (${credAddress})`,
    );
  }
  let typedData = raw;
  if (typeof raw === "string") {
    try {
      typedData = JSON.parse(raw);
    } catch {
      throw new Error(`${EVM_SIGN_TYPED_DATA}: typed data is not valid JSON`);
    }
  }
  const allowlist = Array.isArray(constraints.typedDataAllowlist) ? constraints.typedDataAllowlist : [];
  if (!allowlist.some((rule) => typedDataRuleMatches(rule, typedData))) {
    const name = typedData && typedData.domain && typeof typedData.domain.name === "string"
      ? typedData.domain.name
      : "(unnamed)";
    throw new Error(
      `${EVM_SIGN_TYPED_DATA}: '${typedData && typedData.primaryType}' for domain '${name}' is ` +
        "not in this credential's typedDataAllowlist",
    );
  }
  const { signature, digest } = signTypedData(typedData, Buffer.from(privateKeyHex, "hex"));
  return { ...reply(signature), signed: true, digests: [digest] };
}

// Hold one transaction object to a wallet record's constraints (all optional,
// default-allow) and pin its `from` to the credential, so the wallet actually
// being spent is always explicit. Throws on a violation, before anything is
// signed. `what` names the entrance in the refusal.
function constrainEvmTransaction(tx, credAddress, constraints, what) {
  if (!tx || typeof tx !== "object" || Array.isArray(tx)) {
    throw new Error(`${what}: a transaction object is required`);
  }
  if (tx.from && String(tx.from).toLowerCase() !== credAddress.toLowerCase()) {
    throw new Error(
      `${what}: 'from' (${tx.from}) does not match the credential address (${credAddress})`,
    );
  }
  if (!tx.from) tx.from = credAddress;
  const chainIdAllowlist = Array.isArray(constraints.chainIdAllowlist)
    ? constraints.chainIdAllowlist
    : null;
  const toAllowlist = Array.isArray(constraints.toAllowlist)
    ? constraints.toAllowlist.map((a) => a.toLowerCase())
    : null;
  if (chainIdAllowlist) {
    const chainId = Number(qty(tx.chainId, "chainId"));
    if (!chainIdAllowlist.includes(chainId)) {
      throw new Error(`${what}: chainId ${chainId} not in this credential's chainIdAllowlist`);
    }
  }
  if (toAllowlist) {
    const to = tx.to == null ? "" : String(tx.to).toLowerCase();
    if (!toAllowlist.includes(to)) {
      throw new Error(
        `${what}: recipient ${tx.to || "(contract-creation)"} not in this credential's toAllowlist`,
      );
    }
  }
}

function evmCredentialKey(privateKeyHex) {
  if (!/^[0-9a-fA-F]{64}$/.test(privateKeyHex || "")) {
    throw new Error("evm credential: privateKey must be 32 bytes of hex");
  }
  return Buffer.from(privateKeyHex, "hex");
}

/**
 * Sign one EIP-1559 transaction object with a wallet credential, under the
 * record's constraints — the same checks `eth_sendTransaction` gets through
 * the proxy, for a caller that holds the vault itself and broadcasts the raw
 * transaction on its own. Returns { raw, hash, from }: public material only.
 */
export function signEvmTransactionFor(tx, privateKeyHex, credAddress, constraints = {}) {
  const priv = evmCredentialKey(privateKeyHex);
  const pinned = { ...tx };
  constrainEvmTransaction(pinned, credAddress, constraints, "transaction");
  return signEip1559Transaction(pinned, priv);
}

/**
 * Sign one EIP-712 payload with a wallet credential, under the record's
 * `typedDataAllowlist` (default-deny). Returns { signature, digest, address }.
 */
export function signEvmTypedDataFor(typedData, privateKeyHex, credAddress, constraints = {}) {
  const answer = answerEvmWalletRpc(
    JSON.stringify({ jsonrpc: "2.0", id: 1, method: EVM_SIGN_TYPED_DATA, params: [credAddress, typedData] }),
    privateKeyHex,
    credAddress,
    constraints,
  );
  return {
    signature: JSON.parse(answer.body).result,
    digest: answer.digests[0],
    address: credAddress,
  };
}

/**
 * Transform an EVM JSON-RPC body: `eth_sendTransaction` becomes
 * `eth_sendRawTransaction` with the EIP-1559 tx signed by the vaulted key.
 * If the request names a `from`, it must match the credential's address.
 * Everything else (eth_getTransactionCount, eth_call, …) passes through.
 * Batches are handled element-wise.
 *
 * Returns { body, signed, hashes }.
 */
export function signEvmRpcBody(bodyText, privateKeyHex, credAddress, constraints = {}) {
  let parsed;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    return { body: bodyText, signed: false, hashes: [] };
  }
  const priv = evmCredentialKey(privateKeyHex);
  const hashes = [];

  const signOne = (msg) => {
    if (!msg || typeof msg !== "object" || msg.method !== "eth_sendTransaction") return msg;
    if (!Array.isArray(msg.params) || typeof msg.params[0] !== "object" || msg.params[0] == null) {
      throw new Error("eth_sendTransaction: params[0] must be a transaction object");
    }
    const tx = msg.params[0];
    // Optional, default-allow signing constraints from the credential record.
    constrainEvmTransaction(tx, credAddress, constraints, "eth_sendTransaction");
    const { raw, hash } = signEip1559Transaction(tx, priv);
    hashes.push(hash);
    return { ...msg, method: "eth_sendRawTransaction", params: [raw] };
  };

  const transformed = Array.isArray(parsed) ? parsed.map(signOne) : signOne(parsed);
  return { body: JSON.stringify(transformed), signed: hashes.length > 0, hashes };
}
