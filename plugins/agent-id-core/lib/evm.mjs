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
  if (!/^[0-9a-fA-F]{64}$/.test(privateKeyHex || "")) {
    throw new Error("evm credential: privateKey must be 32 bytes of hex");
  }
  const priv = Buffer.from(privateKeyHex, "hex");
  const hashes = [];

  // Optional, default-allow signing constraints from the credential record.
  const chainIdAllowlist = Array.isArray(constraints.chainIdAllowlist)
    ? constraints.chainIdAllowlist
    : null;
  const toAllowlist = Array.isArray(constraints.toAllowlist)
    ? constraints.toAllowlist.map((a) => a.toLowerCase())
    : null;

  const signOne = (msg) => {
    if (!msg || typeof msg !== "object" || msg.method !== "eth_sendTransaction") return msg;
    if (!Array.isArray(msg.params) || typeof msg.params[0] !== "object" || msg.params[0] == null) {
      throw new Error("eth_sendTransaction: params[0] must be a transaction object");
    }
    const tx = msg.params[0];
    if (tx.from && String(tx.from).toLowerCase() !== credAddress.toLowerCase()) {
      throw new Error(
        `eth_sendTransaction: 'from' (${tx.from}) does not match the credential address (${credAddress})`,
      );
    }
    // Pin 'from' to the credential address when the agent omitted it, so the
    // wallet actually being spent is always explicit.
    if (!tx.from) tx.from = credAddress;
    if (chainIdAllowlist) {
      const chainId = Number(qty(tx.chainId, "chainId"));
      if (!chainIdAllowlist.includes(chainId)) {
        throw new Error(
          `eth_sendTransaction: chainId ${chainId} not in this credential's chainIdAllowlist`,
        );
      }
    }
    if (toAllowlist) {
      const to = tx.to == null ? "" : String(tx.to).toLowerCase();
      if (!toAllowlist.includes(to)) {
        throw new Error(
          `eth_sendTransaction: recipient ${tx.to || "(contract-creation)"} not in this credential's toAllowlist`,
        );
      }
    }
    const { raw, hash } = signEip1559Transaction(tx, priv);
    hashes.push(hash);
    return { ...msg, method: "eth_sendRawTransaction", params: [raw] };
  };

  const transformed = Array.isArray(parsed) ? parsed.map(signOne) : signOne(parsed);
  return { body: JSON.stringify(transformed), signed: hashes.length > 0, hashes };
}
