// Alien Agent ID — RFC 6238 TOTP code generator.
//
// Used by the proxy at injection time to materialize `totp` credentials
// into the 6-digit code expected by the upstream service, and by the vault /
// browser to store and consume a 2FA seed for a `login` credential.

import { createHmac } from "node:crypto";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Decode(input) {
  const clean = input.replace(/=+$/, "").replace(/\s+/g, "").toUpperCase();
  const out = [];
  let bits = 0;
  let value = 0;
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error(`Invalid base32 char: ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >> bits) & 0xff);
    }
  }
  return Buffer.from(out);
}

// Validate a base32 TOTP secret and return it normalized (whitespace/padding
// stripped, upper-cased). Throws on an empty secret or a non-base32 character.
export function validateBase32Secret(secret) {
  const clean = String(secret || "")
    .replace(/=+$/, "")
    .replace(/\s+/g, "")
    .toUpperCase();
  if (!clean) throw new Error("empty TOTP secret");
  base32Decode(clean); // throws on an invalid base32 character
  return clean;
}

// Parse an `otpauth://totp/...` URI (the QR-code payload shown during 2FA setup)
// into { secret, period?, digits?, algorithm? }. Throws on a non-otpauth input or
// a missing/invalid secret.
export function parseOtpauthUri(uri) {
  let u;
  try {
    u = new URL(uri);
  } catch {
    throw new Error("not a valid otpauth URI");
  }
  if (u.protocol !== "otpauth:") throw new Error("not an otpauth:// URI");
  if (u.host.toLowerCase() !== "totp") throw new Error("only otpauth://totp/ URIs are supported");
  const out = { secret: validateBase32Secret(u.searchParams.get("secret") || "") };
  const period = Number(u.searchParams.get("period"));
  if (Number.isFinite(period) && period > 0) out.period = period;
  const digits = Number(u.searchParams.get("digits"));
  if (Number.isFinite(digits) && digits > 0) out.digits = digits;
  const algorithm = u.searchParams.get("algorithm");
  if (algorithm) out.algorithm = algorithm.toUpperCase();
  return out;
}

// Normalize user-supplied TOTP input that is EITHER a raw base32 secret OR a full
// otpauth:// URI into { secret, period?, digits?, algorithm? }. The single entry
// point the vault uses when capturing a seed from the secure prompt.
export function normalizeTotpInput(input) {
  const s = String(input || "").trim();
  if (/^otpauth:\/\//i.test(s)) return parseOtpauthUri(s);
  return { secret: validateBase32Secret(s) };
}

export function generateTotp({
  secret,
  period = 30,
  digits = 6,
  algorithm = "SHA1",
  now = Date.now(),
}) {
  const counter = Math.floor(now / 1000 / period);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));
  const key = base32Decode(secret);
  const hmac = createHmac(algorithm.toLowerCase(), key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  const mod = 10 ** digits;
  return String(code % mod).padStart(digits, "0");
}
