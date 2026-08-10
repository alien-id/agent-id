// Alien Agent ID — Self-signed TLS certificate minting (shared).
//
// Used by the proxy control plane and by vault p2p sync. The cert is a pinned
// (or, for sync, ephemeral) key carrier: no CA, hostname/CA validation is
// intentionally bypassed by consumers.
//
// When the control plane is exposed beyond loopback (a phone on a trusted LAN),
// it runs over TLS so the bearer token isn't sniffable. There's no CA and no
// trust-store install: the proxy serves a self-signed leaf, and the approver
// pins its SHA-256 fingerprint, which it learns out-of-band from the pairing QR.
//
// Node can sign P-256 ECDSA and export an SPKI DER, but has no API to MINT an
// X.509 cert — so we hand-encode the small surrounding ASN.1 DER (zero-dep, in
// the spirit of the rest of this codebase). The cert is used purely as a pinned
// key carrier; hostname/CA validation is intentionally bypassed on the client.

import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign,
  X509Certificate,
} from "node:crypto";

// ── Minimal DER ────────────────────────────────────────────────────────────────
function derLen(n) {
  if (n < 0x80) return Buffer.from([n]);
  const b = [];
  while (n > 0) {
    b.unshift(n & 0xff);
    n = Math.floor(n / 256);
  }
  return Buffer.from([0x80 | b.length, ...b]);
}
function tlv(tag, content) {
  return Buffer.concat([Buffer.from([tag]), derLen(content.length), content]);
}
const SEQ = (...parts) => tlv(0x30, Buffer.concat(parts));
const SET = (...parts) => tlv(0x31, Buffer.concat(parts));
// DER INTEGER for a non-negative value, in MINIMAL form. Two rules that both
// bite a 16-byte random serial:
//   - strip redundant leading 0x00 bytes (a leading zero whose successor has the
//     high bit clear is illegal padding — strict parsers throw
//     "asn1 …::illegal padding"); happens ~1/512 random serials, which was the
//     source of the flaky control-plane TLS test.
//   - keep exactly one leading 0x00 when the top byte's high bit is set, so the
//     value stays positive (X.509 serials must be positive).
function INTEGER(buf) {
  let start = 0;
  while (start < buf.length && buf[start] === 0x00) start++;
  let b = buf.subarray(start);
  if (b.length === 0) b = Buffer.from([0]); // the value is zero
  else if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]); // keep positive
  return tlv(0x02, b);
}
const OID = (bytes) => tlv(0x06, Buffer.from(bytes));
const BOOL = (v) => tlv(0x01, Buffer.from([v ? 0xff : 0x00]));
const BITSTRING = (buf) => tlv(0x03, Buffer.concat([Buffer.from([0]), buf])); // 0 unused bits
const OCTETSTRING = (buf) => tlv(0x04, buf);
const UTF8 = (s) => tlv(0x0c, Buffer.from(s, "utf8"));
const UTCTIME = (s) => tlv(0x17, Buffer.from(s, "ascii"));
const ctx = (tagNo, content) => tlv(0xa0 | tagNo, content); // [tagNo] constructed

const OID_ECDSA_SHA256 = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]; // 1.2.840.10045.4.3.2
const OID_CN = [0x55, 0x04, 0x03]; // 2.5.4.3
const OID_BASIC_CONSTRAINTS = [0x55, 0x1d, 0x13]; // 2.5.29.19

function utcTime(date) {
  const p = (n) => String(n).padStart(2, "0");
  return (
    p(date.getUTCFullYear() % 100) +
    p(date.getUTCMonth() + 1) +
    p(date.getUTCDate()) +
    p(date.getUTCHours()) +
    p(date.getUTCMinutes()) +
    p(date.getUTCSeconds()) +
    "Z"
  );
}

// Invariant: never emit a blank line, even when the base64 body length is an
// exact multiple of 64 — Node's PEM parser rejects a blank line inside a PEM
// block (e.g. `replace(/(.{64})/g, "$1\n")` would leave a trailing "\n" that,
// combined with the "\n" added below, produces "\n\n" before the footer).
function pem(label, der) {
  const b64 = (der.toString("base64").match(/.{1,64}/g) || [""]).join("\n");
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
}

// Normalize a fingerprint (strip colons, lowercase) for comparison. Node's
// getPeerCertificate().fingerprint256 is uppercase, colon-separated.
export function normalizeFingerprint(fp) {
  return String(fp || "").replace(/:/g, "").toLowerCase();
}

// SHA-256 fingerprint of a PEM cert (for a cert loaded from disk).
export function fingerprintOfCertPem(certPem) {
  return normalizeFingerprint(new X509Certificate(certPem).fingerprint256);
}

// Generate a fresh self-signed P-256 cert. Returns { certPem, keyPem, fingerprint }
// where fingerprint is the lowercase hex SHA-256 of the cert DER (what the phone
// pins, and what tls.getPeerCertificate().fingerprint256 yields once normalized).
export function generateControlCert({
  cn = "alien-agent-id-control",
  days = 3650,
  now = new Date(),
  // Serial bytes — injectable so tests can pin the leading-zero / high-bit edge
  // cases the random default only hits ~1/512 of the time.
  serial: serialBytes = randomBytes(16),
} = {}) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const spki = publicKey.export({ type: "spki", format: "der" }); // complete SubjectPublicKeyInfo

  const algId = SEQ(OID(OID_ECDSA_SHA256));
  const name = SEQ(SET(SEQ(OID(OID_CN), UTF8(cn))));
  const validity = SEQ(
    UTCTIME(utcTime(new Date(now.getTime() - 60_000))),
    UTCTIME(utcTime(new Date(now.getTime() + days * 86_400_000))),
  );
  const version = ctx(0, INTEGER(Buffer.from([2]))); // [0] EXPLICIT v3
  const serial = INTEGER(serialBytes);
  const basicConstraints = SEQ(OID(OID_BASIC_CONSTRAINTS), BOOL(true), OCTETSTRING(SEQ())); // cA=FALSE (default)
  const extensions = ctx(3, SEQ(basicConstraints)); // [3] EXPLICIT Extensions

  const tbs = SEQ(version, serial, algId, name, validity, name, spki, extensions);
  const signature = sign("SHA256", tbs, privateKey); // ECDSA-Sig-Value DER
  const certDer = SEQ(tbs, algId, BITSTRING(signature));

  return {
    certPem: pem("CERTIFICATE", certDer),
    keyPem: privateKey.export({ type: "pkcs8", format: "pem" }),
    fingerprint: createHash("sha256").update(certDer).digest("hex"),
  };
}
