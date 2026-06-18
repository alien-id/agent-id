// Alien Agent ID — SSRF guard for upstream connections.
//
// The per-credential host allowlist is the primary control over where the proxy
// will send an injected credential. This module is defense-in-depth for when an
// allowlist is broad or mis-scoped: it refuses connections to addresses that
// should never be a legitimate credentialed upstream — the cloud-metadata
// service and other link-local / unspecified / multicast ranges — and,
// optionally, all loopback/private ranges.
//
// The check runs at CONNECT time via a custom `lookup` handed to http(s)
// .request, so it inspects the *resolved* address(es). That closes the
// DNS-rebinding gap a name-only check would leave (a hostname that resolves to
// 169.254.169.254 is blocked even though the name looks innocuous).

import dns from "node:dns";

// Returns a human-readable reason string if `ip` is blocked, else null.
// `blockPrivate` additionally blocks loopback and RFC1918/ULA/CGNAT ranges.
export function blockedAddressReason(ip, { blockPrivate = false } = {}) {
  if (typeof ip !== "string" || !ip) return null;
  let addr = ip.trim();

  // Unwrap an IPv4-mapped IPv6 address (::ffff:a.b.c.d) to its IPv4 form.
  const mapped = addr.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
  if (mapped) addr = mapped[1];

  if (addr.includes(".") && !addr.includes(":")) {
    const parts = addr.split(".");
    if (parts.length !== 4) return null;
    const n = parts.map((p) => Number(p));
    if (n.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) return null;
    const [a, b] = n;
    // Always blocked — never a legitimate credentialed upstream.
    if (a === 0) return "unspecified/this-network (0.0.0.0/8)";
    if (a === 169 && b === 254) return "link-local (169.254/16, incl. cloud metadata)";
    if (a >= 224) return "multicast/reserved";
    if (blockPrivate) {
      if (a === 127) return "loopback (127/8)";
      if (a === 10) return "private (10/8)";
      if (a === 172 && b >= 16 && b <= 31) return "private (172.16/12)";
      if (a === 192 && b === 168) return "private (192.168/16)";
      if (a === 100 && b >= 64 && b <= 127) return "CGNAT (100.64/10)";
    }
    return null;
  }

  // IPv6
  const low = addr.toLowerCase();
  if (low === "::" || low === "::0") return "unspecified (::)";
  if (low.startsWith("fe80") || low.startsWith("fe9") || low.startsWith("fea") || low.startsWith("feb")) {
    return "link-local (fe80::/10)";
  }
  if (low.startsWith("ff")) return "multicast (ff00::/8)";
  if (blockPrivate) {
    if (low === "::1") return "loopback (::1)";
    if (/^f[cd]/.test(low)) return "unique-local (fc00::/7)";
  }
  return null;
}

// Build a `lookup` function for http(s).request options. It resolves the host,
// refuses any blocked resolved address, and otherwise behaves like dns.lookup.
export function makeUpstreamLookup({ blockPrivate = false } = {}) {
  return function upstreamLookup(hostname, options, callback) {
    if (typeof options === "function") {
      callback = options;
      options = {};
    }
    const opts = { ...options, all: true };
    dns.lookup(hostname, opts, (err, addresses) => {
      if (err) return callback(err);
      const list = Array.isArray(addresses)
        ? addresses
        : [{ address: addresses, family: opts.family || 0 }];
      for (const a of list) {
        const reason = blockedAddressReason(a.address, { blockPrivate });
        if (reason) {
          const e = new Error(
            `blocked upstream address: ${hostname} → ${a.address} (${reason})`,
          );
          e.code = "ESSRFBLOCKED";
          return callback(e);
        }
      }
      if (options.all) return callback(null, list);
      return callback(null, list[0].address, list[0].family);
    });
  };
}
