// Alien Agent ID — Identity assurance ladder.
//
// An agent identity is a single, stable Ed25519 key. What changes as the agent
// onboards is not the key but the *attestation backing it* — so assurance is a
// property of the attestation, never a precondition for having an identity.
// Three rungs, each a strict superset of trust over the one below:
//
//   L0 self-asserted   — the agent key alone. No human. Usable immediately:
//                        local audit trail, vault, signed operations, and L0
//                        git commits ("signed by key X, no human backing").
//   L1 anonymous-human — an Alien SSO id_token whose cnf.jkt binds this key and
//                        which attests a *verified human* authorized it, but
//                        with a pairwise/pseudonymous `sub` (and the marker
//                        `alien_assurance: "anonymous"`). A verifier learns "a
//                        real human stands behind this key" — not which human,
//                        and not linkable across relying parties.
//   L2 linked          — an id_token whose `sub` is the canonical AlienID. Full
//                        provenance: artifact → key → this specific human.
//
// The key never changes across rungs, so L0→L1→L2 never invalidates a prior
// signature: the cnf.jkt anchor is stable. Upgrades are monotonic — a higher
// attestation is simply added later.

export const ASSURANCE = Object.freeze({
  SELF: 0,
  ANONYMOUS: 1,
  LINKED: 2,
});

const ASSURANCE_NAME = Object.freeze({
  0: "self-asserted",
  1: "anonymous-human",
  2: "linked",
});

// The id_token claim the SSO sets to mark an anonymous (privacy-preserving)
// binding. Absent ⇒ a legacy/linked token (every token issued before the
// ladder existed is a full owner binding, so absence means L2, not L1).
export const ASSURANCE_CLAIM = "alien_assurance";

/**
 * Classify the assurance level from an id_token payload (or null/undefined for
 * an unbound agent).
 *
 * An anchoring token needs BOTH `cnf.jkt` (RFC 7800 — binds the key) and a
 * `sub` (the human handle, canonical or pairwise). Missing either means the
 * token can't attest this agent, so it's treated as self-asserted (L0) rather
 * than trusted as human-backed.
 */
export function classifyAssurance(idTokenPayload) {
  if (!idTokenPayload || typeof idTokenPayload !== "object") return ASSURANCE.SELF;
  const hasCnf = typeof idTokenPayload?.cnf?.jkt === "string" && idTokenPayload.cnf.jkt.length > 0;
  const hasSub = typeof idTokenPayload.sub === "string" && idTokenPayload.sub.length > 0;
  if (!hasCnf || !hasSub) return ASSURANCE.SELF;
  if (idTokenPayload[ASSURANCE_CLAIM] === "anonymous") return ASSURANCE.ANONYMOUS;
  return ASSURANCE.LINKED;
}

export function describeAssurance(level) {
  return ASSURANCE_NAME[level] || "unknown";
}

// One-line hint on how to climb to the next rung — surfaced by `status` so the
// onboarding path is always visible.
export function nextAssuranceStep(level) {
  if (level >= ASSURANCE.LINKED) return null;
  if (level === ASSURANCE.ANONYMOUS) {
    return "Re-bind with a linked (non-anonymous) Alien SSO flow to reach L2 (linked to your AlienID).";
  }
  return "Run `agent-id-core auth` then `bind` to add human attestation (L1 anonymous or L2 linked).";
}
