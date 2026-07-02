# Vault p2p sync — PoC design

**Date:** 2026-07-03
**Status:** approved design, pre-implementation
**Scope:** PoC — live, fully decentralized p2p synchronization of the
agent-id-vault credential set between a user's PCs.

## Goals and non-goals

**Goals**

- Sync vault credential records between 2+ PCs (any OS the vault runs on)
  with no central server, relay, or third-party storage anywhere in the sync
  path. Data exists only on the devices themselves.
- Live sync: devices exchange state when both are reachable (same LAN via
  discovery, or any network via an explicit peer address).
- Trust rooted in the existing Alien Agent ID identity layer: a peer is
  authenticated by its owner binding (v3 bundle), and authorized by a one-time
  human approval per device.
- Convergent, clock-independent conflict handling with no silent secret loss.

**Non-goals (phase 2, foundation laid but not built)**

- Asynchronous store-and-forward sync (devices never online together).
- Phones as sync participants.
- Syncing `browser-profile` records and their sealed profile sidecars.
- Transitive device trust (signed device-add operations); PoC requires
  full-mesh pairwise pairing for 3+ devices.
- Oplog compaction (history squash to snapshot).
- Real mDNS/DNS-SD, NAT traversal, internet-wide discovery.

## Decisions made during brainstorming

| Question | Decision |
| --- | --- |
| Devices | PCs only (where the Node vault runs); no phones in PoC |
| Availability model | Live sync (both ends online); strictly no centralization |
| Trust / pairing | Owner binding (v3 bundle, same SSO `sub`) authenticates; a one-time explicit approval per device authorizes; peer agent keys are pinned locally |
| What syncs | Credential records only; `browser-profile` records + sidecars, agent identity, trust store, and conflict journal stay device-local |
| Conflict model | Signed op-log DAG (git-like causality), deterministic tiebreak on true concurrency, conflict journal, manual `sync resolve` override |
| Channel | TLS 1.3 with ephemeral self-signed certs; identity bound via Ed25519 signature over RFC 5705 exported keying material |
| Run mode | One-shot `sync` command + `--listen` resident mode, same code path; UDP multicast beacon discovery + explicit `--peer` |

## Architecture overview

```
Device A                                    Device B
┌─────────────────────────┐                ┌─────────────────────────┐
│ vault.json (own MK,     │                │ vault.json (own MK,     │
│  own slots)             │                │  own slots)             │
│  payload:               │   TLS 1.3      │  payload:               │
│   ├ credentials (view)  │◄──────────────►│   ├ credentials (view)  │
│   ├ oplog (DAG)         │  identity =    │   ├ oplog (DAG)         │
│   └ syncMeta (trust,    │  Ed25519 over  │   └ syncMeta (trust,    │
│      conflict journal)  │  channel bind  │      conflict journal)  │
└─────────────────────────┘                └─────────────────────────┘
```

Key properties:

- **The master key never leaves a device.** Each device remains a fully
  self-contained vault: its own master key, its own slots (agent-key, passkey,
  etc.). Operations travel in plaintext only *inside* the E2E TLS channel;
  each end stores them under its own local master key. Both ends unlock with
  their agent-key slot for the duration of a sync.
- **`credentials` becomes a materialized view** — a deterministic fold of the
  op-log DAG. Existing CRUD code keeps working; every mutation additionally
  appends a signed operation to the log.
- **Migration:** a pre-sync vault has no oplog. On first sync initialization,
  current records are converted into genesis operations.

## Components

All inside `plugins/agent-id-vault`, new directory `lib/sync/`:

| Module | Responsibility |
| --- | --- |
| `oplog.mjs` | operation format, hash DAG, sign/verify, merge, deterministic fold to view, tombstones |
| `trust.mjs` | pinned device list, peer v3-bundle verification (same owner), approval ceremony |
| `channel.mjs` | TLS server/client, ephemeral self-signed cert, RFC 5705 channel binding export, identity handshake |
| `discovery.mjs` | UDP multicast beacon (simplified, not full mDNS) + explicit `--peer` |
| `protocol.mjs` | wire protocol: hello → exchange missing ops → atomic apply |
| CLI | `sync`, `sync --listen`, `sync status`, `sync devices [add/list]`, `sync revoke`, `sync resolve` |

**One refactor outside the vault plugin:** the self-signed certificate minter
currently lives in `agent-id-proxy/lib/control-tls.mjs`, but the dependency
direction is proxy → vault → core. Cert minting is promoted into
`agent-id-core` (e.g. `lib/tls-cert.mjs`); the proxy re-imports from core.
This is a minor change to core + a patch to proxy (two changesets; vault gets
its own minor changeset for the sync feature).

## Data model

### Operation (the unit of sync)

```js
{
  h:       "sha256 of the canonical JSON of the body",   // operation id
  parents: ["h1", "h2"],   // DAG heads at creation time (usually 1)
  device:  "jkt thumbprint of the author's agent key",
  ts:      1730000000000,  // informational; causality comes from the DAG
  op:      { kind: "add" | "update" | "remove", name: "github-pat",
             record: {...} | null },
  sig:     "Ed25519 signature of h by the author device's agent key"
}
```

### Fold to view

For each record name the causally-latest operation wins. When operations are
truly concurrent (neither is an ancestor of the other), both sides pick the
same winner via the deterministic tiebreak: the op with the greater `ts`
wins; on equal `ts`, the lexicographically greater `h` wins. The losing version
is written to the **conflict journal** (local, never synced):
`{name, losingRecord, winnerHash, decidedAt}`. `sync resolve <name>` lets the
human re-instate a journaled version (which becomes a new op, superseding the
auto-winner).

### Trust store

`syncMeta.devices`, stored inside the encrypted payload (integrity via the
payload AEAD): `{deviceJkt, agentJwk, label, ownerSub, addedAt}`. Revocation =
local deletion on each device (`sync revoke`).

### Operation acceptance rule

An operation is accepted only if its `sig` verifies against the **pinned**
agent key of its author. Consequence for the PoC: with 3+ devices, full-mesh
pairing is required (each pair approves once). Transitive trust is phase 2.

### Not synced

`browser-profile` records (+ their sealed sidecars), the agent identity and
key, the trust store, the conflict journal — all device-local.

## Pairing and per-connection handshake

Every TLS connection runs the same identity handshake — pairing is simply its
first successful pass plus the approval ceremony.

1. **Channel.** Both sides generate an ephemeral P-256 key + self-signed cert
   at startup (minter from core). TLS 1.3, mutual certs, CA/hostname
   validation disabled — the cert is only a key carrier.
2. **Channel binding.** Both sides export
   `tlsSocket.exportKeyingMaterial(32, "agent-id-vault-sync-v1")` — a secret
   unique to this TLS session.
3. **`hello`** (both directions):
   `{bundle: v3, deviceLabel, sig: Ed25519(agent_sk, EKM || role || peer nonce)}`.
4. **Verification** (symmetric): signature ↔ `agent_jwk` from the bundle;
   `cnf.jkt` ↔ thumbprint of `agent_jwk`; id_token signature ↔ cached SSO
   JWKS; peer `sub` == own `sub`. A MITM terminates two TLS legs with
   different EKM values, so the signature check fails and the connection is
   dropped. No SSO call is needed at sync time — JWKS is cached at binding
   time.
5. **Authorization:** peer key pinned → sync proceeds. Not pinned but owner
   matches → approval ceremony: interactive TTY prompt («Device `macbook-air`,
   agent `a1b2…`, owner verified (L2). Trust? [y/N]»); approval pins the key.
   A headless side without a TTY replies `approval-required` and logs the jkt;
   the human then adds it explicitly via `sync devices add <jkt>`. Each device
   pins the other (each keeps its own list).

L0 agents (no owner binding) do not participate in the PoC.

## Wire protocol

JSON-lines inside TLS, symmetric:

```
A → B: hello            B → A: hello        (mutual verification, above)
A → B: heads {h...}     B → A: heads {h...}
A → B: want [hashes]    B → A: want [hashes]
A → B: ops [operations] B → A: ops [operations]
A → B: done             B → A: done
```

The difference is computed by exchanging full op-hash sets — logs are small in
the PoC; DAG-walk narrowing is a phase-2 optimization.

**Atomic apply:** incoming ops accumulate in staging; after `done` —
signature + DAG-connectivity verification, merge, re-fold of the view,
conflict-journal writes, and **one** vault-file write (existing save path,
plus an advisory lock file against races with a concurrent CLI). A connection
drop at any step changes nothing; the next sync restarts cleanly (operations
are idempotent by hash).

## Discovery and run modes

- **Beacon:** UDP multicast (fixed group/port), payload
  `{v, deviceJkt, tcpPort}`, unsigned — a beacon is only an invitation to
  establish TLS; all authentication happens in the handshake. The listening
  side announces; one-shot `sync` listens for beacons for a couple of seconds,
  connects to all known/approvable peers, syncs, exits.
- `--peer <host:port>` — bypasses discovery (VPN / Tailscale / different
  network).
- `sync --listen` — resident mode on the same code path: listens on TCP +
  announces beacons. Daemonization (launchd/systemd) is out of PoC scope.

## Error handling and edge cases

| Case | Behavior |
| --- | --- |
| op / hello signature mismatch | drop connection, log to stderr, vault untouched |
| Owner mismatch | polite `owner-mismatch` refusal, no details leaked |
| Peer not approved, no TTY | `approval-required`, jkt logged, no sync |
| Network drop mid-sync | staging discarded, vault intact |
| Skewed clocks | causality unaffected (DAG); tiebreak stays deterministic |
| Concurrent local CRUD during apply | advisory lock: second writer waits or fails explicitly |
| `user`-mode vault ↔ `dev`-mode vault | sync allowed (mode governs slots, not records), warning printed |
| Revoked device | new connections refused; previously accepted ops remain (history is not rewritten) |

## Security notes

- Oplog entries contain secret material (credential values inside ops), so
  the oplog lives inside the AEAD-encrypted vault payload, under the local
  master key — same protection as the credentials themselves.
- The trust boundary is *pinned devices*, not "anything bound to the owner":
  owner binding answers "who are you", the one-time approval answers "are you
  allowed in". A stolen SSO session alone is not sufficient to join the mesh.
- Beacons carry no secrets and are unauthenticated by design; they can at
  worst trigger an outbound TLS attempt that then fails the handshake.
- Certs are ephemeral per-process and never pinned; identity lives entirely
  in the Ed25519-over-EKM signature, so cert rotation is a non-event.

## Testing (node --test, zero-dep, in `tests/`)

1. **oplog units:** convergence — random application orders of one op set
   produce an identical view; tombstones; concurrent edit of one record →
   same winner on both sides + journal entry.
2. **handshake units:** valid exchange passes; MITM simulation (two TLS legs,
   different EKM) fails; foreign owner fails; unsigned/tampered op rejected.
3. **Integration:** two processes on loopback with separate stateDirs —
   pairing with auto-approve (test-only env flag), divergent edits, sync,
   assert equal views and expected journal contents.
4. **Migration:** legacy vault without an oplog → genesis ops → sync onto an
   empty new device transfers everything.

## Release notes

Touches `plugins/agent-id-core` (cert-minter promotion, minor) and
`plugins/agent-id-vault` (sync feature, minor) → both need changesets.
`agent-id-proxy` (re-import of the cert minter) is private/marketplace-only —
no changeset required.
