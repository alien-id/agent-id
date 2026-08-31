#!/usr/bin/env node

// Optional, default-allow signing constraints on in-vault wallet credentials.
// EVM credentials may pin a chainId allowlist and a recipient (to) allowlist;
// Solana credentials may pin a program-id allowlist. When a constraint is set,
// the proxy's signer refuses any transaction that violates it BEFORE signing;
// when unset, behavior is unchanged (signs anything well-formed).
//
// Run: node --test tests/test-wallet-constraints.mjs

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  generateEvmKeypair,
  signEvmRpcBody,
} from "../plugins/agent-id-core/lib/evm.mjs";
import {
  base58Encode,
  buildSolanaTransferTx,
  generateSolanaKeypair,
  signSolanaRpcBody,
  solanaProgramIds,
} from "../plugins/agent-id-core/lib/solana.mjs";
import { validateRecord } from "../plugins/agent-id-vault/lib/store.mjs";

const SYSTEM_PROGRAM = "11111111111111111111111111111111";
const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

function evmTx({ chainId = 137, to = "0x" + "ab".repeat(20) } = {}) {
  return JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "eth_sendTransaction",
    params: [
      {
        chainId,
        nonce: "0x1",
        to,
        value: "0x1",
        gas: "0x5208",
        maxFeePerGas: "0x1",
        maxPriorityFeePerGas: "0x1",
      },
    ],
  });
}

describe("evm signing constraints", () => {
  const { address, privateKeyHex } = generateEvmKeypair();

  it("signs when no constraints are set (unchanged behavior)", () => {
    const out = signEvmRpcBody(evmTx(), privateKeyHex, address);
    assert.equal(out.signed, true);
  });

  it("refuses a chainId not on the allowlist", () => {
    assert.throws(
      () =>
        signEvmRpcBody(evmTx({ chainId: 137 }), privateKeyHex, address, {
          chainIdAllowlist: [1],
        }),
      /chainId 137 not in/
    );
  });

  it("allows a chainId on the allowlist", () => {
    const out = signEvmRpcBody(
      evmTx({ chainId: 137 }),
      privateKeyHex,
      address,
      {
        chainIdAllowlist: [1, 137],
      }
    );
    assert.equal(out.signed, true);
  });

  it("refuses a recipient not on the to-allowlist", () => {
    assert.throws(
      () =>
        signEvmRpcBody(
          evmTx({ to: "0x" + "ab".repeat(20) }),
          privateKeyHex,
          address,
          {
            toAllowlist: ["0x" + "99".repeat(20)],
          }
        ),
      /not in this credential's toAllowlist/
    );
  });

  it("allows a recipient on the to-allowlist (case-insensitive)", () => {
    const to = "0x" + "AB".repeat(20);
    const out = signEvmRpcBody(evmTx({ to }), privateKeyHex, address, {
      toAllowlist: ["0x" + "ab".repeat(20)],
    });
    assert.equal(out.signed, true);
  });

  it("pins 'from' to the credential address when omitted", () => {
    // No throw, and the from-mismatch guard still holds for a wrong explicit from.
    assert.doesNotThrow(() => signEvmRpcBody(evmTx(), privateKeyHex, address));
    assert.throws(() => {
      const tx = JSON.parse(evmTx());
      tx.params[0].from = "0x" + "11".repeat(20);
      signEvmRpcBody(JSON.stringify(tx), privateKeyHex, address);
    }, /does not match the credential address/);
  });
});

describe("solana signing constraints", () => {
  const { publicKey, secretSeedHex } = generateSolanaKeypair();
  const dest = base58Encode(Buffer.alloc(32, 9));
  const blockhash = base58Encode(Buffer.alloc(32, 3));

  function transferBody() {
    const wire = buildSolanaTransferTx({
      from: publicKey,
      to: dest,
      lamports: 1000,
      recentBlockhash: blockhash,
    });
    return JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "sendTransaction",
      params: [base58Encode(wire)],
    });
  }

  it("decodes the System Program id from a transfer", () => {
    const wire = buildSolanaTransferTx({
      from: publicKey,
      to: dest,
      lamports: 1000,
      recentBlockhash: blockhash,
    });
    assert.deepEqual(solanaProgramIds(wire), [SYSTEM_PROGRAM]);
  });

  it("signs a System Program transfer when no constraints are set", () => {
    const out = signSolanaRpcBody(transferBody(), secretSeedHex);
    assert.equal(out.signed, true);
  });

  it("allows a transfer when the System Program is on the allowlist", () => {
    const out = signSolanaRpcBody(transferBody(), secretSeedHex, {
      programAllowlist: [SYSTEM_PROGRAM],
    });
    assert.equal(out.signed, true);
  });

  it("refuses a transfer when only another program is allowed", () => {
    assert.throws(
      () =>
        signSolanaRpcBody(transferBody(), secretSeedHex, {
          programAllowlist: [TOKEN_PROGRAM],
        }),
      /program 11111111111111111111111111111111 not in/
    );
  });
});

describe("store validation of constraint fields", () => {
  const base = { name: "w", domains: ["rpc.example.com"] };

  it("accepts valid evm allowlists", () => {
    validateRecord({
      ...base,
      type: "evm-keypair",
      privateKey: "ab".repeat(32),
      address: "0x" + "cd".repeat(20),
      chainIdAllowlist: [1, 137],
      toAllowlist: ["0x" + "ef".repeat(20)],
    });
  });

  it("rejects a non-integer chainId", () => {
    assert.throws(
      () =>
        validateRecord({
          ...base,
          type: "evm-keypair",
          privateKey: "ab".repeat(32),
          address: "0x" + "cd".repeat(20),
          chainIdAllowlist: ["mainnet"],
        }),
      /chainIdAllowlist entries must be positive integers/
    );
  });

  it("rejects a non-address to-allowlist entry", () => {
    assert.throws(
      () =>
        validateRecord({
          ...base,
          type: "evm-keypair",
          privateKey: "ab".repeat(32),
          address: "0x" + "cd".repeat(20),
          toAllowlist: ["not-an-address"],
        }),
      /toAllowlist entries must be 0x EVM addresses/
    );
  });

  it("accepts a valid solana programAllowlist", () => {
    validateRecord({
      ...base,
      type: "solana-keypair",
      secretSeed: "ab".repeat(32),
      publicKey: SYSTEM_PROGRAM,
      programAllowlist: [SYSTEM_PROGRAM],
    });
  });
});
