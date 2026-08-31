#!/usr/bin/env node

// Unit tests for the zero-dependency EVM primitives. The EIP-1559 signing
// vectors were produced with `eth-account` (Python) for the throwaway key
// 0x4646…46 — our RFC 6979 deterministic signatures must byte-match its
// raw transactions exactly.
//
// Run: node --test tests/test-evm-lib.mjs

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  ecdsaSignHash,
  evmAddressFromPrivate,
  generateEvmKeypair,
  keccak256,
  rlpEncode,
  rlpIntBuf,
  signEip1559Transaction,
  signEvmRpcBody,
  toChecksumAddress,
} from "../plugins/agent-id-core/lib/evm.mjs";

// Throwaway test key (the classic EIP-155 example key) — NOT a real wallet.
const TEST_KEY = Buffer.from(
  "4646464646464646464646464646464646464646464646464646464646464646",
  "hex"
);
const TEST_ADDRESS = "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F";

describe("keccak256", () => {
  it("matches known vectors", () => {
    assert.equal(
      keccak256(Buffer.alloc(0)).toString("hex"),
      "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );
    assert.equal(
      keccak256("abc").toString("hex"),
      "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    );
  });

  it("handles multi-block input (>136 bytes)", () => {
    const big = Buffer.alloc(500, 0xab);
    // Self-consistency: hashing twice gives the same result, length 32.
    assert.equal(keccak256(big).length, 32);
    assert.deepEqual(keccak256(big), keccak256(Buffer.alloc(500, 0xab)));
  });
});

describe("RLP", () => {
  it("encodes canonical vectors", () => {
    assert.equal(rlpEncode(Buffer.from("dog")).toString("hex"), "83646f67");
    assert.equal(rlpEncode(Buffer.alloc(0)).toString("hex"), "80");
    assert.equal(rlpEncode([]).toString("hex"), "c0");
    assert.equal(rlpEncode(Buffer.from([0x0f])).toString("hex"), "0f");
    assert.equal(
      rlpEncode([Buffer.from("cat"), Buffer.from("dog")]).toString("hex"),
      "c88363617483646f67"
    );
  });

  it("integer buffers are minimal big-endian", () => {
    assert.equal(rlpIntBuf(0).length, 0);
    assert.equal(rlpIntBuf(127).toString("hex"), "7f");
    assert.equal(rlpIntBuf(256).toString("hex"), "0100");
    assert.equal(rlpIntBuf(137n).toString("hex"), "89");
  });
});

describe("address derivation", () => {
  it("derives the eth-account address for the test key", () => {
    assert.equal(evmAddressFromPrivate(TEST_KEY), TEST_ADDRESS);
  });

  it("EIP-55 checksum vectors", () => {
    assert.equal(
      toChecksumAddress("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"),
      "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    );
    assert.equal(
      toChecksumAddress("fb6916095ca1df60bb79ce92ce3ea74c37c5d359"),
      "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
    );
  });

  it("generates distinct keypairs with valid checksummed addresses", () => {
    const a = generateEvmKeypair();
    const b = generateEvmKeypair();
    assert.notEqual(a.address, b.address);
    assert.match(a.privateKeyHex, /^[0-9a-f]{64}$/);
    assert.equal(toChecksumAddress(a.address), a.address);
  });
});

describe("ECDSA (RFC 6979)", () => {
  it("is deterministic and low-s", () => {
    const hash = keccak256("determinism test");
    const sig1 = ecdsaSignHash(hash, TEST_KEY);
    const sig2 = ecdsaSignHash(hash, TEST_KEY);
    assert.equal(sig1.r, sig2.r);
    assert.equal(sig1.s, sig2.s);
    assert.equal(sig1.yParity, sig2.yParity);
    const N =
      0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
    assert.ok(sig1.s <= N / 2n, "s must be normalized (EIP-2)");
  });
});

describe("EIP-1559 signing (cross-validated against eth-account)", () => {
  it("vector 1: simple value transfer on Polygon (chainId 137)", () => {
    const { raw, hash, from } = signEip1559Transaction(
      {
        chainId: 137,
        nonce: 7,
        maxPriorityFeePerGas: 30_000_000_000,
        maxFeePerGas: 100_000_000_000,
        gas: 21000,
        to: "0x000000000000000000000000000000000000dEaD",
        value: 12345678901234567n,
        data: "0x",
      },
      TEST_KEY
    );
    assert.equal(
      raw,
      "0x02f8748189078506fc23ac0085174876e80082520894000000000000000000000000000000000000dead872bdc545d6b4b8780c001a08a237992595e001e45d6dd3d4e86e02ead894b0b377b74a4ff4da9bd7116ee17a07cda7d3fe4dea2b3d8d8f2749bfe34a65914168ead1f82207ca06b3ddf3472ce"
    );
    assert.equal(
      hash,
      "0x0ee145f3ce3051c0e14fddb1b157c0f6955cba05a348c730c98bee4a4e24c23d"
    );
    assert.equal(from, TEST_ADDRESS);
  });

  it("vector 2: zero value with calldata", () => {
    const { raw } = signEip1559Transaction(
      {
        chainId: 137,
        nonce: 0,
        maxPriorityFeePerGas: "0x6fc23ac00",
        maxFeePerGas: "0x174876e800",
        gas: "0x5208",
        to: "0x264487655998352572F725951C7838c69c73f50A",
        value: 0,
        data: "0xdeadbeef00",
      },
      TEST_KEY
    );
    assert.equal(
      raw,
      "0x02f8728189808506fc23ac0085174876e80082520894264487655998352572f725951c7838c69c73f50a8085deadbeef00c080a072b43b132f71b2a5087c793282d5d19c7bb2edb11fb011da50d2a9920e42babaa05d48a4b3768fd4786b60a77704797f48c230138feb0c2d5cc0ba360ce5662c26"
    );
  });

  it("requires explicit gas/fee/nonce/chainId fields", () => {
    assert.throws(
      () =>
        signEip1559Transaction(
          { chainId: 1, to: "0x" + "11".repeat(20) },
          TEST_KEY
        ),
      /required/
    );
  });
});

describe("JSON-RPC body transform", () => {
  const txObj = {
    from: TEST_ADDRESS,
    to: "0x000000000000000000000000000000000000dEaD",
    value: "0x2bdc545d6b4b87",
    chainId: 137,
    nonce: 7,
    gas: 21000,
    maxFeePerGas: 100_000_000_000,
    maxPriorityFeePerGas: 30_000_000_000,
  };

  it("rewrites eth_sendTransaction → eth_sendRawTransaction (signed)", () => {
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "eth_sendTransaction",
      params: [txObj],
    });
    const {
      body: out,
      signed,
      hashes,
    } = signEvmRpcBody(body, TEST_KEY.toString("hex"), TEST_ADDRESS);
    assert.ok(signed);
    assert.equal(hashes.length, 1);
    const parsed = JSON.parse(out);
    assert.equal(parsed.method, "eth_sendRawTransaction");
    assert.match(parsed.params[0], /^0x02f874/);
    assert.equal(
      hashes[0],
      "0x0ee145f3ce3051c0e14fddb1b157c0f6955cba05a348c730c98bee4a4e24c23d"
    );
  });

  it("rejects a mismatched from address", () => {
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "eth_sendTransaction",
      params: [{ ...txObj, from: "0x" + "22".repeat(20) }],
    });
    assert.throws(
      () => signEvmRpcBody(body, TEST_KEY.toString("hex"), TEST_ADDRESS),
      /does not match the credential address/
    );
  });

  it("passes other methods through untouched", () => {
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id: 9,
      method: "eth_getTransactionCount",
      params: [TEST_ADDRESS, "latest"],
    });
    const r = signEvmRpcBody(body, TEST_KEY.toString("hex"), TEST_ADDRESS);
    assert.equal(r.signed, false);
    assert.deepEqual(JSON.parse(r.body), JSON.parse(body));
  });

  it("passes non-JSON bodies through untouched", () => {
    const r = signEvmRpcBody(
      "plain text",
      TEST_KEY.toString("hex"),
      TEST_ADDRESS
    );
    assert.equal(r.signed, false);
    assert.equal(r.body, "plain text");
  });
});
