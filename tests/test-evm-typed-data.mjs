#!/usr/bin/env node

// EIP-712 typed data: the digest, the signature, and the default-deny rules
// that decide which payloads an in-vault EVM key signs.
//
// The digests and signatures are reference values for the key keccak256("cow"):
// the EIP-712 specification's own example, the nested-array example wallets
// test `eth_signTypedData_v4` with, and a payload of every atomic kind produced
// with `eth-account` (Python). Our RFC 6979 signatures must byte-match them.
//
// Run: node --test tests/test-evm-typed-data.mjs

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  answerEvmWalletRpc,
  encodeTypedType,
  evmAddressFromPrivate,
  hashTypedData,
  keccak256,
  signTypedData,
  typedDataRuleMatches,
} from "../plugins/agent-id-core/lib/evm.mjs";
import { isTypedDataRelaxation, validateRecord } from "../plugins/agent-id-vault/lib/store.mjs";

// The specification's throwaway key — NOT a real wallet.
const COW_KEY = keccak256(Buffer.from("cow"));
const COW_KEY_HEX = COW_KEY.toString("hex");
const COW = "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826";

const DOMAIN_TYPE = [
  { name: "name", type: "string" },
  { name: "version", type: "string" },
  { name: "chainId", type: "uint256" },
  { name: "verifyingContract", type: "address" },
];
const MAIL_DOMAIN = {
  name: "Ether Mail",
  version: "1",
  chainId: 1,
  verifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
};

function specMail() {
  return {
    types: {
      EIP712Domain: DOMAIN_TYPE,
      Person: [
        { name: "name", type: "string" },
        { name: "wallet", type: "address" },
      ],
      Mail: [
        { name: "from", type: "Person" },
        { name: "to", type: "Person" },
        { name: "contents", type: "string" },
      ],
    },
    primaryType: "Mail",
    domain: { ...MAIL_DOMAIN },
    message: {
      from: { name: "Cow", wallet: COW },
      to: { name: "Bob", wallet: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB" },
      contents: "Hello, Bob!",
    },
  };
}

function nestedArrayMail() {
  return {
    types: {
      EIP712Domain: DOMAIN_TYPE,
      Person: [
        { name: "name", type: "string" },
        { name: "wallets", type: "address[]" },
      ],
      Mail: [
        { name: "from", type: "Person" },
        { name: "to", type: "Person[]" },
        { name: "contents", type: "string" },
      ],
      Group: [
        { name: "name", type: "string" },
        { name: "members", type: "Person[]" },
      ],
    },
    primaryType: "Mail",
    domain: { ...MAIL_DOMAIN },
    message: {
      from: {
        name: "Cow",
        wallets: [COW, "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"],
      },
      to: [
        {
          name: "Bob",
          wallets: [
            "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
            "0xB0BdaBea57B0BDABeA57b0bdABEA57b0BDabEa57",
            "0xB0B0b0b0b0b0B000000000000000000000000000",
          ],
        },
      ],
      contents: "Hello, Bob!",
    },
  };
}

// Every atomic kind, a fixed-size array of structs, and a domain that carries
// two fields only and is not spelled out under `types`.
function everyKind() {
  return {
    types: {
      Leg: [
        { name: "token", type: "address" },
        { name: "amount", type: "uint256" },
        { name: "delta", type: "int64" },
        { name: "tag", type: "bytes4" },
      ],
      Ticket: [
        { name: "id", type: "bytes32" },
        { name: "open", type: "bool" },
        { name: "side", type: "uint8" },
        { name: "legs", type: "Leg[2]" },
        { name: "note", type: "string" },
        { name: "blob", type: "bytes" },
      ],
    },
    primaryType: "Ticket",
    domain: { name: "Ticket Desk", chainId: 137 },
    message: {
      id: "0x00000000000000000000000000000000000000000000000000000000000000ff",
      open: true,
      side: 1,
      legs: [
        {
          token: "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
          amount: "115792089237316195423570985008687907853269984665640564039457584007913129639935",
          delta: -42,
          tag: "0x095ea7b3",
        },
        {
          token: "0x0000000000000000000000000000000000000000",
          amount: "0",
          delta: 9007199254740991,
          tag: "0x00000000",
        },
      ],
      note: "naïve — ünïcode ✓",
      blob: "0xdeadbeef",
    },
  };
}

describe("EIP-712 digest and signature", () => {
  it("reproduces the specification's example", () => {
    const typed = specMail();
    assert.equal(evmAddressFromPrivate(COW_KEY), COW);
    assert.equal(
      encodeTypedType("Mail", typed.types),
      "Mail(Person from,Person to,string contents)Person(string name,address wallet)",
    );
    const { digest, domainSeparator, messageHash } = hashTypedData(typed);
    assert.equal(
      domainSeparator.toString("hex"),
      "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f",
    );
    assert.equal(
      messageHash.toString("hex"),
      "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e",
    );
    assert.equal(
      digest.toString("hex"),
      "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2",
    );
    assert.equal(
      signTypedData(typed, COW_KEY).signature,
      "0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d" +
        "07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b91562" +
        "1c",
    );
  });

  it("hashes arrays of structs and ignores a type nothing refers to", () => {
    const signed = signTypedData(nestedArrayMail(), COW_KEY);
    assert.equal(signed.digest, "0xa85c2e2b118698e88db68a8105b794a8cc7cec074e89ef991cb4f5f533819cc2");
    assert.equal(
      signed.signature,
      "0x65cbd956f2fae28a601bebc9b906cea0191744bd4c4247bcd27cd08f8eb6b71c" +
        "78efdf7a31dc9abee78f492292721f362d296cf86b4538e07b51303b67f74906" +
        "1b",
    );
  });

  it("encodes every atomic kind as eth-account does", () => {
    const signed = signTypedData(everyKind(), COW_KEY);
    assert.equal(signed.digest, "0xe903b3764a85a7c2326be38cd854435642ff99392975419a392bd334e653111d");
    assert.equal(
      signed.signature,
      "0x623e4e4baa6e3c913242a5bc6483fdcf8ad467b700afe65cb33bc0f462158ca4" +
        "4f0c003a18661483fdee478380de008fac91fcdf6f2af636ab5c9dc03e447b30" +
        "1c",
    );
  });

  it("gives the same digest whether or not the domain's type is spelled out", () => {
    const derived = everyKind();
    const declared = everyKind();
    declared.types.EIP712Domain = [
      { name: "name", type: "string" },
      { name: "chainId", type: "uint256" },
    ];
    assert.deepEqual(hashTypedData(declared).digest, hashTypedData(derived).digest);
  });
});

describe("EIP-712 refuses what it cannot encode exactly", () => {
  const refuses = (mutate, pattern) => {
    const typed = specMail();
    mutate(typed);
    assert.throws(() => hashTypedData(typed), pattern);
  };

  it("a field the type does not declare", () => {
    refuses((t) => (t.message.amount = "1"), /does not declare/);
    refuses((t) => (t.message.from.admin = true), /does not declare/);
  });

  it("a missing value", () => {
    refuses((t) => delete t.message.contents, /message\.contents is missing/);
    refuses((t) => (t.message.to = null), /message\.to is missing/);
  });

  it("a malformed address", () => {
    refuses((t) => (t.message.from.wallet = "0x1234"), /20-byte address/);
  });

  it("a type nobody defined", () => {
    refuses((t) => t.types.Mail.push({ name: "extra", type: "Receipt" }), /unknown type/);
    refuses((t) => (t.primaryType = "Parcel"), /not defined/);
  });

  it("a declared domain type that differs from the domain's own fields", () => {
    refuses((t) => delete t.domain.verifyingContract, /does not match the fields of `domain`/);
    refuses((t) => (t.domain.owner = COW), /unknown field 'owner'/);
  });

  it("numbers outside their type", () => {
    const typed = everyKind();
    typed.message.side = 256;
    assert.throws(() => hashTypedData(typed), /out of range for uint8/);
    typed.message.side = -1;
    assert.throws(() => hashTypedData(typed), /out of range for uint8/);
    typed.message.side = 1.5;
    assert.throws(() => hashTypedData(typed), /not a safe integer/);
    typed.message.side = 1;
    typed.message.legs[0].delta = "9223372036854775808";
    assert.throws(() => hashTypedData(typed), /out of range for int64/);
  });

  it("bytes of the wrong length and a short fixed array", () => {
    const typed = everyKind();
    typed.message.legs[0].tag = "0x095ea7";
    assert.throws(() => hashTypedData(typed), /exactly 4 bytes/);
    typed.message.legs[0].tag = "0x095ea7b3";
    typed.message.legs.pop();
    assert.throws(() => hashTypedData(typed), /must hold 2 items/);
  });
});

describe("typed-data rules", () => {
  const rule = { primaryType: "Mail", domain: { ...MAIL_DOMAIN } };

  it("match the primary type and the whole domain", () => {
    assert.equal(typedDataRuleMatches(rule, specMail()), true);
  });

  it("compare the contract without case and the chain as a number", () => {
    const typed = specMail();
    typed.domain.verifyingContract = typed.domain.verifyingContract.toLowerCase();
    typed.domain.chainId = "0x1";
    assert.equal(typedDataRuleMatches(rule, typed), true);
  });

  it("do not match another type, chain, contract or name", () => {
    const other = (mutate) => {
      const typed = specMail();
      mutate(typed);
      return typedDataRuleMatches(rule, typed);
    };
    assert.equal(other((t) => (t.primaryType = "Person")), false);
    assert.equal(other((t) => (t.domain.chainId = 137)), false);
    assert.equal(other((t) => (t.domain.verifyingContract = "0x" + "11".repeat(20))), false);
    assert.equal(other((t) => (t.domain.name = "Ether Mail ")), false);
  });

  it("do not match a domain with a field more or a field fewer than the rule", () => {
    const more = specMail();
    more.domain.salt = "0x" + "00".repeat(32);
    assert.equal(typedDataRuleMatches(rule, more), false);
    const fewer = specMail();
    delete fewer.domain.verifyingContract;
    assert.equal(typedDataRuleMatches(rule, fewer), false);
    // The reverse: a rule for a contract-less domain does not cover one that names a contract.
    const bare = { primaryType: "Mail", domain: { name: "Ether Mail", version: "1", chainId: 1 } };
    assert.equal(typedDataRuleMatches(bare, specMail()), false);
  });
});

describe("the wallet's own JSON-RPC answers", () => {
  const allow = { typedDataAllowlist: [{ primaryType: "Mail", domain: { ...MAIL_DOMAIN } }] };
  const request = (method, params, id = 7) => JSON.stringify({ jsonrpc: "2.0", id, method, params });

  it("answers eth_accounts with the credential's address", () => {
    const out = answerEvmWalletRpc(request("eth_accounts", []), COW_KEY_HEX, COW);
    assert.deepEqual(JSON.parse(out.body), { jsonrpc: "2.0", id: 7, result: [COW] });
    assert.equal(out.signed, false);
  });

  it("signs allowlisted typed data, given as an object or as a JSON string", () => {
    const expected = signTypedData(specMail(), COW_KEY);
    for (const payload of [specMail(), JSON.stringify(specMail())]) {
      const out = answerEvmWalletRpc(
        request("eth_signTypedData_v4", [COW.toLowerCase(), payload]),
        COW_KEY_HEX,
        COW,
        allow,
      );
      assert.equal(JSON.parse(out.body).result, expected.signature);
      assert.deepEqual(out.digests, [expected.digest]);
      assert.equal(out.signed, true);
      assert.ok(!out.body.includes(COW_KEY_HEX), "the answer never carries the key");
    }
  });

  it("signs no typed data for a record without rules", () => {
    assert.throws(
      () => answerEvmWalletRpc(request("eth_signTypedData_v4", [COW, specMail()]), COW_KEY_HEX, COW),
      /'Mail' for domain 'Ether Mail' is not in this credential's typedDataAllowlist/,
    );
  });

  it("refuses typed data outside the rules, and for another signer", () => {
    const permit = specMail();
    permit.domain.verifyingContract = "0x" + "22".repeat(20);
    assert.throws(
      () => answerEvmWalletRpc(request("eth_signTypedData_v4", [COW, permit]), COW_KEY_HEX, COW, allow),
      /not in this credential's typedDataAllowlist/,
    );
    assert.throws(
      () =>
        answerEvmWalletRpc(
          request("eth_signTypedData_v4", ["0x" + "33".repeat(20), specMail()]),
          COW_KEY_HEX,
          COW,
          allow,
        ),
      /does not match the credential address/,
    );
  });

  it("refuses blind-signing methods rather than forwarding them", () => {
    for (const method of ["personal_sign", "eth_sign", "eth_signTypedData_v3", "eth_signTransaction"]) {
      assert.throws(
        () => answerEvmWalletRpc(request(method, ["0xdeadbeef", COW]), COW_KEY_HEX, COW, allow),
        /this wallet signs transactions/,
      );
    }
  });

  it("refuses a signature inside a batch", () => {
    const batch = JSON.stringify([
      { jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] },
      { jsonrpc: "2.0", id: 2, method: "eth_signTypedData_v4", params: [COW, specMail()] },
    ]);
    assert.throws(() => answerEvmWalletRpc(batch, COW_KEY_HEX, COW, allow), /not served inside a batch/);
  });

  it("leaves everything else to the upstream", () => {
    assert.equal(answerEvmWalletRpc(request("eth_getBalance", [COW, "latest"]), COW_KEY_HEX, COW), null);
    assert.equal(answerEvmWalletRpc(request("eth_sendTransaction", [{}]), COW_KEY_HEX, COW), null);
    assert.equal(answerEvmWalletRpc("not json", COW_KEY_HEX, COW), null);
    assert.equal(
      answerEvmWalletRpc(JSON.stringify([{ jsonrpc: "2.0", id: 1, method: "eth_chainId" }]), COW_KEY_HEX, COW),
      null,
    );
  });
});

describe("store validation of typedDataAllowlist", () => {
  const record = (typedDataAllowlist) => ({
    name: "evm-hot",
    type: "evm-keypair",
    domains: ["rpc.example.com"],
    privateKey: COW_KEY_HEX,
    address: COW,
    typedDataAllowlist,
  });

  it("accepts a rule that pins a whole domain", () => {
    validateRecord(record([{ primaryType: "Mail", domain: { ...MAIL_DOMAIN } }]));
    validateRecord(record([{ primaryType: "Auth", domain: { name: "Desk", version: "1", chainId: 137 } }]));
  });

  it("rejects an empty list, a rule without a domain, and unknown keys", () => {
    assert.throws(() => validateRecord(record([])), /non-empty array/);
    assert.throws(() => validateRecord(record([{ primaryType: "Mail" }])), /needs a domain object/);
    assert.throws(() => validateRecord(record([{ primaryType: "Mail", domain: {} }])), /at least one/);
    assert.throws(
      () => validateRecord(record([{ primaryType: "Mail", domain: { name: "x" }, any: true }])),
      /primaryType and domain only/,
    );
    assert.throws(
      () => validateRecord(record([{ primaryType: "Mail", domain: { name: "x", owner: COW } }])),
      /holds name, version, chainId, verifyingContract, salt only/,
    );
  });

  it("rejects a malformed primary type, chain or contract", () => {
    assert.throws(
      () => validateRecord(record([{ primaryType: "EIP712Domain", domain: { name: "x" } }])),
      /must name a message type/,
    );
    assert.throws(
      () => validateRecord(record([{ primaryType: "Mail", domain: { chainId: "137" } }])),
      /chainId must be a positive integer/,
    );
    assert.throws(
      () => validateRecord(record([{ primaryType: "Mail", domain: { verifyingContract: "0xabc" } }])),
      /verifyingContract must be a 0x EVM address/,
    );
  });

  it("tells a widening from a tightening", () => {
    const one = record([{ primaryType: "Mail", domain: { ...MAIL_DOMAIN } }]);
    const two = record([
      { primaryType: "Mail", domain: { ...MAIL_DOMAIN } },
      { primaryType: "Auth", domain: { name: "Desk", chainId: 137 } },
    ]);
    const none = record(undefined);
    assert.equal(isTypedDataRelaxation(none, one), true);
    assert.equal(isTypedDataRelaxation(one, two), true);
    assert.equal(isTypedDataRelaxation(two, one), false);
    assert.equal(isTypedDataRelaxation(one, none), false);
    // The same rule written with the contract in another case is not a new rule.
    const recased = record([
      { primaryType: "Mail", domain: { ...MAIL_DOMAIN, verifyingContract: MAIL_DOMAIN.verifyingContract.toLowerCase() } },
    ]);
    assert.equal(isTypedDataRelaxation(one, recased), false);
  });
});
