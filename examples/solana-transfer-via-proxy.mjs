#!/usr/bin/env node

// Demo: an agent moves SOL from a VAULT-HELD wallet without ever touching the
// private key. Everything the agent does here uses public material only:
//
//   1. getLatestBlockhash  — through the proxy (passthrough)
//   2. build an UNSIGNED System Program transfer (public keys + blockhash)
//   3. sendTransaction     — through the proxy, which signs it in-process
//   4. poll getSignatureStatuses until the transfer is confirmed
//
// Usage:
//   node examples/solana-transfer-via-proxy.mjs \
//     --proxy http://127.0.0.1:48771 --cred sol-hot \
//     --from <fromAddress> --to <toAddress> --lamports 2000000 \
//     [--rpc-host api.mainnet-beta.solana.com]
//
// The from-address is printed by `agent-id-vault generate` / `list` — the
// agent never needs anything else.

import { parseArgs } from "node:util";
import { buildSolanaTransferTx } from "../plugins/agent-id-core/lib/solana.mjs";

const { values: args } = parseArgs({
  options: {
    proxy: { type: "string", default: "http://127.0.0.1:48771" },
    cred: { type: "string" },
    from: { type: "string" },
    to: { type: "string" },
    lamports: { type: "string" },
    "rpc-host": { type: "string", default: "api.mainnet-beta.solana.com" },
  },
});

for (const k of ["cred", "from", "to", "lamports"]) {
  if (!args[k]) {
    console.error(`--${k} is required`);
    process.exit(2);
  }
}

const base = `${args.proxy.replace(/\/$/, "")}/${args.cred}/${args["rpc-host"]}/`;

async function rpc(method, params) {
  const res = await fetch(base, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const body = await res.json();
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  if (body.ok === false) throw new Error(`proxy: ${JSON.stringify(body)}`);
  return body.result;
}

const lamports = Number(args.lamports);

const balance = await rpc("getBalance", [args.from]);
console.log(`from ${args.from}: ${balance.value / 1e9} SOL`);
if (balance.value < lamports + 5000) {
  console.error("insufficient balance for transfer + fee");
  process.exit(1);
}

const bh = await rpc("getLatestBlockhash", [{ commitment: "finalized" }]);
const blockhash = bh.value.blockhash;
console.log(`blockhash: ${blockhash}`);

const unsigned = buildSolanaTransferTx({
  from: args.from,
  to: args.to,
  lamports,
  recentBlockhash: blockhash,
});
console.log(`built UNSIGNED transfer of ${lamports / 1e9} SOL → ${args.to}`);

// The proxy fills in the signature; the agent never sees the key.
const signature = await rpc("sendTransaction", [
  unsigned.toString("base64"),
  { encoding: "base64", preflightCommitment: "confirmed" },
]);
console.log(`submitted via proxy. signature: ${signature}`);

for (let i = 0; i < 30; i++) {
  await new Promise((r) => setTimeout(r, 2000));
  const st = await rpc("getSignatureStatuses", [[signature]]);
  const s = st.value?.[0];
  const status = s ? s.confirmationStatus : "pending";
  console.log(`[${(i + 1) * 2}s] status: ${status}${s?.err ? ` err=${JSON.stringify(s.err)}` : ""}`);
  if (s?.err) process.exit(1);
  if (status === "confirmed" || status === "finalized") {
    const toBal = await rpc("getBalance", [args.to, { commitment: "confirmed" }]);
    console.log(`destination ${args.to}: ${toBal.value / 1e9} SOL`);
    console.log("transfer confirmed — signed by the vault, key never exposed.");
    process.exit(0);
  }
}
console.error("timed out waiting for confirmation (tx may still land)");
process.exit(1);
