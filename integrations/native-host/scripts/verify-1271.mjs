#!/usr/bin/env node
// On-chain ERC-1271 verification gate for the Kernel v3.3 + P256Validator wallet.
//
// Calls `account.isValidSignature(hash, signature)` via eth_call and checks for
// the magic value 0x1626ba7e. This is the end-to-end proof that the Swift
// Kernel-wrap (EthHashing.kernelWrappedHash) + the host's 0x00||r||s envelope
// are accepted by the deployed account. Requires a DEPLOYED account on a chain
// with the P-256 precompile (Base Sepolia / Sepolia).
//
// Usage:
//   node verify-1271.mjs --account 0x.. --hash 0x<dappHash> --sig 0x00<r><s> \
//        [--rpc https://sepolia.base.org]
//
// `--hash` is the ORIGINAL dApp hash (EIP-191 personal-message hash or the
// EIP-712 typed-data digest) — NOT the Kernel-wrapped one; Kernel wraps it
// internally before calling the validator.
//
// Node 18+ (global fetch). Zero dependencies.

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, cur, i, arr) => {
    if (cur.startsWith("--")) acc.push([cur.slice(2), arr[i + 1]]);
    return acc;
  }, [])
);

const account = args.account;
const hash = args.hash;
const sig = args.sig;
const rpc = args.rpc || "https://sepolia.base.org";

if (!account || !hash || !sig) {
  console.error("usage: node verify-1271.mjs --account 0x.. --hash 0x.. --sig 0x.. [--rpc URL]");
  process.exit(2);
}

const SELECTOR = "1626ba7e"; // isValidSignature(bytes32,bytes)

function strip(h) { return h.replace(/^0x/, ""); }
function pad32(hex) { return hex.padStart(64, "0"); }
function rpad32(hex) {
  const rem = hex.length % 64;
  return rem === 0 ? hex : hex + "0".repeat(64 - rem);
}

const hashHex = pad32(strip(hash));
const sigHex = strip(sig);
const sigLen = pad32((sigHex.length / 2).toString(16));
const offset = pad32((0x40).toString(16)); // bytes32 + offset word = 2 words → data starts at 0x40

const calldata = "0x" + SELECTOR + hashHex + offset + sigLen + rpad32(sigHex);

const body = {
  jsonrpc: "2.0",
  id: 1,
  method: "eth_call",
  params: [{ to: account, data: calldata }, "latest"],
};

const res = await fetch(rpc, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});
const json = await res.json();

if (json.error) {
  console.error("eth_call error:", json.error.message);
  process.exit(1);
}

const result = strip(json.result || "");
const magic = result.slice(0, 8).toLowerCase();
console.log("account:    ", account);
console.log("rpc:        ", rpc);
console.log("raw result: ", json.result);
if (magic === SELECTOR) {
  console.log("RESULT: ✅ VALID (returned ERC-1271 magic 0x1626ba7e)");
  process.exit(0);
} else {
  console.log("RESULT: ❌ INVALID (expected 0x1626ba7e). Check: signed wrapped digest? low-s? account vs validator? domain version 0.3.3? account deployed + pubkey installed?");
  process.exit(1);
}
