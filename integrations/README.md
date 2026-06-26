# Bastion web-connect (browser extension)

Connect any browser dApp (Uniswap, etc.) to your **local Bastion wallet**. Bastion
appears in the wallet list via **EIP-6963**, exposes a standard **EIP-1193**
provider, and routes every request to the local Bastion app (rule engine +
approval + Secure Enclave signing).

This is the "connect the web to the local wallet" feature. It does not change how
Uniswap works — Uniswap just sees a wallet.

## Why a browser extension + native host (not direct HTTP)

Bastion's local API deliberately **rejects any request carrying an `Origin`
header** (CSRF guard), and browser fetches always send one. So the page/extension
can't call Bastion over HTTP. Instead:

```
dApp page ──EIP-6963/EIP-1193──▶ inpage provider (MAIN world)
                                       │ window.postMessage
                                       ▼
                                 content script (ISOLATED)
                                       │ chrome.runtime
                                       ▼
                                 background service worker
                                       │ chrome.runtime.connectNative
                                       ▼
                                 native host (host.mjs)  ── spawns ──▶ bastion-mcp (MCP stdio)
                                   holds BASTION_AGENT_PROFILE_ID                  │ XPC
                                                                                   ▼
                                                                            Bastion.app
                                                              rule engine + approval + SE sign
```

Native messaging is length-prefixed JSON over stdio (no HTTP, no Origin, no
bearer token). The host spawns `bastion-mcp` in MCP stdio mode and the read-only
JSON-RPC (`eth_call`, balances, gas, receipts) is forwarded to a public RPC for
the active chain.

## What works (M1)

- **Discovery + connect:** `eth_requestAccounts`, `eth_accounts`, `eth_chainId`,
  `wallet_switchEthereumChain`, events (`connect`, `accountsChanged`,
  `chainChanged`).
- **Reads:** `eth_call`, `eth_getBalance`, `eth_estimateGas`, `eth_gasPrice`,
  `eth_getTransactionReceipt`, `eth_blockNumber`, … (RPC passthrough).
- **First-run pairing** from the extension popup (approve a code in the Bastion
  menu bar).
- **Signing (M2):** `personal_sign` and `eth_signTypedData_v4` (Permit2) return a
  **Kernel v3.3 ERC-1271 signature** — the app signs the Kernel-wrapped digest
  (`EthHashing.kernelWrappedHash`, bound to the account + active chain) and the
  host assembles the root envelope `0x00 ‖ r ‖ s`, which `account.isValidSignature`
  accepts. The account must be deployed first (see counterfactual note).
- **Send (M3):** `eth_sendTransaction` → UserOp → bundler → returns the inner tx
  hash once mined.

## Prerequisites

- macOS with **Bastion.app installed and running** (`bastion-cli status` works).
- **Node 18+** (`node -v`).
- A Chromium-family browser (Chrome / Brave / Edge / Arc).

## Install

1. **Load the extension** (unpacked):
   - `chrome://extensions` → enable Developer mode → "Load unpacked" →
     select `integrations/extension/`.
   - Copy the extension's **ID** from its card.

2. **Register the native host** with that ID:
   ```bash
   integrations/native-host/scripts/install-host.sh <EXTENSION_ID>
   ```
   This writes a launcher (pinning your `node` path) and installs
   `app.bastion.host.json` into each browser's `NativeMessagingHosts/` dir.
   Restart the browser after installing.

3. **Pair** (first run): click the Bastion extension icon → "Connect to Bastion"
   → a pairing code appears → open the **Bastion menu-bar app** and confirm the
   matching code. The popup then shows your smart-account address. The paired
   profile id is stored in
   `~/Library/Application Support/Bastion/web-connect.json`.

## Use

Open a dApp (e.g. Uniswap, or `https://eip6963.org`), click "Connect wallet", and
pick **Bastion**. It connects to your local wallet; reads render; signs/sends pop
the Bastion approval UI.

### Config (`~/Library/Application Support/Bastion/web-connect.json`)

```json
{ "profileId": "<uuid>", "chainId": 84532, "rpcUrls": { "84532": "https://..." } }
```
Default chain is Base Sepolia (84532). `rpcUrls` overrides the built-in public RPC
per chain.

## ERC-1271 details (M2)

Kernel v3.3 does **not** use ERC-7739. For `isValidSignature(hash, sig)` it wraps
the dApp `hash` in a single EIP-712 envelope and routes `sig` to the root
validator. The signature the wallet produces is:

- digest signed `D = keccak256(0x1901 ‖ DS ‖ SH)`, `DS` = `EIP712Domain(name="Kernel",
  version="0.3.3", chainId, verifyingContract=account)`, `SH = keccak256(abi.encode(
  keccak256("Kernel(bytes32 hash)"), H))` — done in `EthHashing.kernelWrappedHash`
  (unit-cross-checked against Foundry `cast`).
- envelope `0x00 ‖ r ‖ s` (root validation type) — the deployed `P256Validator`
  (`contracts/src/P256Validator.sol`) `abi.decode`s the 64-byte `(r,s)`.

Verify on-chain once an account is deployed:

```bash
node integrations/native-host/scripts/verify-1271.mjs \
  --account 0x<smartAccount> --hash 0x<dappHash> --sig 0x00<r><s> \
  --rpc https://sepolia.base.org   # expects ✅ magic 0x1626ba7e
```

## Caveats / roadmap

- **Counterfactual accounts:** ERC-1271 needs deployed code and Permit2 does not
  support ERC-6492, so the host **refuses** `personal_sign`/`eth_signTypedData_v4`
  until the account is deployed (clear error). Send one `eth_sendTransaction`
  first (the initial UserOp deploys the account), then signatures verify.
- **Chains:** `P256Validator` (`0x9906…`) is deployed on **Base Sepolia + Sepolia**
  only — not Base/Eth mainnet yet. 1271/4337 flows require the validator on-chain.
- **eth_sendTransaction:** returns the inner tx hash once the UserOp is mined;
  long-pending bundler inclusion may time out the request.
- **Approvals:** every sign/send hits Bastion's approval popup; multi-step dApp
  flows mean multiple prompts. Session-key batching is future work.

## Testing the native host directly (no browser)

The host speaks Chrome native-messaging framing on stdio. Smoke test:

```bash
node integrations/native-host/host.mjs   # then feed it uint32-LE length + JSON frames
```
See the host's `dispatch()` for the message shapes (`state`, `rpc`, `pairStart`,
`pairPoll`). A passing run returns the chain id, an unpaired `eth_accounts` error
(4100), and a real `eth_blockNumber` via RPC passthrough.
