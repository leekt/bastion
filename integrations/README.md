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
- **Wired (M2/M3, see Caveats):** `personal_sign`, `eth_signTypedData_v4`,
  `eth_sendTransaction` route through to Bastion, but signatures are returned in
  Bastion's raw P-256 form — see the EIP-1271 caveat.

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

## Caveats / roadmap

- **EIP-1271 (M2):** smart-account signatures (Permit2, off-chain orders) must be
  verified via `account.isValidSignature`. The host currently returns Bastion's
  raw P-256 `(r,s)`; it still needs the Kernel v3.3 ERC-7579 1271 wrapper. Until
  then, dApp flows that verify signatures off-chain (Permit2) won't validate.
- **Counterfactual accounts:** an undeployed smart account can't satisfy EIP-1271
  (no code) and Permit2 doesn't support ERC-6492. Deploy the account (first
  `eth_sendTransaction`) before relying on signature verification.
- **eth_sendTransaction (M3):** returns the inner tx hash once the UserOp is mined;
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
