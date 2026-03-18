# Bastion CLI Request Examples

## Setup

Rebuild the signed development app and restart the XPC service:

```bash
cd /Users/taek/workspace/bastion-app/bastion
./scripts/dev-rebuild-signed.sh
```

If `bastion` is not on your `PATH`, symlink the bundled sidecar:

```bash
BASTION_APP="$HOME/Applications/Bastion Dev.app"
sudo ln -sf "$BASTION_APP/Contents/MacOS/bastion-cli" /usr/local/bin/bastion
```

Or use the DerivedData path directly during development:

```bash
CLI="/Users/taek/Library/Developer/Xcode/DerivedData/bastion-gjbkchfvkjeiahfdhhrwhyoqrmyt/Build/Products/Debug/bastion.app/Contents/MacOS/bastion-cli"
alias bastion="$CLI"
```

---

## Status & Info

```bash
# Check if Bastion app is running
bastion status

# Get the P-256 public key and smart account address
bastion pubkey

# Get current rules for the calling client
bastion rules

# Get signing state (rate limit counters, spending limit totals)
bastion state
```

---

## Signing

### Raw Bytes

Signs 32 bytes directly — **no Ethereum prefix is applied**.

`--data` must be exactly 64 hex characters (32 bytes) with **no `0x` prefix**.

```bash
bastion sign --data deadbeefcafebabe1234567890abcdef1122334455667788aabbccddeeff0011
```

Requires `rawMessagePolicy.enabled = true` **and** `allowRawSigning = true` in Settings → Default Rules → Raw/Message.
When `enabled = false`, the request still goes through but always triggers the approval window.

---

### EIP-191 Personal Message

Prepends `\x19Ethereum Signed Message:\n{len}` before signing.

```bash
# Plain UTF-8 text
bastion eth message "Review this Bastion approval request"

# Multiple words
bastion eth message "Hello from Bastion test"

# Hex payload — 0x prefix causes it to be treated as raw bytes before EIP-191 wrapping
bastion eth message "0xdeadbeef"
```

Requires `rawMessagePolicy.enabled = true` for silent rule-based signing.
When `enabled = false`, always triggers the approval window.

---

### EIP-712 Typed Data

Signs a structured typed-data payload per EIP-712.

**Inline JSON:**

```bash
bastion eth typedData --json '{
  "types": {
    "EIP712Domain": [
      {"name":"name","type":"string"},
      {"name":"version","type":"string"},
      {"name":"chainId","type":"uint256"},
      {"name":"verifyingContract","type":"address"}
    ],
    "Permit": [
      {"name":"owner","type":"address"},
      {"name":"spender","type":"address"},
      {"name":"value","type":"uint256"},
      {"name":"nonce","type":"uint256"},
      {"name":"deadline","type":"uint256"}
    ]
  },
  "primaryType": "Permit",
  "domain": {
    "name": "Permit2",
    "version": "1",
    "chainId": 11155111,
    "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3"
  },
  "message": {
    "owner": "0x1234567890abcdef1234567890abcdef12345678",
    "spender": "0x7777777777777777777777777777777777777777",
    "value": "50000000",
    "nonce": "7",
    "deadline": "1710000000"
  }
}'
```

**From file:**

```bash
cat > /tmp/bastion-typedData-example.json <<'JSON'
{
  "types": {
    "EIP712Domain": [
      {"name":"name","type":"string"},
      {"name":"version","type":"string"},
      {"name":"chainId","type":"uint256"},
      {"name":"verifyingContract","type":"address"}
    ],
    "Permit": [
      {"name":"owner","type":"address"},
      {"name":"spender","type":"address"},
      {"name":"value","type":"uint256"},
      {"name":"nonce","type":"uint256"},
      {"name":"deadline","type":"uint256"}
    ]
  },
  "primaryType": "Permit",
  "domain": {
    "name": "Permit2",
    "version": "1",
    "chainId": 11155111,
    "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3"
  },
  "message": {
    "owner": "0x1234567890abcdef1234567890abcdef12345678",
    "spender": "0x7777777777777777777777777777777777777777",
    "value": "50000000",
    "nonce": "7",
    "deadline": "1710000000"
  }
}
JSON

bastion eth typedData --json-file /tmp/bastion-typedData-example.json
```

Requires `typedDataPolicy.enabled = true` for silent rule-based signing.
When `enabled = false`, always triggers the approval window.

---

### UserOperation (ERC-4337)

#### High-level `--op` (preferred)

Describe the action — Bastion builds the Kernel `execute()` calldata and full UserOperation.

```bash
# Single action: target, value (decimal or 0x hex), calldata (0x-prefixed hex)
bastion eth userOp --op 0x0000000000000000000000000000000000000001,0,0x

# Single action with ETH value
bastion eth userOp --op 0x0000000000000000000000000000000000000001,1000000000000000,0x

# Batch: two actions
bastion eth userOp \
  --op 0x0000000000000000000000000000000000000001,0,0x \
  --op 0x0000000000000000000000000000000000000002,1000000000000000,0x

# Sign and submit via ZeroDev (uses project ID from Settings → App Preferences)
bastion eth userOp --submit --op 0x0000000000000000000000000000000000000001,0,0x

# Sign, submit, and override the project ID
bastion eth userOp --submit --project-id <your-project-id> --op 0x0000000000000000000000000000000000000001,0,0x

# Target a specific chain (default: Sepolia 11155111)
bastion eth userOp --chain-id 8453 --op 0x0000000000000000000000000000000000000001,0,0x
```

#### Advanced: explicit UserOperation JSON

For replaying a fully formed UserOperation or debugging gas values.

```bash
bastion eth userOp --json '{
  "sender": "0x2dda58a793fe8b895f2b5d452f05fd9a0d4357af",
  "nonce": "0x01",
  "callData": "0xe9ae5c530000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000de0b6b3a7640000",
  "verificationGasLimit": "0x57749",
  "callGasLimit": "0x4623",
  "preVerificationGas": "0xd5d9",
  "maxPriorityFeePerGas": "0x233f76",
  "maxFeePerGas": "0x233f83",
  "chainId": 11155111,
  "entryPoint": "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
  "entryPointVersion": "v0.7"
}'
```

From file:

```bash
cat > /tmp/bastion-userop-example.json <<'JSON'
{
  "sender": "0x2dda58a793fe8b895f2b5d452f05fd9a0d4357af",
  "nonce": "0x01",
  "callData": "0xe9ae5c53000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000034a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a9059cbb000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb9226600000000000000000000000000000000000000000000000000000000004c4b40",
  "factory": "0xd703aaE79538628d27099B8c4f621bE4CCd142d5",
  "factoryData": "0xc5265d5d",
  "verificationGasLimit": "0x57749",
  "callGasLimit": "0x4623",
  "preVerificationGas": "0xd5d9",
  "maxPriorityFeePerGas": "0x233f76",
  "maxFeePerGas": "0x233f83",
  "paymaster": "0x777777777777AeC03fd955926DbF81597e66834C",
  "paymasterVerificationGasLimit": "0x8a8e",
  "paymasterPostOpGasLimit": "0x01",
  "paymasterData": "0x0102030405",
  "chainId": 11155111,
  "entryPoint": "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
  "entryPointVersion": "v0.7"
}
JSON

bastion eth userOp --json-file /tmp/bastion-userop-example.json

# Sign and submit
bastion eth userOp --submit --json-file /tmp/bastion-userop-example.json
```

Requires `rules.enabled = true` for silent rule-based signing.
When `enabled = false` or `requireExplicitApproval = true`, always triggers the approval window.

---

## Rule Behavior Quick Reference

| Sign type | `enabled = false` | `enabled = true`, sub-rule off | `enabled = true`, sub-rule on |
|---|---|---|---|
| Raw bytes | Approval window | **Denied** (`allowRawSigning = false`) | Allowed |
| EIP-191 message | Approval window | Allowed | Allowed |
| EIP-712 typed data | Approval window | Silent if domain/struct rules pass | — |
| UserOperation | Approval window | Silent if all rules pass | — |

Settings location:
- **Raw bytes / Message**: Settings → Default Rules → Raw/Message tab
- **EIP-712**: Settings → Default Rules → EIP-712 tab
- **UserOperation**: Settings → Default Rules → UserOperation tab

---

## Utility

```bash
# Convert raw bytes file to 0x-prefixed hex
xxd -p -c 1000 your-bytes.bin | tr -d '\n' | sed 's/^/0x/'

# Generate a random 32-byte hash for raw bytes testing (no 0x prefix)
openssl rand -hex 32
```
