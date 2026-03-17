# Bastion CLI Request Examples

These examples are for opening Bastion's approval UI from the CLI.

## Before you run them

1. Rebuild the signed development app and restart the XPC service:

```bash
cd /Users/taek/workspace/bastion-app/bastion
./scripts/dev-rebuild-signed.sh
```

2. If `bastion` is not on your `PATH`, symlink the bundled sidecar executable from the fixed signed build path:

```bash
BASTION_APP="$HOME/Applications/Bastion Dev.app"
sudo ln -sf "$BASTION_APP/Contents/MacOS/bastion-cli" /usr/local/bin/bastion
```

3. In `Default -> App Preferences`, set:
- `ZeroDev Project ID` if you plan to use `--submit`
- `Chain RPC Endpoints` for any chain you want Bastion to query directly

4. Start `Bastion.app` if it is not already running.

## Personal message

```bash
bastion eth message "Review this Bastion approval request"
```

## EIP-712 typed data

Save the request first:

```bash
cat > /tmp/bastion-typedData-example.json <<'JSON'
{
  "types": {
    "EIP712Domain": [
      { "name": "name", "type": "string" },
      { "name": "version", "type": "string" },
      { "name": "chainId", "type": "uint256" },
      { "name": "verifyingContract", "type": "address" }
    ],
    "Permit": [
      { "name": "owner", "type": "address" },
      { "name": "spender", "type": "address" },
      { "name": "value", "type": "uint256" },
      { "name": "nonce", "type": "uint256" },
      { "name": "deadline", "type": "uint256" }
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
```

Then send it:

```bash
bastion eth typedData --json-file /tmp/bastion-typedData-example.json
```

## ERC-4337 UserOperation from `--op`

This is the preferred path. The CLI only describes the action, and Bastion builds the Kernel `execute()` calldata plus the final ERC-4337 UserOperation inside the app.

Single action:

```bash
bastion eth userOp \
  --op 0x0000000000000000000000000000000000000001,0,0x
```

Batch action:

```bash
bastion eth userOp \
  --op 0x0000000000000000000000000000000000000001,0,0x \
  --op 0x0000000000000000000000000000000000000002,1000000000000000,0x
```

`value` accepts decimal or `0x` hex. `data` must be `0x`-prefixed hex.

## ERC-4337 UserOperation with bundler submission

If you want Bastion to submit the signed UserOperation immediately after approval:

```bash
bastion eth userOp \
  --submit \
  --op 0x0000000000000000000000000000000000000001,0,0x
```

`--submit` uses the ZeroDev project ID configured in `Default -> App Preferences`. `--project-id` is still accepted as a temporary override for debugging.

## Advanced: explicit UserOperation JSON

This path is mainly for debugging or replaying a fully formed UserOperation.

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
```

Then send it:

```bash
bastion eth userOp --json-file /tmp/bastion-userop-example.json
```

The response JSON includes a `submission` object. Bastion's `Audit History` window groups the entire request into one row and shows the request timeline there, including:

- `Signed`
- `Submitted`
- `Confirmed`
- `Receipt Failed`
- `Receipt Pending`
- `Send Failed`

When the bundler confirms or fails the request, Bastion also posts a native macOS notification. Clicking that notification opens `Audit History`.

## Converting bytes to hex for UserOperation fields

If you want to replace the sample `callData` with your own bytes:

```bash
printf '%s' '<hex-without-0x>' | sed 's/^/0x/'
```

If you already have raw bytes:

```bash
xxd -p -c 1000 your-bytes.bin | tr -d '\n' | sed 's/^/0x/'
```
