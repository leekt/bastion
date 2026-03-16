# Bastion CLI Request Examples

These examples are for opening Bastion's approval UI from the CLI.

## Before you run them

1. Start `Bastion.app`.
2. If `bastion` is not on your `PATH`, symlink the bundled sidecar executable:

```bash
BASTION_APP=$(find ~/Library/Developer/Xcode/DerivedData -path "*/Build/Products/*/bastion.app" -type d | head -1)
sudo ln -sf "$BASTION_APP/Contents/MacOS/bastion-cli" /usr/local/bin/bastion
```

3. In Rules Settings, enable `Require explicit approval even when the request is within policy`.

If you leave that toggle off, Bastion only shows the popup when a request violates the active rules.

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

## ERC-4337 UserOperation

This sample is only for opening the approval popup. It does not need to be on-chain valid.

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

## Converting bytes to hex for UserOperation fields

If you want to replace the sample `callData` with your own bytes:

```bash
printf '%s' '<hex-without-0x>' | sed 's/^/0x/'
```

If you already have raw bytes:

```bash
xxd -p -c 1000 your-bytes.bin | tr -d '\n' | sed 's/^/0x/'
```
