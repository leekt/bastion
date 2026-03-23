# Bastion MCP Server & REST API

AI agent integration layer for Bastion. Wraps `bastion-cli` to expose signing capabilities via MCP (Model Context Protocol) and REST.

## Quick Start

```bash
cd mcp
bun install

# MCP server (stdio transport — for Claude, Cursor, etc.)
bun run mcp

# REST API (localhost HTTP — for any language/tool)
bun run rest
```

## MCP Server

Runs on stdio. Add to your Claude Code config:

```json
{
  "mcpServers": {
    "bastion": {
      "command": "bun",
      "args": ["run", "/path/to/bastion/mcp/src/mcp-server.ts"],
      "env": {
        "BASTION_CLI_PATH": "/path/to/bastion-cli"
      }
    }
  }
}
```

### Available Tools

| Tool | Description |
|------|-------------|
| `bastion_status` | Check if Bastion app is running |
| `bastion_get_account` | Get P-256 public key + smart account address |
| `bastion_get_rules` | Get current effective signing rules |
| `bastion_get_state` | Get rate limit + spending counters |
| `bastion_sign_message` | Sign EIP-191 personal message |
| `bastion_sign_typed_data` | Sign EIP-712 typed data |
| `bastion_sign_raw` | Sign raw 32-byte hash |
| `bastion_send_user_op` | Build + sign + optionally send UserOp |
| `bastion_sign_user_op_json` | Sign explicit UserOperation JSON |

## REST API

Binds to `127.0.0.1` only. Requires bearer token authentication.

```bash
# Start with auto-generated token (printed to console)
bun run rest

# Or set a fixed token
BASTION_API_TOKEN=mytoken bun run rest
```

### Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | No | Health check |
| GET | `/status` | Yes | Service info |
| GET | `/account` | Yes | Public key + address |
| GET | `/rules` | Yes | Effective rules |
| GET | `/state` | Yes | Signing state |
| POST | `/sign/message` | Yes | Sign EIP-191 message |
| POST | `/sign/typed-data` | Yes | Sign EIP-712 typed data |
| POST | `/sign/raw` | Yes | Sign raw hash |
| POST | `/sign/user-op` | Yes | Build + sign UserOp |

### Examples

```bash
TOKEN="your-token-here"

# Get account
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9587/account

# Sign a message
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello from agent"}' \
  http://127.0.0.1:9587/sign/message

# Send a UserOp (ETH transfer)
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"actions": [{"target": "0x...", "value": "1000000000000000", "data": "0x"}], "send": true}' \
  http://127.0.0.1:9587/sign/user-op
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BASTION_CLI_PATH` | Auto-detect | Path to `bastion-cli` binary |
| `BASTION_API_TOKEN` | Random | REST API bearer token |
| `BASTION_API_PORT` | `9587` | REST API port |

## Security

- REST API binds to `127.0.0.1` only — no network exposure
- Bearer token required for all signing/read endpoints
- All requests go through Bastion's rule engine (same as CLI)
- No key material is exposed — only signatures are returned
