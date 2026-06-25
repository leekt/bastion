# Bastion MCP Server & REST API

AI agent integration layer for Bastion. Wraps `bastion-cli` to expose signing capabilities via MCP (Model Context Protocol) and REST.

## Quick Start

```bash
cd mcp
bun install --frozen-lockfile

# MCP server (stdio transport — for Claude, Cursor, etc.)
bun run mcp

# REST API (localhost HTTP — for any language/tool)
BASTION_API_TOKEN="$(openssl rand -hex 32)" bun run rest
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

**Signing & status:**

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

**Wallet groups (sudo owner + scoped agents):**

| Tool | Description |
|------|-------------|
| `bastion_create_wallet_group` | Create a new shared wallet group with a sudo owner |
| `bastion_list_wallet_groups` | List all wallet groups |
| `bastion_get_wallet_group` | Show one group, its members, and per-agent scoped rules |
| `bastion_add_agent_to_group` | Add an agent (validator-scoped client) to a group |
| `bastion_remove_agent_from_group` | Remove an agent from a group |
| `bastion_update_agent_scope` | Update an agent's scoped rules (rate / spending / target lists) |
| `bastion_mark_agent_installed` | Mark agent validator as installed (manual override) |
| `bastion_install_agent_on_chain` | Build + sign + send the on-chain `installModule` UserOp for the agent validator |
| `bastion_uninstall_agent_on_chain` | Build + sign + send the on-chain `uninstallModule` UserOp |

## REST API

Binds to `127.0.0.1` only. Requires bearer token authentication. The token
must be provided through `BASTION_API_TOKEN`; the server refuses to generate or
write a bearer credential to disk.

```bash
# Start with an explicit high-entropy token
BASTION_API_TOKEN="$(openssl rand -hex 32)" bun run rest
```

### Endpoints

All routes require bearer auth (including `/health`). Browser-origin requests
are rejected at the edge — the `Origin` header on a request is treated as a
CSRF signal and refused with `403`.

**Signing & status:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Auth-gated liveness probe |
| GET | `/status` | Service info |
| GET | `/account` | Public key + address |
| GET | `/rules` | Effective rules |
| GET | `/state` | Signing state |
| POST | `/sign/message` | Sign EIP-191 message |
| POST | `/sign/typed-data` | Sign EIP-712 typed data |
| POST | `/sign/raw` | Sign raw hash |
| POST | `/sign/user-op` | Build + sign UserOp |

**Wallet groups:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/groups` | List all wallet groups |
| POST | `/groups` | Create a wallet group |
| GET | `/groups/:id` | Show a group with members and scoped rules |
| POST | `/groups/:id/agents` | Add an agent member |
| DELETE | `/groups/:id/agents/:memberId` | Remove an agent member |
| POST | `/groups/:id/agents/:memberId/install-on-chain` | Build + send `installModule` UserOp |
| POST | `/groups/:id/agents/:memberId/uninstall-on-chain` | Build + send `uninstallModule` UserOp |
| POST | `/groups/:id/agents/:memberId/installed` | Mark agent installed (manual override) |

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
| `BASTION_API_TOKEN` | Required | REST API bearer token; must pass a 128-bit estimated entropy check |
| `BASTION_API_PORT` | `9587` | REST API port |

## Security

- REST API binds to `127.0.0.1` only — no network exposure
- Bearer token required for **all** routes (including `/health`)
- Requests carrying an `Origin` header are rejected (`403`) — blocks CSRF from any local browser context that learns the token
- Request bodies are capped at 1 MiB; all string/JSON/hex inputs are length- and shape-validated before reaching the CLI
- UserOperation actions are capped by count and aggregate CLI argument size before spawning `bastion-cli`
- REST never auto-generates or writes bearer tokens to disk
- Low-entropy repeated or patterned bearer tokens are rejected at startup, even when they meet the length floor
- The CLI binary path is validated: configured and auto-detected paths must be absolute regular files and must not be world-writable
- All requests go through Bastion's rule engine (same as CLI)
- No key material is exposed — only signatures are returned
