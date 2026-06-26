# Bastion MCP Server & REST API

Bastion's production agent bridge is the signed Swift executable bundled at:

```bash
/Applications/Bastion.app/Contents/MacOS/bastion-mcp
```

It implements MCP stdio tools and a localhost REST API directly over
`com.bastion.xpc`. It does not spawn or depend on `bastion-cli`.

The TypeScript files in this directory are kept as a legacy development
reference for the original wrapper surface. Production DMG artifacts ship the
Swift `bastion-mcp` sidecar instead.

## MCP Setup

Add the bundled executable to your agent's MCP config:

```json
{
  "mcpServers": {
    "bastion": {
      "command": "/Applications/Bastion.app/Contents/MacOS/bastion-mcp",
      "env": {
        "BASTION_AGENT_PROFILE_ID": "<paired-profile-id>"
      }
    }
  }
}
```

First-time pairing:

1. Call `bastion_pair_agent` with a stable `agentIdentifier` and optional label.
2. Approve the pairing in Bastion.
3. Poll `bastion_poll_pairing` with the returned `requestId`.
4. Save the returned paired profile ID in `BASTION_AGENT_PROFILE_ID`.

Signing, rules, and state tools require a paired profile ID either in
`BASTION_AGENT_PROFILE_ID` or the tool argument `agentProfileId`.

## MCP Tools

**Pairing, signing, and status:**

| Tool | Description |
|------|-------------|
| `bastion_pair_agent` | Start owner-approved pairing for an agent behind the signed bridge |
| `bastion_poll_pairing` | Poll a pairing request |
| `bastion_status` | Check Bastion service status |
| `bastion_get_account` | Get P-256 public key and smart account address |
| `bastion_get_rules` | Get current effective signing rules |
| `bastion_get_state` | Get rate limit and spending counters |
| `bastion_sign_message` | Sign EIP-191 personal message |
| `bastion_sign_typed_data` | Sign EIP-712 typed data |
| `bastion_sign_raw` | Sign raw 32-byte hash |
| `bastion_send_user_op` | Build, sign, and optionally send a UserOperation |
| `bastion_sign_user_op_json` | Sign explicit UserOperation JSON |

**Wallet groups:**

| Tool | Description |
|------|-------------|
| `bastion_create_wallet_group` | Create a shared wallet group with a sudo owner |
| `bastion_list_wallet_groups` | List wallet groups |
| `bastion_get_wallet_group` | Show one group, members, and scoped rules |
| `bastion_add_agent_to_group` | Add an agent validator-scoped profile to a group |
| `bastion_remove_agent_from_group` | Remove an agent from a group |
| `bastion_update_agent_scope` | Update an agent's scoped rules |
| `bastion_mark_agent_installed` | Mark an agent validator installed after manual on-chain install |
| `bastion_install_agent_on_chain` | Build and optionally submit `installModule` UserOp |
| `bastion_uninstall_agent_on_chain` | Build and optionally submit `uninstallModule` UserOp |

## REST API

Run REST mode from the bundled bridge:

```bash
TOKEN="$(openssl rand -hex 32)"
BASTION_API_TOKEN="$TOKEN" /Applications/Bastion.app/Contents/MacOS/bastion-mcp rest
```

The server binds to `127.0.0.1` only. Every route, including `/health`, requires
`Authorization: Bearer <token>`. Browser-origin requests are rejected when an
`Origin` header is present. Request bodies are capped at 1 MiB.

Use the paired profile header for profile-scoped requests:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  -H "X-Bastion-Agent-Profile: <paired-profile-id>" \
  http://127.0.0.1:9587/account
```

### Endpoints

**Pairing, signing, and status:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Auth-gated liveness probe |
| POST | `/pair` | Start owner-approved agent pairing |
| GET | `/pair/:requestId` | Poll pairing status |
| GET | `/status` | Service info |
| GET | `/account` | Public key and smart account address |
| GET | `/rules` | Effective rules |
| GET | `/state` | Signing state |
| POST | `/sign/message` | Sign EIP-191 message |
| POST | `/sign/typed-data` | Sign EIP-712 typed data |
| POST | `/sign/raw` | Sign raw hash |
| POST | `/sign/user-op` | Build, sign, and optionally send UserOp |

**Wallet groups:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/groups` | List wallet groups |
| POST | `/groups` | Create wallet group |
| GET | `/groups/:id` | Show a group |
| POST | `/groups/:id/agents` | Add agent member |
| DELETE | `/groups/:id/agents/:memberId` | Remove agent member |
| PATCH | `/groups/:id/agents/:memberId/scope` | Update scoped rules |
| POST | `/groups/:id/agents/:memberId/install-on-chain` | Build and optionally send `installModule` UserOp |
| POST | `/groups/:id/agents/:memberId/uninstall-on-chain` | Build and optionally send `uninstallModule` UserOp |
| POST | `/groups/:id/agents/:memberId/installed` | Mark agent installed |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BASTION_AGENT_PROFILE_ID` | none | Paired profile ID used by MCP tools when `agentProfileId` is omitted |
| `BASTION_API_TOKEN` | required for REST | Bearer token; must pass the 128-bit estimated entropy and pattern checks |
| `BASTION_API_PORT` | `9587` | REST API port on `127.0.0.1` |

## Security Notes

- The production bridge is signed as `com.bastion.mcp` and must run from
  `Bastion.app/Contents/MacOS/bastion-mcp` to proxy agent profile identity.
- Profile-scoped requests use Bastion-managed paired agent profiles as the
  policy and audit identity.
- REST binds to `127.0.0.1` only and rejects `Origin` headers.
- REST requires bearer auth for all routes and refuses low-entropy or patterned
  tokens at startup.
- REST request bodies are capped at 1 MiB.
- Signing and UserOperation requests go through the same XPC rule engine,
  Secure Enclave signing flow, state counters, owner-auth prompts, and audit log
  as native app requests.
