/**
 * Bastion MCP Server — exposes signing capabilities as MCP tools.
 * Runs over stdio (standard MCP transport).
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import * as cli from "./cli.js";

const server = new McpServer({
  name: "bastion",
  version: "0.1.0",
});

const MAX_RECEIPT_WAIT_SECONDS = 120;
const MAX_CHAIN_ID = 2_147_483_647;
const MAX_JSON_BYTES = 512 * 1024;
const MAX_DATA_CHARS = 256 * 1024;
const MAX_LABEL_CHARS = 128;
const MAX_PROJECT_ID_CHARS = 128;

// --- Tools ---

server.tool(
  "bastion_status",
  "Check if Bastion app is running and get service info",
  {},
  async () => {
    try {
      const info = await cli.status();
      return {
        content: [{ type: "text", text: JSON.stringify(info, null, 2) }],
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Error: ${(e as Error).message}` }],
        isError: true,
      };
    }
  },
);

server.tool(
  "bastion_get_account",
  "Get the P-256 public key and smart account address",
  {},
  async () => {
    try {
      const key = await cli.pubkey();
      return {
        content: [{ type: "text", text: JSON.stringify(key, null, 2) }],
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Error: ${(e as Error).message}` }],
        isError: true,
      };
    }
  },
);

server.tool(
  "bastion_get_rules",
  "Get the current effective signing rules for this client",
  {},
  async () => {
    try {
      const r = await cli.rules();
      return {
        content: [{ type: "text", text: JSON.stringify(r, null, 2) }],
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Error: ${(e as Error).message}` }],
        isError: true,
      };
    }
  },
);

server.tool(
  "bastion_get_state",
  "Get signing state (rate limit counters, spending totals)",
  {},
  async () => {
    try {
      const s = await cli.state();
      return {
        content: [{ type: "text", text: JSON.stringify(s, null, 2) }],
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Error: ${(e as Error).message}` }],
        isError: true,
      };
    }
  },
);

server.tool(
  "bastion_sign_message",
  "Sign an EIP-191 personal message. Returns P-256 signature (r, s) and public key.",
  { message: z.string().max(64 * 1024).describe("The message text to sign") },
  async ({ message }) => {
    try {
      const sig = await cli.signMessage(message);
      return {
        content: [{ type: "text", text: JSON.stringify(sig, null, 2) }],
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Error: ${(e as Error).message}` }],
        isError: true,
      };
    }
  },
);

server.tool(
  "bastion_sign_typed_data",
  "Sign EIP-712 typed data. Provide the full EIP-712 JSON (types, primaryType, domain, message).",
  {
    typedData: z
      .string()
      .max(512 * 1024)
      .describe("Full EIP-712 typed data JSON string"),
  },
  async ({ typedData }) => {
    try {
      const sig = await cli.signTypedData(typedData);
      return {
        content: [{ type: "text", text: JSON.stringify(sig, null, 2) }],
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Error: ${(e as Error).message}` }],
        isError: true,
      };
    }
  },
);

server.tool(
  "bastion_sign_raw",
  "Sign a raw 32-byte hash (64 hex characters, no 0x prefix). No Ethereum prefix applied.",
  {
    data: z
      .string()
      .regex(/^(0x)?[0-9a-fA-F]{64}$/, "data must be 32 bytes of hex (64 chars, optional 0x prefix)")
      .describe("32-byte hex hash to sign (64 hex chars, no 0x prefix)"),
  },
  async ({ data }) => {
    try {
      const sig = await cli.signRawBytes(data);
      return {
        content: [{ type: "text", text: JSON.stringify(sig, null, 2) }],
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Error: ${(e as Error).message}` }],
        isError: true,
      };
    }
  },
);

const HEX_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const HEX_BYTES_RE = /^0x([0-9a-fA-F]{2})*$/;
const TX_HASH_RE = /^0x[0-9a-fA-F]{64}$/;
const UINT_RE = /^([0-9]+|0x[0-9a-fA-F]+)$/;
const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

const chainIdSchema = z
  .number()
  .int()
  .min(1)
  .max(MAX_CHAIN_ID);
const walletIdSchema = z.string().regex(UUID_RE, "id must be a UUID");
const labelSchema = z.string().min(1).max(MAX_LABEL_CHARS);
const jsonArgSchema = z.string().max(MAX_JSON_BYTES);
const projectIdSchema = z.string().min(1).max(MAX_PROJECT_ID_CHARS).optional();
const txHashSchema = z
  .string()
  .regex(TX_HASH_RE, "txHash must be a 0x-prefixed 32-byte hash");
const validatorAddressSchema = z
  .string()
  .regex(HEX_ADDRESS_RE, "validatorAddress must be a 0x-prefixed 20-byte hex address");

const userOpActionSchema = z.object({
  target: z
    .string()
    .regex(HEX_ADDRESS_RE, "target must be a 0x-prefixed 20-byte hex address")
    .describe("Target contract address (0x...)"),
  value: z
    .string()
    .regex(UINT_RE, "value must be a decimal or 0x-hex non-negative integer")
    .default("0")
    .describe("ETH value in wei (decimal or 0x hex)"),
  data: z
    .string()
    .max(MAX_DATA_CHARS)
    .regex(HEX_BYTES_RE, "data must be 0x-prefixed hex bytes")
    .refine((s) => !s.includes(","), "data must not contain commas")
    .default("0x")
    .describe("Calldata (0x-prefixed hex, or 0x for empty)"),
});

server.tool(
  "bastion_send_user_op",
  `Build, sign, and optionally send an ERC-4337 UserOperation via Kernel v3.3.
Each action is a (target, value, calldata) tuple. Multiple actions = batch execution.
Set send=true to submit via ZeroDev bundler after signing.`,
  {
    actions: z
      .array(userOpActionSchema)
      .min(1)
      .max(cli.MAX_USER_OP_ACTIONS)
      .describe("One or more execution actions"),
    send: z
      .boolean()
      .default(false)
      .describe("Submit the signed UserOp to the bundler"),
    chainId: chainIdSchema
      .optional()
      .describe("Target chain ID (default: 11155111 Sepolia)"),
    projectId: projectIdSchema
      .describe("Override ZeroDev project ID"),
  },
  async ({ actions, send, chainId, projectId }) => {
    try {
      const sig = await cli.sendUserOp({
        actions,
        send,
        chainId,
        projectId,
      });
      return {
        content: [{ type: "text", text: JSON.stringify(sig, null, 2) }],
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Error: ${(e as Error).message}` }],
        isError: true,
      };
    }
  },
);

server.tool(
  "bastion_sign_user_op_json",
  "Sign an explicit ERC-4337 UserOperation from full JSON. For advanced use — prefer bastion_send_user_op for high-level actions. Set send=true to submit via ZeroDev after signing.",
  {
    userOpJson: z
      .string()
      .max(MAX_JSON_BYTES)
      .describe("Full UserOperation JSON string"),
    send: z
      .boolean()
      .default(false)
      .describe("Submit the signed UserOp to the bundler"),
    projectId: projectIdSchema
      .describe("Override ZeroDev project ID"),
  },
  async ({ userOpJson, send, projectId }) => {
    try {
      const sig = await cli.signUserOpJson({ userOpJson, send, projectId });
      return {
        content: [{ type: "text", text: JSON.stringify(sig, null, 2) }],
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Error: ${(e as Error).message}` }],
        isError: true,
      };
    }
  },
);

// --- Wallet Group Tools ---

server.tool(
  "bastion_create_wallet_group",
  "Create a shared wallet group. The caller becomes the sudo owner with a fresh Secure Enclave key. Requires biometric/passcode auth on the Bastion host.",
  {
    label: labelSchema.describe("Human-readable label for the group, e.g. 'Team Alpha'"),
    chainIds: z
      .array(chainIdSchema)
      .optional()
      .describe("Chain IDs where this wallet will be deployed. Used for on-chain install targeting."),
    sharedRulesJson: jsonArgSchema
      .optional()
      .describe("Optional JSON of RuleConfig that applies to ALL agents in this group (intersection semantics with per-agent scope)."),
  },
  async ({ label, chainIds, sharedRulesJson }) => {
    try {
      const group = await cli.createWalletGroup({ label, chainIds, sharedRulesJson });
      return {
        content: [{ type: "text", text: JSON.stringify(group, null, 2) }],
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Error: ${(e as Error).message}` }],
        isError: true,
      };
    }
  },
);

server.tool(
  "bastion_list_wallet_groups",
  "List all wallet groups the owner has created, including members and their validator install status.",
  {},
  async () => {
    try {
      const out = await cli.listWalletGroups();
      return {
        content: [{ type: "text", text: JSON.stringify(out, null, 2) }],
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Error: ${(e as Error).message}` }],
        isError: true,
      };
    }
  },
);

server.tool(
  "bastion_get_wallet_group",
  "Get a single wallet group by id with full member details.",
  {
    groupId: walletIdSchema.describe("The wallet group id (UUID)"),
  },
  async ({ groupId }) => {
    try {
      const group = await cli.getWalletGroup(groupId);
      return {
        content: [{ type: "text", text: JSON.stringify(group, null, 2) }],
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Error: ${(e as Error).message}` }],
        isError: true,
      };
    }
  },
);

server.tool(
  "bastion_add_agent_to_group",
  "Add a new agent to a wallet group with scoped signing powers. A fresh P-256 SE key is provisioned for the agent. The owner must submit the on-chain validator install UserOp separately, then call bastion_mark_agent_installed. Requires owner biometric auth.",
  {
    groupId: walletIdSchema.describe("Target wallet group id"),
    label: labelSchema.optional().describe("Human-readable label for the agent"),
    clientProfileId: walletIdSchema
      .optional()
      .describe("Optional existing ClientProfile id to bind this membership to. If omitted, link later with a separate call."),
    scopedRulesJson: jsonArgSchema
      .optional()
      .describe("JSON of RuleConfig scoped to this agent (selectors, targets, spending caps)"),
  },
  async ({ groupId, label, clientProfileId, scopedRulesJson }) => {
    try {
      const member = await cli.addAgentToGroup({
        groupId,
        label,
        clientProfileId,
        scopedRulesJson,
      });
      return {
        content: [{ type: "text", text: JSON.stringify(member, null, 2) }],
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Error: ${(e as Error).message}` }],
        isError: true,
      };
    }
  },
);

server.tool(
  "bastion_remove_agent_from_group",
  "Revoke an agent's membership. Deletes the agent's Secure Enclave key and unbinds its ClientProfile. Bastion will refuse to sign for this agent immediately; the on-chain validator uninstall is the owner's responsibility unless Phase 2 auto-uninstall is enabled.",
  {
    groupId: walletIdSchema.describe("Wallet group id"),
    memberId: walletIdSchema.describe("Agent membership id to revoke"),
    txHash: txHashSchema
      .optional()
      .describe("Optional tx hash if the on-chain uninstall has already been submitted"),
  },
  async ({ groupId, memberId, txHash }) => {
    try {
      await cli.removeAgentFromGroup(groupId, memberId, txHash);
      return {
        content: [
          {
            type: "text",
            text: `Agent ${memberId} revoked from group ${groupId}.`,
          },
        ],
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Error: ${(e as Error).message}` }],
        isError: true,
      };
    }
  },
);

server.tool(
  "bastion_update_agent_scope",
  "Update an agent's scoped signing rules. Requires owner biometric auth.",
  {
    groupId: walletIdSchema.describe("Wallet group id"),
    memberId: walletIdSchema.describe("Agent membership id"),
    scopedRulesJson: jsonArgSchema
      .describe("Full JSON of the new RuleConfig to apply to this agent"),
  },
  async ({ groupId, memberId, scopedRulesJson }) => {
    try {
      await cli.updateAgentScope(groupId, memberId, scopedRulesJson);
      return {
        content: [
          {
            type: "text",
            text: `Scope updated for agent ${memberId} in group ${groupId}.`,
          },
        ],
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Error: ${(e as Error).message}` }],
        isError: true,
      };
    }
  },
);

server.tool(
  "bastion_mark_agent_installed",
  "Record that an agent's validator module has been installed on-chain. Phase 1: the owner submits the install UserOp manually and calls this to update Bastion's view. Phase 2: Bastion will submit the UserOp itself and call this internally.",
  {
    groupId: walletIdSchema.describe("Wallet group id"),
    memberId: walletIdSchema.describe("Agent membership id"),
    txHash: txHashSchema.describe("Transaction hash of the install UserOp"),
    validatorAddress: validatorAddressSchema
      .optional()
      .describe("On-chain validator module address bound to this agent, if different from the default P256Validator"),
  },
  async ({ groupId, memberId, txHash, validatorAddress }) => {
    try {
      const member = await cli.markAgentInstalled(
        groupId,
        memberId,
        txHash,
        validatorAddress,
      );
      return {
        content: [{ type: "text", text: JSON.stringify(member, null, 2) }],
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Error: ${(e as Error).message}` }],
        isError: true,
      };
    }
  },
);

// --- Phase 2 on-chain install tools ---

server.tool(
  "bastion_install_agent_on_chain",
  "Phase 2: build and optionally submit the owner-signed UserOp that installs an agent's validator module on the group's Kernel smart account via ERC-7579 installModule. Set submit=true to send it via ZeroDev and poll for a receipt. Requires owner biometric auth.",
  {
    groupId: walletIdSchema.describe("Wallet group id"),
    memberId: walletIdSchema.describe("Agent membership id"),
    chainId: chainIdSchema.describe("Target chain id (must have a bundler + RPC configured)"),
    submit: z
      .boolean()
      .optional()
      .describe("If true, submit the signed UserOp via ZeroDev. Default false — returns the signed UserOp for the caller to submit."),
    projectId: projectIdSchema
      .describe("ZeroDev project id override (falls back to Bastion's configured default)"),
    waitForReceiptSeconds: z
      .number()
      .int()
      .min(0)
      .max(MAX_RECEIPT_WAIT_SECONDS)
      .optional()
      .describe("How long to poll for a UserOp receipt. 0 = don't wait. Default 30s."),
  },
  async ({ groupId, memberId, chainId, submit, projectId, waitForReceiptSeconds }) => {
    try {
      const result = await cli.installAgentOnChain({
        groupId,
        memberId,
        chainId,
        submit,
        projectId,
        waitForReceiptSeconds,
      });
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Error: ${(e as Error).message}` }],
        isError: true,
      };
    }
  },
);

server.tool(
  "bastion_uninstall_agent_on_chain",
  "Phase 2: inverse of bastion_install_agent_on_chain. Submits ERC-7579 uninstallModule for the agent's validator. Requires owner biometric auth.",
  {
    groupId: walletIdSchema.describe("Wallet group id"),
    memberId: walletIdSchema.describe("Agent membership id"),
    chainId: chainIdSchema.describe("Target chain id"),
    submit: z.boolean().optional(),
    projectId: projectIdSchema,
    waitForReceiptSeconds: z.number().int().min(0).max(MAX_RECEIPT_WAIT_SECONDS).optional(),
  },
  async ({ groupId, memberId, chainId, submit, projectId, waitForReceiptSeconds }) => {
    try {
      const result = await cli.uninstallAgentOnChain({
        groupId,
        memberId,
        chainId,
        submit,
        projectId,
        waitForReceiptSeconds,
      });
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Error: ${(e as Error).message}` }],
        isError: true,
      };
    }
  },
);

// --- Start ---

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Bastion MCP server running on stdio");
}

main().catch((e) => {
  console.error("Fatal:", e);
  process.exit(1);
});
