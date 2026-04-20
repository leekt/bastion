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
  { message: z.string().describe("The message text to sign") },
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

const userOpActionSchema = z.object({
  target: z.string().describe("Target contract address (0x...)"),
  value: z
    .string()
    .default("0")
    .describe("ETH value in wei (decimal or 0x hex)"),
  data: z
    .string()
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
      .describe("One or more execution actions"),
    send: z
      .boolean()
      .default(false)
      .describe("Submit the signed UserOp to the bundler"),
    chainId: z
      .number()
      .optional()
      .describe("Target chain ID (default: 11155111 Sepolia)"),
    projectId: z
      .string()
      .optional()
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
  "Sign an explicit ERC-4337 UserOperation from full JSON. For advanced use — prefer bastion_send_user_op for high-level actions.",
  {
    userOpJson: z
      .string()
      .describe("Full UserOperation JSON string"),
  },
  async ({ userOpJson }) => {
    try {
      const sig = await cli.signUserOpJson(userOpJson);
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
    label: z.string().describe("Human-readable label for the group, e.g. 'Team Alpha'"),
    chainIds: z
      .array(z.number().int())
      .optional()
      .describe("Chain IDs where this wallet will be deployed. Used for on-chain install targeting."),
    sharedRulesJson: z
      .string()
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
    groupId: z.string().describe("The wallet group id (UUID)"),
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
    groupId: z.string().describe("Target wallet group id"),
    label: z.string().optional().describe("Human-readable label for the agent"),
    clientProfileId: z
      .string()
      .optional()
      .describe("Optional existing ClientProfile id to bind this membership to. If omitted, link later with a separate call."),
    scopedRulesJson: z
      .string()
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
    groupId: z.string().describe("Wallet group id"),
    memberId: z.string().describe("Agent membership id to revoke"),
    txHash: z
      .string()
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
    groupId: z.string().describe("Wallet group id"),
    memberId: z.string().describe("Agent membership id"),
    scopedRulesJson: z
      .string()
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
    groupId: z.string().describe("Wallet group id"),
    memberId: z.string().describe("Agent membership id"),
    txHash: z.string().describe("Transaction hash of the install UserOp"),
    validatorAddress: z
      .string()
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
