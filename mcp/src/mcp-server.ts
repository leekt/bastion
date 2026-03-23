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
