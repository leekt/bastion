#!/usr/bin/env node
// Bastion web-connect — Chrome native-messaging host.
//
// Chrome launches this process when the extension calls
// chrome.runtime.connectNative("app.bastion.host"). It speaks Chrome's
// native-messaging framing on stdin/stdout (uint32-LE length prefix + JSON),
// and bridges EIP-1193 requests from the page to the local Bastion wallet by
// spawning `bastion-mcp` in MCP stdio mode (no HTTP, no token, no Origin issue).
//
// Read-only JSON-RPC (eth_call, balances, gas, receipts) is forwarded to a
// public RPC for the active chain. Writes/signs go to Bastion, which applies
// its rule engine + approval + Secure Enclave signing.
//
// Node 18+ (global fetch). Zero dependencies.

import { spawn } from "node:child_process";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

// ---------------------------------------------------------------- config

const SUPPORT_DIR = join(homedir(), "Library", "Application Support", "Bastion");
const CONFIG_PATH = join(SUPPORT_DIR, "web-connect.json");

const DEFAULT_RPCS = {
  1: "https://eth.llamarpc.com",
  8453: "https://mainnet.base.org",
  84532: "https://sepolia.base.org",
  11155111: "https://ethereum-sepolia-rpc.publicnode.com",
  42161: "https://arb1.arbitrum.io/rpc",
  10: "https://mainnet.optimism.io",
  137: "https://polygon-rpc.com",
};

function loadConfig() {
  try {
    const cfg = JSON.parse(readFileSync(CONFIG_PATH, "utf8"));
    return { chainId: 84532, rpcUrls: {}, ...cfg };
  } catch {
    return { profileId: null, chainId: 84532, rpcUrls: {} };
  }
}

function saveConfig(cfg) {
  try {
    mkdirSync(SUPPORT_DIR, { recursive: true });
    writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2));
  } catch (e) {
    log("config save failed: " + e.message);
  }
}

let config = loadConfig();

function rpcUrl(chainId) {
  return config.rpcUrls?.[chainId] || DEFAULT_RPCS[chainId] || null;
}

function resolveMcpPath() {
  const candidates = [
    process.env.BASTION_MCP_PATH,
    join(homedir(), "Applications", "Bastion Dev.app", "Contents", "MacOS", "bastion-mcp"),
    "/Applications/Bastion.app/Contents/MacOS/bastion-mcp",
  ].filter(Boolean);
  return candidates.find((p) => existsSync(p)) || null;
}

// stderr is the only safe place to log — stdout is the framed Chrome channel.
function log(msg) {
  process.stderr.write(`[bastion-host] ${msg}\n`);
}

// ---------------------------------------------------- MCP stdio client

class McpClient {
  constructor() {
    this.proc = null;
    this.buf = "";
    this.nextId = 1;
    this.pending = new Map();
    this.profileId = null;
  }

  start(profileId) {
    this.stop();
    this.profileId = profileId || null;
    const bin = resolveMcpPath();
    if (!bin) throw new Error("bastion-mcp not found. Is Bastion.app installed?");
    const env = { ...process.env };
    if (profileId) env.BASTION_AGENT_PROFILE_ID = profileId;
    else delete env.BASTION_AGENT_PROFILE_ID;

    this.proc = spawn(bin, [], { env, stdio: ["pipe", "pipe", "inherit"] });
    this.proc.on("exit", (code) => {
      log(`bastion-mcp exited (${code})`);
      for (const { reject } of this.pending.values()) reject(new Error("bastion-mcp exited"));
      this.pending.clear();
      this.proc = null;
    });
    this.proc.stdout.on("data", (chunk) => this._onData(chunk));

    // MCP initialize handshake (fire-and-forget; the server replies but we
    // don't gate tool calls on it — bastion-mcp answers tools immediately).
    this._send("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "bastion-web-connect", version: "0.1.0" },
    }).catch(() => {});
  }

  stop() {
    if (this.proc) {
      try { this.proc.kill(); } catch {}
      this.proc = null;
    }
  }

  ensure(profileId) {
    if (!this.proc || this.profileId !== (profileId || null)) this.start(profileId);
  }

  _onData(chunk) {
    this.buf += chunk.toString("utf8");
    let nl;
    while ((nl = this.buf.indexOf("\n")) >= 0) {
      const line = this.buf.slice(0, nl);
      this.buf = this.buf.slice(nl + 1);
      if (!line.trim()) continue;
      let msg;
      try { msg = JSON.parse(line); } catch { continue; }
      const entry = this.pending.get(msg.id);
      if (!entry) continue;
      this.pending.delete(msg.id);
      if (msg.error) entry.reject(new Error(msg.error.message || "mcp error"));
      else entry.resolve(msg.result);
    }
  }

  _send(method, params) {
    const id = this.nextId++;
    const payload = JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n";
    return new Promise((resolve, reject) => {
      if (!this.proc) return reject(new Error("bastion-mcp not running"));
      this.pending.set(id, { resolve, reject });
      this.proc.stdin.write(payload);
    });
  }

  // Call an MCP tool and return its parsed JSON payload (tools return
  // { content: [{ type: "text", text: "<json|message>" }], isError? }).
  async callTool(name, args = {}) {
    const result = await this._send("tools/call", { name, arguments: args });
    const text = result?.content?.[0]?.text ?? "";
    if (result?.isError) throw new Error(text || `${name} failed`);
    try { return JSON.parse(text); } catch { return { text }; }
  }
}

const mcp = new McpClient();

// ---------------------------------------------------- EIP-1193 handling

const READ_METHODS = new Set([
  "eth_call", "eth_getBalance", "eth_estimateGas", "eth_gasPrice",
  "eth_maxPriorityFeePerGas", "eth_feeHistory", "eth_blockNumber",
  "eth_getBlockByNumber", "eth_getBlockByHash", "eth_getCode",
  "eth_getTransactionByHash", "eth_getTransactionReceipt", "eth_getTransactionCount",
  "eth_getLogs", "eth_getStorageAt", "net_version",
]);

async function rpcPassthrough(method, params, chainId) {
  const url = rpcUrl(chainId);
  if (!url) throw new Error(`no RPC configured for chain ${chainId}`);
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: params || [] }),
  });
  const body = await res.json();
  if (body.error) throw new Error(body.error.message || "rpc error");
  return body.result;
}

function toHexChainId(chainId) {
  return "0x" + Number(chainId).toString(16);
}

async function requireAccount() {
  if (!config.profileId) {
    const err = new Error("Bastion is not connected yet. Open the Bastion extension and pair.");
    err.code = 4100; // EIP-1193 Unauthorized
    throw err;
  }
  mcp.ensure(config.profileId);
  const acct = await mcp.callTool("bastion_get_account", { agentProfileId: config.profileId });
  if (!acct.accountAddress) throw new Error("no account address from Bastion");
  return acct.accountAddress;
}

// ERC-1271 verification needs deployed code at the account, and Permit2 does NOT
// support ERC-6492 (counterfactual) signatures. So a smart-account signature is
// only verifiable once the account is deployed. eth_sendTransaction deploys it
// (initCode on first UserOp); until then, refuse 1271 signing with a clear error.
async function assertDeployed(account, chainId) {
  const code = await rpcPassthrough("eth_getCode", [account, "latest"], chainId);
  if (!code || code === "0x") {
    const err = new Error(
      `Smart account ${account} is not deployed on chain ${chainId}. Send a transaction first ` +
      `(the first UserOp deploys the account) before requesting an on-chain-verifiable signature. ` +
      `Permit2 does not support ERC-6492 counterfactual signatures.`
    );
    err.code = 4100;
    throw err;
  }
}

// Handle one EIP-1193 request. Returns the JSON-RPC `result`.
async function handleRpc(method, params) {
  switch (method) {
    case "eth_requestAccounts":
    case "eth_accounts":
      return [await requireAccount()];

    case "eth_chainId":
      return toHexChainId(config.chainId);

    case "net_version":
      return String(config.chainId);

    case "wallet_switchEthereumChain": {
      const target = parseInt(params?.[0]?.chainId, 16);
      if (!rpcUrl(target)) throw new Error(`chain ${target} not supported`);
      config.chainId = target;
      saveConfig(config);
      return null; // success → background emits chainChanged
    }

    case "personal_sign": {
      // params: [message, address]. The app signs the Kernel v3.3-wrapped digest
      // (bound to account + active chain); we assemble the root 1271 envelope.
      const acct = await requireAccount();
      await assertDeployed(acct, config.chainId);
      const message = hexToUtf8(params?.[0]);
      const sig = await mcp.callTool("bastion_sign_message", {
        message, chainId: config.chainId, agentProfileId: config.profileId,
      });
      return kernel1271Envelope(sig);
    }

    case "eth_signTypedData_v4": {
      // params: [address, typedDataJSON] (Permit2 etc.)
      const acct = await requireAccount();
      await assertDeployed(acct, config.chainId);
      const typedData = typeof params?.[1] === "string" ? params[1] : JSON.stringify(params?.[1]);
      const sig = await mcp.callTool("bastion_sign_typed_data", {
        typedData, chainId: config.chainId, agentProfileId: config.profileId,
      });
      return kernel1271Envelope(sig);
    }

    case "eth_sendTransaction": {
      // params: [{ to, value?, data? }] → UserOp → bundler → tx hash (M3)
      await requireAccount();
      const tx = params?.[0] || {};
      const r = await mcp.callTool("bastion_send_user_op", {
        actions: [{ target: tx.to, value: tx.value || "0x0", data: tx.data || "0x" }],
        send: true,
        chainId: config.chainId,
        agentProfileId: config.profileId,
      });
      const hash = r.transactionHash || r.txHash || r?.submission?.transactionHash;
      if (!hash) throw new Error("no transaction hash from Bastion (UserOp may still be pending)");
      return hash;
    }

    default:
      if (READ_METHODS.has(method)) return rpcPassthrough(method, params, config.chainId);
      throw new Error(`unsupported method: ${method}`);
  }
}

function hexToUtf8(value) {
  if (typeof value !== "string") return String(value ?? "");
  if (!value.startsWith("0x")) return value;
  return Buffer.from(value.slice(2), "hex").toString("utf8");
}

function kernel1271Envelope(sig) {
  // The app returns { r, s } over the Kernel-wrapped digest. Assemble the
  // Kernel v3.3 root-validator ERC-1271 envelope: 0x00 || r(32) || s(32).
  // Kernel reads the leading 0x00 as the ROOT validation type and the
  // P256Validator abi.decodes the 64-byte (r, s).
  const r = String(sig.r || "").replace(/^0x/, "").padStart(64, "0");
  const s = String(sig.s || "").replace(/^0x/, "").padStart(64, "0");
  if (r.length !== 64 || s.length !== 64) throw new Error("unexpected signature shape");
  return "0x00" + r + s;
}

// ---------------------------------------------------- pairing

async function pairStart() {
  mcp.ensure(null); // pairing doesn't need a profile
  const res = await mcp.callTool("bastion_pair_agent", {
    agentIdentifier: "app.bastion.web-connect",
    label: "Bastion Web Wallet",
  });
  return { requestId: res.requestId, pairingCode: res.pairingCode, expiresAt: res.expiresAt };
}

async function pairPoll(requestId) {
  const res = await mcp.callTool("bastion_poll_pairing", { requestId });
  if (res.state === "accepted" && res.profile?.id) {
    config.profileId = res.profile.id;
    saveConfig(config);
    mcp.start(config.profileId); // respawn with the profile scope
    return { state: "accepted", account: res.profile.accountAddress, profileId: res.profile.id };
  }
  return { state: res.state, reason: res.reason };
}

function stateSnapshot() {
  return {
    paired: !!config.profileId,
    profileId: config.profileId,
    chainId: toHexChainId(config.chainId),
    mcpFound: !!resolveMcpPath(),
  };
}

// ---------------------------------------------------- native messaging IO

function writeMessage(obj) {
  const json = Buffer.from(JSON.stringify(obj), "utf8");
  const header = Buffer.alloc(4);
  header.writeUInt32LE(json.length, 0);
  process.stdout.write(Buffer.concat([header, json]));
}

async function dispatch(msg) {
  const { id, kind, method, params } = msg;
  try {
    let result;
    switch (kind) {
      case "rpc": result = await handleRpc(method, params); break;
      case "state": result = stateSnapshot(); break;
      case "pairStart": result = await pairStart(); break;
      case "pairPoll": result = await pairPoll(params?.requestId); break;
      default: throw new Error(`unknown kind: ${kind}`);
    }
    writeMessage({ id, result });
  } catch (e) {
    writeMessage({ id, error: { code: e.code || -32603, message: e.message || String(e) } });
  }
}

let inbuf = Buffer.alloc(0);
process.stdin.on("data", (chunk) => {
  inbuf = Buffer.concat([inbuf, chunk]);
  while (inbuf.length >= 4) {
    const len = inbuf.readUInt32LE(0);
    if (inbuf.length < 4 + len) break;
    const body = inbuf.subarray(4, 4 + len);
    inbuf = inbuf.subarray(4 + len);
    let msg;
    try { msg = JSON.parse(body.toString("utf8")); } catch { continue; }
    dispatch(msg);
  }
});
process.stdin.on("end", () => { mcp.stop(); process.exit(0); });

log(`started; mcp=${resolveMcpPath() || "NOT FOUND"}; paired=${!!config.profileId}`);
