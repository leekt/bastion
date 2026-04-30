/**
 * Bastion CLI wrapper — executes bastion-cli commands and parses JSON output.
 * Uses Bun.spawn (execFile-style) to prevent shell injection.
 */

import { existsSync, statSync } from "node:fs";
import { isAbsolute } from "node:path";

const DEFAULT_CLI_PATHS = [
  "/usr/local/bin/bastion",
  `${process.env.HOME}/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli`,
  "/Applications/Bastion.app/Contents/MacOS/bastion-cli",
];

function assertSafeCliPath(p: string): string {
  if (!isAbsolute(p)) {
    throw new Error(`BASTION_CLI_PATH must be absolute: ${p}`);
  }
  if (!existsSync(p)) {
    throw new Error(`BASTION_CLI_PATH does not exist: ${p}`);
  }
  const st = statSync(p);
  if (!st.isFile()) {
    throw new Error(`BASTION_CLI_PATH is not a regular file: ${p}`);
  }
  // Reject world-writable binaries — defense in depth against env-redirection
  // attacks where a hostile process plants a binary at a writable location.
  if ((st.mode & 0o002) !== 0) {
    throw new Error(`BASTION_CLI_PATH is world-writable, refusing to use: ${p}`);
  }
  return p;
}

function resolveCliPath(): string {
  if (process.env.BASTION_CLI_PATH) {
    return assertSafeCliPath(process.env.BASTION_CLI_PATH);
  }
  for (const p of DEFAULT_CLI_PATHS) {
    if (existsSync(p) && statSync(p).isFile()) return p;
  }
  throw new Error(
    "bastion-cli not found. Set BASTION_CLI_PATH or install Bastion.",
  );
}

const CLI = resolveCliPath();

// --- Input validation helpers ---

const HEX_ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const HEX_BYTES = /^0x([0-9a-fA-F]{2})*$/;
const HEX_32 = /^[0-9a-fA-F]{64}$/;
const DECIMAL = /^[0-9]+$/;
const HEX_UINT = /^0x[0-9a-fA-F]+$/;

const MAX_MESSAGE_BYTES = 64 * 1024;
const MAX_JSON_BYTES = 512 * 1024;
const MAX_DATA_BYTES = 256 * 1024; // 0x-prefixed hex string upper bound

function validateAddress(label: string, value: string): string {
  if (!HEX_ADDRESS.test(value)) {
    throw new Error(`${label} must be a 0x-prefixed 20-byte hex address`);
  }
  return value;
}

function validateUintString(label: string, value: string): string {
  const v = value.trim();
  if (DECIMAL.test(v) || HEX_UINT.test(v)) return v;
  throw new Error(`${label} must be a decimal or 0x-hex non-negative integer`);
}

function validateHexBytes(label: string, value: string, maxBytes = MAX_DATA_BYTES): string {
  if (value.length > maxBytes) {
    throw new Error(`${label} exceeds maximum size`);
  }
  if (!HEX_BYTES.test(value)) {
    throw new Error(`${label} must be 0x-prefixed hex bytes`);
  }
  return value;
}

function validateRaw32(value: string): string {
  const hex = value.startsWith("0x") ? value.slice(2) : value;
  if (!HEX_32.test(hex)) {
    throw new Error("data must be 32 bytes of hex (64 hex chars, with or without 0x prefix)");
  }
  return hex;
}

function validateString(label: string, value: string, maxBytes: number): string {
  // Byte length, not char length — UTF-8 expansion matters for argv limits.
  const byteLen = Buffer.byteLength(value, "utf8");
  if (byteLen > maxBytes) {
    throw new Error(`${label} exceeds maximum size of ${maxBytes} bytes`);
  }
  return value;
}

/**
 * Execute bastion-cli with arguments. Uses Bun.spawn (no shell) to prevent injection.
 */
async function run(
  args: string[],
  timeoutMs = 120_000,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const proc = Bun.spawn([CLI, ...args], {
    stdout: "pipe",
    stderr: "pipe",
  });

  const timeout = setTimeout(() => proc.kill(), timeoutMs);
  const [stdout, stderr] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  const exitCode = await proc.exited;
  clearTimeout(timeout);

  return { stdout: stdout.trim(), stderr: stderr.trim(), exitCode };
}

function parseJson<T>(stdout: string): T {
  try {
    return JSON.parse(stdout);
  } catch {
    throw new Error(`Failed to parse CLI output: ${stdout.slice(0, 200)}`);
  }
}

// --- Types ---

export interface SignResponse {
  pubkeyX: string;
  pubkeyY: string;
  r: string;
  s: string;
  accountAddress?: string;
  clientBundleId?: string;
  submission?: {
    provider: string;
    status: string;
    userOpHash?: string;
    transactionHash?: string;
    error?: string;
  };
}

export interface PublicKeyResponse {
  x: string;
  y: string;
  accountAddress?: string;
}

export interface ServiceInfo {
  version: string;
  serviceRegistrationStatus: string;
  configCorrupted: boolean;
}

export interface UserOpAction {
  target: string;
  value: string;
  data: string;
}

export interface SendUserOpOptions {
  actions: UserOpAction[];
  send?: boolean;
  chainId?: number;
  projectId?: string;
}

// --- Public API ---

export async function status(): Promise<ServiceInfo> {
  const r = await run(["status"]);
  if (r.exitCode !== 0) throw new Error(r.stderr || "status failed");
  return parseJson(r.stdout);
}

export async function pubkey(): Promise<PublicKeyResponse> {
  const r = await run(["pubkey"]);
  if (r.exitCode !== 0) throw new Error(r.stderr || "pubkey failed");
  return parseJson(r.stdout);
}

export async function rules(): Promise<unknown> {
  const r = await run(["rules"]);
  if (r.exitCode !== 0) throw new Error(r.stderr || "rules failed");
  return parseJson(r.stdout);
}

export async function state(): Promise<unknown> {
  const r = await run(["state"]);
  if (r.exitCode !== 0) throw new Error(r.stderr || "state failed");
  return parseJson(r.stdout);
}

export async function signMessage(message: string): Promise<SignResponse> {
  validateString("message", message, MAX_MESSAGE_BYTES);
  const r = await run(["eth", "message", message]);
  if (r.exitCode !== 0) throw new Error(r.stderr || "sign message failed");
  return parseJson(r.stdout);
}

export async function signTypedData(json: string): Promise<SignResponse> {
  validateString("typedData", json, MAX_JSON_BYTES);
  // Surface malformed JSON early instead of forwarding it to the CLI.
  try { JSON.parse(json); } catch {
    throw new Error("typedData must be valid JSON");
  }
  const r = await run(["eth", "typedData", "--json", json]);
  if (r.exitCode !== 0) throw new Error(r.stderr || "sign typed data failed");
  return parseJson(r.stdout);
}

export async function signRawBytes(hexData: string): Promise<SignResponse> {
  const hex = validateRaw32(hexData);
  const r = await run(["sign", "--data", hex]);
  if (r.exitCode !== 0) throw new Error(r.stderr || "sign raw bytes failed");
  return parseJson(r.stdout);
}

function validateUserOpAction(a: UserOpAction, idx: number): UserOpAction {
  validateAddress(`actions[${idx}].target`, a.target);
  validateUintString(`actions[${idx}].value`, a.value);
  // Reject any comma in data to prevent argument-tuple smuggling at the
  // CLI's CSV --op parser. The hex regex already excludes commas, but be
  // explicit about the threat.
  if (a.data.includes(",")) {
    throw new Error(`actions[${idx}].data must not contain commas`);
  }
  validateHexBytes(`actions[${idx}].data`, a.data);
  return a;
}

export async function sendUserOp(
  opts: SendUserOpOptions,
): Promise<SignResponse> {
  const args: string[] = ["eth", "userOp"];
  if (opts.send) args.push("--send");
  if (opts.chainId) args.push("--chain-id", String(opts.chainId));
  if (opts.projectId) args.push("--project-id", opts.projectId);
  opts.actions.forEach((a, i) => validateUserOpAction(a, i));
  for (const a of opts.actions) {
    args.push("--op", `${a.target},${a.value},${a.data}`);
  }
  const r = await run(args);
  if (r.exitCode !== 0) throw new Error(r.stderr || "userOp failed");
  return parseJson(r.stdout);
}

export async function signUserOpJson(json: string): Promise<SignResponse> {
  validateString("userOpJson", json, MAX_JSON_BYTES);
  try { JSON.parse(json); } catch {
    throw new Error("userOpJson must be valid JSON");
  }
  const r = await run(["eth", "userOp", "--json", json]);
  if (r.exitCode !== 0) throw new Error(r.stderr || "sign userOp failed");
  return parseJson(r.stdout);
}

// --- Wallet Groups ---

export interface WalletGroupInfo {
  id: string;
  label: string;
  ownerKeyTag: string;
  accountAddress?: string;
  chainIds: number[];
  sharedRules: unknown;
  members: AgentMembershipInfo[];
  createdAt: string;
  memberCount: number;
  activeMemberCount: number;
}

export interface AgentMembershipInfo {
  id: string;
  label?: string;
  keyTag: string;
  clientProfileId?: string;
  scopedRules: unknown;
  validatorAddress?: string;
  installStatus: { state: "pending" } | { state: "installed"; txHash: string } | { state: "revoked"; txHash: string };
  installedAt?: string;
  revokedAt?: string;
}

export interface CreateWalletGroupOptions {
  label: string;
  chainIds?: number[];
  sharedRulesJson?: string;
}

export interface AddAgentOptions {
  groupId: string;
  label?: string;
  clientProfileId?: string;
  scopedRulesJson?: string;
}

export async function createWalletGroup(
  opts: CreateWalletGroupOptions,
): Promise<WalletGroupInfo> {
  const args: string[] = ["groups", "create", "--label", opts.label];
  for (const id of opts.chainIds ?? []) {
    args.push("--chain", String(id));
  }
  if (opts.sharedRulesJson) {
    args.push("--scope-json", opts.sharedRulesJson);
  }
  const r = await run(args, 60_000);
  if (r.exitCode !== 0) throw new Error(r.stderr || "create wallet group failed");
  return parseJson(r.stdout);
}

export async function listWalletGroups(): Promise<{ groups: WalletGroupInfo[] }> {
  const r = await run(["groups", "list"]);
  if (r.exitCode !== 0) throw new Error(r.stderr || "list wallet groups failed");
  return parseJson(r.stdout);
}

export async function getWalletGroup(groupId: string): Promise<WalletGroupInfo> {
  const r = await run(["groups", "show", groupId]);
  if (r.exitCode !== 0) throw new Error(r.stderr || "get wallet group failed");
  return parseJson(r.stdout);
}

export async function addAgentToGroup(
  opts: AddAgentOptions,
): Promise<AgentMembershipInfo> {
  const args: string[] = ["groups", "add-agent", opts.groupId];
  if (opts.label) args.push("--label", opts.label);
  if (opts.clientProfileId) args.push("--profile-id", opts.clientProfileId);
  if (opts.scopedRulesJson) args.push("--scope-json", opts.scopedRulesJson);
  const r = await run(args, 60_000);
  if (r.exitCode !== 0) throw new Error(r.stderr || "add agent failed");
  return parseJson(r.stdout);
}

export async function removeAgentFromGroup(
  groupId: string,
  memberId: string,
  txHash?: string,
): Promise<void> {
  const args = ["groups", "remove-agent", groupId, memberId];
  if (txHash) args.push("--tx", txHash);
  const r = await run(args, 60_000);
  if (r.exitCode !== 0) throw new Error(r.stderr || "remove agent failed");
}

export async function updateAgentScope(
  groupId: string,
  memberId: string,
  scopedRulesJson: string,
): Promise<void> {
  const r = await run(
    ["groups", "update-scope", groupId, memberId, "--scope-json", scopedRulesJson],
    60_000,
  );
  if (r.exitCode !== 0) throw new Error(r.stderr || "update scope failed");
}

export async function markAgentInstalled(
  groupId: string,
  memberId: string,
  txHash: string,
  validatorAddress?: string,
): Promise<AgentMembershipInfo> {
  const args = ["groups", "mark-installed", groupId, memberId, "--tx", txHash];
  if (validatorAddress) args.push("--validator", validatorAddress);
  const r = await run(args, 60_000);
  if (r.exitCode !== 0) throw new Error(r.stderr || "mark installed failed");
  return parseJson(r.stdout);
}

export interface WalletGroupChainResult {
  groupId: string;
  memberId: string;
  chainId: number;
  userOp: unknown;
  userOpHash?: string;
  txHash?: string;
  membership?: AgentMembershipInfo;
}

export interface InstallAgentOnChainOptions {
  groupId: string;
  memberId: string;
  chainId: number;
  submit?: boolean;
  projectId?: string;
  waitForReceiptSeconds?: number;
}

export async function installAgentOnChain(
  opts: InstallAgentOnChainOptions,
): Promise<WalletGroupChainResult> {
  const args: string[] = [
    "groups",
    "install-agent",
    opts.groupId,
    opts.memberId,
    "--chain",
    String(opts.chainId),
  ];
  if (opts.submit) args.push("--submit");
  if (opts.projectId) args.push("--project-id", opts.projectId);
  if (opts.waitForReceiptSeconds !== undefined) {
    args.push("--wait-seconds", String(opts.waitForReceiptSeconds));
  }
  // Generous client-side timeout — server-side polling is bounded by waitForReceiptSeconds.
  const timeoutMs = Math.max(120_000, ((opts.waitForReceiptSeconds ?? 30) + 60) * 1000);
  const r = await run(args, timeoutMs);
  if (r.exitCode !== 0) throw new Error(r.stderr || "install agent on-chain failed");
  return parseJson(r.stdout);
}

export async function uninstallAgentOnChain(
  opts: InstallAgentOnChainOptions,
): Promise<WalletGroupChainResult> {
  const args: string[] = [
    "groups",
    "uninstall-agent",
    opts.groupId,
    opts.memberId,
    "--chain",
    String(opts.chainId),
  ];
  if (opts.submit) args.push("--submit");
  if (opts.projectId) args.push("--project-id", opts.projectId);
  if (opts.waitForReceiptSeconds !== undefined) {
    args.push("--wait-seconds", String(opts.waitForReceiptSeconds));
  }
  const timeoutMs = Math.max(120_000, ((opts.waitForReceiptSeconds ?? 30) + 60) * 1000);
  const r = await run(args, timeoutMs);
  if (r.exitCode !== 0) throw new Error(r.stderr || "uninstall agent on-chain failed");
  return parseJson(r.stdout);
}

export { CLI as cliPath };
