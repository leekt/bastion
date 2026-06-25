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
    if (existsSync(p) && statSync(p).isFile()) return assertSafeCliPath(p);
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
const MAX_RECEIPT_WAIT_SECONDS = 120;
const MAX_CHAIN_ID = 2_147_483_647;
const MAX_LABEL_BYTES = 128;
const MAX_ID_BYTES = 64;
const MAX_PROJECT_ID_BYTES = 128;
export const MAX_USER_OP_ACTIONS = 16;
const MAX_USER_OP_ARG_BYTES = 512 * 1024;

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const TX_HASH_RE = /^0x[0-9a-fA-F]{64}$/;

export class CliInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CliInputError";
  }
}

function inputError(message: string): never {
  throw new CliInputError(message);
}

function validateAddress(label: string, value: string): string {
  if (typeof value !== "string") {
    inputError(`${label} must be a string`);
  }
  if (!HEX_ADDRESS.test(value)) {
    inputError(`${label} must be a 0x-prefixed 20-byte hex address`);
  }
  return value;
}

function validateUintString(label: string, value: string): string {
  if (typeof value !== "string") {
    inputError(`${label} must be a string`);
  }
  const v = value.trim();
  if (DECIMAL.test(v) || HEX_UINT.test(v)) return v;
  inputError(`${label} must be a decimal or 0x-hex non-negative integer`);
}

function validateHexBytes(label: string, value: string, maxBytes = MAX_DATA_BYTES): string {
  if (typeof value !== "string") {
    inputError(`${label} must be a string`);
  }
  if (value.length > maxBytes) {
    inputError(`${label} exceeds maximum size`);
  }
  if (!HEX_BYTES.test(value)) {
    inputError(`${label} must be 0x-prefixed hex bytes`);
  }
  return value;
}

function validateRaw32(value: string): string {
  const hex = value.startsWith("0x") ? value.slice(2) : value;
  if (!HEX_32.test(hex)) {
    inputError("data must be 32 bytes of hex (64 hex chars, with or without 0x prefix)");
  }
  return hex;
}

function validateString(label: string, value: string, maxBytes: number): string {
  if (value.includes("\0")) {
    inputError(`${label} must not contain NUL bytes`);
  }
  // Byte length, not char length — UTF-8 expansion matters for argv limits.
  const byteLen = Buffer.byteLength(value, "utf8");
  if (byteLen > maxBytes) {
    inputError(`${label} exceeds maximum size of ${maxBytes} bytes`);
  }
  return value;
}

function validateRequiredString(label: string, value: string, maxBytes: number): string {
  const v = validateString(label, value, maxBytes).trim();
  if (!v) {
    inputError(`${label} is required`);
  }
  return v;
}

function validateJSONArg(label: string, value: string): string {
  validateString(label, value, MAX_JSON_BYTES);
  try {
    JSON.parse(value);
  } catch {
    inputError(`${label} must be valid JSON`);
  }
  return value;
}

function validateChainId(label: string, value: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > MAX_CHAIN_ID) {
    inputError(`${label} must be an integer from 1 to ${MAX_CHAIN_ID}`);
  }
  return value;
}

function validateOptionalChainId(label: string, value: number | undefined): number | undefined {
  return value === undefined ? undefined : validateChainId(label, value);
}

function validateWalletId(label: string, value: string): string {
  validateString(label, value, MAX_ID_BYTES);
  if (!UUID_RE.test(value)) {
    inputError(`${label} must be a UUID`);
  }
  return value;
}

function validateOptionalWalletId(label: string, value: string | undefined): string | undefined {
  return value === undefined ? undefined : validateWalletId(label, value);
}

function validateTxHash(label: string, value: string): string {
  validateString(label, value, 66);
  if (!TX_HASH_RE.test(value)) {
    inputError(`${label} must be a 0x-prefixed 32-byte transaction hash`);
  }
  return value;
}

function validateOptionalTxHash(label: string, value: string | undefined): string | undefined {
  return value === undefined ? undefined : validateTxHash(label, value);
}

function validateOptionalAddress(label: string, value: string | undefined): string | undefined {
  return value === undefined ? undefined : validateAddress(label, value);
}

function validateProjectId(value: string | undefined): string | undefined {
  return value === undefined ? undefined : validateRequiredString("projectId", value, MAX_PROJECT_ID_BYTES);
}

function validateOptionalBoolean(label: string, value: unknown): boolean | undefined {
  if (value === undefined) return undefined;
  if (typeof value === "boolean") return value;
  inputError(`${label} must be a boolean`);
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
    env: {
      HOME: process.env.HOME ?? "",
      PATH: process.env.PATH ?? "/usr/bin:/bin:/usr/sbin:/sbin",
      LANG: process.env.LANG ?? "C.UTF-8",
      ...(process.env.BASTION_ZERODEV_PROJECT_ID
        ? { BASTION_ZERODEV_PROJECT_ID: process.env.BASTION_ZERODEV_PROJECT_ID }
        : {}),
    },
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

function validateReceiptWaitSeconds(value: number | undefined): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isInteger(value) || value < 0 || value > MAX_RECEIPT_WAIT_SECONDS) {
    throw new Error(`waitForReceiptSeconds must be an integer from 0 to ${MAX_RECEIPT_WAIT_SECONDS}`);
  }
  return value;
}

function parseJson<T>(stdout: string): T {
  try {
    return JSON.parse(stdout);
  } catch {
    throw new Error(`Failed to parse CLI output: ${stdout.slice(0, 200)}`);
  }
}

function cliFailureMessage(result: { stderr: string }, fallback: string): string {
  const message = result.stderr || fallback;
  return message.replace(/^(?:Error:\s*)+/, "");
}

function walletGroupListFailureMessage(result: { stderr: string }): string {
  const message = cliFailureMessage(result, "list wallet groups failed");
  if (message === "Request timed out") {
    return "List wallet groups timed out — ensure the signed Bastion service is running and update to a build where read-only group listing does not require owner authentication";
  }
  return message;
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
    failureStage?: string;
    failureCategory?: string;
    retryable?: boolean;
    recoverySuggestion?: string;
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
  bundlePath?: string;
  executablePath?: string;
  bundleIdentifier?: string;
  processIdentifier?: number;
  launchMode?: string;
  machServiceName?: string;
  launchAgentPlistName?: string;
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

export interface SignUserOpJsonOptions {
  userOpJson: string;
  send?: boolean;
  projectId?: string;
}

// --- Public API ---

export async function status(): Promise<ServiceInfo> {
  const r = await run(["status"]);
  if (r.exitCode !== 0) throw new Error(cliFailureMessage(r, "status failed"));
  return parseJson(r.stdout);
}

export async function pubkey(): Promise<PublicKeyResponse> {
  const r = await run(["pubkey"]);
  if (r.exitCode !== 0) throw new Error(cliFailureMessage(r, "pubkey failed"));
  return parseJson(r.stdout);
}

export async function rules(): Promise<unknown> {
  const r = await run(["rules"]);
  if (r.exitCode !== 0) throw new Error(cliFailureMessage(r, "rules failed"));
  return parseJson(r.stdout);
}

export async function state(): Promise<unknown> {
  const r = await run(["state"]);
  if (r.exitCode !== 0) throw new Error(cliFailureMessage(r, "state failed"));
  return parseJson(r.stdout);
}

export async function signMessage(message: string): Promise<SignResponse> {
  validateString("message", message, MAX_MESSAGE_BYTES);
  const r = await run(["eth", "message", message]);
  if (r.exitCode !== 0) throw new Error(cliFailureMessage(r, "sign message failed"));
  return parseJson(r.stdout);
}

export async function signTypedData(json: string): Promise<SignResponse> {
  validateJSONArg("typedData", json);
  const r = await run(["eth", "typedData", "--json", json]);
  if (r.exitCode !== 0) throw new Error(cliFailureMessage(r, "sign typed data failed"));
  return parseJson(r.stdout);
}

export async function signRawBytes(hexData: string): Promise<SignResponse> {
  const hex = validateRaw32(hexData);
  const r = await run(["sign", "--data", hex]);
  if (r.exitCode !== 0) throw new Error(cliFailureMessage(r, "sign raw bytes failed"));
  return parseJson(r.stdout);
}

function validateUserOpAction(a: UserOpAction, idx: number): UserOpAction {
  validateAddress(`actions[${idx}].target`, a.target);
  validateUintString(`actions[${idx}].value`, a.value);
  const data = validateHexBytes(`actions[${idx}].data`, a.data);
  // Reject any comma in data to prevent argument-tuple smuggling at the
  // CLI's CSV --op parser. The hex regex already excludes commas, but be
  // explicit about the threat.
  if (data.includes(",")) {
    inputError(`actions[${idx}].data must not contain commas`);
  }
  return { ...a, data };
}

function validateUserOpActions(actions: UserOpAction[]): UserOpAction[] {
  if (actions.length < 1) {
    inputError("actions must include at least one action");
  }
  if (actions.length > MAX_USER_OP_ACTIONS) {
    inputError(`actions exceeds maximum count of ${MAX_USER_OP_ACTIONS}`);
  }
  let argvBytes = 0;
  const validated = actions.map((action, index) => {
    const item = validateUserOpAction(action, index);
    argvBytes += Buffer.byteLength(`${item.target},${item.value},${item.data}`, "utf8");
    return item;
  });
  if (argvBytes > MAX_USER_OP_ARG_BYTES) {
    inputError(`actions exceed aggregate argv size of ${MAX_USER_OP_ARG_BYTES} bytes`);
  }
  return validated;
}

export async function sendUserOp(
  opts: SendUserOpOptions,
): Promise<SignResponse> {
  const args: string[] = ["eth", "userOp"];
  if (validateOptionalBoolean("send", opts.send)) args.push("--send");
  const chainId = validateOptionalChainId("chainId", opts.chainId);
  if (chainId !== undefined) args.push("--chain-id", String(chainId));
  const projectId = validateProjectId(opts.projectId);
  if (projectId) args.push("--project-id", projectId);
  const actions = validateUserOpActions(opts.actions);
  for (const a of actions) {
    args.push("--op", `${a.target},${a.value},${a.data}`);
  }
  const r = await run(args);
  if (r.exitCode !== 0) throw new Error(cliFailureMessage(r, "userOp failed"));
  return parseJson(r.stdout);
}

export async function signUserOpJson(
  opts: SignUserOpJsonOptions | string,
): Promise<SignResponse> {
  const normalized =
    typeof opts === "string" ? { userOpJson: opts } : opts;
  const json = validateJSONArg("userOpJson", normalized.userOpJson);
  const args = ["eth", "userOp", "--json", json];
  if (validateOptionalBoolean("send", normalized.send)) args.push("--send");
  const projectId = validateProjectId(normalized.projectId);
  if (projectId) args.push("--project-id", projectId);
  const r = await run(args);
  if (r.exitCode !== 0) throw new Error(cliFailureMessage(r, "sign userOp failed"));
  return parseJson(r.stdout);
}

// --- Wallet Groups ---

export interface WalletGroupInfo {
  id: string;
  label: string;
  ownerKeyTag?: string;
  accountAddress?: string;
  chainIds: number[];
  sharedRules?: unknown;
  members: AgentMembershipInfo[];
  createdAt: string;
  memberCount: number;
  activeMemberCount: number;
}

export interface AgentMembershipInfo {
  id: string;
  label?: string;
  keyTag?: string;
  clientProfileId?: string;
  scopedRules?: unknown;
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
  const label = validateRequiredString("label", opts.label, MAX_LABEL_BYTES);
  const args: string[] = ["groups", "create", "--label", label];
  for (const id of opts.chainIds ?? []) {
    args.push("--chain", String(validateChainId("chainIds[]", id)));
  }
  if (opts.sharedRulesJson) {
    args.push("--scope-json", validateJSONArg("sharedRulesJson", opts.sharedRulesJson));
  }
  const r = await run(args, 60_000);
  if (r.exitCode !== 0) throw new Error(cliFailureMessage(r, "create wallet group failed"));
  return parseJson(r.stdout);
}

export async function listWalletGroups(): Promise<{ groups: WalletGroupInfo[] }> {
  const r = await run(["groups", "list"]);
  if (r.exitCode !== 0) throw new Error(walletGroupListFailureMessage(r));
  return parseJson(r.stdout);
}

export async function getWalletGroup(groupId: string): Promise<WalletGroupInfo> {
  validateWalletId("groupId", groupId);
  const r = await run(["groups", "show", groupId]);
  if (r.exitCode !== 0) throw new Error(cliFailureMessage(r, "get wallet group failed"));
  return parseJson(r.stdout);
}

export async function addAgentToGroup(
  opts: AddAgentOptions,
): Promise<AgentMembershipInfo> {
  validateWalletId("groupId", opts.groupId);
  const args: string[] = ["groups", "add-agent", opts.groupId];
  if (opts.label) args.push("--label", validateRequiredString("label", opts.label, MAX_LABEL_BYTES));
  const clientProfileId = validateOptionalWalletId("clientProfileId", opts.clientProfileId);
  if (clientProfileId) args.push("--profile-id", clientProfileId);
  if (opts.scopedRulesJson) {
    args.push("--scope-json", validateJSONArg("scopedRulesJson", opts.scopedRulesJson));
  }
  const r = await run(args, 60_000);
  if (r.exitCode !== 0) throw new Error(cliFailureMessage(r, "add agent failed"));
  return parseJson(r.stdout);
}

export async function removeAgentFromGroup(
  groupId: string,
  memberId: string,
  txHash?: string,
): Promise<void> {
  validateWalletId("groupId", groupId);
  validateWalletId("memberId", memberId);
  const args = ["groups", "remove-agent", groupId, memberId];
  const validatedTxHash = validateOptionalTxHash("txHash", txHash);
  if (validatedTxHash) args.push("--tx", validatedTxHash);
  const r = await run(args, 60_000);
  if (r.exitCode !== 0) throw new Error(cliFailureMessage(r, "remove agent failed"));
}

export async function updateAgentScope(
  groupId: string,
  memberId: string,
  scopedRulesJson: string,
): Promise<void> {
  validateWalletId("groupId", groupId);
  validateWalletId("memberId", memberId);
  const r = await run(
    ["groups", "update-scope", groupId, memberId, "--scope-json", validateJSONArg("scopedRulesJson", scopedRulesJson)],
    60_000,
  );
  if (r.exitCode !== 0) throw new Error(cliFailureMessage(r, "update scope failed"));
}

export async function markAgentInstalled(
  groupId: string,
  memberId: string,
  txHash: string,
  validatorAddress?: string,
): Promise<AgentMembershipInfo> {
  validateWalletId("groupId", groupId);
  validateWalletId("memberId", memberId);
  const args = ["groups", "mark-installed", groupId, memberId, "--tx", validateTxHash("txHash", txHash)];
  const validatedAddress = validateOptionalAddress("validatorAddress", validatorAddress);
  if (validatedAddress) args.push("--validator", validatedAddress);
  const r = await run(args, 60_000);
  if (r.exitCode !== 0) throw new Error(cliFailureMessage(r, "mark installed failed"));
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
  validateWalletId("groupId", opts.groupId);
  validateWalletId("memberId", opts.memberId);
  const chainId = validateChainId("chainId", opts.chainId);
  const args: string[] = [
    "groups",
    "install-agent",
    opts.groupId,
    opts.memberId,
    "--chain",
    String(chainId),
  ];
  if (validateOptionalBoolean("submit", opts.submit)) args.push("--submit");
  const projectId = validateProjectId(opts.projectId);
  if (projectId) args.push("--project-id", projectId);
  const waitForReceiptSeconds = validateReceiptWaitSeconds(opts.waitForReceiptSeconds);
  if (waitForReceiptSeconds !== undefined) {
    args.push("--wait-seconds", String(waitForReceiptSeconds));
  }
  // Generous client-side timeout — server-side polling is bounded by waitForReceiptSeconds.
  const timeoutMs = Math.max(120_000, ((waitForReceiptSeconds ?? 30) + 60) * 1000);
  const r = await run(args, timeoutMs);
  if (r.exitCode !== 0) throw new Error(cliFailureMessage(r, "install agent on-chain failed"));
  return parseJson(r.stdout);
}

export async function uninstallAgentOnChain(
  opts: InstallAgentOnChainOptions,
): Promise<WalletGroupChainResult> {
  validateWalletId("groupId", opts.groupId);
  validateWalletId("memberId", opts.memberId);
  const chainId = validateChainId("chainId", opts.chainId);
  const args: string[] = [
    "groups",
    "uninstall-agent",
    opts.groupId,
    opts.memberId,
    "--chain",
    String(chainId),
  ];
  if (validateOptionalBoolean("submit", opts.submit)) args.push("--submit");
  const projectId = validateProjectId(opts.projectId);
  if (projectId) args.push("--project-id", projectId);
  const waitForReceiptSeconds = validateReceiptWaitSeconds(opts.waitForReceiptSeconds);
  if (waitForReceiptSeconds !== undefined) {
    args.push("--wait-seconds", String(waitForReceiptSeconds));
  }
  const timeoutMs = Math.max(120_000, ((waitForReceiptSeconds ?? 30) + 60) * 1000);
  const r = await run(args, timeoutMs);
  if (r.exitCode !== 0) throw new Error(cliFailureMessage(r, "uninstall agent on-chain failed"));
  return parseJson(r.stdout);
}

export { CLI as cliPath };
