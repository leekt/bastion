/**
 * Bastion CLI wrapper — executes bastion-cli commands and parses JSON output.
 * Uses Bun.spawn (execFile-style) to prevent shell injection.
 */

const DEFAULT_CLI_PATHS = [
  "/usr/local/bin/bastion",
  `${process.env.HOME}/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli`,
  "/Applications/Bastion.app/Contents/MacOS/bastion-cli",
];

function resolveCliPath(): string {
  if (process.env.BASTION_CLI_PATH) return process.env.BASTION_CLI_PATH;
  for (const p of DEFAULT_CLI_PATHS) {
    try {
      const stat = Bun.file(p);
      if (stat.size > 0) return p;
    } catch {
      continue;
    }
  }
  throw new Error(
    "bastion-cli not found. Set BASTION_CLI_PATH or install Bastion.",
  );
}

const CLI = resolveCliPath();

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
  const r = await run(["eth", "message", message]);
  if (r.exitCode !== 0) throw new Error(r.stderr || "sign message failed");
  return parseJson(r.stdout);
}

export async function signTypedData(json: string): Promise<SignResponse> {
  const r = await run(["eth", "typedData", "--json", json]);
  if (r.exitCode !== 0) throw new Error(r.stderr || "sign typed data failed");
  return parseJson(r.stdout);
}

export async function signRawBytes(hexData: string): Promise<SignResponse> {
  const hex = hexData.startsWith("0x") ? hexData.slice(2) : hexData;
  const r = await run(["sign", "--data", hex]);
  if (r.exitCode !== 0) throw new Error(r.stderr || "sign raw bytes failed");
  return parseJson(r.stdout);
}

export async function sendUserOp(
  opts: SendUserOpOptions,
): Promise<SignResponse> {
  const args: string[] = ["eth", "userOp"];
  if (opts.send) args.push("--send");
  if (opts.chainId) args.push("--chain-id", String(opts.chainId));
  if (opts.projectId) args.push("--project-id", opts.projectId);
  for (const a of opts.actions) {
    args.push("--op", `${a.target},${a.value},${a.data}`);
  }
  const r = await run(args);
  if (r.exitCode !== 0) throw new Error(r.stderr || "userOp failed");
  return parseJson(r.stdout);
}

export async function signUserOpJson(json: string): Promise<SignResponse> {
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
