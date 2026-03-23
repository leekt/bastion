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

export { CLI as cliPath };
