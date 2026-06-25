/**
 * Bastion REST API — local HTTP server for signing operations.
 * Binds to 127.0.0.1 only. Requires bearer token authentication.
 */

import { Hono, type Context } from "hono";
import { bearerAuth } from "hono/bearer-auth";
import { bodyLimit } from "hono/body-limit";
import * as cli from "./cli.js";

const app = new Hono();

const SESSION_TOKEN = process.env.BASTION_API_TOKEN;
const PORT = parseInt(process.env.BASTION_API_PORT || "9587", 10);
const MAX_BODY_BYTES = 1 * 1024 * 1024; // 1 MiB — generous for any signing payload.
const MAX_RECEIPT_WAIT_SECONDS = 120;
const MAX_CHAIN_ID = 2_147_483_647;
const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const HEX_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const TX_HASH_RE = /^0x[0-9a-fA-F]{64}$/;

class RestInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RestInputError";
  }
}

function inputError(message: string): never {
  throw new RestInputError(message);
}

function estimatedShannonBits(value: string): number {
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropyPerChar = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropyPerChar -= p * Math.log2(p);
  }
  return entropyPerChar * value.length;
}

function hasRepeatedPattern(value: string): boolean {
  const normalized = value.toLowerCase();
  const maxPatternLength = Math.min(16, Math.floor(normalized.length / 2));
  for (let size = 1; size <= maxPatternLength; size++) {
    if (normalized.length % size !== 0) continue;
    const pattern = normalized.slice(0, size);
    if (pattern.repeat(normalized.length / size) === normalized) return true;
  }
  return false;
}

function hasLongSequence(value: string): boolean {
  const normalized = value.toLowerCase();
  const sequences = [
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiopasdfghjklzxcvbnm",
  ];
  return sequences.some((sequence) => {
    const reverse = [...sequence].reverse().join("");
    for (let size = 8; size <= sequence.length; size++) {
      for (let offset = 0; offset + size <= sequence.length; offset++) {
        const chunk = sequence.slice(offset, offset + size);
        if (normalized.includes(chunk)) return true;
        if (normalized.includes(reverse.slice(offset, offset + size))) return true;
      }
    }
    return false;
  });
}

function tokenLooksHighEntropy(value: string | undefined): value is string {
  if (!value || value.length < 32) return false;
  if (new Set(value).size < 8) return false;
  if (/(.)\1{12,}/.test(value)) return false;
  if (hasRepeatedPattern(value)) return false;
  if (hasLongSequence(value)) return false;
  return estimatedShannonBits(value) >= 128;
}

if (!tokenLooksHighEntropy(SESSION_TOKEN)) {
  console.error(
    "BASTION_API_TOKEN must be set to a high-entropy value of at least 128 estimated bits.",
  );
  process.exit(1);
}

// Reject browser-origin requests outright. The only legitimate callers of
// this loopback signing API are local processes; an Origin header is sent
// by browsers and absent on curl/programmatic clients, so its mere
// presence is sufficient signal to deny — protecting against CSRF from
// any malicious page on the user's machine that learns the token.
app.use("/*", async (c, next) => {
  const origin = c.req.header("origin");
  if (origin) {
    return c.json({ error: "Cross-origin requests are not allowed" }, 403);
  }
  return next();
});

// Bound request bodies before parsing/auth runs.
app.use("/*", bodyLimit({ maxSize: MAX_BODY_BYTES }));

// Auth middleware — all routes including /health.
app.use("/*", async (c, next) => {
  const middleware = bearerAuth({ token: SESSION_TOKEN });
  return middleware(c, next);
});

function validReceiptWait(value: unknown): value is number | undefined {
  return (
    value === undefined ||
    (typeof value === "number" &&
      Number.isInteger(value) &&
      value >= 0 &&
      value <= MAX_RECEIPT_WAIT_SECONDS)
  );
}

function receiptWaitErrorMessage(): string {
  return `waitForReceiptSeconds must be an integer from 0 to ${MAX_RECEIPT_WAIT_SECONDS}`;
}

function validChainId(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 1 &&
    value <= MAX_CHAIN_ID
  );
}

function validUUID(value: string): boolean {
  return UUID_RE.test(value);
}

function validOptionalTxHash(value: unknown): value is string | undefined {
  return value === undefined || (typeof value === "string" && TX_HASH_RE.test(value));
}

function validOptionalAddress(value: unknown): value is string | undefined {
  return value === undefined || (typeof value === "string" && HEX_ADDRESS_RE.test(value));
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== "string") {
    inputError(`${label} must be a string`);
  }
  if (!value.trim()) {
    inputError(`${label} is required`);
  }
  return value;
}

function optionalString(value: unknown, label: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string") {
    inputError(`${label} must be a string`);
  }
  return value;
}

function optionalChainIds(value: unknown): number[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.some((id) => !validChainId(id))) {
    inputError(`chainIds must be integers from 1 to ${MAX_CHAIN_ID}`);
  }
  return value;
}

function jsonArg(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  const rendered = typeof value === "string" ? value : JSON.stringify(value);
  try {
    JSON.parse(rendered);
  } catch {
    inputError("JSON argument must be valid JSON");
  }
  return rendered;
}

async function jsonBody<T>(c: Context): Promise<T> {
  try {
    return await c.req.json<T>();
  } catch {
    inputError("request body must be valid JSON");
  }
}

function optionalBoolean(value: unknown, label: string): boolean | undefined {
  if (value === undefined) return undefined;
  if (typeof value === "boolean") return value;
  inputError(`${label} must be a boolean`);
}

function errorStatus(error: unknown, fallback: 400 | 500 | 502 = 500): 400 | 500 | 502 {
  if (error instanceof RestInputError || error instanceof cli.CliInputError) return 400;
  return fallback;
}

function errorPayload(error: unknown) {
  return { error: error instanceof Error ? error.message : String(error) };
}

// --- Health ---

// Authenticated and minimal — does not leak server identity or version.
app.get("/health", (c) => c.json({ status: "ok" }));

// --- Read endpoints ---

app.get("/status", async (c) => {
  try {
    return c.json(await cli.status());
  } catch (e) {
    return c.json({ error: (e as Error).message }, 502);
  }
});

app.get("/account", async (c) => {
  try {
    return c.json(await cli.pubkey());
  } catch (e) {
    return c.json({ error: (e as Error).message }, 502);
  }
});

app.get("/rules", async (c) => {
  try {
    return c.json(await cli.rules());
  } catch (e) {
    return c.json({ error: (e as Error).message }, 502);
  }
});

app.get("/state", async (c) => {
  try {
    return c.json(await cli.state());
  } catch (e) {
    return c.json({ error: (e as Error).message }, 502);
  }
});

// --- Signing endpoints ---

app.post("/sign/message", async (c) => {
  try {
    const body = await jsonBody<{ message: unknown }>(c);
    return c.json(await cli.signMessage(requiredString(body.message, "message")));
  } catch (e) {
    return c.json(errorPayload(e), errorStatus(e));
  }
});

app.post("/sign/typed-data", async (c) => {
  try {
    const body = await jsonBody<{ typedData: unknown }>(c);
    if (!body.typedData)
      return c.json({ error: "typedData is required" }, 400);
    const json =
      typeof body.typedData === "string"
        ? body.typedData
        : JSON.stringify(body.typedData);
    return c.json(await cli.signTypedData(json));
  } catch (e) {
    return c.json(errorPayload(e), errorStatus(e));
  }
});

app.post("/sign/raw", async (c) => {
  try {
    const body = await jsonBody<{ data: unknown }>(c);
    return c.json(await cli.signRawBytes(requiredString(body.data, "data")));
  } catch (e) {
    return c.json(errorPayload(e), errorStatus(e));
  }
});

app.post("/sign/user-op", async (c) => {
  try {
    const body = await jsonBody<{
      actions?: cli.UserOpAction[];
      userOpJson?: unknown;
      send?: unknown;
      chainId?: number;
      projectId?: string;
    }>(c);

    if (body.userOpJson) {
      const userOpJson = jsonArg(body.userOpJson);
      if (!userOpJson)
        return c.json({ error: "userOpJson is required" }, 400);
      const send = optionalBoolean(body.send, "send");
      return c.json(
        await cli.signUserOpJson({
          userOpJson,
          send,
          projectId: optionalString(body.projectId, "projectId"),
        }),
      );
    }

    if (!Array.isArray(body.actions) || !body.actions.length)
      return c.json({ error: "actions or userOpJson required" }, 400);
    if (body.actions.length > cli.MAX_USER_OP_ACTIONS) {
      return c.json({ error: `actions exceeds maximum count of ${cli.MAX_USER_OP_ACTIONS}` }, 400);
    }

    if (body.chainId !== undefined && !validChainId(body.chainId)) {
      return c.json({ error: `chainId must be an integer from 1 to ${MAX_CHAIN_ID}` }, 400);
    }
    const send = optionalBoolean(body.send, "send");

    return c.json(
      await cli.sendUserOp({
        actions: body.actions,
        send,
        chainId: body.chainId,
        projectId: optionalString(body.projectId, "projectId"),
      }),
    );
  } catch (e) {
    return c.json(errorPayload(e), errorStatus(e));
  }
});

// --- Wallet Group endpoints ---

app.get("/groups", async (c) => {
  try {
    return c.json(await cli.listWalletGroups());
  } catch (e) {
    return c.json({ error: (e as Error).message }, 502);
  }
});

app.post("/groups", async (c) => {
  try {
    const body = await jsonBody<{
      label: unknown;
      chainIds?: unknown;
      sharedRules?: unknown;
    }>(c);
    const label = requiredString(body.label, "label");
    const chainIds = optionalChainIds(body.chainIds);
    const sharedRulesJson = jsonArg(body.sharedRules);
    return c.json(
      await cli.createWalletGroup({
        label,
        chainIds,
        sharedRulesJson,
      }),
    );
  } catch (e) {
    return c.json(errorPayload(e), errorStatus(e));
  }
});

app.get("/groups/:id", async (c) => {
  try {
    const groupId = c.req.param("id");
    if (!validUUID(groupId)) return c.json({ error: "group id must be a UUID" }, 400);
    return c.json(await cli.getWalletGroup(groupId));
  } catch (e) {
    return c.json({ error: (e as Error).message }, 502);
  }
});

app.post("/groups/:id/agents", async (c) => {
  try {
    const groupId = c.req.param("id");
    if (!validUUID(groupId)) return c.json({ error: "group id must be a UUID" }, 400);
    const body = await jsonBody<{
      label?: unknown;
      clientProfileId?: unknown;
      scopedRules?: unknown;
    }>(c);
    const clientProfileId = optionalString(body.clientProfileId, "clientProfileId");
    if (clientProfileId && !validUUID(clientProfileId)) {
      return c.json({ error: "clientProfileId must be a UUID" }, 400);
    }
    const scopedRulesJson = jsonArg(body.scopedRules);
    return c.json(
      await cli.addAgentToGroup({
        groupId,
        label: optionalString(body.label, "label"),
        clientProfileId,
        scopedRulesJson,
      }),
    );
  } catch (e) {
    return c.json(errorPayload(e), errorStatus(e));
  }
});

app.delete("/groups/:id/agents/:memberId", async (c) => {
  try {
    const groupId = c.req.param("id");
    const memberId = c.req.param("memberId");
    if (!validUUID(groupId) || !validUUID(memberId))
      return c.json({ error: "groupId and memberId must be UUIDs" }, 400);
    const txHash = c.req.query("tx") ?? undefined;
    if (!validOptionalTxHash(txHash))
      return c.json({ error: "tx must be a 0x-prefixed 32-byte hash" }, 400);
    await cli.removeAgentFromGroup(groupId, memberId, txHash);
    return c.json({ revoked: true, groupId, memberId });
  } catch (e) {
    return c.json(errorPayload(e), errorStatus(e));
  }
});

app.patch("/groups/:id/agents/:memberId/scope", async (c) => {
  try {
    const groupId = c.req.param("id");
    const memberId = c.req.param("memberId");
    if (!validUUID(groupId) || !validUUID(memberId))
      return c.json({ error: "groupId and memberId must be UUIDs" }, 400);
    const body = await jsonBody<{ scopedRules: unknown }>(c);
    if (!body.scopedRules)
      return c.json({ error: "scopedRules is required" }, 400);
    const scopedRulesJson = jsonArg(body.scopedRules);
    if (!scopedRulesJson)
      return c.json({ error: "scopedRules is required" }, 400);
    await cli.updateAgentScope(groupId, memberId, scopedRulesJson);
    return c.json({ updated: true, groupId, memberId });
  } catch (e) {
    return c.json(errorPayload(e), errorStatus(e));
  }
});

app.post("/groups/:id/agents/:memberId/install-on-chain", async (c) => {
  try {
    const groupId = c.req.param("id");
    const memberId = c.req.param("memberId");
    if (!validUUID(groupId) || !validUUID(memberId))
      return c.json({ error: "groupId and memberId must be UUIDs" }, 400);
    const body = await jsonBody<{
      chainId: number;
      submit?: unknown;
      projectId?: unknown;
      waitForReceiptSeconds?: number;
    }>(c);
    if (!validChainId(body.chainId))
      return c.json({ error: `chainId must be an integer from 1 to ${MAX_CHAIN_ID}` }, 400);
    if (!validReceiptWait(body.waitForReceiptSeconds))
      return c.json({ error: receiptWaitErrorMessage() }, 400);
    const submit = optionalBoolean(body.submit, "submit");
    return c.json(
      await cli.installAgentOnChain({
        groupId,
        memberId,
        chainId: body.chainId,
        submit,
        projectId: optionalString(body.projectId, "projectId"),
        waitForReceiptSeconds: body.waitForReceiptSeconds,
      }),
    );
  } catch (e) {
    return c.json(errorPayload(e), errorStatus(e));
  }
});

app.post("/groups/:id/agents/:memberId/uninstall-on-chain", async (c) => {
  try {
    const groupId = c.req.param("id");
    const memberId = c.req.param("memberId");
    if (!validUUID(groupId) || !validUUID(memberId))
      return c.json({ error: "groupId and memberId must be UUIDs" }, 400);
    const body = await jsonBody<{
      chainId: number;
      submit?: unknown;
      projectId?: unknown;
      waitForReceiptSeconds?: number;
    }>(c);
    if (!validChainId(body.chainId))
      return c.json({ error: `chainId must be an integer from 1 to ${MAX_CHAIN_ID}` }, 400);
    if (!validReceiptWait(body.waitForReceiptSeconds))
      return c.json({ error: receiptWaitErrorMessage() }, 400);
    const submit = optionalBoolean(body.submit, "submit");
    return c.json(
      await cli.uninstallAgentOnChain({
        groupId,
        memberId,
        chainId: body.chainId,
        submit,
        projectId: optionalString(body.projectId, "projectId"),
        waitForReceiptSeconds: body.waitForReceiptSeconds,
      }),
    );
  } catch (e) {
    return c.json(errorPayload(e), errorStatus(e));
  }
});

app.post("/groups/:id/agents/:memberId/installed", async (c) => {
  try {
    const groupId = c.req.param("id");
    const memberId = c.req.param("memberId");
    if (!validUUID(groupId) || !validUUID(memberId))
      return c.json({ error: "groupId and memberId must be UUIDs" }, 400);
    const body = await jsonBody<{
      txHash: unknown;
      validatorAddress?: unknown;
    }>(c);
    const txHash = requiredString(body.txHash, "txHash");
    const validatorAddress = optionalString(body.validatorAddress, "validatorAddress");
    if (!TX_HASH_RE.test(txHash)) return c.json({ error: "txHash must be a 0x-prefixed 32-byte hash" }, 400);
    if (!validOptionalAddress(validatorAddress))
      return c.json({ error: "validatorAddress must be a 0x-prefixed 20-byte address" }, 400);
    return c.json(
      await cli.markAgentInstalled(
        groupId,
        memberId,
        txHash,
        validatorAddress,
      ),
    );
  } catch (e) {
    return c.json(errorPayload(e), errorStatus(e));
  }
});

// --- Start ---

if (import.meta.main) {
  console.log(`Bastion REST API starting on http://127.0.0.1:${PORT}`);
}

export default {
  port: PORT,
  hostname: "127.0.0.1",
  fetch: app.fetch,
};
