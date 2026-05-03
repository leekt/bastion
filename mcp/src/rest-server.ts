/**
 * Bastion REST API — local HTTP server for signing operations.
 * Binds to 127.0.0.1 only. Requires bearer token authentication.
 */

import { Hono } from "hono";
import { bearerAuth } from "hono/bearer-auth";
import { bodyLimit } from "hono/body-limit";
import * as cli from "./cli.js";
import { randomBytes } from "crypto";
import { chmodSync, mkdirSync, writeFileSync } from "fs";
import { homedir } from "os";
import { dirname, join } from "path";

const app = new Hono();

// Generate session token on startup
const SESSION_TOKEN =
  process.env.BASTION_API_TOKEN || randomBytes(32).toString("hex");
const TOKEN_PROVIDED_BY_ENV = !!process.env.BASTION_API_TOKEN;
const PORT = parseInt(process.env.BASTION_API_PORT || "9587", 10);
const MAX_BODY_BYTES = 1 * 1024 * 1024; // 1 MiB — generous for any signing payload.

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
    const body = await c.req.json<{ message: string }>();
    if (!body.message) return c.json({ error: "message is required" }, 400);
    return c.json(await cli.signMessage(body.message));
  } catch (e) {
    return c.json({ error: (e as Error).message }, 500);
  }
});

app.post("/sign/typed-data", async (c) => {
  try {
    const body = await c.req.json<{ typedData: unknown }>();
    if (!body.typedData)
      return c.json({ error: "typedData is required" }, 400);
    const json =
      typeof body.typedData === "string"
        ? body.typedData
        : JSON.stringify(body.typedData);
    return c.json(await cli.signTypedData(json));
  } catch (e) {
    return c.json({ error: (e as Error).message }, 500);
  }
});

app.post("/sign/raw", async (c) => {
  try {
    const body = await c.req.json<{ data: string }>();
    if (!body.data) return c.json({ error: "data is required" }, 400);
    return c.json(await cli.signRawBytes(body.data));
  } catch (e) {
    return c.json({ error: (e as Error).message }, 500);
  }
});

app.post("/sign/user-op", async (c) => {
  try {
    const body = await c.req.json<{
      actions?: cli.UserOpAction[];
      userOpJson?: string;
      send?: boolean;
      chainId?: number;
      projectId?: string;
    }>();

    if (body.userOpJson) {
      return c.json(await cli.signUserOpJson(body.userOpJson));
    }

    if (!body.actions?.length)
      return c.json({ error: "actions or userOpJson required" }, 400);

    return c.json(
      await cli.sendUserOp({
        actions: body.actions,
        send: body.send,
        chainId: body.chainId,
        projectId: body.projectId,
      }),
    );
  } catch (e) {
    return c.json({ error: (e as Error).message }, 500);
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
    const body = await c.req.json<{
      label: string;
      chainIds?: number[];
      sharedRules?: unknown;
    }>();
    if (!body.label) return c.json({ error: "label is required" }, 400);
    const sharedRulesJson = body.sharedRules
      ? JSON.stringify(body.sharedRules)
      : undefined;
    return c.json(
      await cli.createWalletGroup({
        label: body.label,
        chainIds: body.chainIds,
        sharedRulesJson,
      }),
    );
  } catch (e) {
    return c.json({ error: (e as Error).message }, 500);
  }
});

app.get("/groups/:id", async (c) => {
  try {
    return c.json(await cli.getWalletGroup(c.req.param("id")));
  } catch (e) {
    return c.json({ error: (e as Error).message }, 502);
  }
});

app.post("/groups/:id/agents", async (c) => {
  try {
    const groupId = c.req.param("id");
    const body = await c.req.json<{
      label?: string;
      clientProfileId?: string;
      scopedRules?: unknown;
    }>();
    const scopedRulesJson = body.scopedRules
      ? JSON.stringify(body.scopedRules)
      : undefined;
    return c.json(
      await cli.addAgentToGroup({
        groupId,
        label: body.label,
        clientProfileId: body.clientProfileId,
        scopedRulesJson,
      }),
    );
  } catch (e) {
    return c.json({ error: (e as Error).message }, 500);
  }
});

app.delete("/groups/:id/agents/:memberId", async (c) => {
  try {
    const groupId = c.req.param("id");
    const memberId = c.req.param("memberId");
    const txHash = c.req.query("tx") ?? undefined;
    await cli.removeAgentFromGroup(groupId, memberId, txHash);
    return c.json({ revoked: true, groupId, memberId });
  } catch (e) {
    return c.json({ error: (e as Error).message }, 500);
  }
});

app.patch("/groups/:id/agents/:memberId/scope", async (c) => {
  try {
    const groupId = c.req.param("id");
    const memberId = c.req.param("memberId");
    const body = await c.req.json<{ scopedRules: unknown }>();
    if (!body.scopedRules)
      return c.json({ error: "scopedRules is required" }, 400);
    const scopedRulesJson =
      typeof body.scopedRules === "string"
        ? body.scopedRules
        : JSON.stringify(body.scopedRules);
    await cli.updateAgentScope(groupId, memberId, scopedRulesJson);
    return c.json({ updated: true, groupId, memberId });
  } catch (e) {
    return c.json({ error: (e as Error).message }, 500);
  }
});

app.post("/groups/:id/agents/:memberId/install-on-chain", async (c) => {
  try {
    const groupId = c.req.param("id");
    const memberId = c.req.param("memberId");
    const body = await c.req.json<{
      chainId: number;
      submit?: boolean;
      projectId?: string;
      waitForReceiptSeconds?: number;
    }>();
    if (typeof body.chainId !== "number")
      return c.json({ error: "chainId is required" }, 400);
    return c.json(
      await cli.installAgentOnChain({
        groupId,
        memberId,
        chainId: body.chainId,
        submit: body.submit,
        projectId: body.projectId,
        waitForReceiptSeconds: body.waitForReceiptSeconds,
      }),
    );
  } catch (e) {
    return c.json({ error: (e as Error).message }, 500);
  }
});

app.post("/groups/:id/agents/:memberId/uninstall-on-chain", async (c) => {
  try {
    const groupId = c.req.param("id");
    const memberId = c.req.param("memberId");
    const body = await c.req.json<{
      chainId: number;
      submit?: boolean;
      projectId?: string;
      waitForReceiptSeconds?: number;
    }>();
    if (typeof body.chainId !== "number")
      return c.json({ error: "chainId is required" }, 400);
    return c.json(
      await cli.uninstallAgentOnChain({
        groupId,
        memberId,
        chainId: body.chainId,
        submit: body.submit,
        projectId: body.projectId,
        waitForReceiptSeconds: body.waitForReceiptSeconds,
      }),
    );
  } catch (e) {
    return c.json({ error: (e as Error).message }, 500);
  }
});

app.post("/groups/:id/agents/:memberId/installed", async (c) => {
  try {
    const groupId = c.req.param("id");
    const memberId = c.req.param("memberId");
    const body = await c.req.json<{
      txHash: string;
      validatorAddress?: string;
    }>();
    if (!body.txHash) return c.json({ error: "txHash is required" }, 400);
    return c.json(
      await cli.markAgentInstalled(
        groupId,
        memberId,
        body.txHash,
        body.validatorAddress,
      ),
    );
  } catch (e) {
    return c.json({ error: (e as Error).message }, 500);
  }
});

// --- Start ---

console.log(`Bastion REST API starting on http://127.0.0.1:${PORT}`);
if (!TOKEN_PROVIDED_BY_ENV) {
  // P3 fix: previously we printed the generated session token to stderr.
  // Stderr commonly lands in terminal scrollback, supervisor logs, and
  // launchd console.log buffers — leaking the bearer credential.
  // Instead: write the token to a 0600-permissioned file under the user's
  // home dir and tell the operator the *path* (not the token).
  const tokenPath = join(
    homedir(),
    "Library",
    "Application Support",
    "Bastion",
    "rest-token",
  );
  try {
    mkdirSync(dirname(tokenPath), { recursive: true, mode: 0o700 });
    writeFileSync(tokenPath, SESSION_TOKEN, { mode: 0o600 });
    chmodSync(tokenPath, 0o600);
    console.error(
      `Generated session token written to ${tokenPath} (chmod 600). Set BASTION_API_TOKEN to override.`,
    );
  } catch (err) {
    // If we can't write the file, fail closed — refuse to start rather
    // than fall back to logging the token in plaintext.
    console.error(
      `Failed to write session token to ${tokenPath}: ${(err as Error).message}`,
    );
    console.error(
      "Refusing to start without a writable token file. Set BASTION_API_TOKEN to provide one explicitly.",
    );
    process.exit(1);
  }
}

export default {
  port: PORT,
  hostname: "127.0.0.1",
  fetch: app.fetch,
};
