/**
 * Bastion REST API — local HTTP server for signing operations.
 * Binds to 127.0.0.1 only. Requires bearer token authentication.
 */

import { Hono } from "hono";
import { bearerAuth } from "hono/bearer-auth";
import * as cli from "./cli.js";
import { randomBytes } from "crypto";

const app = new Hono();

// Generate session token on startup
const SESSION_TOKEN =
  process.env.BASTION_API_TOKEN || randomBytes(32).toString("hex");
const PORT = parseInt(process.env.BASTION_API_PORT || "9587", 10);

// Auth middleware — all routes except /health
app.use("/*", async (c, next) => {
  if (c.req.path === "/health") return next();
  const middleware = bearerAuth({ token: SESSION_TOKEN });
  return middleware(c, next);
});

// --- Health ---

app.get("/health", (c) =>
  c.json({ status: "ok", server: "bastion", version: "0.1.0" }),
);

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
console.log(`Session token: ${SESSION_TOKEN}`);
console.log(`CLI path: ${cli.cliPath}`);

export default {
  port: PORT,
  hostname: "127.0.0.1",
  fetch: app.fetch,
};
