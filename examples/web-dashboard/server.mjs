// Bastion example — local web dashboard proxy.
//
// Why a server-side proxy instead of calling Bastion from the browser?
// The bastion-mcp REST API (127.0.0.1:9587) deliberately REJECTS any request
// that carries an `Origin` header (a CSRF guard) and requires a bearer token.
// Browsers attach `Origin` to cross-origin and non-GET requests, so a browser
// cannot talk to the Bastion API directly. This tiny Node server is the trusted
// local intermediary: the browser talks only to THIS server (same origin), and
// THIS server talks to Bastion server-side (no Origin header) using the secret
// token, which therefore never reaches the browser.
//
// Run:
//   BASTION_API_TOKEN="$(openssl rand -hex 32)" \
//   BASTION_AGENT_PROFILE_ID="<paired-profile-id>" \
//   bastion-mcp rest                 # in one terminal (the Bastion bridge)
//
//   BASTION_API_TOKEN="<same token>" \
//   BASTION_AGENT_PROFILE_ID="<same profile id>" \
//   node server.mjs                  # in another terminal (this dashboard)
//
// Zero dependencies — Node 18+ only.

import http from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, normalize } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, "public");

const PORT = Number(process.env.PORT || 3000);
const BASTION_API_BASE = process.env.BASTION_API_BASE || "http://127.0.0.1:9587";
const TOKEN = process.env.BASTION_API_TOKEN;
const PROFILE_ID = process.env.BASTION_AGENT_PROFILE_ID;

if (!TOKEN) {
  console.error("BASTION_API_TOKEN is required (must match the token the bridge was started with).");
  process.exit(1);
}
if (!PROFILE_ID) {
  console.error("BASTION_AGENT_PROFILE_ID is required (the paired profile this dashboard acts as).");
  process.exit(1);
}

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
};

/**
 * Call the Bastion REST API server-side. Crucially this sends NO `Origin`
 * header and attaches the bearer token + agent-profile header that the bridge
 * requires. Returns { status, body } where body is parsed JSON when possible.
 */
function bastionFetch(method, path, payload) {
  return new Promise((resolve) => {
    const data = payload === undefined ? undefined : Buffer.from(JSON.stringify(payload));
    const url = new URL(BASTION_API_BASE + path);
    const req = http.request(
      {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname + url.search,
        method,
        headers: {
          Authorization: `Bearer ${TOKEN}`,
          "X-Bastion-Agent-Profile": PROFILE_ID,
          ...(data ? { "Content-Type": "application/json", "Content-Length": data.length } : {}),
          // Intentionally NO Origin header.
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let body;
          try {
            body = text ? JSON.parse(text) : {};
          } catch {
            body = { raw: text };
          }
          resolve({ status: res.statusCode || 502, body });
        });
      }
    );
    req.on("error", (err) => {
      resolve({
        status: 502,
        body: {
          error: `Could not reach Bastion at ${BASTION_API_BASE}. Is \`bastion-mcp rest\` running? (${err.message})`,
        },
      });
    });
    if (data) req.write(data);
    req.end();
  });
}

function sendJSON(res, status, obj) {
  const body = Buffer.from(JSON.stringify(obj));
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Content-Length": body.length });
  res.end(body);
}

function readBody(req, limitBytes = 256 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > limitBytes) {
        reject(new Error("request body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      const text = Buffer.concat(chunks).toString("utf8");
      if (!text) return resolve({});
      try {
        resolve(JSON.parse(text));
      } catch {
        reject(new Error("invalid JSON body"));
      }
    });
    req.on("error", reject);
  });
}

async function serveStatic(req, res) {
  let path = req.url === "/" ? "/index.html" : req.url.split("?")[0];
  // Prevent path traversal.
  const full = normalize(join(PUBLIC_DIR, path));
  if (!full.startsWith(PUBLIC_DIR)) {
    return sendJSON(res, 403, { error: "forbidden" });
  }
  try {
    const data = await readFile(full);
    const ext = full.slice(full.lastIndexOf("."));
    res.writeHead(200, { "Content-Type": MIME[ext] || "application/octet-stream", "Content-Length": data.length });
    res.end(data);
  } catch {
    sendJSON(res, 404, { error: "not found" });
  }
}

const server = http.createServer(async (req, res) => {
  const { method, url } = req;
  const path = url.split("?")[0];

  try {
    // --- read endpoints ---
    if (method === "GET" && path === "/api/status") {
      const r = await bastionFetch("GET", "/status");
      return sendJSON(res, r.status, r.body);
    }
    if (method === "GET" && path === "/api/account") {
      const r = await bastionFetch("GET", "/account");
      return sendJSON(res, r.status, r.body);
    }
    if (method === "GET" && path === "/api/rules") {
      const r = await bastionFetch("GET", "/rules");
      return sendJSON(res, r.status, r.body);
    }
    if (method === "GET" && path === "/api/state") {
      const r = await bastionFetch("GET", "/state");
      return sendJSON(res, r.status, r.body);
    }

    // --- write endpoints (trigger Bastion's rule engine + approval UI) ---
    if (method === "POST" && path === "/api/sign-message") {
      const { message } = await readBody(req);
      if (typeof message !== "string" || message.length === 0) {
        return sendJSON(res, 400, { error: "message is required" });
      }
      const r = await bastionFetch("POST", "/sign/message", { message });
      return sendJSON(res, r.status, r.body);
    }
    if (method === "POST" && path === "/api/send-userop") {
      const { actions, send, chainId } = await readBody(req);
      if (!Array.isArray(actions) || actions.length === 0) {
        return sendJSON(res, 400, { error: "actions[] is required" });
      }
      const payload = { actions, send: send === true };
      if (chainId) payload.chainId = Number(chainId);
      const r = await bastionFetch("POST", "/sign/user-op", payload);
      return sendJSON(res, r.status, r.body);
    }

    // --- static frontend ---
    if (method === "GET") return serveStatic(req, res);

    sendJSON(res, 404, { error: "not found" });
  } catch (err) {
    sendJSON(res, 400, { error: err.message || "bad request" });
  }
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`Bastion dashboard → http://127.0.0.1:${PORT}`);
  console.log(`Proxying to Bastion API at ${BASTION_API_BASE} as profile ${PROFILE_ID}`);
});
