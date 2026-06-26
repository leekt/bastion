# Bastion Web Dashboard (example)

A minimal, **zero-dependency** web app that drives the local Bastion signing
bridge: it shows the paired agent's account, rules, and remaining quotas, and
lets you sign an EIP-191 message or build/send an ERC-4337 UserOperation — each
flowing through Bastion's rule engine and approval UI.

It exists to demonstrate the **correct integration shape** for a browser UI.

## Architecture: why a server-side proxy

```
Browser  ──(same-origin fetch /api/*)──►  Node proxy (server.mjs)  ──(Bearer token, no Origin)──►  bastion-mcp rest  ──XPC──►  Bastion.app
  └─ never sees the token                    └─ holds BASTION_API_TOKEN                                (127.0.0.1:9587)         └─ Secure Enclave
```

The Bastion REST API is hardened on purpose and **a browser cannot call it directly**:

- It **rejects any request carrying an `Origin` header** (a CSRF guard). Browsers
  attach `Origin` to cross-origin and non-`GET` requests, so direct `fetch()` to
  `127.0.0.1:9587` is refused.
- It requires `Authorization: Bearer $BASTION_API_TOKEN`. Shipping that token to
  the browser would leak it to any page/script in the origin.
- Identity is scoped by `BASTION_AGENT_PROFILE_ID` — the bridge only acts for the
  profile(s) it was started with.

So the right pattern is a tiny trusted **backend** that holds the secret and
talks to Bastion server-side. `server.mjs` is that backend. The browser only ever
talks to `server.mjs` (same origin), and `server.mjs` adds the token and omits
`Origin` when calling Bastion.

> This mirrors the production rule: **one bridge per agent, token = authority over
> that bridge's profile scope.** Keep the scope minimal.

## Prerequisites

1. **Bastion.app installed and running** (the menu-bar service).
2. **A paired agent profile.** Pair one via the MCP tools (`bastion_pair_agent` →
   approve in the menu bar → `bastion_poll_pairing`) and note the returned
   profile id. See the repo root [`README.md`](../../README.md).
3. **Node 18+** (for `node:fs/promises`, `fetch`-free `http`, `replaceChildren` is browser-side).

## Run

Pick one high-entropy token and reuse it for both processes.

**Terminal 1 — the Bastion REST bridge:**

```bash
export BASTION_API_TOKEN="$(openssl rand -hex 32)"
export BASTION_AGENT_PROFILE_ID="<your-paired-profile-id>"
/Applications/Bastion.app/Contents/MacOS/bastion-mcp rest
# (dev build: "$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-mcp")
```

**Terminal 2 — this dashboard (same token + profile):**

```bash
cd examples/web-dashboard
BASTION_API_TOKEN="$BASTION_API_TOKEN" \
BASTION_AGENT_PROFILE_ID="$BASTION_AGENT_PROFILE_ID" \
node server.mjs
```

Open <http://127.0.0.1:3000>.

### Environment

| Var | Required | Default | Meaning |
|-----|----------|---------|---------|
| `BASTION_API_TOKEN` | yes | — | Bearer token; must match the bridge |
| `BASTION_AGENT_PROFILE_ID` | yes | — | Paired profile this dashboard acts as; must be in the bridge's scope |
| `BASTION_API_BASE` | no | `http://127.0.0.1:9587` | Bridge REST base URL |
| `PORT` | no | `3000` | Dashboard port (binds `127.0.0.1` only) |

## What it exercises

| UI action | Proxy route | Bastion endpoint |
|-----------|-------------|------------------|
| Service / Account / State / Rules cards | `GET /api/{status,account,state,rules}` | `GET /{status,account,state,rules}` |
| Sign message | `POST /api/sign-message` | `POST /sign/message` |
| Send UserOperation | `POST /api/send-userop` | `POST /sign/user-op` |

Signing actions may pop the Bastion approval UI and are subject to the profile's
rate / spending / target / chain limits — watch the **State** card update and the
menu-bar app react.

## Notes & limits

- Example code: minimal error handling, no auth on the dashboard itself (bind it
  to loopback only — it already does).
- The dashboard's authority is exactly the bridge's `BASTION_AGENT_PROFILE_ID`
  scope. It cannot act for other profiles (enforced by the bridge; see
  `audits/2026-06-taek/findings.md`, AC-01).
- Not production-hardened: add real auth/session handling and input validation
  before exposing anything beyond localhost.
