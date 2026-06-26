# Attack Surface — Bastion MCP/REST Bridge (commit 390de47)

## Toolchain / Language
- Swift (macOS app + standalone `bastion-mcp` executable). Built via `bastion.xcodeproj`. No package manager for the bridge — single-file `bastion-mcp/main.swift` (1056 lines) using `Darwin` BSD sockets + `Foundation` `NSXPCConnection`.
- IPC: NSXPC over Mach service `com.bastion.xpc`. Bridge talks to the signed Bastion.app XPC server.
- Keys: Secure Enclave (P-256), accessed app-side only.

## Actors & Authority Tiers
| Actor | How authenticated | Authority |
|---|---|---|
| Owner (human) | Biometric/passcode via `AuthManager` | Create/modify/revoke wallet groups, install validators, reset keys |
| `bastion-mcp` bridge (REST mode) | Code signature `com.bastion.mcp` + path-bound to `Contents/MacOS/bastion-mcp` (XPC accept) AND a shared `BASTION_API_TOKEN` bearer (HTTP) | Proxy ANY paired agent profile's read + SIGN ops |
| `bastion-mcp` bridge (stdio MCP mode) | Code signature only (stdio caller trusted by spawn) — NO bearer token | Same as REST, minus the token gate |
| Remote/local HTTP client | Possession of `BASTION_API_TOKEN` + a profile id; must not send `Origin` header | Whatever the bridge can do, scoped by `agentProfileId` it supplies |
| Agent profile (logical identity) | Previously: kernel-verified caller bundleId. NOW: a bridge-supplied `agentProfileId` string | Sign under that profile's merged policy |
| Legacy direct XPC clients (e.g. `bastion-cli`, debug only) | Kernel code-signature -> `clientBundleId` | Sign under their own bundleId profile |

## Trust Boundary Shift (the core concern)
OLD: each XPC method ran under `clientBundleId` = the **kernel-verified** code signature of the connecting process. Authority was intrinsically bound to caller identity.

NEW: the bridge connects ONCE as `com.bastion.mcp` (trusted binary) and then **names** which profile to act as per-call via `agentProfileId` / `X-Bastion-Agent-Profile`. Entitlement to a profile is reduced to: (bridge is the signed binary) AND (profile id exists & is paired). The single `BASTION_API_TOKEN` is the only secret guarding the REST front door, and it is **not bound to any profile subset**.

## Entry Points (file:line — caller — effect)

### bastion-mcp/main.swift — REST (HTTP on 127.0.0.1:9587)
- `runREST()` L1012 — startup — binds loopback socket; refuses to start unless `tokenLooksHighEntropy(BASTION_API_TOKEN)`.
- `handleClient(fd:)` L996 — per-connection thread — parse + route + reply.
- `readHTTPRequest(fd:)` L826 — raw recv loop — **body cap only after header parsed; no header cap; no timeout** (DoS).
- `parseHTTPRequest` L798 — hand-rolled HTTP parser — splits head/body on `\r\n\r\n`, lowercases header keys.
- `routeREST(req)` L881 — auth + dispatch:
  - L882 reject if `Origin` header present (CSRF gate)
  - L885-887 require high-entropy `BASTION_API_TOKEN` (throws `.auth`->400 if unset)
  - L889 `authorization == "Bearer <token>"` (non-constant-time) else 401
  - Routes (all profile-scoped via `authorizedAgentProfileId` = header or body):
    - `GET /status|/account|/rules|/state` — read pubkey/rules/counters for supplied profile
    - `POST /pair` — start pairing
    - `POST /sign/message|/sign/typed-data|/sign/raw|/sign/user-op` — **Secure Enclave signature under supplied profile**
    - `GET/POST /groups`, `GET /pair/{id}`, `GET /groups/{id}`, `POST /groups/{id}/agents`, `DELETE .../agents/{m}`, `PATCH .../agents/{m}/scope`, `POST .../agents/{m}/install-on-chain|uninstall-on-chain|installed`
- `authorizedAgentProfileId` L874 — **header path has NO length/format validation** (body path caps 64).

### bastion-mcp/main.swift — stdio MCP (JSON-RPC)
- `runMCP()` L680 — reads lines from stdin — `initialize|ping|tools/list|tools/call`. **No bearer-token gate** — trusts the stdio spawner.
- `callTool(name:args:)` L544 — 21 tools mapping to the same XPC ops as REST.
- `validateAgentProfileId(args)` L354 — profile from arg (max 64) or `BASTION_AGENT_PROFILE_ID` env.

### bastion/IPC/XPCServer.swift — XPC server (Bastion.app side)
- `listener(_:shouldAcceptNewConnection:)` L65 — code-sig verify (`verifyClientCodeSignature` L222, requires Team `926A27BQ7W`) + allowlist (bypassed for trusted bridge) + computes `isTrustedAgentBridge` via `isTrustedAgentBridgeClient` L283 (bundleId==`com.bastion.mcp` AND exec path==`<host>/Contents/MacOS/bastion-mcp`). **Identity sampled from PID, not audit token.**
- `bridgeProfileBundleId(agentProfileId:)` L1963 — **the entitlement choke point**: `guard isTrustedAgentBridge` + `ruleEngine.clientProfile(id:) != nil` -> returns that profile's bundleId. NO token/instance-to-profile binding.
- `bridgeSign` L2131 / `bridgeSignStructured` L2161 — resolve profile -> `enforceSigningPreflightAllowed(bundleId:)` + policy -> `SigningManager.processSignRequest` -> **SE signature**. No owner auth.
- `bridgeGetPublicKey` L2032 / `bridgeGetRules` L2062 / `bridgeGetState` L2085 — read for supplied profile.
- `bridgeStartPairing` L1984 / `bridgePollPairing` L2021 / `bridgeGetServiceInfo` L2109 — gated by `isTrustedAgentBridge`.
- Wallet-group writes (`createWalletGroup` L2186, `addAgentToGroup` L2247, `removeAgentFromGroup` L2271, `updateAgentScope` L2293, `markAgentInstalled` L2314, `installAgentOnChain` L2340, `uninstallAgentOnChain` L2366) — owner biometric enforced inside RuleEngine.
- `getWalletGroup` L2224 requires biometric; `listWalletGroups` L2209 does NOT.
- `exportSupportBundle` L1478 — reads full config with NO paired-profile read gate; emits profile-id inventory.

## Assets
- Secure Enclave P-256 signing keys (per agent profile + per wallet-group owner/member). Bridge can trigger signatures but never extracts keys.
- Smart-account signing authority (ERC-4337 UserOps -> on-chain fund movement under policy caps).
- Wallet-group membership / account addresses (disclosed by list/get group + account read).
- `BASTION_API_TOKEN` (the single shared bearer for the REST front door).
- Per-agent rate-limit / spending-limit counters (StateStore).

## Privileged Action Call Graph (sign path)
HTTP `POST /sign/*` (token-gated) -> `authorizedAgentProfileId` (header/body) -> `xpc.signStructured(agentProfileId:)` -> XPC `bridgeSignStructured` -> `bridgeProfileBundleId` (existence-only check) -> `handleSignStructured(effectiveBundleId:)` -> `enforceSigningPreflightAllowed` + `enforceStaticSigningPolicy` (RuleEngine.validate) -> `SigningManager.processSignRequest` -> approval policy / notification -> Secure Enclave signature.

## Key Limits / Guards present
- `maxBodyBytes` 1MiB, `maxMessageBytes` 64KiB, `maxJSONBytes` 512KiB, `maxDataChars` 256KiB, `maxUserOpActions` 16.
- Address/hex/txhash/UUID regex validators (L334-352).
- `tokenLooksHighEntropy` (>=32 chars, >=8 distinct, Shannon>=128 bits, no long run/sequence/repeat).
- Loopback-only bind; `Origin`-present rejection.
- App-side: profile must be paired; UserOp sender must match profile account; pause/lockdown/revoked block signing.
- XPC accept requires Team `926A27BQ7W` code signature.
