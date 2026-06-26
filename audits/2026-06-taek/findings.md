# Findings — Bastion MCP/REST Bridge Audit (commit 390de47)

**Auditor:** taek <leekt216@gmail.com>
**Date:** 2026-06-26
**Scope:** New production bridge `bastion-mcp/main.swift` + `bridge*` XPC surface in `bastion/IPC/XPCServer.swift` + `bastion/IPC/BastionXPCProtocol.swift`, plus the RuleEngine/SigningManager paths they reach.
**Method:** Static source trace + 4 parallel streams (focus subagents, Codex cold pass, cross-cutting pass; Gemini produced no output). Every finding adversarially verified by 3 independent skeptics. **No runtime exploitation performed** — all PoCs are static-derived outlines.

**Tally:** 2 Critical · 2 High · 3 Medium · 0 Low (7 confirmed; 18 candidate findings dismissed by verification).

| ID | Sev | Title | Primary location |
|----|-----|-------|------------------|
| AC-01 | Critical | One shared token / bridge access → sign for **any** paired profile via attacker-chosen UUID | `XPCServer.bridgeProfileBundleId` + `main.swift authorizedAgentProfileId` |
| AC-02 | Critical | XPC client auth uses **PID** not audit token → PID-reuse race impersonates the trusted bridge | `XPCServer.listener` / `verifyClientCodeSignature` |
| RE-01 | High | Cross-tenant disclosure of any profile's account/rules/spend-state via chosen UUID | REST `GET /account /rules /state` |
| DO-01 | High | Raw-socket slowloris + unbounded pre-header buffer (OOM), both pre-auth | `main.swift readHTTPRequest` / `runREST` |
| AC-03 | Medium | `listWalletGroups` leaks all group addresses + topology with no auth (vs biometric `getWalletGroup`) | `XPCServer.listWalletGroups` |
| AC-04 | Medium | `exportSupportBundle` bypasses the paired-profile read gate, leaks profile-id inventory | `XPCServer.exportSupportBundle` |
| RP-01 | Medium | REST `X-Bastion-Agent-Profile` header bypasses the MCP `max:64` + trim/charset validation | `main.swift authorizedAgentProfileId` |

> **Root theme.** The bridge moved identity attribution from a *kernel-verified caller code signature* (old: each agent connected as its own verified `bundleId`) to a *bridge-supplied `agentProfileId` string* gated only by binary identity + a single shared bearer token. AC-01, AC-02, RE-01 and RP-01 are all facets of that one shift; AC-03/AC-04 are pre-existing read-gate asymmetries the new surface makes reachable.

---

## AC-01 — Critical — Single `BASTION_API_TOKEN` holder can sign for EVERY paired profile

**Location:** `XPCServer.swift:1963-1982` (`bridgeProfileBundleId`), `2131-2182` (`bridgeSign`/`bridgeSignStructured`); `bastion-mcp/main.swift:874-879` (`authorizedAgentProfileId`), `914-933` (sign routes), `354-364` (`validateAgentProfileId`); `RuleEngine.swift:473-477` (`clientProfile(id:)`).

**Mechanism.** `bridgeProfileBundleId(agentProfileId:)` is the *only* gate between an inbound signing request and a victim's Secure Enclave key, and it checks exactly two things: (1) `isTrustedAgentBridge` — a per-connection boolean set purely from the connecting binary's code identity; (2) `ruleEngine.clientProfile(id:) != nil`, which just returns `config.clientProfiles.first { $0.id == id }` — i.e. **any** profile UUID present in the machine-global config matches. There is **no binding** between the bridge's token (or the XPC connection instance) and which profile UUIDs it may proxy. Once the victim bundleId is returned, the whole signing pipeline keys off it: `existingClientContext → signingContext(for:) → SigningManager.processSignRequest → seManager.signDigest(keyTag:)`. Profile UUIDs are **not secret** (returned by pairing, `/status`, `/groups`, and written into every agent's MCP config). The REST front door authenticates only the single shared `BASTION_API_TOKEN`, then `authorizedAgentProfileId` takes the target from the attacker-controlled `X-Bastion-Agent-Profile` header / body with zero ownership check.

This is a **strict regression** from the old model where the XPC layer cryptographically bound caller identity to the one profile it could exercise.

**PoC (static).** With `Authorization: Bearer <TOKEN>`: (1) `GET /groups` or `GET /status` to harvest victim UUIDs + account addresses; (2) `POST /sign/user-op` with `X-Bastion-Agent-Profile: <VICTIM_UUID>` and a `userOpJson` whose `sender` == the victim account (so the sender-match check passes against the *victim* context); (3) if the victim profile auto-signs (`.open` authPolicy or op within policy), the Secure Enclave returns a valid signature with **no UI / biometric / passcode** prompt. Repeat per victim UUID on the box. stdio MCP mode is worse — no token at all.

**Impact.** Full cross-profile signing authority from one leaked token (or any process that can reach the stdio bridge). Direct path to unauthorized on-chain fund movement within each victim profile's caps.

---

## AC-02 — Critical — XPC client auth uses PID, not audit token (PID-reuse impersonation)

**Location:** `XPCServer.swift:65-133` (`listener`), `192-214` (`bundleIdentifier(for:)`), `222-261` (`verifyClientCodeSignature`), `283-297` (`isTrustedAgentBridgeClient`), `352-359` (`executablePath(for:)`).

**Mechanism.** The listener identifies the connecting client entirely by **PID**. `shouldAcceptNewConnection` reads `newConnection.processIdentifier` and feeds it to three *independent, non-atomic* kernel lookups: `verifyClientCodeSignature` (`kSecGuestAttributePid`), `bundleIdentifier(for:)` (same), and `executablePath(for:)` (`proc_pidpath`). No `audit_token_t` / `kSecGuestAttributeAudit` is used anywhere (grep: zero hits in `IPC/`). This is the canonical macOS XPC PID-reuse vulnerability (CVE-2020-14977 class). PIDs are not stable: an attacker can `posix_spawn` the legitimate signed binary so the PID the server samples resolves to a *different* image than the one that opened and uses the channel. `audit_token_t` carries `p_idversion` which defeats this; the bare PID does not. The three checks at three instants widen the TOCTOU window.

The prize is large: a connection resolving to `com.bastion.mcp` at the bundled path gets `isTrustedAgentBridge = true`, which (1) **bypasses the global client allowlist** (only checked `if !isTrustedAgentBridge`) and (2) unlocks `bridgeSign`/`bridgeSignStructured` for any profile (→ AC-01).

**PoC (static).** Mirrors the CVE-2020-14977 technique: open the connection, send the privileged message, then `posix_spawn` the genuine bundled `bastion-mcp` so it owns the PID before the server samples it → server resolves trusted identity → `isTrustedAgentBridge=true` → call `bridgeSign(agentProfileId:<any>)`.

**Impact.** An unsigned/untrusted local process gains the trusted-bridge entitlement, then signs for arbitrary profiles. Local privilege escalation into the signing boundary.

---

## RE-01 — High — Cross-tenant read disclosure (account/rules/spend-state)

**Location:** `main.swift:902-909` (`GET /status /account /rules /state`), `874-879`; `XPCServer.swift:2032-2107` (`bridgeGetPublicKey/Rules/State`), `1963-1982`.

**Mechanism.** Same root as AC-01 on the read side. `GET /account /rules /state` pass the attacker-controlled `X-Bastion-Agent-Profile` verbatim into `bridgeGetPublicKey/Rules/State`, each resolving via `bridgeProfileBundleId` (existence-only) and returning the victim's account address, public key, full rule set (spend/rate limits, allowlists) and live counters. `GET /status` passes the header straight through with no binding at all. One token holder fingerprints every tenant — which directly feeds AC-01 (learn which profiles are `.open` or have generous caps before signing).

**PoC (static).** `GET /groups` to enumerate UUIDs, then `GET /account|/rules|/state` with `X-Bastion-Agent-Profile: <VICTIM_UUID>`.

**Impact.** Privacy breach + reconnaissance amplifier for AC-01.

---

## DO-01 — High — Slowloris + unbounded pre-header buffer (OOM), pre-auth

**Location:** `main.swift:826-854` (`readHTTPRequest`), `1019-1043` (`runREST`).

**Mechanism (two defects, same function).**
1. **No timeout (slowloris).** Accepted sockets set only `SO_REUSEADDR`; no `SO_RCVTIMEO`/`SO_SNDTIMEO`, blocking mode, no kqueue/poll. A client that sends nothing — or a partial header without `\r\n\r\n` — leaves `recv` blocked forever. `handleClient` runs synchronously on a `DispatchQueue.global` worker, so each stalled connection permanently consumes one libdispatch thread. Saturate the bounded pool and the signing API freezes for all agents.
2. **Unbounded header buffer (OOM).** The `maxBodyBytes` (1 MiB) guard fires only *after* `\r\n\r\n` is seen. Until then every recv chunk is appended with no ceiling — an endless header section grows `buffer` to OOM. Compounded by `buffer.range(of: marker)` re-scanning the whole growing buffer each 8 KiB recv (O(n²) CPU).

Both trigger **before** `routeREST`/auth — no token needed; any local process qualifies.

**PoC (static).** Slowloris: `for i in $(seq 1 300); do (printf 'GET /health HTTP/1.1\r\nHost: x'; sleep 100000) | nc 127.0.0.1 9587 & done`. OOM: stream `X-Pad: AAAA...\r\n` lines forever without the blank line.

**Impact.** Denial of service of the local signing bridge (thread exhaustion or OOM kill). Pre-auth.

---

## AC-03 — Medium — `listWalletGroups` leaks all group addresses + topology with no auth

**Location:** `XPCServer.swift:2209-2222` (vs `2224-2245` `getWalletGroup`; codec `2492-2510`).

**Mechanism.** `listWalletGroups` runs **no** auth — no `authManager.authenticate`, no allowlist, no `isTrustedAgentBridge` check, no agent-profile requirement. Its sibling `getWalletGroup` requires `.biometricOrPasscode` to view *one* group, yet `listWalletGroups` returns `WalletGroupInfo` for *every* group via the same codec. The codec nils `keyTag`/`sharedRules`/`profileId` but still exposes each group's `label`, funded `accountAddress`, `chainIds`, member labels, validator addresses, install status and counts. Any accepted client (incl. the bridge, which skips the allowlist) reaches it without pairing.

**PoC (static).** Connect as any accepted client → `listWalletGroups` with no `agentProfileId` → decode every group's account address + member roster — the exact data the biometric gate on `getWalletGroup` protects.

**Impact.** Defeats the per-group confidentiality the biometric gate enforces; on-chain account enumeration.

---

## AC-04 — Medium — `exportSupportBundle` bypasses the paired-profile read gate

**Location:** `XPCServer.swift:1478-1512` (vs `getRules`/`getState` calling `existingClientContext` at `510`); `SupportBundleExporter.swift:238-247`.

**Mechanism.** `getRules`/`getState` both call `existingClientContext()` (enforces allowlist + a matching paired profile). `exportSupportBundle` is the read sibling but calls **neither** that gate **nor** owner auth — it loads `ruleEngine.loadConfig()` and hands it to `SupportBundleExporter`, which emits `clientProfiles[]` (id, bundleId, label, authPolicy, group membership) for **every** profile. Any accepted direct XPC client (or the repo CLI) reads the full profile-id inventory ungated.

**PoC (static).** `bastion support-bundle --output /tmp/b.json; jq '.config.clientProfiles' /tmp/b.json` → every profile id. Chains into AC-01 (those ids are exactly the selectors `bridgeProfileBundleId` accepts → enumerate-then-impersonate end-to-end).

**Impact.** Leaks the enumeration set AC-01 needs.

---

## RP-01 — Medium — REST profile header bypasses MCP-path validation

**Location:** `main.swift:874-879` (`authorizedAgentProfileId`) vs `354-364` (`validateAgentProfileId`).

**Mechanism — parity drift.** Both transports converge on the same XPC calls but validate `agentProfileId` differently. MCP `validateAgentProfileId` enforces `max:64` UTF-8 bytes + trim-nonempty. REST `authorizedAgentProfileId` returns `req.headers["x-bastion-agent-profile"]` **verbatim** whenever `!header.isEmpty` — no length cap, no charset normalization, no trim-then-empty check (a single space `" "` passes). Header size is bounded only by the body-cap (which never applies to headers), so the id can be hundreds of KB. The unvalidated value flows straight into `bridgeSign`/`bridgeSignStructured`/`bridgeGetPublicKey`.

**PoC (static).** `curl .../account -H 'X-Bastion-Agent-Profile:  '` (single space passes `!isEmpty`; MCP would reject); or a 200 000-char header reaching the signing XPC call unnormalized.

**Impact.** Defeats a stated bound and feeds unbounded, non-normalized attacker input across the signing trust boundary. Bounded to Medium because the service-side lookup currently fails-closed on a miss, but the bridge's contract is to normalize *before* crossing XPC.

---

## Remediation status (2026-06-26)

| Finding | Status | Where |
|---------|--------|-------|
| AC-01 | **Mitigated** (bridge-side) + residual deferred | `bastion-mcp/main.swift` — `BASTION_AGENT_PROFILE_ID` is now an enforced allow-set; a bridge rejects any profile outside its scope before XPC. Service-side per-connection capability binding deferred (needs an XPC-protocol change; see note). |
| AC-02 | **Fixed** | `XPCServer.swift` — client identity now resolved from the peer's `audit_token_t` (one `SecCode`), not the bare PID. |
| RE-01 | **Fixed** (with AC-01 bridge-side) | Read endpoints go through the same allow-set authorization. |
| DO-01 | **Fixed** | `bastion-mcp/main.swift` — `SO_RCVTIMEO/SNDTIMEO`, 64 KB pre-header cap, incremental marker scan, bounded-concurrency semaphore. |
| AC-03 | **Fixed** | `XPCServer.swift` — `listWalletGroups` now requires `.biometricOrPasscode`, matching `getWalletGroup`. |
| AC-04 | **Fixed** | `SupportBundleExporter.swift` — profile `id`/`membershipId` selectors redacted to stable placeholders. Regression test added. |
| RP-01 | **Fixed** | `bastion-mcp/main.swift` — REST `X-Bastion-Agent-Profile` normalized through the same validator as MCP. |

**Verification:** bridge fixes — `audits/2026-06-taek/poc/bridge-attribution-regression.sh` (5/5 pass). App-side — `bastionTests/{XPCSecurityTests,SupportBundleTests}` pass (unsigned `xcodebuild test`), incl. a new `supportBundleRedactsProfileSelectors` regression for AC-04.

**AC-01 residual (deferred, tracked).** The bridge-side allow-set + AC-02 (only the genuine signed bridge can connect) break the practical attack chain. A defense-in-depth, service-side binding — where `bridgeProfileBundleId` authorizes `agentProfileId` against a per-connection capability rather than mere existence — requires a new XPC-protocol handshake (pairing-derived capability or per-connection scope declaration) that also changes the bridge binary. That is a protocol design change, not a safe single-pass edit, and is left as follow-up.

## Remediation waves (original plan)

| Wave | Seam | Fixes | Notes |
|------|------|-------|-------|
| **1** | Entitlement (`bridgeProfileBundleId` + `authorizedAgentProfileId`/`validateAgentProfileId`) | AC-01, RP-01 | Bind each connection/token to an explicit set of allowed profile UUIDs; reject ids outside it. Move `max:64` + charset normalization into `authorizedAgentProfileId` so REST == MCP. **Headline.** |
| **2** | XPC identity (`shouldAcceptNewConnection` + sig/path lookups) | AC-02 | Replace all PID-keyed lookups with a single `audit_token_t` snapshot (`kSecGuestAttributeAudit`) captured once per connection; derive validity/team/identifier/path from that one `SecCode`. |
| **3** | Read-gate symmetry (`listWalletGroups` + `exportSupportBundle`) | AC-03, AC-04 | Route both through `existingClientContext()`/biometric consistent with `getWalletGroup`/`getRules`, or redact account addresses + profile-id inventory. |
| **4** | Socket hardening (`readHTTPRequest` + `runREST`) | DO-01 | `SO_RCVTIMEO`/`SO_SNDTIMEO` + per-connection deadline; cap accumulated header bytes before `\r\n\r\n`; incremental scan instead of O(n²) `range(of:)`; bounded-concurrency admission semaphore. |

Waves 1 and 2 are independent, both **must precede any release**. Waves 3 and 4 are independent of 1/2. After each wave, write a regression test (`/audit-poc`) that flips green on the fix; AC-01 and AC-02 first.

## Out of scope (not audited)
SE key-gen/storage/attestation internals; on-chain ERC-4337/7579 contracts & install semantics; pairing cryptography end-to-end; biometric `AuthManager` internals; SwiftUI/UI layer; `bastion-cli` beyond its role as a same-team XPC client; build/CI/codesign/entitlements; dependency supply chain. No dynamic/runtime testing.
