# Bastion — Security Model & Architecture

## Trust Boundary

```
┌──────────────────────────────────────────────────────┐
│  TRUSTED (Bastion.app process)                       │
│  ├── macOS Keychain (com.bastion)                    │
│  └── Secure Enclave                                  │
│      ├── Per-client signing keys                     │
│      └── Per-group owner + per-agent keys            │
└──────────────────────────────────────────────────────┘
         ▲ XPC (team ID verified)
         │
┌──────────────────────────────────────────────────────┐
│  TRUSTED-BRIDGE (distinguished XPC client)           │
│  └── bastion-mcp (bundled, code-signed, path-bound)  │
│      speaks MCP stdio + localhost REST → XPC         │
└──────────────────────────────────────────────────────┘
         ▲ XPC (team ID + bundled-path verified)
         │
┌──────────────────────────────────────────────────────┐
│  UNTRUSTED                                           │
│  ├── bastion-cli (dev/QA only; no secrets)           │
│  ├── AI agents (MCP + REST callers)                  │
│  └── Filesystem (~Library/App Support/)              │
└──────────────────────────────────────────────────────┘
```

Bastion.app is the **single trust boundary** for secrets — the Secure Enclave and Keychain live only inside it.

As of commit `390de47` the production integration path is the **bundled `bastion-mcp` bridge**, which talks to the XPC service *directly* (it no longer wraps `bastion-cli`). The bridge is a **distinguished, path-bound trusted XPC client**: the server only grants the bridge entitlement when the connecting binary is code-signed `com.bastion.mcp` *and* its executable is the bundled `Contents/MacOS/bastion-mcp` inside the host app. Once trusted, the bridge no longer connects *as* a specific agent — it **names** which paired profile to act as per request via an `agentProfileId` (MCP) / `X-Bastion-Agent-Profile` header (REST). The REST front door is additionally gated by a single shared `BASTION_API_TOKEN` (128-bit entropy floor), loopback-only bind, and `Origin`-present rejection.

> **Security status (2026-06 audit, `audits/2026-06-taek/`).** This attribution model is a deliberate trade for a cleaner integration surface. The independent audit found it initially **regressed caller↔profile binding** (identity moved from a kernel-verified caller code signature to a bridge-supplied string), with two Criticals. Remediation landed: **AC-02** (PID→audit-token client auth) is fixed; **AC-01** is mitigated bridge-side — `BASTION_AGENT_PROFILE_ID` is now an enforced authorization allow-set, so a bridge can only act for the profile(s) it is configured for; **DO-01** socket hardening, **AC-03** (biometric-gated `listWalletGroups`) and **AC-04** (redacted support-bundle inventory) are fixed. **One residual remains:** a service-side per-connection capability binding for `agentProfileId` (defense-in-depth) is deferred — until it lands, run **one bridge per agent with a minimal `BASTION_AGENT_PROFILE_ID` scope**, and treat the REST `BASTION_API_TOKEN` as authority over exactly that scope. See `audits/2026-06-taek/findings.md`.

## Trust Assumptions

| Assumption | What Breaks If Violated |
|------------|------------------------|
| macOS kernel is not compromised | Everything — kernel can read any process memory |
| Secure Enclave hardware is sound | Key theft (theoretical, no known attacks) |
| Team signing key is not compromised | Attacker builds fake app with same Keychain access group |
| Bastion.app binary is not tampered with | Malicious app can sign arbitrarily |
| User's biometric is not compromised | Attacker can modify rules freely |

## Attack Surface Analysis

### Agent Deletes State Files
**Previously vulnerable, now mitigated.** Rate limit state was stored at `~/Library/Application Support/Bastion/ratelimit.signed`. Agent could delete the file to reset counters. Now stored in Keychain — agent process cannot call `SecItemDelete` on `com.bastion` items.

### Agent Modifies Config
Config is in Keychain — agent cannot write to it. Config updates require biometric authentication via `LAContext.evaluatePolicy(.biometricOrPasscode)`.

### Agent Kills and Restarts App
All state is in Keychain, which persists across app restarts. No state is lost.

### Agent Bypasses CLI, Connects XPC Directly
XPC connections are verified via `SecCodeCopyGuestWithAttributes` + team ID check. Even with a direct connection, the agent hits the same rule enforcement — CLI has no special privileges.

### CLI Vulnerability / Code Injection
The CLI has **zero secrets**. It cannot access Keychain items. A fully compromised CLI is equivalent to calling XPC endpoints directly — still subject to all rules.

### Compromised Team Signing Key
Impact:
- ✅ Can read `com.bastion` Keychain items (config, state)
- ✅ Can use SE Key B to sign arbitrary data on the victim's machine
- ❌ Cannot **extract** the SE private key (hardware protection)
- ❌ Cannot access any other Keychain items (Safari passwords, SSH keys, etc.)

Blast radius is limited to `com.bastion` access group. The SE private key is usable but not exportable — worst case is unauthorized *use*, not *theft*.

### Malicious Developer Update
Same impact as compromised signing key. This is true for every macOS app — 1Password, MetaMask, any wallet. Mitigations: open source + reproducible builds, Apple notarization (remote revoke).

### Debugger Attachment / Dylib Injection
Blocked by **Hardened Runtime** (enabled in build settings). Prevents debugger attachment, dylib injection, DYLD environment variable injection, and unsigned memory page execution.

## Security Properties

| Property | Guaranteed By |
|----------|--------------|
| Agent cannot extract SE private key | Secure Enclave hardware |
| Agent cannot read/write Keychain | macOS code signing + access groups |
| Agent cannot modify rules without biometric | LAContext + Keychain |
| State survives app restart | Keychain persistence |
| XPC callers are team-verified | SecCodeCopySigningInformation + team ID check |
| CLI compromise leaks nothing | CLI has no secrets (architecture) |
| SE key usable but not extractable even if app compromised | Secure Enclave hardware |

## Comparison to Other Wallet Models

| Model | Compromise Impact |
|-------|-------------------|
| Browser extension wallet (MetaMask) | Full key theft — attacker gets private key |
| Desktop wallet (Ledger Live) | Device must be physically present + approve |
| Mobile wallet (Rainbow) | Use not theft (iOS SE) |
| **Bastion** | **Use not theft — key never exportable** |

## Ethereum Integration

Bastion understands Ethereum operations natively:

| Feature | Status |
|---------|--------|
| Keccak-256 (C, Ethereum 0x01 padding) | Done |
| EIP-191 personal message signing | Done |
| EIP-712 typed data signing | Done |
| ERC-4337 UserOp hash (v0.7, v0.8, v0.9) | Done |
| Kernel v3.3 ERC-7579 calldata encoding | Done |
| Calldata decoding (ERC-20 transfer/approve, Kernel execute) | Done |
| ZeroDev bundler + paymaster API | Done |
| SmartAccount (CREATE2 address, factory data, nonce) | Done |
| P256Validator on-chain (Solidity, audited) | Done |
| Raw digest signing (`signDigest` — no SHA-256 pre-hash) | Done |
| P-256 s-normalization (s <= N/2 for OZ compatibility) | Done |

### Calldata-Aware Rule Engine

The rule engine decodes UserOp calldata before validation:

1. **Target check**: validates decoded inner-call targets (not just the UserOp `sender`), catching delegatecalls and batch operations
2. **Spending limits**: extracts actual transfer amounts from ERC-20 `transfer`/`transferFrom`/`approve` calls in the decoded calldata
3. **Approval popup**: shows human-readable decoded calldata (target, function, token amount) instead of raw hex

### Wallet Groups (sudo owner + scoped agents)

A wallet group is a single smart account shared between an owner and multiple scoped agents. Each agent has its own Secure Enclave key, its own ERC-7579 validator (installed on-chain via `installModule`), and its own scoped policy. Two security properties matter here:

- **Counter isolation**: scoped rules accepted from external callers (CLI / MCP / REST) get fresh UUIDs on add and on every update. `StateStore` keys counters by `rule.id`, so duplicate IDs across agents would otherwise let one agent's spend exhaust another's budget. The team explicitly regenerates IDs to make this impossible.
- **Allowlist nil vs empty**: a `nil` allowlist means "no restriction"; an empty array means "deny all". Earlier code collapsed both into "no restriction", which would have let merge logic emitting an empty sentinel array silently permit every caller. The current rule engine treats empty as a hard deny.

### Agent Integration Surface (MCP + REST)

The production bridge is the bundled Swift binary **`bastion-mcp`** (`bastion-mcp/main.swift`), shipped at `Bastion.app/Contents/MacOS/bastion-mcp`. It exposes Bastion to agents through:

- **MCP stdio server** (default) — for Claude Code / Cursor agents. The agent config points `command` at the bundled `bastion-mcp` and sets `BASTION_AGENT_PROFILE_ID` to the paired profile id. First-run pairing uses the `bastion_pair_agent` / `bastion_poll_pairing` tools; the owner approves in the menu bar.
- **REST API on `127.0.0.1`** (`bastion-mcp rest`) — `Authorization: Bearer $BASTION_API_TOKEN` on every route, `Origin`-present rejection, 1 MiB body cap, regex-validated address/hex/UUID inputs, and startup refusal unless `BASTION_API_TOKEN` passes a 128-bit estimated-entropy check.

The bridge holds **no** Keychain access or Secure Enclave handles — every signing request still funnels through the same XPC + rule-engine + approval path. The difference from the old design: it calls `com.bastion.xpc` *directly* via dedicated `bridge*` methods rather than spawning `bastion-cli`, and it carries the target agent identity as data (`agentProfileId`) rather than inheriting it from the caller's verified code signature.

> The legacy TypeScript server under `mcp/` is retained as a development reference only; it is no longer the production path.

**Open audit items on this surface** (see `audits/2026-06-taek/`): the `agentProfileId` is currently authorized by *existence in the global config*, not by binding to the calling bridge connection/token — so it does not yet isolate one agent's authority from another's (AC-01 Critical, RE-01 High, RP-01 Medium). XPC client auth is PID-based, not audit-token-based (AC-02 Critical). The hand-rolled REST socket parser lacks read timeouts and a pre-header byte cap (DO-01 High). `listWalletGroups` / `exportSupportBundle` read paths are gated more weakly than their siblings (AC-03 / AC-04 Medium). Remediation waves are tracked in `findings.md`.

### On-chain: P256Validator

ERC-7579 IValidator module for Kernel v3.3. Deployed at `0x9906AB44fF795883C5a725687A2705BE4118B0f3`.

- Verifies P-256 ECDSA signatures via RIP-7212/EIP-7951 precompile (no Solidity fallback)
- 30 unit tests, 97% line coverage, 0 critical/high audit findings
- See `contracts/` for the Foundry project

## Hardening Recommendations

### Immediate
- [x] **Hardened Runtime** — prevents code injection (enabled)
- [x] **XPC team ID verification** — rejects connections from other developers (enabled)
- [x] **Calldata decoding** — spending limits validated against decoded calldata, not declared values
- [x] **Audit-token XPC client auth** — AC-02 Critical; client identity now resolved from the peer `audit_token_t`, not the bare PID (defeats PID-reuse)
- [x] **Scope `agentProfileId` to the bridge** — AC-01 Critical (bridge-side): `BASTION_AGENT_PROFILE_ID` is an enforced allow-set; a bridge rejects out-of-scope profiles before XPC. *(Residual: service-side per-connection capability binding deferred — see `audits/2026-06-taek/findings.md`.)*
- [x] **REST socket hardening** — DO-01 High; read/idle timeouts + 64 KB pre-header cap + bounded concurrency
- [x] **Read-gate symmetry** — AC-03/AC-04; `listWalletGroups` now biometric-gated, support-bundle profile-id inventory redacted
- [ ] **Service-side `agentProfileId` capability binding** — AC-01 residual; bind each bridge connection to its authorized profile set via a pairing-derived capability
- [ ] **Notarization** — Apple can remotely revoke compromised builds
- [ ] **App Sandbox** — investigate compatibility with XPC Mach service

### Future
- [ ] **Reproducible builds** — verify binary matches source
- [ ] **Multi-key support** — per-agent keys with per-key rules
- [ ] **Paranoid mode** — Key B with `.userPresence` (biometric per sign, disables autonomous signing)
- [ ] **Simulation-based trace filtering** — TEVM integration for full address trace validation

## Path Forward

### Short-term
- [ ] P256Validator testnet deployment (Base Sepolia / Sepolia)
- [ ] End-to-end integration test: agent -> Bastion -> bundler -> on-chain P256 verify
- [ ] Notarize the app for distribution

### Medium-term
- [ ] Agent SDK (TypeScript) for building UserOps with Bastion signatures
- [ ] Multi-chain support (Base, Arbitrum, Optimism, Polygon)
- [ ] Simulation + full trace validation (TEVM)
- [ ] Multi-key support (different keys for different agents/chains)

### Long-term
- [ ] Open source + reproducible builds
- [ ] Auto-update with signed manifest
- [ ] iOS companion app
