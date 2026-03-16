# Bastion — Security Model & Architecture

## Trust Boundary

```
┌─────────────────────────────────────────────┐
│  TRUSTED (Bastion.app process)              │
│  ├── macOS Keychain (com.bastion)           │
│  └── Secure Enclave (Key B)                 │
└─────────────────────────────────────────────┘
         ▲ XPC (team ID verified)
         │
┌─────────────────────────────────────────────┐
│  UNTRUSTED                                  │
│  ├── bastion-cli (no secrets, no Keychain)  │
│  ├── AI agents (subprocess callers)         │
│  └── Filesystem (~Library/App Support/)     │
└─────────────────────────────────────────────┘
```

Bastion.app is the **single trust boundary**. Everything outside it is untrusted by design.

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
