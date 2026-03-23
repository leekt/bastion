# Known Issues & Design Limitations

This document lists known security and design limitations that have been identified through three rounds of security audits and are accepted as inherent trade-offs or deferred for future work.

All items below have been evaluated and triaged. None are exploitable without additional preconditions (e.g., compromised team signing key, malicious RPC, or physical access).

## Signing Model Limitations

### EIP-191 Messages Have No Chain or Context Binding
**Audit**: R3-02 (Medium)

EIP-191 personal message signatures (`\x19Ethereum Signed Message:\n...`) contain no chain ID, contract address, nonce, or expiry. A signature is valid on every chain, in every protocol, forever.

**Mitigation**: `rawMessagePolicy.enabled = false` (default) requires explicit user approval with the approval window for every message signing request. Users can inspect the message text before approving.

**Recommendation for agents**: Prefer EIP-712 typed data over EIP-191 messages. EIP-712 includes `chainId` and `verifyingContract` in the domain separator, making signatures chain- and contract-scoped.

### EIP-712 Typed Data Can Authorize Permit2/Permit Operations
**Audit**: R3-09 (Informational)

EIP-712 signing can authorize off-chain permit operations (ERC-2612, Permit2) that grant token allowances without an on-chain transaction from the smart account. Bastion validates domain rules and struct rules but does not extract spending amounts from typed data message fields.

**Mitigation**: `typedDataPolicy.requireExplicitApproval = true` forces all EIP-712 signatures through the approval UI. The full message JSON is displayed for user inspection.

### Compromised Paymaster Can Extract Value During postOp
**Audit**: R3-08 (Informational)

The paymaster address is set by the bundler response and included in the signed UserOp hash. Bastion cannot verify or restrict what a paymaster does during `postOp` execution. A compromised bundler could return a malicious paymaster.

**Mitigation**: App-configured ZeroDev project ID takes priority over agent-provided IDs (M-08). Users should only configure trusted bundler endpoints.

## Spending Limit Model

### Sliding Window Allows Up to 2x Limit Across Boundary
**Audit**: R3-03 (Medium)

Spending limits use a sliding time window. An agent can spend up to the configured limit just before the oldest entries expire, then spend again immediately after they expire. This means up to 2x the configured limit can be spent in a period slightly longer than the window.

This is mathematically correct for sliding windows but may not match user expectations of "no more than X per hour."

**Example**: With a 1 ETH/hour limit:
- T=0: spend 0.9 ETH
- T=59m59s: spend 0.1 ETH (total = 1.0 ETH, at limit)
- T=60m01s: T=0 entry expires, spend 0.9 ETH again

**Mitigation**: This is an inherent property of sliding windows. A fixed-window alternative (reset at calendar boundaries) could be offered in the future.

### ERC-777, ERC-1155, and Non-Standard Token Transfers
**Audit**: R3-05 (Low)

`CalldataDecoder` recognizes ERC-20 `transfer`, `approve`, and `transferFrom` only. Non-standard token operations (ERC-777 `send`, ERC-1155 `safeTransferFrom`) are not decoded.

**Mitigation**: Unknown selectors trigger `hasUnrecognizedCalldata = true`, which is a hard block requiring biometric override. This is the safe direction — unrecognized token operations cannot be silently approved.

## XPC & Authentication

### DEBUG Builds Accept Untrusted Code Signatures
**Audit**: H-03 (High, development only)

In DEBUG builds, XPC connections from processes with untrusted developer signatures (ad-hoc signed) are accepted. This allows any locally-compiled binary to connect to the XPC service during development.

**Mitigation**: `#if DEBUG` guard. Production (Release) builds strictly require valid team ID signatures. DEBUG builds must never be distributed.

### Removed Clients Can Query Non-Signing Endpoints
**Audit**: R3-06 (Low)

When a client is removed from `allowedClients`, its existing XPC connection can still call read-only endpoints (`getPublicKey`, `getRules`, `getState`, `getServiceInfo`, `openUI`). Signing operations are properly denied by the live allowlist check.

**Mitigation**: Read-only access on stale connections is low risk. Connections are invalidated when the client process terminates.

### Approval Timeout Is Fixed at 60 Seconds
**Audit**: M-01 (Medium)

The approval window times out after 60 seconds with no user action. Legitimate requests may be auto-denied when the user is briefly away.

**Mitigation**: Timeout is logged as `approval_timeout` in the audit log. A configurable timeout could be added in the future.

## Keychain Trust Boundary

### State Store Uses Predictable Account Names
**Audit**: M-03 (Medium)

Rate limit and spending state are stored in Keychain accounts with predictable names (`state.ratelimit.{ruleId}`, `state.spending.{ruleId}`). If the team signing key is compromised, an attacker can target specific counters.

**Mitigation**: This is acceptable given the Keychain access group trust boundary. Team signing key compromise implies full Keychain access regardless of account naming.

### SE Silent Context Uses Empty Application Password
**Audit**: L-01 (Low)

The `silentContext()` method sets an empty `Data()` as the `.applicationPassword` credential. This is the documented Apple approach for pre-satisfying `.privateKeyUsage` access control. The security relies on the Keychain access group, not the password value.

**Mitigation**: By design. The Keychain access group (`926A27BQ7W.com.bastion`) is the actual security boundary.

### Audit HMAC Key in Same Keychain as Protected Data
**Audit**: M-04 (Mitigated)

The HMAC key for audit log integrity is stored in the same Keychain the app has full access to. An attacker with Keychain access can recompute valid HMACs.

**Mitigation**: SHA-256 hash chain links audit records, detecting insertion, deletion, or reordering even if the HMAC is recomputed. Full Keychain compromise (team signing key) is the precondition.

## Display & UX

### formatAmount Uses Double for Very Large Values
**Audit**: L-03 (Low)

`SpendingLimitRule.formatAmount()` converts `UInt128` to `Double` for display, losing precision for values > 2^53 wei (~9,007 ETH). Actual spending enforcement uses `UInt128` arithmetic correctly.

**Mitigation**: Display only. No impact on actual limit enforcement.

### Keccak-256 Has No Input Length Validation
**Audit**: L-04 (Low)

The C Keccak-256 implementation accepts arbitrary `inputLen` with no upper bound. All callers provide bounded inputs. Not reachable via XPC.

**Mitigation**: Not exploitable through current code paths.

## Concurrency

### validate() and recordSuccess() Sequence Is Not Atomic
**Audit**: R2-M-04 (Medium)

`RuleEngine.validate()` and `RuleEngine.recordSuccess()` are `nonisolated` methods. The validate-then-record sequence is not atomically protected within `RuleEngine` itself.

**Mitigation**: `SigningManager.processSignRequest` runs on `@MainActor` with an `isProcessing` guard, serializing all signing requests. The TOCTOU window only exists if these methods are called outside this serialization context. Future refactors must preserve this invariant.

## Infrastructure

### No TLS Certificate Pinning
**Audit**: I-03 (Informational)

Communication with ZeroDev bundler and RPC endpoints uses standard HTTPS without certificate pinning. A network-level attacker with a CA-trusted certificate could intercept responses.

**Mitigation**: Standard TLS validation. The max-of-both spending principle ensures trace data from a compromised RPC cannot reduce spending below what static analysis found. Users should configure trusted RPC endpoints.

### DER Parser Simplified for SE Output Only
**Audit**: R2-L-02 (Low)

The DER signature parser in `SecureEnclaveManager` is simplified for Secure Enclave-produced P-256 signatures. It does not handle multi-byte length encoding or validate the full DER structure.

**Mitigation**: The parser only processes output from Apple's Secure Enclave, which always produces well-formed DER. Not reusable for external/untrusted input without hardening.
