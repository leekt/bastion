# Known Issues & Design Limitations

_Last reviewed: 2026-05-04 — refreshed alongside the PR1–PR5 architectural cleanup series._

This document is the canonical record of known security and design caveats Bastion ships with. None of the items below are exploitable without one of the preconditions called out in the **Risk** field (e.g. compromised team signing key, malicious bundler, physical access).

## Taxonomy

Every item has the same five fields so readers can scan and decide whether it affects their threat model.

| Field | What it means |
|-------|---------------|
| **Status** | One of: `Accepted` (won't fix, justified), `Deferred` (will fix in a future milestone), `By design` (intentional architecture, surfaced because audits flagged it), `Mitigated` (was open in a prior release, resolved by the listed PR). |
| **Severity** | `Critical` / `High` / `Medium` / `Low` / `Informational`. Severity is independent of status — `Mitigated` items keep their original severity for historical context. |
| **Subsystem** | `Signing model` / `Spending limits` / `XPC & auth` / `Keychain` / `Approval UI` / `Concurrency` / `Infrastructure` / `Display`. |
| **Audit ref** | Round-prefixed (`R2-M-04`, `R3-09`) for audit-round findings; bare letter-prefixed (`M-01`, `L-03`) for findings outside a numbered round. |
| **Risk** / **Mitigation** | Plain prose. Mitigated items have a **Resolution** line instead of **Mitigation**, naming the PR. |

`Open` items are listed first, grouped by severity. `Mitigated` items follow at the bottom for traceability.

---

## Open · Medium

### Sliding window can permit up to 2× the configured limit across a boundary
- **Status**: Accepted
- **Severity**: Medium
- **Subsystem**: Spending limits
- **Audit ref**: R3-03

**Risk.** Spending limits use a sliding time window. An agent can spend up to the configured limit just before the oldest entries expire, then spend again immediately after they expire. The result is up to 2× the configured limit being spent in a span slightly longer than the window. Mathematically correct for sliding windows, but doesn't match the user's intuition of "no more than X per hour."

**Example** with a 1 ETH/hour limit:
- T=0 → spend 0.9 ETH
- T=59m59s → spend 0.1 ETH (total = 1.0 ETH, at limit)
- T=60m01s → T=0 entry rolls off, spend 0.9 ETH again

**Mitigation.** Inherent to sliding windows. A fixed-window alternative (resets at calendar boundaries) is a possible future setting but would change semantics for every user who already configured a sliding limit.

### Approval timeout is fixed at 60 seconds
- **Status**: Deferred
- **Severity**: Medium
- **Subsystem**: Approval UI
- **Audit ref**: M-01

**Risk.** A legitimate signing request whose approval popup is open while the owner steps away will be auto-denied at 60s.

**Mitigation.** Timeout is logged as `approval_timeout` in the audit log so the owner can see they missed something. A configurable per-profile timeout is the planned fix; tracked separately from the architectural cleanup series.

### State-store account names are predictable strings
- **Status**: Accepted
- **Severity**: Medium
- **Subsystem**: Keychain
- **Audit ref**: M-03

**Risk.** Rate-limit and spending state are stored under predictable Keychain account names (`state.ratelimit.{ruleId}`, `state.spending.{ruleId}`). With access to the Keychain, an attacker could target specific counters.

**Mitigation.** Acceptable given the Keychain access-group trust boundary — anyone who can see these accounts can already see every other Bastion-owned secret in the same access group. The trust-boundary owner is the team signing key, not the account names.

### Audit HMAC key lives in the same Keychain as protected data
- **Status**: Accepted
- **Severity**: Medium
- **Subsystem**: Keychain
- **Audit ref**: M-04

**Risk.** The HMAC key for audit-log integrity sits in the same Keychain Bastion has full access to. An attacker with Keychain access could recompute valid HMACs and rewrite history.

**Mitigation.** The audit log additionally maintains a SHA-256 hash chain linking records, so insertion / deletion / reordering is detectable even if the HMAC is recomputed. Full Keychain compromise (i.e. team signing key compromise) is the precondition; once that holds, every other defense already collapsed too.

### `validate()` and `recordSuccess()` are not atomically protected within `RuleEngine`
- **Status**: By design
- **Severity**: Medium
- **Subsystem**: Concurrency
- **Audit ref**: R2-M-04

**Risk.** Both methods are `nonisolated`. The validate-then-record sequence has no internal lock — if a future caller invoked them off the serialization layer that exists today, two concurrent requests could both pass `validate()` against the same counter before either ran `recordSuccess()`.

**Mitigation.** All signing flows go through `SigningManager.processSignRequest`, which is `@MainActor` and gated by an `isProcessing` flag — every request is serialized. Future refactors must preserve this invariant; the typed merge work in PR3 is one step toward making it a structural property of the API rather than a runtime invariant.

---

## Open · Low

### `CalldataDecoder` only recognizes ERC-20 transfer / approve / transferFrom
- **Status**: Accepted
- **Severity**: Low
- **Subsystem**: Signing model
- **Audit ref**: R3-05

**Risk.** Non-standard token operations (ERC-777 `send`, ERC-1155 `safeTransferFrom`) aren't decoded into structured fields, so spending-limit accounting can't apply to them.

**Mitigation.** Unrecognized selectors set `hasUnrecognizedCalldata = true`, which triggers a hard block in the approval UI requiring biometric override. The safe direction — unknown shapes never auto-sign.

### `formatAmount` uses `Double` for very large values
- **Status**: Accepted
- **Severity**: Low
- **Subsystem**: Display
- **Audit ref**: L-03

**Risk.** `SpendingLimitRule.formatAmount()` converts `UInt128` to `Double` for display, losing precision above 2⁵³ wei (~9,007 ETH).

**Mitigation.** Display only. All actual limit enforcement is exact `UInt128` arithmetic — the precision loss never reaches a comparison.

### Keccak-256 implementation has no input-length validation
- **Status**: Accepted
- **Severity**: Low
- **Subsystem**: Infrastructure
- **Audit ref**: L-04

**Risk.** The C Keccak-256 routine accepts arbitrary `inputLen`. Reachable from XPC only with a hypothetical future code path.

**Mitigation.** Every existing caller provides bounded inputs. Not reachable through current XPC entry points; the validator would reject the operation type long before reaching the hashing primitive.

### SE silent-context uses an empty application password
- **Status**: By design
- **Severity**: Low
- **Subsystem**: Keychain
- **Audit ref**: L-01

**Risk.** `silentContext()` sets an empty `Data()` as the `.applicationPassword` credential.

**Mitigation.** This is the documented Apple approach for pre-satisfying `.privateKeyUsage` access control during a no-prompt operation. Security is enforced by the Keychain access group (`926A27BQ7W.com.bastion`), not the password value.

### DER signature parser handles only Secure-Enclave output
- **Status**: Accepted
- **Severity**: Low
- **Subsystem**: Infrastructure
- **Audit ref**: R2-L-02

**Risk.** The DER parser in `SecureEnclaveManager` is simplified — no multi-byte length encoding, no full structure validation.

**Mitigation.** Parser only handles output from Apple's Secure Enclave, which always emits well-formed DER. Not safe to reuse against external/untrusted input without hardening.

---

## Open · Informational

### EIP-191 messages have no chain or context binding
- **Status**: By design (protocol limitation)
- **Severity**: Informational
- **Subsystem**: Signing model
- **Audit ref**: R3-02

**Risk.** EIP-191 personal-message signatures contain no chain ID, contract address, nonce, or expiry. A signature is valid on every chain, in every protocol, forever.

**Mitigation.** `rawMessagePolicy.posture` defaults to a posture that requires the approval popup; the message text is rendered for inspection. Agents are advised to prefer EIP-712 typed data, which carries the domain separator (chain ID + verifying contract). PR2 reified this into a typed posture so the "force approval popup" requirement is structural rather than a flag pair.

### Compromised paymaster could extract value during `postOp`
- **Status**: Accepted
- **Severity**: Informational
- **Subsystem**: Signing model
- **Audit ref**: R3-08

**Risk.** The paymaster address is set by the bundler response and included in the signed UserOp hash; Bastion can't restrict what a paymaster does in `postOp` execution. A compromised bundler could substitute a malicious paymaster.

**Mitigation.** App-configured ZeroDev project ID takes precedence over agent-supplied IDs (PR1 made this trust resolution explicit and tested). Users should configure trusted bundler endpoints; the rule engine surfaces the resolved project source in the audit log.

### No TLS certificate pinning for ZeroDev / RPC endpoints
- **Status**: Accepted
- **Severity**: Informational
- **Subsystem**: Infrastructure
- **Audit ref**: I-03

**Risk.** Communication uses standard HTTPS without certificate pinning. A network-level attacker with a CA-trusted certificate could intercept responses.

**Mitigation.** Standard TLS validation. The "max of static + trace spending" principle in the spending validator ensures trace data from a compromised RPC can never reduce a counter. Users should configure trusted RPC endpoints.

### DEBUG builds accept untrusted code signatures (development only)
- **Status**: By design
- **Severity**: Informational (production); High (development only)
- **Subsystem**: XPC & auth
- **Audit ref**: H-03

**Risk.** In DEBUG builds, XPC connections from processes with untrusted developer signatures (ad-hoc signed) are accepted. Any locally-compiled binary can connect to the XPC service during development.

**Mitigation.** `#if DEBUG` guard. Production (Release) builds strictly require valid team-ID signatures. DEBUG builds must never be distributed.

---

## Mitigated

### EIP-712 typed data could authorize Permit2 / ERC-2612 / ERC-7702 silently
- **Status**: Mitigated in [PR5 (#35)](https://github.com/leekt/bastion/pull/35)
- **Severity**: Informational
- **Subsystem**: Signing model — typed data
- **Audit ref**: R3-09

**Original risk.** EIP-712 signing could authorize off-chain permit operations (ERC-2612, Permit2, ERC-7702 set-code) that grant token allowances or delegate execution authority without any on-chain transaction from the smart account. Bastion validated domain rules and struct rules but did not extract spending amounts, spenders, or expiries from the message body, leaving the user to read JSON.

**Resolution.** `PermitClassifier` parses ERC-2612 Permit, Permit2 (Single / Batch / TransferFrom), and ERC-7702 `Authorization` shapes from typed data and surfaces a structured warning panel in the approval UI with parsed Spender / Amount / Token / Expires fields plus a "Lasting allowance" chip when applicable. `typedDataPolicy.posture` continues to gate whether the popup is required.

### Sessions and XPC connections survived allowlist tightening
- **Status**: Mitigated in [PR4 (#33)](https://github.com/leekt/bastion/pull/33)
- **Severity**: Medium
- **Subsystem**: XPC & auth, Approval UI (sessions)
- **Audit ref**: R3-06 (XPC piece) plus an undocumented gap (sessions piece)

**Original risk.** Two related survival gaps:
1. A temporarily-granted `AgentSession` (e.g. "Claude Code can sign on Base for 30 minutes, max 50 USDC") kept its original scope after the owner removed those permissions from the policy. The session ran to expiry on the older, broader rules.
2. A live XPC connection from an agent kept its connection (and could call read-only endpoints such as `getPublicKey`, `getRules`, `getState`) after that agent's bundle was removed from `rules.allowedClients`. Signing was correctly denied on each call by the live allowlist check, but the connection itself stayed open until the agent process exited.

**Resolution.** `RuleEngine.updateConfig` now runs a reconciliation pass after persisting the new policy:
- `SessionStore.reconcile` walks every active `AgentSession` through the new pure `SessionReconciler`. Sessions that exceed the new policy are downgraded (chains / targets narrow to the surviving intersection) or revoked outright (when `allowedClients` no longer admits the bundle, or when no scope survives).
- `XPCServer.reconcileConnections(against:)` cuts every active XPC connection whose verified bundle id is no longer in `rules.allowedClients`. Connections are tracked in a registry behind an `NSLock` and pruned via `invalidationHandler`.
- `LockdownManager.enterLockdown` additionally calls `XPCServer.invalidateAllConnections()` so panicked owners get instant-stop semantics.

### `enabled × requireExplicitApproval` boolean pair was structurally ambiguous
- **Status**: Mitigated in [PR2 (#31)](https://github.com/leekt/bastion/pull/31)
- **Severity**: Medium (ambiguity-class)
- **Subsystem**: Signing model
- **Audit ref**: post-R3 architectural finding

**Original risk.** The "rules enabled" + "require explicit approval" boolean pair admitted a contradictory state: `enabled=false` + `requireExplicitApproval=true` and `enabled=false` + `requireExplicitApproval=false` were structurally distinct but should have meant the same thing ("don't evaluate rules, just always pop the approval"). Bug-prone in code reading and serialization.

**Resolution.** Replaced with a typed `SigningPosture` enum (three legal cases: `enforceRulesAndAutoSign`, `enforceRulesAndRequireApproval`, `requireApprovalWithoutRuleEvaluation`) per operation type. Legacy boolean-pair JSON migrates to the right case via `SigningPosture.from(enabled:requireExplicitApproval:)`; encoder still writes the legacy mirrors so older readers stay coherent.

### Wallet-group ∩ member rule merge used sentinel values for "deny everything"
- **Status**: Mitigated in [PR3 (#32)](https://github.com/leekt/bastion/pull/32)
- **Severity**: Low (clarity-class)
- **Subsystem**: Signing model
- **Audit ref**: post-R3 architectural finding

**Original risk.** `RuleEngine.mergeGroupRules` encoded "intersection is empty so deny everything" using shape sentinels: `AllowedHours(0, 0)` for hours, `[]` for client allowlists. Every consumer of the merged result had to know which sentinel meant deny vs which meant intentionally empty. New consumers (UI surfacing the merged policy, audit log, future tooling) would each have to relearn the mapping or risk treating a sentinel as permissive.

**Resolution.** `MergedPolicy` (typed `MergedConstraint<T>` per field — `.unrestricted | .restricted(T) | .unsatisfiable(reason)`) is now the canonical merge value. `RuleEngine.mergeGroupRules` is a thin shim that flattens through `MergedPolicy.toRuleConfig()` for legacy validation paths. The wallet-group settings panel surfaces `unsatisfiabilityReasons` so owners see exactly which constraints disagree instead of staring at silently-denying agents.

### ZeroDev project trust resolution was implicit and inconsistent
- **Status**: Mitigated in [PR1 (#30)](https://github.com/leekt/bastion/pull/30)
- **Severity**: Medium (precedence-class)
- **Subsystem**: Signing model
- **Audit ref**: post-R3 architectural finding

**Original risk.** Two code paths were independently deciding which ZeroDev project ID to trust (the one in the user's saved config vs the one the agent supplied with the request). Their precedence was implied by call-site ordering rather than written down, so a bundler-config drift would land different paths in different states.

**Resolution.** `BundlerTrustResolver` is the single resolver. Returns a typed `ResolvedBundler` carrying the project id + a `Source` enum (`configMatchedRequest` / `configOverrodeRequest` / `requestFallback`). Validators and audit-log entries cite the source so precedence is auditable.
