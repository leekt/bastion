# Bastion Release Plan

## Goal

Ship Bastion as a macOS app that can safely manage signing requests for multiple clients, submit ERC-4337 UserOperations, and provide auditable history without fragile service behavior or misleading policy UX.

This plan assumes the current codebase is **internal alpha** quality: useful for development and controlled testing, but not yet ready for public release.

## Release Bar

### Internal Alpha

- Engineers can build and run the app locally.
- Core flows work: sign, approve, submit, history, notifications.
- Some service lifecycle issues and UX inconsistencies still exist.

### Private Beta

- App lifecycle is stable on clean machines and after reboots.
- Policy behavior is predictable and recoverable.
- Audit history is reliable enough for operators and testers.
- Key flows are covered by deterministic tests.

### Public Beta

- Packaging, signing, notarization, auto-update, logging, and crash reporting are in place.
- Clear user-facing recovery paths exist for service issues, config issues, and provider failures.
- ZeroDev integration is resilient enough that common provider-side failures are diagnosable and recoverable.

### Production Ready

- Release process is repeatable and supportable.
- Security boundaries are explicit and enforced.
- Policy storage, key lifecycle, and audit history meet a defensible standard.
- The team can diagnose, recover, and support failures without manual intervention.

## Current Gaps

1. Service lifecycle is still too fragile.
   - Manual LaunchAgent rewriting has been removed, but the service still shares a binary with the menu bar app and development still relies on a `~/Applications/Bastion Dev.app` install path.
   - Notification click behavior and duplicate app instances have already shown that lifecycle control is not yet robust enough for release.

2. Configuration storage is partially hardened. *(Updated 2026-06-03)*
   - ✅ Corrupt config is now detected, surfaced, and loaded into a paused fail-closed state rather than silently falling back to permissive defaults.
   - ✅ Keychain read/write failures now distinguish missing data from unavailable storage and fail signing-state/config/session enforcement closed.
   - ✅ Pause/lockdown resume/unlock is authenticated and failed resume persistence keeps the app paused/locked down in memory via a Keychain fallback.
   - ✅ Secure Enclave signing keys are scoped to the Bastion access group and data-protection Keychain.
   - ✅ Pre-migration backups are preserved and surfaced in Policy History as a review-before-save restore source.
   - ✅ Partially written or schema-incompatible configs are captured as raw recovery snapshots that owners can export while restoring from a known-good backup or saved version.

3. Audit history is hardened for the private-beta baseline. *(Updated 2026-06-03)*
   - ✅ Request-level records with a clear timeline, `sign_pending` durable state, and 90-day age rotation are in place.
   - ✅ Audit logs have HMAC + hash-chain tamper evidence, and tamper state is surfaced in audit history.
   - ✅ Configurable audit redaction removes payloads, sensitive detail lines, summaries, reasons, client account addresses, and submission hashes/details depending on the configured level.
   - ✅ Missing/unreadable audit HMAC keys or MACs are treated as tamper, and tamper detection refuses to append/rewrite records while HMAC or hash-chain state is broken.
   - ✅ Owner-facing tamper recovery lets operators export visible records, archive the broken log, clear the stored MAC/key, and resume audit writes with a fresh chain.

4. Provider integration has a private-beta resilience baseline, but support tooling is still thin.
   - Bastion is intentionally ZeroDev-first for ERC-4337 operations.
   - ✅ Transient ZeroDev transport failures now use bounded retry/backoff, and provider failures are classified by stage/category before reaching UI, CLI, MCP, or audit surfaces.
   - Remaining provider work is mostly operational depth: health checks and live operational coverage.

5. Simulation and preflight have a private-beta baseline; support exports still need more depth.
   - ✅ UserOperation flows run pre-submit simulation before the approval window.
   - ✅ Bastion distinguishes policy failure, validation failure, bundler rejection, and execution failure before or during approval/send flows.
   - ✅ Debug tooling can export request JSON, decoded calldata summary, and simulation result.
   - ✅ Support bundles now include redacted preflight and provider-response summaries derived from recent audit context; full standalone preflight debug bundles remain exportable from the approval UI.

6. Key lifecycle has a private-beta baseline; external account recovery remains future work.
   - ✅ Private-client Secure Enclave keys can be owner-authenticated and rotated through `bastion rotate-client-key <profileId>`.
   - ✅ Device replacement, lost-machine, wallet-group agent validator rotation, and wallet-group owner-key loss now have documented runbooks and deterministic planner tests.
   - Remaining production work is external account-recovery integration for deployed owner accounts that need recovery beyond Bastion's local non-exportable keys.

7. Testing is not yet at release depth.
   - Core paths have been exercised manually and with targeted tests. Deterministic request-flow coverage now exists for raw signing, typed-data approval, UserOperation approve-and-send, UserOperation preflight-failure audit/debug behavior, notification UI routing, service reconnect, per-client key separation, and config migration, but live macOS lifecycle flows still need stronger coverage.

8. Release engineering is incomplete.
   - Notarization, manifest generation, artifact verification, signed GitHub Actions release workflow, a manifest-driven update checker/downloader, and verified staged update installation with rollback are in place; remaining release work is mostly live lifecycle validation and production channel policy.

## Phase 0: Stabilize the Foundation

Objective: move from internal alpha to a trustworthy private beta baseline.

### P0.1 Service and App Lifecycle

**Status: In progress.** Docs and stale code corrected; lifecycle root causes identified.

- ✅ `SMAppService` registration path preserved. `BundleProgram = Contents/MacOS/bastion` (main binary) is the correct registered target. The helper-owned path was investigated and failed with `EX_CONFIG (78)` / `spawn failed` — see `docs/CLAUDE_MENU_BAR_HANDOFF.md` for postmortem.
- ✅ Stale helper-owned architecture claims removed from docs, scripts, and `BastionAgentMain.swift`.
- ✅ `bastion status` reports responding process ID, launch mode, bundle identifier/path, executable path, Mach service name, and launch-agent plist name for stale-owner diagnosis.
- ✅ Existing single-binary service startup takes an exclusive `~/Library/Application Support/Bastion/service.lock` before XPC starts, so a second service process exits before it can own the Mach interface.
- ✅ Relay launches and notification clicks route through the registered XPC service instead of running-app discovery.
- ✅ Deterministic singleton service-lock tests cover second-owner rejection before XPC startup.
- ✅ Deterministic route-decision tests cover service-owned notification clicks and relay launches.
- ✅ Add a lifecycle diagnostic gate for `EX_CONFIG (78)` surfaces before attempting the helper split again.
- ✅ Add a live lifecycle verification gate for signed-install service identity, duplicate process checks, relay handoff, and XPC UI opening.
- ✅ Add a correlated notification-click probe to the live lifecycle gate.
- ✅ Add an evidence audit gate for completed fresh-install, reinstall, reboot, login, and notification-click logs.
- ⬜ Run the lifecycle diagnostic against a signed stable install and capture the live root cause before attempting the helper split again.
- ⬜ Verify behavior across: fresh install, rebuild/reinstall, reboot, logout/login, notification click.

Exit criteria:

- No duplicate service instances.
- Notification click consistently opens the intended UI.
- CLI requests do not bind to stale builds or stale services.

### P0.2 Config Safety and Migration

**Status: Complete for private beta.** *(Updated 2026-06-03)*

- ✅ Versioned config schema (version field, migration for pre-v6 configs).
- ✅ `loadConfigRaw()` distinguishes "no config" (new install) from "data exists but decode failed" (corruption).
- ✅ Corrupt configs load into a paused fail-closed fallback; signing remains blocked until rules are recovered.
- ✅ Keychain write failures throw `storageFailed` and state counters fail closed on corrupted data.
- ✅ `configCorrupted: Bool` property on `RuleEngine` — set on startup, cleared on successful save.
- ✅ Menu bar shows red warning label when config is corrupt. 3 tests added.
- ✅ Backup/recovery behavior before destructive schema migrations is owner-visible in Policy History.
- ✅ Partially written or schema-incompatible configs are preserved as exportable recovery snapshots.

Exit criteria:

- Old configs migrate forward deterministically. ✅
- Corrupt configs do not silently reset to permissive defaults. ✅
- Corrupt-state recovery is visible and testable. ✅

### P0.3 Policy Model Hardening

**Status: Complete for private beta.** *(Updated 2026-06-03)*

- ✅ Request-type split as first-class model: `message`, `rawBytes`, `typedData`, `userOperation`.
- ✅ UI, storage, and enforcement all use `SigningOperation` enum consistently.
- ✅ Typed data rules: domain filters, primary type filters, structured JSON matcher constraints.
- ✅ `allowedSelectors` (per-target function whitelist) and `denySelectors` (global blocklist) implemented and enforced.
- ✅ Temporary agent sessions now load before XPC starts, apply the tightest active scope, and enforce cumulative ETH/USDC spend caps for the grant window.
- ✅ Simulation-derived spend observations enforce spending limits and record counters using the higher of static vs simulated spend.

Exit criteria:

- Every visible policy is actually enforced. ✅
- No policy editor field is misleading or non-functional. ✅
- Typed data restrictions can express real-world approval patterns such as permit-style allowlists. ✅

### P0.4 Audit Model Hardening

**Status: Complete for private beta.** *(Updated 2026-06-03)*

- ✅ Request-level audit record model: one request → one record with a full event timeline.
- ✅ `sign_pending` event recorded before the approval window opens — durable state even if the process is killed mid-approval.
- ✅ 90-day age-based rotation: records older than 90 days are dropped on each write (D-01).
- ✅ 1000-record count cap (L-05) still enforced after age filter.
- ✅ `bastion status` now returns `{version, serviceRegistrationStatus, configCorrupted}` via `getServiceInfo`.
- ✅ Tamper evidence via HMAC plus newest-to-oldest SHA-256 hash chain; missing/empty logs with stored MAC stay flagged instead of resealing.
- ✅ Explicit redaction levels are wired into audit event snapshots and history status.
- ✅ Owner-facing tamper recovery/export/reset workflow in Audit History.

Exit criteria:

- One request maps to one audit record with a clear timeline. ✅
- Operators can inspect enough detail to understand what happened. ✅
- Stored history does not grow without bounds or leak more than intended. ✅ (retention, count cap, and redaction in place)

### P0.5 Simulation and Preflight

**Status: Complete for private beta.** *(Updated 2026-06-03)*

- ✅ `PreflightSimulator` runs before the approval window for every UserOperation request.
- ✅ Calls `eth_estimateUserOperationGas` on the configured bundler — success means account, paymaster, and calldata validation all pass.
- ✅ Local static checks: gas limit sanity, fee ordering.
- ✅ AA error code extraction and structured diagnosis for AA10–AA51 range.
- ✅ `preflightResult` attached to `ApprovalRequest` — visible in the approval UI.
- ✅ `preflightCompleted` audit event recorded before the approval window opens.
- ✅ Preflight banner shown in the signing approval UI (pass/warning/error with recommendations).
- ✅ Calldata simulation runs direct `eth_call` against decoded leaf calls to distinguish validation vs execution failures.
- ✅ Debug export path produces a preflight bundle with request JSON, decoded calldata summary, and simulation result.
- ✅ Fee sanity check uses live bundler gas price (`pimlico_getUserOperationGasPrice`) when available.

Exit criteria:

- Bastion can show whether a request is expected to pass validation before submission. ✅
- Common AA errors can be diagnosed from Bastion without manual reverse-engineering. ✅
- Operators can reproduce failures from stored request + simulation context. ✅

## Phase 1: Make Beta Operations Viable

Objective: make the app supportable outside the core development machine.

### P1.1 Provider and Network Resilience

**Status: Complete for private beta.** *(Updated 2026-06-03)*

- ✅ Chain RPC reads and ZeroDev account-abstraction calls use separate clients (`EthRPC` vs `ZeroDevAPI`).
- ✅ `BundlerTrustResolver` is the trust boundary before a request reaches ZeroDev submission, sponsorship, or preflight paths.
- ✅ The ZeroDev integration surface is explicit for sponsorship, submission, receipt tracking, fee estimation, and simulation/preflight.
- ✅ Transient ZeroDev failures use bounded retry/backoff: 2 attempts for send/receipt lookup and 3 attempts for other provider calls.
- ✅ Provider failures are classified with stage/category/retry guidance for sponsorship failure, submission failure, receipt timeout, simulation failure, ZeroDev API failure, paymaster failure, bundler validation failure, on-chain execution failure, and minimum fee mismatch.
- ✅ `UserOperationSubmissionResponse`, audit history details, preflight failures, CLI, and MCP types expose provider diagnostics instead of raw error strings only.
- ✅ Degraded-mode behavior is documented in `docs/PROVIDER_RESILIENCE.md`: fail closed when provider state is missing or unsafe, preserve submitted hashes on receipt timeout, and require rebuild/re-approval for stale fee mismatches.

Exit criteria:

- User-facing errors clearly explain whether the failure is policy, signing, RPC, ZeroDev, paymaster, bundler validation, or on-chain execution. ✅
- Bastion can recover from common transient ZeroDev failures without manual surgery. ✅

### P1.2 Key Lifecycle and Recovery

**Status: Complete for private beta.** *(Updated 2026-06-03)*

- ✅ Per-client private key rotation flow is defined and exposed through `bastion rotate-client-key <profileId>`.
- ✅ Rotation is owner-authenticated, creates a replacement Secure Enclave key, saves the profile's new key tag, deletes the old local key only after save, and records a `key_rotated` audit event.
- ✅ Wallet-group agent key rotation is defined as an on-chain validator lifecycle: create replacement key/membership, install the new validator, re-pair/re-bind the client, then uninstall/revoke the old validator.
- ✅ Replacement-machine and lost-machine behavior is documented in `docs/KEY_LIFECYCLE.md`: config backup restores policy/profile context, but Secure Enclave keys must be recreated and clients re-enrolled.
- ✅ Wallet-group owner key loss is explicitly fail-closed locally; recovery requires a pre-existing external on-chain recovery authority or creating a replacement group.
- ✅ Deterministic tests cover private-client rotation planning, group-agent on-chain requirements, owner-key loss blocking, device replacement planning, and profile key-tag mutation.

Exit criteria:

- There is a documented and tested path for device replacement. ✅
- Per-client key rotation is possible without undefined manual steps. ✅

### P1.3 UX and Product Cohesion

**Status: Complete for private beta.** *(Updated 2026-06-03)*

- ✅ Keep the compact settings layout and continue trimming low-signal spacing.
- ✅ Make policy editing, approval UI, audit history, and notifications feel like one product.
- ✅ Approval UI, audit history, and menu bar now distinguish `Sign only` from `Approve + send` using shared vocabulary.
- ✅ Improve approval density further so raw, typed data, and UserOp flows are easy to scan quickly.
- ✅ Add better in-app status for pending submission/confirmation states.

Exit criteria:

- A user can understand the difference between sign-only and approve-and-send at a glance. ✅
- Audit history, approval UI, notifications, and policy settings use the same vocabulary and states. ✅

### P1.4 Diagnostics and Supportability

**Status: Complete for private beta.** *(Updated 2026-06-03)*

- ✅ Add structured app logs for lifecycle, XPC, approval, submission, and notification routing.
- ✅ Add crash reporting.
- ✅ Add a support bundle export flow that includes logs, sanitized config, and recent audit context.
- ✅ Include simulation/preflight artifacts and provider responses in support exports when relevant.
- ✅ Add an in-app diagnostics page or support panel.

Exit criteria:

- Most support incidents can be diagnosed from exported logs/support bundles.
- Crashes and fatal service failures are observable.

## Phase 2: Build a Real Release Pipeline

Objective: move from private beta quality to public beta / production readiness.

### P2.1 Release Engineering

**Status: Complete for public-beta release mechanics.** *(Updated 2026-06-03)*

- ✅ Finalize app signing, notarization, and distribution flow.
- ✅ Add a repeatable CI/CD pipeline for signed release builds.
- ✅ Add release verification steps for:
  - app bundle
  - service/helper components
  - CLI packaging
  - update integrity
- ✅ Decide on a manifest-driven, verified-staged update strategy and implement update check/download clients.
- ✅ Add automatic install, relaunch, service recovery, and rollback for staged update artifacts.

Exit criteria:

- A release build can be generated and verified without local hand-edits.
- Install and update paths are deterministic.

### P2.2 Security Review

**Status: Complete for private beta.** *(Updated 2026-06-03)*

- ✅ Review XPC trust boundaries and client enrollment rules.
- ✅ Review policy bypass paths and fail-open behavior.
- ✅ Review audit storage/privacy exposure.
- ✅ Review notification and history exposure for sensitive payload data.
- ✅ Remove remaining concrete concurrency hazards found in this review.
- ✅ Document private-beta review notes and remaining caveats in `docs/SECURITY_REVIEW.md`.

Exit criteria:

- Security-sensitive flows have explicit review notes and fixes.
- No known high-severity fail-open behavior remains.

### P2.3 End-to-End Test Coverage

**Status: Complete for deterministic private-beta coverage.** *(Updated 2026-06-03)*

- Add deterministic integration coverage for:
  - ✅ raw sign flow
  - ✅ typed data approval flow
  - ✅ UserOperation approve-and-send flow
  - ✅ UserOperation preflight/simulation failure flow
  - ✅ notification click -> audit history open
  - ✅ per-client key separation
  - ✅ config migration
  - ✅ service restart/reconnect
- Keep live provider tests, but separate them from core deterministic release tests.

Exit criteria:

- Release candidates can be validated without depending only on manual testing.
- Flaky provider/live tests do not block confidence in core app correctness.

## Recommended Workstreams

### Workstream A: App Lifecycle and Packaging

- Service model
- launch behavior
- notification routing
- signed release builds
- notarization and updates

### Workstream B: Policy and Storage

- schema versioning
- migration
- per-request-type enforcement
- audit data model
- retention and redaction

### Workstream C: Chain and Provider Reliability

- RPC abstraction
- bundler abstraction
- retry/fallback
- fee strategy
- receipt tracking

### Workstream D: Product UX

- compact settings UX
- approval density
- audit history usability
- in-app diagnostics and support tooling

### Workstream E: QA and Release Validation

- end-to-end tests
- lifecycle regression tests
- migration tests
- release checklist

## Suggested Order

1. Finish Phase 0 first.
2. Start Phase 1 diagnostics work in parallel once service lifecycle is stable enough.
3. Do not call the app public beta until Phase 2.1 and Phase 2.3 are complete.
4. Do not call the app production ready until security review, recovery flows, and release automation are all complete.

## Definition of Done for a Production Claim

Bastion can be called production ready only when all of the following are true:

- The service lifecycle is stable without manual cleanup scripts.
- Policy storage is versioned, recoverable, and not silently permissive on failure.
- Per-client keys can be rotated and recovered through a documented flow.
- UserOperation submission works with resilient provider handling and understandable failures.
- Audit history is trustworthy, bounded, and privacy-aware.
- Release builds are signed, notarized, repeatable, and updateable.
- End-to-end tests cover the critical approval, submission, notification, and history flows.
- Operators can diagnose failures through logs, crash reports, and support exports.
