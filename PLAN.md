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

2. Configuration storage is not hardened.
   - Config decode failures can fall back too easily.
   - There is no formal migration/recovery strategy for corrupted or partially written config data.

3. Audit history is useful, but not yet strong enough for production claims.
   - Raw payloads are stored for operator visibility, but there is no tamper evidence, retention policy, or redaction strategy.

4. Provider integration is still operationally thin.
   - Bastion is intentionally ZeroDev-first for ERC-4337 operations.
   - Retry, degraded mode, simulation, and ZeroDev-specific diagnostics still need to be formalized.

5. Simulation and preflight are not yet first-class.
   - UserOperation flows need a clear pre-submit simulation layer, not just best-effort submission.
   - Bastion should be able to distinguish policy failure, validation failure, bundler rejection, and execution failure before the user approves or sends.
   - Debug tooling should make it easy to reproduce failures with traces and preflight artifacts.

6. Key lifecycle is incomplete.
   - Per-client Secure Enclave keys exist, but rotation, device migration, and recovery are not productized.

7. Testing is not yet at release depth.
   - Core paths have been exercised manually and with targeted tests, but macOS lifecycle and full end-to-end flows still need stronger coverage.

8. Release engineering is incomplete.
   - Notarization, auto-update, crash reporting, support bundles, and release verification are not yet fully defined as a product pipeline.

## Phase 0: Stabilize the Foundation

Objective: move from internal alpha to a trustworthy private beta baseline.

### P0.1 Service and App Lifecycle

- Keep the `SMAppService` registration path. The current registered launch target is the main binary (`Contents/MacOS/bastion`). An attempt to move service ownership to the nested helper failed with `EX_CONFIG (78)`. Finish diagnosing and resolving that before the helper-owned architecture can be used.
- Ensure only one active Bastion service instance can own the XPC interface at a time.
- Make notification click, CLI invocation, app launch, and settings/history window routing deterministic.
- Verify behavior across:
  - fresh install
  - rebuild/reinstall
  - reboot
  - logout/login
  - notification click while app is foreground/background/not running

Exit criteria:

- No duplicate service instances.
- Notification click consistently opens the intended UI.
- CLI requests do not bind to stale builds or stale services.

### P0.2 Config Safety and Migration

- Introduce a versioned config schema.
- Add explicit migration logic for stored policy/config data.
- Fail closed, or at minimum surface a visible recovery mode, on config decode/migration failure.
- Add backup/recovery behavior for policy data before destructive migrations.

Exit criteria:

- Old configs migrate forward deterministically.
- Corrupt configs do not silently reset to permissive defaults.
- Recovery behavior is visible and testable.

### P0.3 Policy Model Hardening

- Finish the request-type split as a first-class model:
  - raw signing
  - UserOperation signing
  - EIP-712 typed data signing
- Ensure UI, storage, and enforcement all use the same model.
- Strengthen typed data rules:
  - domain filters
  - primary type filters
  - structured JSON constraints for critical fields

Exit criteria:

- Every visible policy is actually enforced.
- No policy editor field is misleading or non-functional.
- Typed data restrictions can express real-world approval patterns such as permit-style allowlists.

### P0.4 Audit Model Hardening

- Keep the request-level audit record model.
- Add stable request states and lifecycle transitions.
- Define which fields are stored verbatim, summarized, or redacted.
- Add rotation/retention rules for audit data.

Exit criteria:

- One request maps to one audit record with a clear timeline.
- Operators can inspect enough detail to understand what happened.
- Stored history does not grow without bounds or leak more than intended.

### P0.5 Simulation and Preflight

- Add an explicit preflight stage for UserOperation flows before approval-and-send.
- Run deterministic simulation checks before submission, including:
  - account validation
  - paymaster validation
  - expected calldata target/action decoding
  - fee sanity checks
- Preserve enough simulation output to explain failures in the UI and audit history.
- Add a debug path that can export trace-ready artifacts for reproduction.

Exit criteria:

- Bastion can show whether a request is expected to pass validation before submission.
- Common AA errors can be diagnosed from Bastion without manual reverse-engineering.
- Operators can reproduce failures from stored request + simulation context.

## Phase 1: Make Beta Operations Viable

Objective: make the app supportable outside the core development machine.

### P1.1 Provider and Network Resilience

- Separate chain RPC reads from ZeroDev submission logic cleanly.
- Formalize the ZeroDev integration surface for:
  - sponsorship
  - submission
  - receipt tracking
  - fee estimation
  - simulation / preflight
- Add retry/backoff and clear error taxonomy for:
  - sponsorship failure
  - submission failure
  - receipt timeout
  - simulation failure
  - ZeroDev API failure
  - minimum fee mismatch
- Define degraded-mode behavior when ZeroDev is unavailable, slow, or returns partial results.

Exit criteria:

- User-facing errors clearly explain whether the failure is policy, signing, RPC, ZeroDev, paymaster, bundler validation, or on-chain execution.
- Bastion can recover from common transient ZeroDev failures without manual surgery.

### P1.2 Key Lifecycle and Recovery

- Define per-client key rotation flow.
- Define what happens when a machine is replaced or lost.
- Define validator/account recovery or re-binding flow for deployed accounts.
- Document operator runbooks for key loss and client re-enrollment.

Exit criteria:

- There is a documented and tested path for device replacement.
- Per-client key rotation is possible without undefined manual steps.

### P1.3 UX and Product Cohesion

- Keep the compact settings layout and continue trimming low-signal spacing.
- Make policy editing, approval UI, audit history, and notifications feel like one product.
- Improve approval density further so raw, typed data, and UserOp flows are easy to scan quickly.
- Add better in-app status for pending submission/confirmation states.

Exit criteria:

- A user can understand the difference between sign-only and approve-and-send at a glance.
- Audit history, approval UI, and policy settings use the same vocabulary and states.

### P1.4 Diagnostics and Supportability

- Add structured app logs for lifecycle, XPC, approval, submission, and notification routing.
- Add crash reporting.
- Add a support bundle export flow that includes logs, sanitized config, and recent audit context.
- Include simulation/preflight artifacts and provider responses in support exports when relevant.
- Add an in-app diagnostics page or support panel.

Exit criteria:

- Most support incidents can be diagnosed from exported logs/support bundles.
- Crashes and fatal service failures are observable.

## Phase 2: Build a Real Release Pipeline

Objective: move from private beta quality to public beta / production readiness.

### P2.1 Release Engineering

- Finalize app signing, notarization, and distribution flow.
- Add a repeatable CI/CD pipeline for signed release builds.
- Add release verification steps for:
  - app bundle
  - service/helper components
  - CLI packaging
  - update integrity
- Decide on and implement auto-update strategy.

Exit criteria:

- A release build can be generated and verified without local hand-edits.
- Install and update paths are deterministic.

### P2.2 Security Review

- Review XPC trust boundaries and client enrollment rules.
- Review policy bypass paths and fail-open behavior.
- Review audit storage/privacy exposure.
- Review notification and history exposure for sensitive payload data.
- Remove remaining concurrency warnings and other undefined-behavior risks.

Exit criteria:

- Security-sensitive flows have explicit review notes and fixes.
- No known high-severity fail-open behavior remains.

### P2.3 End-to-End Test Coverage

- Add deterministic integration coverage for:
  - raw sign flow
  - typed data approval flow
  - UserOperation approve-and-send flow
  - UserOperation preflight/simulation failure flow
  - notification click -> audit history open
  - per-client key separation
  - config migration
  - service restart/reconnect
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
