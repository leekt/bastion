# Bastion Long-Term Architecture Roadmap

This document describes the long-term architectural work required to make Bastion production-grade.

It should be read together with:

- `/Users/taek/workspace/bastion-app/bastion/PLAN.md`
- `/Users/taek/workspace/bastion-app/bastion/docs/SERVICE_LIFECYCLE.md`
- `/Users/taek/workspace/bastion-app/bastion/docs/CLAUDE_MENU_BAR_HANDOFF.md`

## Goal

Bastion should eventually operate as a stable macOS product with:

- deterministic menu bar behavior
- explicit background service ownership
- durable request state
- recoverable key and policy lifecycle
- reliable ZeroDev-backed operational behavior
- release and update flows that do not rely on development scripts or manual repair

The long-term goal is not just "make the current app work better." It is to reduce ambiguity about which process owns what, how requests survive failures, and how operators recover from real-world problems.

## Current Reality

The codebase is currently in a transitional state:

- the main app currently owns the visible menu bar
- the helper-owned launch target experiment was rolled back
- the product has useful functionality, but service/UI ownership is still not fully settled
- some documents still reflect the more ambitious helper-owned architecture rather than the currently working state

That means the long-term roadmap should not assume the current helper split is complete. It should treat the present system as a partially stabilized intermediate state.

## Architectural Principles

### 1. One Clear UI Owner

Only one process should own:

- the menu bar icon
- settings
- approval windows
- audit history windows

The current best direction is:

- **main app = UI owner**

This avoids mixing lifecycle-critical UI with speculative background ownership work.

### 2. One Clear Background Owner

Background responsibilities should be isolated behind a stable process boundary.

Those responsibilities include:

- XPC command handling
- request orchestration
- Secure Enclave signing flow coordination
- UserOperation submission
- receipt polling
- notification scheduling

The long-term target should be:

- **worker/helper = background owner**

But this should only be adopted after the helper launch model is proven in a minimal, repeatable way.

### 3. UI and Background Must Be Loosely Coupled

The UI must be able to disappear and come back without invalidating the service.

The background service must be able to restart without corrupting request state or losing the meaning of in-flight operations.

The rule is:

- UI is a client surface
- the service is the stateful executor

### 4. Every Request Needs Durable State

A request should not be "understood" only while one process stays alive.

At minimum, the app should always be able to reconstruct:

- request ID
- client identity
- request type
- approval state
- signing state
- submission state
- receipt / final outcome
- relevant error context

## Recommended Long-Term Target Architecture

### UI App

The main app should own:

- menu bar icon and menu
- settings UI
- approval UI
- audit history UI
- diagnostics/support UI

The main app should **not** be the place where long-running background logic fundamentally lives.

### Background Worker

The worker/helper should own:

- XPC endpoint
- request queue / orchestration
- policy evaluation execution
- submission lifecycle
- receipt polling
- durable request updates
- ZeroDev/network coordination

The worker should not be the primary UI owner.

### Shared Contract Layer

There should be a stable shared contract for:

- request types
- request states
- service status
- diagnostics
- UI-open requests
- version/capability negotiation

This should make app/worker/CLI mismatches detectable instead of implicit.

## Long-Term Improvement Areas

### A. Finalize Ownership Boundaries

This is the most important long-term improvement.

Bastion should move to a model where:

- the UI app always owns the menu bar
- the worker always owns background execution
- neither side is pretending to fully own both concerns

The system becomes easier to reason about once that line is explicit.

### B. Build a Worker That Is Restart-Safe

The worker should survive:

- logout/login
- reboot
- service crash
- update/relaunch

without leaving requests in an unintelligible state.

This requires:

- durable request state
- resume/reconcile logic
- explicit state transitions
- request recovery rules

### C. Harden Policy Storage and Migration

Policy and config need a production-grade lifecycle:

- versioned schema
- explicit migration
- backup before migration
- fail-closed behavior or visible recovery mode
- supportable corruption handling

This is required before Bastion can claim serious policy guarantees.

### D. Make Audit History Operationally Strong

Audit history should evolve from "helpful history UI" into a defensible operator tool.

That means:

- request-centric records
- stable lifecycle timeline
- payload storage policy
- retention/rotation strategy
- redaction rules
- exportable support artifacts

Tamper evidence may eventually be necessary depending on product claims.

### E. Harden the ZeroDev Integration

Long-term, Bastion does not need broad provider portability. It should be explicitly ZeroDev-first and operationally strong on that chosen surface.

It should clearly separate:

- read RPC
- simulation/preflight
- sponsorship
- submission
- receipt monitoring

This allows:

- degraded mode
- more understandable failure modes
- better testing

The goal is not “support every provider.” The goal is “make ZeroDev usage reliable, diagnosable, and supportable.”

### F. Make Simulation First-Class

Pre-submit simulation should become a normal part of the request lifecycle, not an operator-only debug feature.

Long-term Bastion should be able to tell the user:

- whether the request is likely to pass validation
- which step is expected to fail
- whether the failure is policy, signing, bundler, paymaster, or execution

This should feed:

- approval UI
- audit history
- support diagnostics

### G. Finish Release and Update Architecture

DMG packaging, notarization, manifests, and stable install paths are good progress, but not the end state.

The final release model should include:

- deterministic install/update path
- explicit app/worker version coordination
- rollback behavior
- release channels
- updater client strategy
- post-update recovery checks

### H. Build Real Diagnostics

A production app needs more than logs in the console.

Long-term Bastion should expose:

- current registered service owner
- current CLI/service compatibility
- last request outcome
- last submission error
- current ZeroDev / chain RPC status
- policy/config integrity status

This should exist both for users and for support.

### I. Grow End-to-End Test Coverage

The long-term architecture is not credible without system-level tests for:

- fresh install
- reboot/login recovery
- notification click routing
- service restart
- config migration
- request recovery
- stale build rejection
- update migration

## Recommended Multi-Phase Execution Order

### Phase 1: Stabilize the Current Truth

First, document and protect the currently working model:

- main app owns menu bar
- helper-owned launch target is not yet accepted
- docs match reality

Do not continue architectural changes from stale assumptions.

### Phase 2: Isolate the Worker Problem

Create a minimal experiment that proves or disproves the desired worker launch model.

Questions to answer:

- can `SMAppService.agent(plistName:)` launch the helper in the intended layout?
- if not, what layout is acceptable?
- what exactly does launchd require here?

This phase is about evidence, not feature work.

### Phase 3: Move Background Logic Behind a Stable Worker

Once the worker launch model is real and repeatable:

- move background orchestration there
- keep the UI in the main app
- make the app a true client of the worker

### Phase 4: Add Durability and Diagnostics

Once ownership is stable:

- durable request state
- support exports
- richer diagnostics
- recovery flows

### Phase 5: Finish Release / Update / Recovery

Only after the service model is stable should Bastion finalize:

- updater strategy
- rollback
- production incident handling
- formal supportability

## Anti-Goals

The roadmap should avoid these traps:

- treating menu bar disappearance as just a cosmetic issue
- merging UI ownership and service ownership again without a strong reason
- relying on development scripts as the long-term production lifecycle
- assuming provider behavior is stable enough without abstraction
- calling the helper split "done" before launchd behavior is proven

## What “Good” Looks Like in the End

The long-term architecture is in good shape when all of these are true:

1. The menu bar behaves predictably across launch, reboot, update, and notification clicks.
2. The service owner is explicit and testable.
3. Requests survive process failure in a legible way.
4. Operators can tell what happened without reverse-engineering logs by hand.
5. Policy guarantees are enforced, migrated safely, and recoverable.
6. Provider issues are understandable and non-catastrophic.
7. Release/update behavior is deterministic and supportable.

## Bottom Line

The most important long-term improvement is not “more helper work.”

It is:

- explicit ownership
- durable request state
- evidence-based service architecture
- operational resilience

Bastion becomes production-grade when it is boring to operate, not just powerful when everything goes right.
