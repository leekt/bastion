# Bastion Service Lifecycle

## Why This Matters

Bastion is not a normal foreground-only macOS app. It has to coordinate:

- a menu bar UI
- approval windows
- an XPC endpoint for CLI and client requests
- background submission and receipt polling
- native notifications that can reopen UI later

That means service lifecycle quality is a product requirement, not just an implementation detail.

## Current Problem Pattern

The unstable behavior seen during development has come from a few recurring failure modes:

1. The UI app and the background/XPC owner used to be the same binary.
2. Relay launches and notification clicks can create a second process with the same bundle identifier.
3. Manual LaunchAgent path management makes stale builds and stale registrations easy.
4. UI handoff paths that depend on running app discovery are fragile.

These issues show up as:

- the wrong app instance receiving events
- notification click opening the wrong build
- menu bar state disappearing
- CLI requests binding to stale processes

## Industry Standard on macOS

For production-quality macOS apps, the standard model is:

- `launchd` owns the background service lifecycle
- `ServiceManagement` (`SMAppService`) registers and manages the service
- `XPC` / `NSXPCConnection` is the process boundary for commands and state access
- the foreground app is a UI surface, not the source of truth for service ownership
- the background service is restart-safe and keeps minimal in-memory-only state

In practical terms, that means:

- no manual plist rewriting as the long-term architecture
- no stale build selection through Launch Services heuristics
- no app-instance scanning as the primary routing mechanism

## Target Architecture

### 1. Dedicated Background Owner (Planned, Not Yet in Production)

The intended long-term model is a dedicated per-user background helper that owns:

- the Mach service
- signing orchestration
- UserOperation submission
- receipt polling
- durable request state

The main app would own:

- settings
- audit history
- approval UI
- diagnostics UI

**Current state**: The main app binary (`Contents/MacOS/bastion`) is still the registered launch target and owns both the Mach service and the menu bar UI. The helper-owned path was attempted but failed to reach production. See the migration notes below.

### 2. Explicit UI Routing Through XPC

UI opening should happen through the service contract, not by guessing which app instance is alive.

Examples:

- notification click -> ask service to open `Audit History`
- relay launch -> ask service to open the requested UI target
- CLI diagnostics -> ask service for status instead of inferring process state

### 3. Stable Service Identity

The service should be identified by launchd registration, not by:

- DerivedData path guessing
- stale bundle registration
- whichever app instance the OS chooses to launch

### 4. Restart-Safe State

In-flight request state should survive service restarts where practical.

At minimum:

- request ID
- request status
- submission status
- receipt status
- audit timeline

should not depend on one process staying alive forever.

## Migration Plan

### Phase A: Harden the Existing Single-Binary Model

This was the short-term path while Bastion still used the menu bar app as the service owner.

Required changes:

- route relay and notification-click UI opening through Mach XPC
- stop using running-app discovery for UI handoff
- keep a single registered service path in development
- make failures visible instead of silently disappearing

This phase improved reliability before the helper split landed.

### Phase B: Split UI and Background Ownership

Introduce a dedicated background helper/agent and move service ownership there.

**Status: Not yet complete.** An attempt was made to move service ownership to the nested helper at `Contents/Helpers/bastion-helper.app/Contents/MacOS/bastion-helper`. This caused launchd to fail spawning the service entirely — `EX_CONFIG (78)` / `spawn failed` — with the error "Could not find and/or execute program specified by service". The helper process never started. The direct failure was launchd/xpcproxy being unable to resolve and execute the nested helper path in the current registration layout. It was not proven whether this is a path resolution issue, a bundle structure requirement, an entitlement mismatch, or a registration layout constraint.

The `BundleProgram` was reverted to `Contents/MacOS/bastion` as an immediate fix. The main binary currently acts as both the menu bar owner and the background service owner.

The `bastion-helper` target exists and contains AppKit-based status item code (`BastionAgentMain.swift`), but this code is not currently executed. Do not treat Phase B as complete until the `EX_CONFIG` spawn failure is diagnosed and resolved with direct evidence, not assumptions.

### Phase C: Replace Manual Service Registration

Move from manual LaunchAgent management to a more Apple-native registration path using `SMAppService`.

Goals:

- deterministic service registration
- no ad hoc plist rewriting as the release model
- no path pinning as a core production mechanism

## What Was Applied Now

The current codebase has been moved to a cleaner short-term lifecycle model:

1. Relay/UI handoff no longer depends on app-instance discovery.
   - Relay launches now ask the registered Mach service to open the target UI.

2. Notification click routing now uses the same service boundary.
   - If the service process handles the click, it opens the UI directly.
   - If a relay process is launched, it forwards the request over XPC and exits.

3. Service-unavailable failures are surfaced explicitly.
   - Relay launches now show a visible error instead of silently disappearing when the service cannot be reached.

4. The development rebuild flow pins a single signed build path.
   - The signed build is copied into `~/Applications/Bastion Dev.app` before registration so `SMAppService` runs from a stable bundle location.
   - The registered job points at `Contents/MacOS/bastion` (the main binary).
   - This remains a development hardening step, not the long-term release/update architecture.

5. Service bootstrap is split out of the SwiftUI app lifecycle.
   - `BastionServiceRuntime` owns XPC startup, notification setup, config load, and key warmup.
   - `BastionRelayRuntime` owns relay handoff and service-unavailable behavior.
   - The dedicated helper target reuses the same runtime without duplicating app bootstrap code.

6. The dedicated helper target exists but is not the background service owner in the current build.
   - `bastion-helper` is embedded at `Contents/Helpers/bastion-helper.app`.
   - `launchd` owns the main binary's lifecycle through the bundled `SMAppService` agent plist (`BundleProgram = Contents/MacOS/bastion`).
   - The menu bar UI and the Mach service are both owned by the main `bastion` binary in the current configuration.
   - The helper-owned path was attempted and failed. See Phase B notes above.

## Remaining Work to Reach Production Quality

### Short-Term

- add richer service status/diagnostics over XPC
- validate service registration after reboot and login
- add tests for notification click -> XPC handoff -> history window open

### Medium-Term

- move request orchestration fully out of the menu bar app surface area
- add request recovery after service restart
- add helper-specific diagnostics and health reporting over XPC

### Long-Term

- add release-grade packaging, notarization, and update behavior
- replace the development-only `~/Applications/Bastion Dev.app` install path with the final release install/update path
- add explicit migration and rollback handling across helper versions

## Decision Rule

Bastion should not be called production-ready until:

- UI handoff is deterministic
- stale builds cannot steal service ownership
- service identity is managed by the platform, not by development scripts
- request state remains understandable after process restarts
- diagnostics can explain service, XPC, notification, and submission failures
