# Bastion Menu Bar / Service Ownership Handoff

This document is intended for Claude as a factual handoff after the failed helper-owned menu bar migration.

## Executive Summary

The current working configuration uses the **main app binary** as the registered `SMAppService` launch target:

- `Contents/MacOS/bastion`

This is the correct short-term state because it restores the menu bar icon and keeps the app usable.

The previous attempt to move service ownership to:

- `Contents/Helpers/bastion-helper.app/Contents/MacOS/bastion-helper`

did **not** fail because "launchd-spawned processes cannot reliably show UI."

It failed because the registered launchd job could not successfully resolve and execute the nested helper path in the current registration/layout setup.

## What Actually Happened

When `BundleProgram` was changed to the nested helper path, the user-visible symptom was:

- the menu bar icon disappeared

The important observed evidence was:

- `launchctl print gui/$(id -u)/com.bastion.xpc` showed:
  - `job state = spawn failed`
  - `last exit code = 78: EX_CONFIG`
- system logs showed:
  - `Could not find and/or execute program specified by service`
  - `Invalid or missing Program/ProgramArguments`

This means the helper was not even getting to the point of presenting a status item. The helper process failed during launchd/xpcproxy initialization.

## What Is True Right Now

1. The menu bar UI currently lives in the main app code path.
   - `MenuBarExtra` is in `/Users/taek/workspace/bastion-app/bastion/bastion/App/BastionApp.swift`
   - That code is compiled under `#if !BASTION_HELPER`

2. The helper does contain menu/status-item-related code.
   - `/Users/taek/workspace/bastion-app/bastion/bastion/Service/BastionAgentMain.swift`
   - But this was not the first failing point in the broken rollout.

3. The current registered launch target has already been reverted to:
   - `/Users/taek/workspace/bastion-app/bastion/scripts/build-bastion-cli.sh`
   - `BundleProgram = Contents/MacOS/bastion`

4. Any document that still claims the helper currently owns the menu bar or the primary Mach service runtime is stale and needs review.

## Immediate Position

Treat the current state as:

- **menu bar owned by the main app**
- **helper ownership experiment rolled back**
- **dedicated helper architecture not production-ready yet**

Do not describe the helper migration as complete.

## What Claude Should Do Next

### P0: Correct Documentation

Update these documents so they reflect reality:

- `/Users/taek/workspace/bastion-app/bastion/docs/SERVICE_LIFECYCLE.md`
- `/Users/taek/workspace/bastion-app/bastion/README.md`
- `/Users/taek/workspace/bastion-app/bastion/PLAN.md`

Specifically:

- remove or soften claims that the helper currently owns the menu bar or the stable production service path
- document that the current working launch target is `Contents/MacOS/bastion`
- describe the helper-owned path as an experiment that failed under the current launchd registration model

### P1: Decide Process Ownership Explicitly

Before changing more code, decide the intended long-term ownership model:

Option A:

- main app owns menu bar, settings, approval UI, audit history
- background worker/helper owns signing orchestration, UserOperation submission, receipt polling

Option B:

- helper owns both background service and menu bar/status item

Right now Option A is the safer and more realistic path.

Claude should not continue assuming Option B works until it is proven with a minimal, repeatable launchd/SMAppService setup.

### P2: Reproduce the Helper Launch Failure Minimally

If helper ownership is still desired, create a minimal reproducible test that answers:

- can `SMAppService.agent(plistName:)` launch a nested helper executable from `Contents/Helpers/...` in this exact app layout?
- if not, what bundle structure does launchd actually accept?
- does the helper need a different bundle placement or registration model?

This must be answered with direct evidence, not assumptions.

### P3: Separate UI Ownership from Worker Ownership

Regardless of which long-term path is chosen, the following should be explicit:

- only one process should own the menu bar UI
- background work should not depend on menu bar ownership
- approval windows and audit history should have a deterministic owner
- service lifecycle and UI lifecycle should be related, but not conflated

## What Not to Claim

Do **not** write any of the following as root cause unless there is direct evidence:

- "launchd-spawned processes cannot reliably connect to the window server"
- "NSStatusItem does not work from a helper"
- "the helper cannot show UI on macOS"

Those may or may not be true in some contexts, but they were **not** the demonstrated root cause here.

The only supported claim from the current evidence is:

- launchd/xpcproxy could not successfully initialize the registered nested helper executable in the current app/registration layout

## Recommended Architecture Direction

The recommended next-step architecture is:

- main app remains the menu bar owner
- a separate worker/helper is introduced only for background service duties
- UI open requests are routed explicitly
- service registration experiments happen behind a minimal reproduction and do not replace the working menu bar path until proven

In other words:

- restore correctness first
- make ownership explicit
- isolate the helper problem
- only then retry a true split

## Acceptance Criteria for the Next Iteration

Claude should consider the next iteration successful only if all of the following are true:

1. The menu bar icon is visible after build/install/relaunch.
2. The registered launch target is clearly documented and matches reality.
3. Notification click does not kill or replace the visible app instance.
4. `bastion-cli status` still works.
5. If helper ownership is retried, launchd can start it repeatedly without `spawn failed`, `EX_CONFIG`, or invalid program path errors.

## Short Version

The correct short-term fix was reverting `BundleProgram` to `Contents/MacOS/bastion`.

The menu bar disappeared because the helper-owned launchd registration failed to spawn, not because we proved helper UI is impossible.

The next step is not "try helper UI again blindly." The next step is:

- correct the docs
- define ownership
- isolate the helper launch problem
- retry only with a minimal, evidence-based design
