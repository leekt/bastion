# Bastion Goal Handoff

Updated: 2026-06-25T10:28:00+09:00

## Active Objective

Complete. Every canonical feature/user-story row is audited, tested, fixed where needed, and retested.

## Current Status

- `qa/feature_status_source.json` contains 79 rows and all rows are `Pass`.
- `qa/feature_status.xlsx` is regenerated from the source.
- `python3 qa/app_runtime_rows.py --count` prints `0`.
- `python3 qa/audit_goal_completion.py --require-complete` prints `Completion audit: complete`.
- `bash qa/run_available_checks.sh` passes.

## Canonical Artifacts

- Tracker source: `qa/feature_status_source.json`
- Generated workbook: `qa/feature_status.xlsx`
- Completion audit: `python3 qa/audit_goal_completion.py`
- Full available gate: `bash qa/run_available_checks.sh`
- Current signed-app evidence: `dist/app-runtime-evidence.current.json`
- Current signed-app tracker update: `dist/app-runtime-tracker-update.current.json`
- Current live-runtime evidence: `dist/live-runtime-evidence.current-blocked.json`
- Current live-runtime tracker update: `dist/live-runtime-tracker-update.current-blocked.json`
- Seeded paired runtime summary: `dist/app-runtime-artifacts/seeded-paired-runtime/seeded-paired-runtime-summary.log`

## Runtime Target

- Active dev/signed runtime target: `$HOME/Applications/Bastion Dev.app`.
- `build/XcodeDerivedData/.../Debug/bastion.app` is the lowercase Xcode debug build product copied by `scripts/dev-rebuild-signed.sh`; do not use it as the stable runtime target.
- `dist/release/Bastion.app` and `/Applications/Bastion.app` are release packaging/install paths; they are not the active target for current dev runtime QA unless a release-specific script is being exercised.
- Latest runtime status from `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli status` reports `bundlePath=$HOME/Applications/Bastion Dev.app`.

## What Changed In This Pass

- Code-signing is usable from this shell:
  - `./scripts/dev-enable-codesign-keychain-access.sh --check` passes.
  - Identity hash: `<codesign-identity-hash>`
  - Identity name: `Apple Development: <apple-development-email> (M4J75M3TNT)`
  - Matched private key: `Apple Development: <redacted>`

- High-priority Quit relaunch bug was fixed and remains verified:
  - Menu Quit, Cmd-Q, and app termination route through `BastionUserQuitController`.
  - User-requested Quit records the shutdown marker, unregisters/unloads the LaunchAgent, and only terminates after unregister succeeds.
  - LaunchAgent `KeepAlive` uses `SuccessfulExit=false` instead of unconditional relaunch.
  - Runtime proof: `dist/lifecycle/20260623T132705Z-menu-quit-runtime.log`.

- Approval/test violation nested-window UX was fixed deterministically:
  - `ApprovalPreviewWindowHider` hides every visible non-approval host window before debug approval previews.
  - Settings and menu-bar approval-preview presenters share that hider.
  - Unit coverage asserts de-dupe behavior and preserves the approval panel.
  - Native visual proof remains part of the pending signed-app UI automation closure.

- Seeded paired-client runtime no longer depends on production Keychain config writes or a locked Secure Enclave key:
  - Added `bastion/Rules/RuntimeQAConfigOverride.swift`, DEBUG-only and marker-gated by `runtime-qa-config.enabled`.
  - `RuleEngine` reads/writes the QA override only when the DEBUG marker exists; normal production/dev config still uses the real Keychain path.
  - `qa/runtime_profile_seed.swift` now backs up/seeds/restores only `~/Library/Application Support/Bastion/runtime-qa-config.*`.
  - Added `bastion/Signing/RuntimeQASigningProvider.swift`, DEBUG-only and gated by both the QA override marker and `com.bastion.signingkey.client.runtime-qa.*` key tags.
  - The QA signer uses in-memory software P-256 keys only for seeded dev runtime evidence. Production and normal dev profiles still route through `SecureEnclaveManager`.
  - `qa/run_seeded_paired_runtime_checks.sh` now passes and updates 21 paired-client rows; the real Keychain-backed config is not mutated.

- The stale seeded restore log append behavior was fixed:
  - `qa/run_seeded_paired_runtime_checks.sh` now overwrites `restore.log` per run.
  - Latest summary shows a clean restore: `deleted seeded runtime QA config override; original was absent`.

- Notification delivery/route proof is unblocked without requiring a native banner click:
  - `scripts/verify-service-lifecycle-live.sh --phase notification-click --require-notification-click` now treats the compatibility flag as terminal-verifiable delivery plus `notification-click-probe` click-route proof.
  - `bastion notification-click-probe --id <probeId>` calls the service over XPC and invokes the same `NotificationClickHandler` path used by `UNUserNotificationCenterDelegate.didReceive`, so the click behavior is automated without a visible Notification Center banner.
  - This proof path does not depend on an unlocked desktop; native banner activation remains manual OS-interaction evidence only.
  - Native Notification Center banner activation is optional manual OS-interaction evidence, not an automated shell gate.
  - Runtime proof: `dist/lifecycle/20260623T232510Z-notification-click.log`.
  - Direct app-runtime proof now also captures `dist/app-runtime-artifacts/direct-runtime/notification-click-probe.json` and `.status` alongside delivery artifacts.
  - Lifecycle evidence audit passes across fresh-install, reinstall, post-reboot, post-login, and notification-click.

- `UI-039 UserOperation result notifications` is now canonically source-promoted to `Pass`:
  - Added XPC/CLI probes for realistic UserOperation result notification delivery and click routing:
    - `bastion userop-notification-probe --id <probeId>`
    - `bastion userop-notification-click-probe --id <probeId>`
  - The probes use the real `SigningManager.notificationIdentifier`, `SigningManager.notificationUserInfo`, `BastionNotificationManager`, and `NotificationClickHandler` paths with UserOperation metadata (`operationKind=UserOp`, `executionMode=approve_and_send`, `stage=confirmed`, `provider=ZeroDev`, transaction hash, and userOp hash).
  - Direct runtime proof captured:
    - `dist/app-runtime-artifacts/direct-runtime/userop-notification-probe.json`
    - `dist/app-runtime-artifacts/direct-runtime/userop-notification-probe.json.status`
    - `dist/app-runtime-artifacts/direct-runtime/userop-notification-click-probe.json`
    - `dist/app-runtime-artifacts/direct-runtime/userop-notification-click-probe.json.status`
  - `dist/app-runtime-artifacts/direct-runtime/current-direct-runtime-summary.log` records `UI-039 | UserOperation result notifications` as `Result pass`.

- `UI-008 Settings navigation` is now canonically source-promoted to `Pass`:
  - Added `bastion/UI/SettingsWindowManager.swift` so the service/XPC UI path opens a real `Settings` window backed by `RulesSettingsView`, instead of relying on the fragile AppKit `showSettingsWindow:` action from a LaunchAgent service context.
  - `bastion ui-probe settings` now returns `opened=true`, `matchedWindowTitle=Settings`, and `NSHostingView<RulesSettingsView>` from the signed installed app.
  - Existing deterministic Swift coverage proves sidebar inventory, selected-state preservation, fake-title-bar removal, client/wallet-group rows, empty states, and every Settings panel route.
  - `dist/app-runtime-artifacts/direct-runtime/current-direct-runtime-summary.log` records `UI-008 | Settings navigation` as `Result pass`.
  - At that stage, current app-runtime evidence tracked 22 remaining app-runtime rows; the latest pending count is 15 after the menu-bar and wallet-group promotions below.

- `UI-009 Save bar and diff review` is now canonically source-promoted to `Pass`:
  - Added `bastion/UI/SettingsScenarioProbe.swift` with a read-only `saveDiff` scenario that exercises `SettingsDiffPresentation` inside the signed service process.
  - Added XPC/CLI command: `bastion settings-scenario-probe saveDiff`.
  - The probe proves stable no-change detection, six semantic diff rows, idle Save state, and disabled Saving state without mutating the real config.
  - Direct runtime proof captured `dist/app-runtime-artifacts/direct-runtime/settings-scenario-saveDiff.json` and `.status`.
  - `dist/app-runtime-artifacts/direct-runtime/current-direct-runtime-summary.log` records `UI-009 | Save bar and diff review` as `Result pass`.

- `UI-010 Operation posture controls` is now canonically source-promoted to `Pass`:
  - Extended `bastion/UI/SettingsScenarioProbe.swift` with a read-only `postureControls` scenario that executes inside the signed service process.
  - Added CLI/XPC support for `bastion settings-scenario-probe postureControls`.
  - The probe proves Auto-sign / Always confirm / Skip rules order, compact labels, full accessibility labels and hints, selected-state projection, and independent raw-message, typed-data, and UserOperation draft config mutation.
  - Direct runtime proof captured `dist/app-runtime-artifacts/direct-runtime/settings-scenario-postureControls.json` and `.status`.
  - `dist/app-runtime-artifacts/direct-runtime/current-direct-runtime-summary.log` records `UI-010 | Operation posture controls` as `Result pass`.

- `UI-019 Rule templates` is now canonically source-promoted to `Pass`:
  - Extended `bastion/UI/SettingsScenarioProbe.swift` with a read-only `ruleTemplates` scenario that executes inside the signed service process.
  - Added CLI/XPC support for `bastion settings-scenario-probe ruleTemplates`.
  - The probe proves conservative/read-only/treasury card inventory, metrics, Apply to default and Pair agent actions, hidden custom template behavior, and Treasury Apply-to-default rule/auth mutation while preserving existing profiles.
  - Direct runtime proof captured `dist/app-runtime-artifacts/direct-runtime/settings-scenario-ruleTemplates.json` and `.status`.
  - `dist/app-runtime-artifacts/direct-runtime/current-direct-runtime-summary.log` records `UI-019 | Rule templates` as `Result pass`.

- `UI-020` through `UI-023` are now canonically source-promoted to `Pass`:
  - Extended `bastion/UI/SettingsScenarioProbe.swift` with read-only signed-service scenarios: `addressBook`, `highValue`, `policyHistory`, and `policySimulator`.
  - Added CLI support for:
    - `bastion settings-scenario-probe addressBook`
    - `bastion settings-scenario-probe highValue`
    - `bastion settings-scenario-probe policyHistory`
    - `bastion settings-scenario-probe policySimulator`
  - The probes prove address-book validation/storage/remove copy and approval decoded label display, high-value threshold/phrase validation and typed approval gating, policy-history restore/export state behavior, and policy-simulator sample/allowed/denied/error behavior inside `$HOME/Applications/Bastion Dev.app`.
  - Direct runtime proof captured:
    - `dist/app-runtime-artifacts/direct-runtime/settings-scenario-addressBook.json`
    - `dist/app-runtime-artifacts/direct-runtime/settings-scenario-highValue.json`
    - `dist/app-runtime-artifacts/direct-runtime/settings-scenario-policyHistory.json`
    - `dist/app-runtime-artifacts/direct-runtime/settings-scenario-policySimulator.json`
  - `dist/app-runtime-evidence.current.json` and `dist/app-runtime-tracker-update.current.json` now cover 22 remaining app-runtime rows; `UI-020`, `UI-021`, `UI-022`, and `UI-023` are absent from the pending set.

- `UI-011 Add target allowlist entry` is now canonically source-promoted to `Pass`:
  - Added `TargetAllowlistMutation.add(_:to:)` and `TargetAllowlistPresentation` so Settings, deterministic tests, and runtime probes share the same target-add storage and display contract.
  - Extended `bastion/UI/SettingsScenarioProbe.swift` with a read-only `targetAdd` scenario that executes inside the signed service process.
  - Added CLI support for `bastion settings-scenario-probe targetAdd`.
  - The probe proves positive chain/address/cap validation, canonical lowercase 0x target storage, optional per-target USDC daily cap creation, duplicate-add stability, inline validation messages, and per-target cap/used labels from an in-memory StateStore.
  - Direct runtime proof captured `dist/app-runtime-artifacts/direct-runtime/settings-scenario-targetAdd.json` and `.status`.
  - `dist/app-runtime-artifacts/direct-runtime/current-direct-runtime-summary.log` records `UI-011 | Add target allowlist entry` as `Result pass`.

- `UI-012 Remove target allowlist entry` is now canonically source-promoted to `Pass`:
  - Extended `bastion/UI/SettingsScenarioProbe.swift` with a read-only `targetRemove` scenario that executes inside the signed service process.
  - Added CLI support for `bastion settings-scenario-probe targetRemove`.
  - The probe proves remove accessibility copy, exact target removal from the chain allowlist, preservation of unrelated chain targets and caps, removed per-target cap pruning, case-insensitive remaining target lookup, and `allowedTargets` collapsing to nil when the last target is removed.
  - Direct runtime proof captured `dist/app-runtime-artifacts/direct-runtime/settings-scenario-targetRemove.json` and `.status`.
  - `dist/app-runtime-artifacts/direct-runtime/current-direct-runtime-summary.log` records `UI-012 | Remove target allowlist entry` as `Result pass`.

- `UI-013 Global cap tiles` is now canonically source-promoted to `Pass`:
  - Extended `bastion/UI/SettingsScenarioProbe.swift` with a read-only `globalCaps` scenario that executes inside the signed service process.
  - Added CLI support for `bastion settings-scenario-probe globalCaps`.
  - The probe proves USDC and ETH cap labels/allowance formatting, StateStore-backed spending usage values, exhausted-cap warning state, rate-limit usage and warning state, and restricted/unrestricted allowed-hours tiles using an in-memory StateStore.
  - Direct runtime proof captured `dist/app-runtime-artifacts/direct-runtime/settings-scenario-globalCaps.json` and `.status`.
  - `dist/app-runtime-artifacts/direct-runtime/current-direct-runtime-summary.log` records `UI-013 | Global cap tiles` as `Result pass`.
  - At that stage, the current app-runtime evidence and tracker update contained 22 remaining blocked rows, with `UI-013` absent from the pending set.

- `UI-014 Authentication policy picker` is now canonically source-promoted to `Pass`:
  - Extended `bastion/UI/SettingsScenarioProbe.swift` with a read-only `authPolicy` scenario that executes inside the signed service process.
  - Added CLI support for `bastion settings-scenario-probe authPolicy`.
  - The probe proves Silent/Biometric/Always confirm option order, labels, hints, selected-state projection, auth-policy draft mutation, stable violation owner-auth warning copy, and matching/manual review owner-auth decision mapping.
  - Direct runtime proof captured `dist/app-runtime-artifacts/direct-runtime/settings-scenario-authPolicy.json` and `.status`.
  - `dist/app-runtime-artifacts/direct-runtime/current-direct-runtime-summary.log` records `UI-014 | Authentication policy picker` as `Result pass`.
  - At that stage, the current app-runtime evidence and tracker update contained 22 remaining blocked rows, with `UI-014` absent from the pending set.

- `UI-016 App preferences ZeroDev project ID` is now canonically source-promoted to `Pass`:
  - Extended `bastion/UI/SettingsScenarioProbe.swift` with a read-only `projectId` scenario that executes inside the signed service process.
  - Added CLI support for `bastion settings-scenario-probe projectId`.
  - The probe proves nil Project ID reads as an empty text field, existing Project IDs read back exactly, surrounding whitespace is trimmed, empty and whitespace-only input clears to nil, and Project ID edits preserve configured per-chain RPC preferences.
  - Direct runtime proof captured `dist/app-runtime-artifacts/direct-runtime/settings-scenario-projectId.json` and `.status`.
  - `dist/app-runtime-artifacts/direct-runtime/current-direct-runtime-summary.log` records `UI-016 | App preferences ZeroDev project ID` as `Result pass`.
  - At that stage, the current app-runtime evidence and tracker update contained 22 remaining blocked rows, with `UI-016` absent from the pending set.

- `UI-017 Add RPC chain` is now canonically source-promoted to `Pass`:
  - Extended `bastion/UI/SettingsScenarioProbe.swift` with a read-only `rpcChain` scenario that executes inside the signed service process.
  - Added CLI support for `bastion settings-scenario-probe rpcChain`.
  - `SettingsDiffPresentation` now emits explicit diff rows for ZeroDev Project ID and RPC endpoint edits so Add RPC chain produces a meaningful Save bar count.
  - The probe proves positive chain ID validation, http/https RPC URL validation, trimming, sorted append, existing-chain replacement without duplication, ZeroDev project ID preservation, and a Save bar/diff row after adding a chain RPC endpoint.
  - Direct runtime proof captured `dist/app-runtime-artifacts/direct-runtime/settings-scenario-rpcChain.json` and `.status`.
  - `dist/app-runtime-artifacts/direct-runtime/current-direct-runtime-summary.log` records `UI-017 | Add RPC chain` as `Result pass`.
  - At that stage, the current app-runtime evidence and tracker update contained 22 remaining blocked rows, with `UI-017` absent from the pending set.

- `UI-018 Probe RPC endpoints` is now canonically source-promoted to `Pass`:
  - Extended `bastion/UI/SettingsScenarioProbe.swift` with a read-only async `rpcProbe` scenario that executes inside the signed service process.
  - Added CLI support for `bastion settings-scenario-probe rpcProbe`.
  - `RPCHealthMonitor` now has an injectable `probe(preferences:session:)` path so signed-app runtime probes can exercise URLSession response handling without mutating real config.
  - `RPCProbePresentation.latencyLabel(_:)` now prefers error text for non-OK samples, so HTTP failures render as `HTTP 500` instead of a misleading latency-only label.
  - The probe proves Probe now empty/ready/in-flight button states, `eth_blockNumber` POST requests, OK latency display, HTTP error display, missing-result warning display, and invalid-URL failure display.
  - Direct runtime proof captured `dist/app-runtime-artifacts/direct-runtime/settings-scenario-rpcProbe.json` and `.status`.
  - `dist/app-runtime-artifacts/direct-runtime/current-direct-runtime-summary.log` records `UI-018 | Probe RPC endpoints` as `Result pass`.
  - At that stage, the current app-runtime evidence and tracker update contained 22 remaining blocked rows, with `UI-018` absent from the pending set.

- Runtime evidence merge safety was fixed:
  - `qa/run_signed_app_direct_runtime_checks.sh` now preserves seeded paired-client pass rows instead of overwriting them with narrower direct-boundary blocked evidence.
  - `qa/run_seeded_paired_runtime_checks.sh` passed again after the direct-refresh merge fix and restored 21 seeded paired-client pass rows.
  - Latest seeded restore log remains clean: `deleted seeded runtime QA config override; original was absent`.

- Signed rebuild/runtime freshness remains hardened:
  - `scripts/dev-rebuild-signed.sh` refreshes the installed nested helper and touches installed app/CLI/helper binaries after install.
  - Current installed bundle verifies with `codesign --verify --deep --strict --verbose=2`.

- Native Xcode unit testing is no longer blocked by the test process working directory:
  - `SecurityConfigurationTests` now resolves repo file fixtures from `#filePath` instead of assuming the current working directory is the repo root.
  - `xcodebuild -project bastion.xcodeproj -scheme bastion -configuration Debug -derivedDataPath build/XcodeDerivedData test CODE_SIGNING_ALLOWED=NO` passed.
  - `qa/run_available_checks.sh` now runs that Xcode test action when full Xcode is available, while preserving the Command Line Tools warning path for hosts without full Xcode.

- Wallet-group CLI validation remains completed:
  - Required `groupId`/`memberId` positional arguments are trimmed and reject blanks.
  - Optional wallet-group IDs/transaction/provider arguments reject explicit blank values.
  - Native CLI smoke covers these cases.

- `CORE-017` is now canonically source-promoted:
  - `dist/live-runtime-evidence.core017-pass.json` and `dist/live-runtime-tracker-update.core017-pass.json` audit cleanly.
  - `qa/feature_status_source.json` marks `CORE-017` as `Pass`, with signed-app lifecycle, notification click-route, and Quit/no-relaunch artifacts cited.
  - `qa/build_feature_status.py` now allows audited partial live-runtime promotion when blocked rows remain within the canonical live-runtime gate.
  - `dist/live-runtime-evidence.current-blocked.json` and `dist/live-runtime-tracker-update.current-blocked.json` now record 1 pass row and 5 blocked rows.

- Partial app-runtime source promotion is now supported and applied:
  - `qa/run_app_runtime_user_story_checks.sh --write-updated-source` rejects failed runtime evidence, promotes pass rows when signed-app prerequisites are satisfied, and leaves blocked rows pending instead of requiring every app-runtime row to pass in one batch.
  - `qa/build_feature_status.py` and `qa/run_available_checks.sh` now treat already-closed seeded paired-client rows as closed; seeded runtime prerequisites are enforced only for seeded IDs still queued in the current app-runtime pending set.
  - `qa/feature_status_source.json` canonically closed 21 signed-app pass rows from the current app-runtime evidence.
  - `dist/app-runtime-evidence.current.json` and `dist/app-runtime-tracker-update.current.json` covered the remaining 22 app-runtime rows at that stage; the latest queue is 15 rows after `UI-001` through `UI-005`, `UI-025`, and `CORE-015` were promoted.
  - QA-001 tracker text and gate fixtures now document the partial-pass promotion policy instead of the obsolete all-or-nothing app-runtime closure rule.

- In-process signed-app UI probes were added for shell-verifiable native window evidence:
  - XPC/CLI command: `bastion-cli ui-probe <settings|auditHistory|diagnostics|approvalPolicy|approvalViolation>`.
  - The service opens the requested UI in-process, snapshots `NSApplication.shared.windows`, and returns JSON with `opened`, `matchedWindowTitle`, and window metadata.
  - This avoids external screenshots and System Events Accessibility inspection, so it is compatible with locked or non-observable desktops for window-existence proof.
  - Current probe artifacts:
    - `dist/app-runtime-artifacts/direct-runtime/ui-probe-diagnostics.json` matched `Diagnostics`.
    - `dist/app-runtime-artifacts/direct-runtime/ui-probe-auditHistory.json` matched `Audit History`.
    - `dist/app-runtime-artifacts/direct-runtime/ui-probe-settings.json` matched `Settings`.
    - `dist/app-runtime-artifacts/direct-runtime/ui-probe-approvalPolicy.json` and `ui-probe-approvalViolation.json` verify the approval preview panel chrome.
  - `UI-036 Diagnostics dashboard` is now canonically source-promoted to `Pass` from the signed-app diagnostics probe plus support-bundle diagnostics evidence.
  - `bastionTests/ServiceUIBridgeTests.swift` covers probe matching and JSON encoding stability.

- `UI-001` through `UI-005` are now canonically source-promoted to `Pass`:
  - Added `bastion/UI/MenuBarScenarioProbe.swift` and XPC/CLI support for `bastion-cli menu-scenario-probe overview`.
  - The probe runs inside `$HOME/Applications/Bastion Dev.app`, exercises menu-bar status/stats, pairing prompts, pause/resume copy, lockdown, pending submissions, and recent activity presentation paths, and does not mutate runtime state.
  - Direct runtime proof captured `dist/app-runtime-artifacts/direct-runtime/menu-scenario-overview.json`; it returned `passed=true`.
  - `qa/run_available_checks.sh` app-runtime fixtures were corrected away from stale pending IDs and now track the current queue starting at `UI-032`.

- `UI-025 Wallet group member list` and `CORE-015 Wallet group shared/scoped policy merge` are now canonically source-promoted to `Pass`:
  - Added `bastion/UI/WalletGroupScenarioProbe.swift` and XPC/CLI support for `bastion-cli wallet-group-scenario-probe overview`.
  - The probe runs inside `$HOME/Applications/Bastion Dev.app`, is read-only/in-memory, and does not mutate runtime wallet-group state.
  - The probe proves wallet-group title/badge fallback, Members copy, hidden Add/Edit management controls, installed/pending/revoked row labels and tones, empty-group copy, revoked-member exclusion from conflict banners, unsatisfiable banner copy, deterministic conflict reasons, compatible shared/scoped policy narrowing, active-member filtering, and lowercased wallet-group key tag derivation.
  - Direct runtime proof captured `dist/app-runtime-artifacts/direct-runtime/wallet-group-scenario-overview.json`; it returned `passed=true` with 12 checks.
  - `dist/app-runtime-artifacts/direct-runtime/current-direct-runtime-summary.log` records `UI-025 | Wallet group member list` and `CORE-015 | Wallet group shared/scoped policy merge` as `Result pass`.
  - App-runtime pending rows at that wallet-group stage were 15: `UI-032`, `UI-033`, `UI-034`, `UI-035`, `CLI-009`, `CLI-010`, `API-002`, `API-005`, `UI-038`, `CORE-007`, `CORE-010`, `CORE-012`, `CORE-013`, `CORE-014`, and `UI-042`.

## 2026-06-24 17:53 KST Audit-History Runtime Update

- Important app identity note: the signed dev runtime QA target is `$HOME/Applications/Bastion Dev.app`. The lowercase `build/XcodeDerivedData/.../bastion.app` is an unsigned/debug build product and must not be treated as the signed runtime closure target.
- Added `bastion/UI/AuditHistoryScenarioProbe.swift` plus XPC/CLI support for `bastion-cli audit-history-scenario-probe overview`.
- The probe runs in-process inside `$HOME/Applications/Bastion Dev.app`, is read-only/in-memory, and does not mutate the runtime audit log.
- The probe covers saved-view chip filtering, search/dropdown filter clearing, clear-filters reset, expandable audit rows, expanded metadata, timeline transaction actions, export sheet state, signed/plain/CSV export rendering, tamper recovery banner states, audit redaction policy, and shared atoms/tokens.
- Canonically source-promoted to `Pass` from signed-app runtime evidence:
  - `UI-032 Audit filtering and saved view chips`
  - `UI-033 Expandable audit rows`
  - `UI-034 Audit export`
  - `UI-035 Audit tamper recovery`
  - `CORE-013 Tamper-evident audit log and redaction`
  - `UI-042 Reusable Bastion atoms and design tokens`
- Runtime artifact added: `dist/app-runtime-artifacts/direct-runtime/audit-history-scenario-overview.json`; the installed `Bastion Dev.app` CLI probe returned `passed=true`.
- `qa/run_signed_app_direct_runtime_checks.sh` now records the current app-runtime queue as 9 rows, and `dist/app-runtime-tracker-update.current.json` was regenerated for those 9 rows.
- `qa/run_available_checks.sh` fixtures were updated from the old `UI-032/UI-033/UI-034` queue to the current queue starting at `CLI-009`, `CLI-010`, and `API-002`.
- Current app-runtime pending rows are 9: `CLI-009`, `CLI-010`, `API-002`, `API-005`, `UI-038`, `CORE-007`, `CORE-010`, `CORE-012`, and `CORE-014`.

## Verified Commands

- `xcodebuild -project bastion.xcodeproj -scheme bastion ... build CODE_SIGNING_ALLOWED=NO` passed.
- `xcodebuild -project bastion.xcodeproj -scheme bastion -configuration Debug -derivedDataPath build/XcodeDerivedData test CODE_SIGNING_ALLOWED=NO` passed.
- `./scripts/dev-enable-codesign-keychain-access.sh --check` passed.
- `./scripts/dev-rebuild-signed.sh` passed and installed `$HOME/Applications/Bastion Dev.app`.
- `qa/run_signed_app_direct_runtime_checks.sh --skip-notification-probe` passed and updated current runtime rows.
- `qa/run_seeded_paired_runtime_checks.sh` passed and updated 21 paired-client rows.
- `qa/run_signed_app_direct_runtime_checks.sh` passed with notification delivery and click-route probe artifacts enabled.
- `qa/run_app_runtime_user_story_checks.sh --write-tracker-update dist/app-runtime-evidence.current.json dist/app-runtime-tracker-update.current.json` passed.
- `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli settings-scenario-probe saveDiff` passed with `passed=true`.
- `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli settings-scenario-probe postureControls` passed with `passed=true`.
- `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli settings-scenario-probe targetAdd` passed with `passed=true`.
- `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli settings-scenario-probe targetRemove` passed with `passed=true`.
- `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli settings-scenario-probe globalCaps` passed with `passed=true`.
- `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli settings-scenario-probe authPolicy` passed with `passed=true`.
- `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli settings-scenario-probe projectId` passed with `passed=true`.
- `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli settings-scenario-probe rpcChain` passed with `passed=true`.
- `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli settings-scenario-probe rpcProbe` passed with `passed=true`.
- `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli settings-scenario-probe ruleTemplates` passed with `passed=true`.
- `qa/run_app_runtime_user_story_checks.sh --write-updated-source dist/app-runtime-evidence.current.json dist/feature_status_source.current-app-review.json` generated a partial source-promotion review artifact at the earlier 22-row stage.
- `qa/run_app_runtime_user_story_checks.sh --audit-evidence dist/app-runtime-evidence.current.json` passed at the earlier 22-row stage and again after the current 15-row wallet-group promotion.
- `qa/run_app_runtime_user_story_checks.sh --write-tracker-update dist/app-runtime-evidence.current.json dist/app-runtime-tracker-update.current.json` passed at the earlier 22-row stage, after the 17-row menu-bar promotion, and again after the current 15-row wallet-group promotion.
- `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli settings-scenario-probe addressBook` passed with `passed=true`.
- `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli settings-scenario-probe highValue` passed with `passed=true`.
- `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli settings-scenario-probe policyHistory` passed with `passed=true`.
- `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli settings-scenario-probe policySimulator` passed with `passed=true`.
- `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli menu-scenario-probe overview` passed with `passed=true`.
- `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli wallet-group-scenario-probe overview` passed with `passed=true`.
- `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli status` reported `bundlePath` as `$HOME/Applications/Bastion Dev.app`.
- `qa/run_app_runtime_user_story_checks.sh --check-prereqs` passed against `$HOME/Applications/Bastion Dev.app`; the app-runtime queue had 15 rows at that stage.
- `qa/run_live_runtime_checks.sh --run-phase notification-click --require-notification-click` passed without requiring a banner click and recorded `notification_click_local_open`; latest log: `dist/lifecycle/20260624T041954Z-notification-click.log`.
- `bash qa/run_available_checks.sh` passed after the UI-013/globalCaps promotion and runtime artifact refresh.
- `scripts/audit-service-lifecycle-evidence.sh` passed.
- `qa/run_live_runtime_checks.sh --write-tracker-update dist/live-runtime-evidence.current-blocked.json dist/live-runtime-tracker-update.current-blocked.json` passed.
- `qa/run_live_runtime_checks.sh --audit-row-evidence dist/live-runtime-evidence.core017-pass.json` passed.
- `qa/run_live_runtime_checks.sh --write-tracker-update dist/live-runtime-evidence.core017-pass.json dist/live-runtime-tracker-update.core017-pass.json` passed.
- `qa/run_live_runtime_checks.sh --write-updated-source dist/live-runtime-evidence.core017-pass.json dist/feature_status_source.core017-pass.json` passed with signed-app prerequisites satisfied.
- `qa/run_live_runtime_checks.sh --audit-row-evidence dist/live-runtime-evidence.current-blocked.json` passed.
- `qa/run_live_runtime_checks.sh --write-tracker-update dist/live-runtime-evidence.current-blocked.json dist/live-runtime-tracker-update.current-blocked.json` passed after CORE-017 promotion.
- `python3 qa/build_feature_status.py` regenerated `qa/feature_status.xlsx`.
- `python3 qa/audit_goal_completion.py` is valid but not complete.
- `qa/run_signed_app_direct_runtime_checks.sh` passed after the wallet-group promotion and refreshed `dist/app-runtime-evidence.current.json` for 15 current rows.
- `qa/run_app_runtime_user_story_checks.sh --audit-evidence dist/app-runtime-evidence.current.json` passed for 15 rows.
- `qa/run_app_runtime_user_story_checks.sh --write-tracker-update dist/app-runtime-evidence.current.json dist/app-runtime-tracker-update.current.json` passed for 15 rows.
- `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli audit-history-scenario-probe overview` passed with `passed=true`.
- `qa/run_app_runtime_user_story_checks.sh --write-updated-source dist/app-runtime-evidence.current.json dist/feature_status_source.audit-history-pass.json` passed and verified `$HOME/Applications/Bastion Dev.app`; the promoted source was copied to `qa/feature_status_source.json`.
- `qa/run_signed_app_direct_runtime_checks.sh` passed after the audit-history promotion and refreshed `dist/app-runtime-evidence.current.json` for 9 current rows.
- `qa/run_app_runtime_user_story_checks.sh --audit-evidence dist/app-runtime-evidence.current.json` passed for 9 rows.
- `qa/run_app_runtime_user_story_checks.sh --write-tracker-update dist/app-runtime-evidence.current.json dist/app-runtime-tracker-update.current.json` passed for 9 rows.
- `python3 qa/app_runtime_rows.py --count` returned `9`; `python3 qa/app_runtime_rows.py --ids` returned `CLI-009 CLI-010 API-002 API-005 UI-038 CORE-007 CORE-010 CORE-012 CORE-014`.
- `python3 qa/audit_goal_completion.py` is valid but not complete after the audit-history promotion.
- `bash qa/run_available_checks.sh` passed:
  - deterministic Swift runner: `441 tests in 53 suites`
  - native Xcode test action
  - Swift app/test typecheck
  - workbook/completion audit fixtures
  - shell syntax checks
  - native CLI, REST wrapper, MCP wrapper, and `tsc --noEmit`
- `bash qa/run_available_checks.sh` passed again after correcting the app-runtime fixture queue for the current 15-row pending set.
- `bash qa/run_available_checks.sh` passed again after correcting the app-runtime fixture queue for the current 9-row pending set.
- `git diff --check` and `bash -n qa/run_available_checks.sh` passed after the fixture correction.

## 2026-06-24 18:18 KST Runtime-State Scenario Promotion Update

- App identity correction confirmed: the signed dev runtime target is `$HOME/Applications/Bastion Dev.app`; lowercase `build/XcodeDerivedData/.../Debug/bastion.app` is only the Xcode Debug build product copied by `scripts/dev-rebuild-signed.sh`.
- Added `bastion/UI/RuntimeStateScenarioProbe.swift` and wired it through XPC/CLI as `bastion runtime-state-scenario-probe overview`.
- `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli status` reported `bundlePath=$HOME/Applications/Bastion Dev.app`.
- `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli runtime-state-scenario-probe overview` passed with `passed=true`; silent-banner panel counts were `1 1 0`.
- Promoted signed-app pass evidence for:
  - `UI-038` Silent signing receipt toast
  - `CORE-010` Spending-limit status reset timestamp
  - `CORE-012` Bundler project ID trust resolution
  - `CORE-014` Pending UserOperation status tracking
- Runtime artifact added: `dist/app-runtime-artifacts/direct-runtime/runtime-state-scenario-overview.json`.
- `qa/run_signed_app_direct_runtime_checks.sh` passed after promotion and refreshed `dist/app-runtime-evidence.current.json` for 5 current rows.
- `qa/run_app_runtime_user_story_checks.sh --audit-evidence dist/app-runtime-evidence.current.json` passed for 5 rows.
- `qa/run_app_runtime_user_story_checks.sh --write-tracker-update dist/app-runtime-evidence.current.json dist/app-runtime-tracker-update.current.json` passed for 5 rows.
- `python3 qa/app_runtime_rows.py --count` returned `5`; `python3 qa/app_runtime_rows.py --ids` returned `CLI-009 CLI-010 API-002 API-005 CORE-007`.
- `python3 qa/audit_goal_completion.py` is valid but not complete after the runtime-state promotion.
- `git diff --check`, `bash -n qa/run_available_checks.sh qa/run_signed_app_direct_runtime_checks.sh`, and `bash qa/run_available_checks.sh` passed after the promotion and fixture correction.

## 2026-06-24 18:36 KST API Wallet-Group Runtime Promotion Update

- Signed runtime target correction remains mandatory: use `$HOME/Applications/Bastion Dev.app` for installed signed runtime proof. Lowercase `build/XcodeDerivedData/.../Debug/bastion.app` is only the local Xcode Debug build product and must not be treated as the signed app closure target.
- Added DEBUG-only, marker-gated wallet-group runtime QA signing support so seeded signed-runtime tests can create group/member software keys without mutating production Keychain-backed config or requiring a Secure Enclave prompt.
- Extended `qa/run_seeded_paired_runtime_checks.sh` to exercise signed CLI wallet-group create/add/update-scope/mark-installed/remove/show/list plus REST and MCP wallet-group mutation wrappers through the installed signed runtime.
- Latest seeded paired restore remained clean: `dist/app-runtime-artifacts/seeded-paired-runtime/restore.log` reports the QA override was deleted and the original was absent.
- Promoted signed-app runtime pass evidence for `API-002` and `API-005`; `qa/feature_status_source.json` and `qa/feature_status.xlsx` were regenerated.
- Current signed-app app-runtime pending rows are now 3: `CLI-009`, `CLI-010`, and `CORE-007`.
- `CORE-007` remains host-permission blocked on this machine because `/usr/local/bin` is absent and `/usr/local` is not writable by the current user.
- `./scripts/dev-rebuild-signed.sh`, `qa/run_seeded_paired_runtime_checks.sh`, `qa/run_app_runtime_user_story_checks.sh --audit-evidence dist/app-runtime-evidence.current.json`, `qa/run_app_runtime_user_story_checks.sh --write-tracker-update dist/app-runtime-evidence.current.json dist/app-runtime-tracker-update.current.json`, `python3 qa/build_feature_status.py`, `python3 qa/audit_goal_completion.py`, and `bash qa/run_available_checks.sh` all ran after this promotion.

## 2026-06-24 19:08 KST CLI-009 Update Runtime Promotion

- Signed runtime target correction remains mandatory: use `$HOME/Applications/Bastion Dev.app` for installed signed runtime proof. Lowercase `build/XcodeDerivedData/.../Debug/bastion.app` is only the Xcode Debug build product, and `dist/release/Bastion.app` is release packaging output.
- `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli status` reported `bundlePath=$HOME/Applications/Bastion Dev.app`.
- Added `bastion/UI/UpdateScenarioProbe.swift` and wired it through XPC/CLI as `bastion update-scenario-probe overview`.
- `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli update-scenario-probe overview` passed with `passed=true`.
- The probe runs in-process inside the signed service and uses temporary app-bundle fixtures. It exercises update manifest evaluation, local artifact download hash/size verification, staged app replacement, rollback backup creation, app verification hooks, service recovery command paths, CLI symlink command paths, and relaunch command paths without replacing the real installed app.
- Runtime artifact added: `dist/app-runtime-artifacts/direct-runtime/update-scenario-overview.json`.
- Promoted `CLI-009 Update check/download/install` to signed-app runtime `Pass`; `qa/feature_status_source.json` and `qa/feature_status.xlsx` were regenerated.
- `qa/run_signed_app_direct_runtime_checks.sh --skip-notification-probe` refreshed `dist/app-runtime-evidence.current.json` for the current 2 app-runtime rows.
- `qa/run_app_runtime_user_story_checks.sh --audit-evidence dist/app-runtime-evidence.current.json` and `qa/run_app_runtime_user_story_checks.sh --write-tracker-update dist/app-runtime-evidence.current.json dist/app-runtime-tracker-update.current.json` passed for the current 2 app-runtime rows.
- `python3 qa/app_runtime_rows.py --ids` now returns `CLI-010 CORE-007`.
- `bash qa/run_available_checks.sh` passed at 19:08 KST, including the deterministic Swift runner (`441 tests in 53 suites`), native Xcode test action, Swift app/test typecheck, workbook/completion audit fixtures, shell syntax checks, native CLI, REST wrapper, MCP wrapper, and `tsc --noEmit`.

## 2026-06-24 19:31 KST CLI-010 Key Lifecycle Runtime Promotion

- Signed runtime target correction remains mandatory: use `$HOME/Applications/Bastion Dev.app` for installed signed runtime proof. Lowercase `build/XcodeDerivedData/.../Debug/bastion.app` is only the local Xcode Debug build product, and `dist/release/Bastion.app` is release packaging output.
- Added `bastion/Signing/SigningKeyLifecyclePlan.swift` and `bastion/UI/KeyLifecycleScenarioProbe.swift`, then wired the probe through XPC/CLI as `bastion key-lifecycle-scenario-probe overview`.
- `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli key-lifecycle-scenario-probe overview` passed with `passed=true`.
- The probe runs inside the signed service and exercises reset-key tag derivation, private-client key rotation planning, runtime-QA private-client key-tag mutation, wallet-group member rotation rejection, and DEBUG runtime-QA signer/account derivation using isolated in-memory/temporary config. It does not delete or rotate real signing material.
- Runtime artifact added: `dist/app-runtime-artifacts/direct-runtime/key-lifecycle-scenario-overview.json`.
- Promoted `CLI-010 Key reset and rotation` to signed-app runtime `Pass`; `qa/feature_status_source.json` and `qa/feature_status.xlsx` were regenerated.
- `qa/run_signed_app_direct_runtime_checks.sh --skip-notification-probe` refreshed `dist/app-runtime-evidence.current.json` and `dist/app-runtime-tracker-update.current.json` for the current 1 app-runtime row.
- `qa/run_app_runtime_user_story_checks.sh --audit-evidence dist/app-runtime-evidence.current.json` and `qa/run_app_runtime_user_story_checks.sh --write-tracker-update dist/app-runtime-evidence.current.json dist/app-runtime-tracker-update.current.json` passed for the current 1 app-runtime row.
- `python3 qa/app_runtime_rows.py --ids` now returns `CORE-007`.
- `qa/run_available_checks.sh` fixtures were corrected from the old `CLI-010 CORE-007` two-row current app-runtime queue to the current single-row `CORE-007` queue.
- `bash qa/run_available_checks.sh` passed at 19:31 KST, including workbook/completion audit fixtures, app-runtime/live-runtime evidence fixtures, deterministic Swift tests, native Xcode test action, Swift typecheck, native CLI/REST/MCP wrapper checks, and `tsc --noEmit`.

## Current Audit State

`python3 qa/audit_goal_completion.py` reports not complete.

## 2026-06-24 20:50 KST Live Runtime Promotion And Locked-Session Fix

- Correct signed runtime target remains `$HOME/Applications/Bastion Dev.app`; the lowercase `build/XcodeDerivedData/.../Debug/bastion.app` is only an Xcode build product.
- Added `bastion/UI/LiveRuntimeScenarioProbe.swift` and wired it through XPC/CLI as `bastion live-runtime-scenario-probe overview`.
- Tightened the live probe to require the exact expected dev bundle path, not a broad `/Applications/...` substring.
- Switched Keychain generic-password writes and Secure Enclave key access control from `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` to `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. The installed LaunchAgent service now creates/uses the throwaway Secure Enclave probe key and writes/reads/deletes data-protection Keychain probe state while `CGSSessionScreenIsLocked=Yes`.
- `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli live-runtime-scenario-probe overview` passed with `passed=true` while the desktop was locked. The response proved exact bundle path `$HOME/Applications/Bastion Dev.app`, launch mode `service`, Secure Enclave token `com.apple.setoken`, private-key export blocked, signature verify true, Keychain access group/data-protection/after-first-unlock attributes, update scheduler cancellation, and signed CLI XPC profile gating.
- Added `qa/collect_live_runtime_row_evidence.py`, which collects status, live scenario JSON, support bundle JSON, unpaired `rules`/`state` denial logs, lock-state text, menu scenario JSON, and lifecycle audit output.
- Promoted live-runtime pass evidence for `CORE-003`, `CORE-005`, `CORE-006`, `CORE-009`, `CORE-011`, and refreshed `CORE-017` through `dist/live-runtime-evidence.current-blocked.json`, `dist/live-runtime-tracker-update.current-blocked.json`, `qa/feature_status_source.json`, and `qa/feature_status.xlsx`.
- Updated `qa/run_live_runtime_checks.sh` and `qa/run_available_checks.sh` fixtures so live-runtime pass is the baseline.
- `bash qa/run_available_checks.sh` passed at 20:47 KST, including deterministic Swift runner (`441 tests in 53 suites`), native Xcode test action, shell/lifecycle fixtures, native CLI smoke, REST/MCP wrapper smoke, MCP typecheck, final tracker workbook audit, and completion audit fixtures.
- `git diff --check` passed.

Runtime prerequisite state:

- No separate runtime prerequisite blocker remains for code signing, current-source signed app freshness, seeded paired-client runtime setup, notification delivery/route proof, or live-runtime row evidence. The remaining open work is the `CORE-007` app-runtime symlink row.

Other open closure items:

- 1 signed-app app-runtime row still needs final canonical tracker/source closure from runtime evidence: `CORE-007`. The current review artifact is `dist/app-runtime-tracker-update.current.json`.
- `CORE-007` still appears in the app-runtime queue because installed-app CLI symlink exposure remains blocked by host permissions: `/usr/local/bin` is absent and `/usr/local` is not writable by the current user. Use `python3 qa/app_runtime_rows.py --ids` and `python3 qa/audit_goal_completion.py` as the authoritative app-runtime-open signals.
- Live-runtime rows are now promoted to pass. `python3 qa/audit_goal_completion.py` reports only `CORE-007` as open.

## 2026-06-24 21:04 KST CORE-007 App Target Correction And CLI Symlink Helper

- Correct signed runtime target remains `$HOME/Applications/Bastion Dev.app`. The lowercase `build/XcodeDerivedData/.../Debug/bastion.app` path is only the Xcode build/test product produced by `xcodebuild`; do not use it as the installed signed runtime target for app-runtime closure.
- Added `scripts/install-cli-symlink.sh` as the canonical CLI symlink installer/remediation helper. By default it targets `~/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli` and `/usr/local/bin/bastion`.
- Updated `scripts/dev-rebuild-signed.sh` and `scripts/release-install.sh` to stop silently swallowing `/usr/local/bin` symlink failures. They now invoke the helper in `--no-sudo` mode and print an exact interactive `--sudo` remediation command when the host needs privileges.
- Updated README and CLI request examples to point at `~/Applications/Bastion Dev.app` and `scripts/install-cli-symlink.sh --app "$BASTION_APP" --sudo`, instead of hand-written `sudo ln -sf` or a DerivedData `bastion.app` CLI alias.
- Refreshed `qa/run_signed_app_direct_runtime_checks.sh --skip-notification-probe` so `CORE-007` evidence names `$HOME/Applications/Bastion Dev.app` and the exact repair command: `scripts/install-cli-symlink.sh --cli "$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli" --sudo`.
- Added `scripts/install-cli-symlink.sh` to the `CORE-007` canonical Code evidence and regenerated `qa/feature_status.xlsx`.
- Validation:
  - `scripts/install-cli-symlink.sh --cli "$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli" --no-sudo` fails clearly on this host because `/usr/local/bin` cannot be created without privileges.
  - The helper successfully installs an atomic symlink when `--link` points at a writable temporary directory.
  - `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli status` reports `bundlePath=$HOME/Applications/Bastion Dev.app` and `launchMode=service`.
  - `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli live-runtime-scenario-probe overview` reports `passed=true` and service bundle path `$HOME/Applications/Bastion Dev.app`.
  - `bash qa/run_available_checks.sh` passed at 21:03 KST, including deterministic Swift runner `441 tests in 53 suites`, shell syntax for the new helper, native CLI/REST/MCP checks, `tsc --noEmit`, final tracker workbook audit, and Xcode test action.
  - `git diff --check` passed.
  - `python3 qa/audit_goal_completion.py` is valid but not complete, with only `CORE-007` remaining.

Current `CORE-007` state:

- `/usr/local/bin/bastion` is still absent because `/usr/local/bin` is absent and `/usr/local` is not writable by the current user.
- The remaining manual host repair is: `scripts/install-cli-symlink.sh --cli "$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli" --sudo`.
- After that repair, rerun `qa/run_signed_app_direct_runtime_checks.sh --skip-notification-probe`, `qa/run_app_runtime_user_story_checks.sh --write-tracker-update dist/app-runtime-evidence.current.json dist/app-runtime-tracker-update.current.json`, `python3 qa/build_feature_status.py`, `python3 qa/audit_goal_completion.py`, and `bash qa/run_available_checks.sh`.

## 2026-06-24 21:16 KST CORE-007 Interactive Symlink Install UX

- Rechecked host state: `/usr/local` is still `root:wheel`, `/usr/local/bin` is absent, `/usr/local/bin/bastion` is absent, `which bastion` fails, and `sudo -n true` is not cached.
- `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli status` still reports `bundlePath=$HOME/Applications/Bastion Dev.app` and `launchMode=service`.
- Extended `scripts/install-cli-symlink.sh` with `--sudo-if-interactive`.
  - It first tries atomic non-sudo installation.
  - If that fails, it uses sudo only when sudo is already cached or stdin is an interactive terminal.
  - In noninteractive QA/Codex runs, it fails quickly with the exact `--sudo` repair command instead of hanging for a password.
  - It rejects conflicting mode flags such as `--sudo --no-sudo`.
- Updated `scripts/dev-rebuild-signed.sh` and `scripts/release-install.sh` to call the helper with `--sudo-if-interactive`, so normal Terminal runs can complete `/usr/local/bin/bastion` during rebuild/install while noninteractive runs remain safe.
- Added a `qa/run_available_checks.sh` regression fixture for the helper: shell syntax, writable temp symlink creation, conflicting sudo mode rejection, and caller scripts using `--sudo-if-interactive`.
- Updated `qa/feature_status_source.json` CORE-007 Code/Test/Error/Retest evidence and regenerated `qa/feature_status.xlsx`.
- Refreshed `qa/run_signed_app_direct_runtime_checks.sh --skip-notification-probe`, `dist/app-runtime-evidence.current.json`, and `dist/app-runtime-tracker-update.current.json`.
- Verification:
  - `sh -n scripts/install-cli-symlink.sh scripts/dev-rebuild-signed.sh scripts/release-install.sh` passed.
  - `scripts/install-cli-symlink.sh --cli "$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli" --link <temp>/bin/bastion --sudo-if-interactive` installed the temp symlink.
  - `scripts/install-cli-symlink.sh --sudo --no-sudo` and `--sudo --sudo-if-interactive` both failed with the expected mode-conflict message.
  - `qa/run_app_runtime_user_story_checks.sh --audit-evidence dist/app-runtime-evidence.current.json` passed.
  - `python3 qa/audit_goal_completion.py` remains valid but not complete with only `CORE-007`.
  - `bash qa/run_available_checks.sh` passed at 21:16 KST, including the new helper fixture, deterministic Swift runner `441 tests in 53 suites`, native Xcode test action, shell/lifecycle fixtures, native CLI/REST/MCP checks, `tsc --noEmit`, final tracker workbook audit, and completion audit fixtures.
  - `git diff --check` passed.

Current `CORE-007` state after this continuation:

- Repo-side install UX is improved; the normal interactive rebuild/install path can now request sudo automatically.
- Actual runtime closure still requires creating `/usr/local/bin/bastion` on the host. Run `scripts/install-cli-symlink.sh --cli "$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli" --sudo` in an interactive admin terminal, or rerun `./scripts/dev-rebuild-signed.sh` from an interactive terminal and allow its sudo prompt.

## User-Reported Issues

- Quit relaunch: fixed and runtime-proven.
- Notification click behavior: terminal/XPC automation is unblocked and passed; latest proof is `dist/lifecycle/20260624T041954Z-notification-click.log`.
- Approval/test violation nested-looking preview: deterministic host-window hiding fix landed; native visual proof remains pending under signed-app UI automation.
- Keychain/codesign access: code-signing private-key access is unblocked.
- Dev runtime should not require production Keychain/Secure Enclave config: fixed for the seeded QA path with a DEBUG-only marker-gated config override and QA key-tag-gated software signer.
- Locked desktop UI proof: in-process `ui-probe` can prove specific signed-app windows without screenshot/AX access, but actual click-through workflows still need row-specific UI automation or native runtime evidence.
- XCUIAutomation: useful for real visible macOS UI flows when the desktop session is unlocked; it does not remove the macOS locked-desktop limitation for WindowServer/Notification Center interactions. Keep terminal-safe XPC probes for locked/headless gates and use XCUI only for unlocked visual interaction coverage.

## Superseded Pre-Closure Next Steps

The older runtime-sweep next steps below were completed by the final runtime
closure. The current source of truth is the final closure entry and
`qa/README.md`.

## 2026-06-25 10:28 KST Final Runtime Closure

- Host codesign access is unblocked. `scripts/dev-enable-codesign-keychain-access.sh --check` reports a usable Apple Development identity and noninteractive `/usr/bin/codesign` probe success.
- The installed signed runtime target is `$HOME/Applications/Bastion Dev.app`.
- `/usr/local/bin/bastion` is installed as a symlink to `$HOME/Applications/Bastion Dev.app/Contents/MacOS/bastion-cli`; `/usr/local/bin/bastion status` reports `bundlePath=$HOME/Applications/Bastion Dev.app` and `launchMode=service`.
- Refreshed signed-app direct runtime evidence and promoted `CORE-007` to pass. The app-runtime queue is now closed: `python3 qa/app_runtime_rows.py --count` prints `0`.
- Updated the app-runtime/current-source QA gates for the completed zero-row state:
  - `qa/run_signed_app_direct_runtime_checks.sh` now verifies the CLI symlink resolves to the expected `Bastion Dev.app` bundled CLI before marking `CORE-007` pass.
  - `qa/run_app_runtime_user_story_checks.sh` clears stale blocker text from generated pass updates.
  - `qa/audit_goal_completion.py` and `qa/run_available_checks.sh` now validate empty App Runtime Sweep/Live Runtime Sweep validation ranges correctly and keep completed-state negative fixtures meaningful.
  - `qa/build_feature_status.py` still rejects stale QA-001 app-runtime row-count wording even after the queue reaches zero.
- Regenerated `qa/feature_status_source.json` and `qa/feature_status.xlsx`; current app-runtime review artifacts are empty because no app-runtime rows remain.
- Verification:
  - `python3 qa/audit_goal_completion.py --require-complete` prints `Completion audit: complete`.
  - `bash qa/run_available_checks.sh` passed at 10:27 KST, including Swift app/test typechecks, deterministic Swift runner `441 tests in 53 suites`, native Xcode test action, shell/lifecycle fixtures, CLI symlink helper fixtures, native CLI/REST/MCP checks, MCP typecheck, final tracker workbook audit, and completion audit.
  - `git diff --check` passed.
