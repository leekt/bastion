# Bastion QA

This directory owns the canonical feature tracker, deterministic gates, runtime
evidence templates, and final completion audit.

## Current Status

- Canonical tracker source: `qa/feature_status_source.json`
- Generated workbook: `qa/feature_status.xlsx`
- Current tracker state: all 79 feature/user-story rows pass.
- App-runtime queue: closed. `python3 qa/app_runtime_rows.py --count` prints `0`.
- Completion gate: `python3 qa/audit_goal_completion.py --require-complete` prints `Completion audit: complete`.
- Full available gate: `bash qa/run_available_checks.sh` rebuilds the workbook and runs the deterministic QA suite.

The workbook includes:

- `Feature Status`: canonical feature/user-story rows.
- `Summary`: high-level tracker counts and gate references.
- `App Runtime Sweep`: signed-app user-story runtime evidence queue.
- `Live Runtime Sweep`: installed-app lifecycle runtime evidence queue.
- `Closure Checklist`: objective-level closure checks.
- `Completion Audit`: proof mapping for the original goal.
- `Runtime Prereqs`: signed app, discovered app-bundle candidates, current-source rebuild, code-signing, notification, and lifecycle prerequisite state.
- `Open Issues`: consolidated runtime evidence gaps or prerequisite blockers.
- `Code Coverage`: selected source-file to tracker-row mapping.
- `Test Matrix`: user-story test lane, error/fix/retest state, and next proof.
- `Error Ledger`: current error, fix, retest, closure requirement, and evidence gate for every row.

## Standard Verification

Use these commands before merging QA or runtime evidence changes:

```bash
python3 qa/audit_goal_completion.py --require-complete
python3 qa/app_runtime_rows.py --count
bash qa/run_bastion_mcp_smoke.sh
bash qa/run_available_checks.sh
git diff --check
```

Expected current results:

```text
Completion audit: complete
0
Available checks passed.
```

`qa/run_bastion_mcp_smoke.sh` compiles the production Swift sidecar and checks
MCP schema/local validation plus REST auth, origin rejection, token entropy, and
body-limit behavior without requiring a live XPC service. `qa/run_available_checks.sh`
covers workbook rebuild/audit, Swift app and test target typechecks,
deterministic Swift tests, shell/lifecycle fixtures, CLI symlink helper
fixtures, native CLI/REST/MCP checks, MCP typecheck, final tracker workbook
audit, and completion-audit negative fixtures.

## Live Integration Tests

Use `.env.test.example` as a template, then export the values before running
live Sepolia flows:

```bash
BASTION_RUN_LIVE_AA_TESTS=1 \
BASTION_ZERODEV_PROJECT_ID=... \
BASTION_SEPOLIA_RPC_URL=... \
xcodebuild -project bastion.xcodeproj -scheme bastion test
```

## Workbook Generation

Rebuild the workbook from the canonical JSON source:

```bash
python3 qa/build_feature_status.py
```

Do not hand-edit `qa/feature_status.xlsx`. Edit
`qa/feature_status_source.json`, then regenerate the workbook.

Runtime artifact writers intentionally reject `qa/feature_status_source.json` as
an output path. Write review artifacts under `dist/`, inspect them, then apply
canonical source changes deliberately.

## Signed-App Runtime Evidence

Runtime-pending user stories use the signed development app at
`$HOME/Applications/Bastion Dev.app` and the App Runtime Sweep worksheet.

The app-runtime queue is currently empty. To regenerate the empty template or
audit an artifact:

```bash
qa/run_app_runtime_user_story_checks.sh --write-template dist/app-runtime-evidence.json
qa/run_app_runtime_user_story_checks.sh --audit-evidence dist/app-runtime-evidence.json --require-pass
```

For shell-verifiable signed-app evidence, refresh direct runtime observations:

```bash
qa/run_signed_app_direct_runtime_checks.sh
qa/run_app_runtime_user_story_checks.sh --write-tracker-update dist/app-runtime-evidence.current.json dist/app-runtime-tracker-update.current.json
qa/run_app_runtime_user_story_checks.sh --write-updated-source dist/app-runtime-evidence.current.json dist/feature_status_source.app-runtime.json
```

When pairing approval needs visual owner interaction, rerun direct evidence in
pairing-approval mode:

```bash
qa/run_signed_app_direct_runtime_checks.sh --wait-for-pair-approval --pair-approval-timeout 180
```

For paired-client signing/read rows that do not specifically require visual
owner-approval UI proof, use the seeded runtime path. It builds a same-team QA
helper, backs up the current runtime QA override, seeds a temporary profile,
collects CLI/REST/MCP evidence, then restores the original state. It requires
noninteractive codesign access:

```bash
qa/run_seeded_paired_runtime_checks.sh
```

Evidence rows must include `Result`, `Evidence`, and `Errors`. Evidence must
mention the row ID and feature, cite an existing `Artifact: ...` path, and the
artifact text must mention the row ID, feature, user story, and expected
behaviour. Failed or blocked rows must include row-specific errors and a rerun
command. Passed rows must keep `Errors` empty.

## Live Runtime Evidence

Live runtime rows are currently closed. To re-run the installed-app lifecycle
evidence flow, collect all phases and audit them:

```bash
qa/run_live_runtime_checks.sh --write-template dist/live-runtime-evidence.json
qa/run_live_runtime_checks.sh --check-prereqs --require-prereqs
qa/run_live_runtime_checks.sh --run-phase fresh-install --register
qa/run_live_runtime_checks.sh --run-phase reinstall
qa/run_live_runtime_checks.sh --run-phase post-reboot
qa/run_live_runtime_checks.sh --run-phase post-login
qa/run_live_runtime_checks.sh --run-phase notification-click --require-notification-click
qa/run_live_runtime_checks.sh --audit-evidence
qa/run_live_runtime_checks.sh --audit-row-evidence dist/live-runtime-evidence.json --require-pass
qa/run_live_runtime_checks.sh --write-tracker-update dist/live-runtime-evidence.json dist/live-runtime-tracker-update.json
qa/run_live_runtime_checks.sh --write-updated-source dist/live-runtime-evidence.json dist/feature_status_source.live-runtime.json
```

Notification click behavior is terminal/XPC-verifiable through the same service
route used by `UNUserNotificationCenterDelegate.didReceive`; native Notification
Center banner activation remains optional manual OS-interaction evidence, not a
shell gate.

## Code Signing Access

Run the non-mutating check to verify whether the current shell can use the
Apple Development identity without changing keychain access:

```bash
./scripts/dev-enable-codesign-keychain-access.sh --check
```

If the check fails, run the interactive helper:

```bash
./scripts/dev-enable-codesign-keychain-access.sh
```

If `./scripts/dev-rebuild-signed.sh` reports missing provisioning profiles for
the sanitized default bundle IDs, set `BASTION_APP_BUNDLE_ID` and
`BASTION_HELPER_BUNDLE_ID` in the shell or in ignored `.bastion-dev-local.env`
to match your private local Apple Development profiles, then rerun the helper.

Prefer the helper over hand-pasted `security` commands. It avoids brittle
identity-name filters, resolves the nested private-key label, and grants the
Apple tool, Apple, and explicit `codesign:` partitions needed by noninteractive
`codesign`.

If you do run the manual equivalent, do not add a `-l` identity-name filter:
Xcode can attach a current certificate to an older-named private key, so the
certificate name and nested private-key label may differ.

## Handoff

`qa/goal_handoff.md` is a chronological work log. Older sections intentionally
record then-current blockers. The current authoritative status is the final
closure entry plus:

```bash
python3 qa/audit_goal_completion.py --require-complete
bash qa/run_available_checks.sh
```
