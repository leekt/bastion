#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TMP_ROOT="${TMPDIR:-/tmp}"
TMP_ROOT="${TMP_ROOT%/}"
RUN_AVAILABLE_CHECKS_LOCK_DIR="$TMP_ROOT/bastion_run_available_checks.lock"
cleanup_run_lock() {
  if [[ -d "$RUN_AVAILABLE_CHECKS_LOCK_DIR" ]] \
    && [[ "$(cat "$RUN_AVAILABLE_CHECKS_LOCK_DIR/pid" 2>/dev/null || true)" == "$$" ]]; then
    rm -rf "$RUN_AVAILABLE_CHECKS_LOCK_DIR"
  fi
}
acquire_run_lock() {
  local existing_pid=""

  if mkdir "$RUN_AVAILABLE_CHECKS_LOCK_DIR" 2>/dev/null; then
    printf '%s\n' "$$" >"$RUN_AVAILABLE_CHECKS_LOCK_DIR/pid"
    return
  fi

  existing_pid="$(cat "$RUN_AVAILABLE_CHECKS_LOCK_DIR/pid" 2>/dev/null || true)"
  if [[ "$existing_pid" =~ ^[0-9]+$ ]] && ps -p "$existing_pid" >/dev/null 2>&1; then
    echo "qa/run_available_checks.sh is already running as pid $existing_pid." >&2
    exit 1
  fi

  rm -rf "$RUN_AVAILABLE_CHECKS_LOCK_DIR"
  if mkdir "$RUN_AVAILABLE_CHECKS_LOCK_DIR" 2>/dev/null; then
    printf '%s\n' "$$" >"$RUN_AVAILABLE_CHECKS_LOCK_DIR/pid"
    return
  fi

  echo "Could not acquire run lock at $RUN_AVAILABLE_CHECKS_LOCK_DIR." >&2
  exit 1
}
acquire_run_lock
trap cleanup_run_lock EXIT

settle_swift_inputs() {
  # The Swift driver rejects inputs whose mtimes appear newer than a build
  # phase's start. Wait until Swift sources are stable and older than the next
  # build phase instead of relying on a blind sleep after rapid patching.
  local newest=""
  local previous=""
  local now=""
  local age=""

  for _ in {1..30}; do
    newest="$(find BastionShared bastion bastionTests -name '*.swift' -print0 | xargs -0 stat -f '%m' | sort -nr | head -1)"
    now="$(date +%s)"
    age=$((now - newest))
    if [[ "$newest" == "$previous" && "$age" -ge 5 ]]; then
      return
    fi
    previous="$newest"
    sleep 1
  done
}

echo "== Tracker workbook =="
python3 qa/build_feature_status.py
COMPLETION_AUDIT_LOG="$(mktemp "$TMP_ROOT/bastion_completion_audit.XXXXXX")"
python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG"
if grep -Fx "Completion audit: complete" "$COMPLETION_AUDIT_LOG" >/dev/null; then
  python3 qa/audit_goal_completion.py --require-complete >"$COMPLETION_AUDIT_LOG.require"
  grep -Fx "Completion audit: complete" "$COMPLETION_AUDIT_LOG.require" >/dev/null
else
  grep -F "Completion audit: not complete" "$COMPLETION_AUDIT_LOG" >/dev/null
  grep -F "signed-app app-runtime user-story rows still require runtime evidence:" "$COMPLETION_AUDIT_LOG" >/dev/null
  if python3 qa/audit_goal_completion.py --require-complete >"$COMPLETION_AUDIT_LOG.require" 2>&1; then
    echo "Expected strict completion audit to fail while signed-app runtime rows remain."
    exit 1
  fi
  grep -F "Completion audit: not complete" "$COMPLETION_AUDIT_LOG.require" >/dev/null
fi
if grep -F "signed-app live-runtime rows still require installed-app lifecycle evidence:" "$COMPLETION_AUDIT_LOG" >/dev/null; then
  echo "Completion audit contains stale live-runtime blocker wording."
  exit 1
fi
if grep -F "Code-signing identities=Blocked:" "$COMPLETION_AUDIT_LOG" >/dev/null; then
  grep -F "matched private key label:" "$COMPLETION_AUDIT_LOG" >/dev/null
fi
if grep -F "Seeded paired-client runtime setup=Blocked:" "$COMPLETION_AUDIT_LOG" >/dev/null; then
  grep -F "seeded paired-client target rows" "$COMPLETION_AUDIT_LOG" >/dev/null
fi
if grep -F "Notification click proof=Blocked:" "$COMPLETION_AUDIT_LOG" >/dev/null; then
  echo "Completion audit contains stale notification-click blocker wording."
  exit 1
fi
if grep -F "Notification delivery and route proof=Blocked:" "$COMPLETION_AUDIT_LOG" >/dev/null; then
  grep -F "notification" "$COMPLETION_AUDIT_LOG" >/dev/null
fi
if grep -F "Code-signing identities=Blocked:" "$COMPLETION_AUDIT_LOG.require" >/dev/null; then
  grep -F "matched private key label:" "$COMPLETION_AUDIT_LOG.require" >/dev/null
fi
if grep -F "Seeded paired-client runtime setup=Blocked:" "$COMPLETION_AUDIT_LOG.require" >/dev/null; then
  grep -F "seeded paired-client target rows" "$COMPLETION_AUDIT_LOG.require" >/dev/null
fi
if grep -F "Notification click proof=Blocked:" "$COMPLETION_AUDIT_LOG.require" >/dev/null; then
  echo "Strict completion audit contains stale notification-click blocker wording."
  exit 1
fi
if grep -F "Notification delivery and route proof=Blocked:" "$COMPLETION_AUDIT_LOG.require" >/dev/null; then
  grep -F "notification" "$COMPLETION_AUDIT_LOG.require" >/dev/null
fi
RUN_LOCK_REENTRY_LOG="$COMPLETION_AUDIT_LOG.run-lock"
if bash qa/run_available_checks.sh >"$RUN_LOCK_REENTRY_LOG" 2>&1; then
  echo "Expected nested qa/run_available_checks.sh invocation to fail while the run lock is held."
  exit 1
fi
grep -F "qa/run_available_checks.sh is already running as pid" "$RUN_LOCK_REENTRY_LOG" >/dev/null
echo "== App-runtime proof focus regression =="
python3 qa/test_app_runtime_rows.py
echo "== Current runtime review artifacts =="
CURRENT_REVIEW_ARTIFACTS=(
  "dist/app-runtime-evidence.current.json"
  "dist/live-runtime-evidence.current-blocked.json"
  "dist/app-runtime-tracker-update.current.json"
  "dist/live-runtime-tracker-update.current-blocked.json"
)
CURRENT_REVIEW_ARTIFACT_BACKUP_DIR="$(mktemp -d "$TMP_ROOT/bastion_current_runtime_artifacts.XXXXXX")"
for artifact in "${CURRENT_REVIEW_ARTIFACTS[@]}"; do
  mkdir -p "$CURRENT_REVIEW_ARTIFACT_BACKUP_DIR/$(dirname "$artifact")"
  cp "$artifact" "$CURRENT_REVIEW_ARTIFACT_BACKUP_DIR/$artifact"
done
restore_original_current_review_artifact() {
  if [[ -d "$CURRENT_REVIEW_ARTIFACT_BACKUP_DIR" ]]; then
    for artifact in "${CURRENT_REVIEW_ARTIFACTS[@]}"; do
      cp "$CURRENT_REVIEW_ARTIFACT_BACKUP_DIR/$artifact" "$artifact"
    done
  fi
  python3 qa/build_feature_status.py >/dev/null
}
write_missing_app_current_review_fixture() {
  local artifact="$CURRENT_REVIEW_ARTIFACT_BACKUP_DIR/app-runtime-current-blocked.log"
  python3 - "$artifact" <<'PY'
import json
import sys
from pathlib import Path

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = Path(sys.argv[1])
rows = runtime_evidence_template(tracker_rows())
artifact.parent.mkdir(parents=True, exist_ok=True)
with artifact.open("w") as handle:
    handle.write("Current app-runtime blocked review artifact.\n")
    for row in rows:
        handle.write(f"ROW {row['ID']}\n")
        handle.write(
            f"{row['ID']} {row['Feature']}: Result blocked. "
            f"User story: {row['User story']} "
            f"Expected behaviour: {row['Expected behaviour']} "
            f"Test instructions: {row['Test instructions']} "
            "Current-source signed-app prerequisite blocked this row.\n"
        )

for row in rows:
    row["Result"] = "blocked"
    row["Evidence"] = (
        f"Observed signed app runtime sweep recorded Result blocked for {row['ID']} {row['Feature']}. "
        f"User story: {row['User story']} "
        f"Expected behaviour: {row['Expected behaviour']} "
        f"Test instructions: {row['Test instructions']} "
        f"Artifact: {artifact} "
        "Rerun: qa/run_app_runtime_user_story_checks.sh"
    )
    row["Errors"] = (
        f"{row['ID']} {row['Feature']}: current-source signed-app runtime prerequisite blocked this row. "
        f"Artifact: {artifact}. Rerun: qa/run_app_runtime_user_story_checks.sh."
    )

Path("dist/app-runtime-evidence.current.json").write_text(json.dumps(rows, indent=2) + "\n")
PY
  BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" \
    qa/run_app_runtime_user_story_checks.sh \
      --write-tracker-update \
      dist/app-runtime-evidence.current.json \
      dist/app-runtime-tracker-update.current.json >/dev/null
}
restore_current_review_artifact() {
  restore_original_current_review_artifact
  write_missing_app_current_review_fixture
  BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/build_feature_status.py >/dev/null
}
restore_current_review_artifact_and_workbook() {
  restore_original_current_review_artifact || true
  cleanup_run_lock
}
trap restore_current_review_artifact_and_workbook EXIT
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-tracker-update.current-blocked.json")
rows = json.loads(path.read_text())
for row in rows:
    if row.get("ID") == "CORE-003":
        feature = row.get("Feature", "Secure Enclave signing and auth flow")
        row["Result"] = "pass"
        row["Test status"] = "Pass"
        row["Retest status"] = (
            f"Passed stale-current promotion check for CORE-003 {feature}. "
            "Evidence: Result pass Artifact: dist/live-runtime-artifacts/live-runtime-current-blockers.log"
        )
        path.write_text(json.dumps(rows, indent=2) + "\n")
        break
else:
    raise SystemExit("current live-runtime tracker-update fixture must contain CORE-003")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.stale-current-review-artifact" 2>&1; then
  echo "Expected completion audit to fail when a current runtime review artifact promotes pass rows while runtime prerequisites are blocked."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.stale-current-review-artifact" >/dev/null
grep -F "does not match dist/live-runtime-evidence.current-blocked.json Evidence artifact" "$COMPLETION_AUDIT_LOG.stale-current-review-artifact" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-evidence.current-blocked.json")
rows = json.loads(path.read_text())
for row in rows:
    if row.get("ID") == "CORE-003":
        row["Evidence"] = row["Evidence"].replace(
            "Artifact: dist/live-runtime-artifacts/live-runtime-row-pass-review.log",
            "Artifact: dist/live-runtime-artifacts/missing-live-runtime-review.log",
            1,
        )
        path.write_text(json.dumps(rows, indent=2) + "\n")
        break
else:
    raise SystemExit("current live-runtime evidence fixture must contain CORE-003")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.stale-current-evidence" 2>&1; then
  echo "Expected completion audit to fail when current runtime evidence cites a missing artifact."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.stale-current-evidence" >/dev/null
grep -F "dist/live-runtime-evidence.current-blocked.json" "$COMPLETION_AUDIT_LOG.stale-current-evidence" >/dev/null
grep -F "Evidence artifact does not exist: dist/live-runtime-artifacts/missing-live-runtime-review.log" "$COMPLETION_AUDIT_LOG.stale-current-evidence" >/dev/null
restore_current_review_artifact
CURRENT_APP_RUNTIME_ROW_COUNT="$(python3 qa/app_runtime_rows.py --count)"
if [[ "$CURRENT_APP_RUNTIME_ROW_COUNT" -gt 0 ]]; then
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-evidence.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime evidence fixture must contain at least one row")
path.write_text(json.dumps(rows[1:], indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.missing-current-evidence-row" 2>&1; then
  echo "Expected completion audit to fail when current runtime evidence is missing a row."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.missing-current-evidence-row" >/dev/null
grep -F "dist/app-runtime-evidence.current.json: missing current runtime rows:" "$COMPLETION_AUDIT_LOG.missing-current-evidence-row" >/dev/null
restore_original_current_review_artifact
SEEDED_PREFLIGHT_BEFORE="$COMPLETION_AUDIT_LOG.seeded-preflight-before.json"
cp dist/app-runtime-evidence.current.json "$SEEDED_PREFLIGHT_BEFORE"
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-evidence.current.json")
rows = json.loads(path.read_text())
for row in rows:
    if (
        "non-mutating codesign usability preflight failed" in row.get("Errors", "")
        and "Additional artifact: dist/app-runtime-artifacts/seeded-paired-runtime/codesign-preflight.log" in row.get("Evidence", "")
    ):
        row["Evidence"] = row["Evidence"].replace(
            " Additional artifact: dist/app-runtime-artifacts/seeded-paired-runtime/codesign-preflight.log",
            "",
        )
        path.write_text(json.dumps(rows, indent=2) + "\n")
        break
else:
    raise SystemExit(0)
PY
if ! cmp -s "$SEEDED_PREFLIGHT_BEFORE" "dist/app-runtime-evidence.current.json"; then
  python3 qa/build_feature_status.py >/dev/null
  if python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.seeded-preflight-missing-raw-artifact" 2>&1; then
    echo "Expected completion audit to fail when seeded preflight blocker evidence omits raw codesign-preflight.log."
    exit 1
  fi
  grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.seeded-preflight-missing-raw-artifact" >/dev/null
  grep -F "seeded paired-client preflight blocker must cite raw codesign-preflight.log as an Additional artifact" "$COMPLETION_AUDIT_LOG.seeded-preflight-missing-raw-artifact" >/dev/null
fi
restore_original_current_review_artifact
UI039_NOTIFICATION_FIXTURE_STATUS="$COMPLETION_AUDIT_LOG.ui039-notification-fixture-status"
python3 - "$UI039_NOTIFICATION_FIXTURE_STATUS" <<'PY'
import json
import sys
from pathlib import Path

status_path = Path(sys.argv[1])
path = Path("dist/app-runtime-evidence.current.json")
rows = json.loads(path.read_text())
for row in rows:
    if row.get("ID") == "UI-039" and "notification probe" in row.get("Evidence", ""):
        row["Evidence"] = row["Evidence"].replace(
            " Additional artifact: dist/app-runtime-artifacts/direct-runtime/notification-probe.json",
            "",
        )
        path.write_text(json.dumps(rows, indent=2) + "\n")
        status_path.write_text("mutated\n")
        break
else:
    status_path.write_text("absent\n")
PY
if [[ "$(cat "$UI039_NOTIFICATION_FIXTURE_STATUS")" == "mutated" ]]; then
  python3 qa/build_feature_status.py >/dev/null
  if python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.ui039-missing-notification-artifact" 2>&1; then
    echo "Expected completion audit to fail when UI-039 notification evidence omits the raw notification probe artifact."
    exit 1
  fi
  grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.ui039-missing-notification-artifact" >/dev/null
  grep -F "UI-039 notification probe evidence must cite dist/app-runtime-artifacts/direct-runtime/notification-probe.json as an Additional artifact" "$COMPLETION_AUDIT_LOG.ui039-missing-notification-artifact" >/dev/null
fi
restore_original_current_review_artifact
UI042_OPEN_UI_FIXTURE_STATUS="$COMPLETION_AUDIT_LOG.ui042-open-ui-fixture-status"
python3 - "$UI042_OPEN_UI_FIXTURE_STATUS" <<'PY'
import json
import sys
from pathlib import Path

status_path = Path(sys.argv[1])
path = Path("dist/app-runtime-evidence.current.json")
rows = json.loads(path.read_text())
for row in rows:
    if row.get("ID") == "UI-042" and "open-ui" in row.get("Evidence", ""):
        row["Evidence"] = row["Evidence"].replace(
            " Additional artifact: dist/app-runtime-artifacts/direct-runtime/open-ui-settings.json",
            "",
        )
        path.write_text(json.dumps(rows, indent=2) + "\n")
        status_path.write_text("mutated\n")
        break
else:
    status_path.write_text("absent\n")
PY
if [[ "$(cat "$UI042_OPEN_UI_FIXTURE_STATUS")" == "mutated" ]]; then
  python3 qa/build_feature_status.py >/dev/null
  if python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.ui042-missing-open-ui-artifact" 2>&1; then
    echo "Expected completion audit to fail when UI-042 open-ui evidence omits the raw settings artifact."
    exit 1
  fi
  grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.ui042-missing-open-ui-artifact" >/dev/null
  grep -F "UI-042 open-ui evidence must cite dist/app-runtime-artifacts/direct-runtime/open-ui-settings.json as an Additional artifact" "$COMPLETION_AUDIT_LOG.ui042-missing-open-ui-artifact" >/dev/null
fi
restore_original_current_review_artifact
SUPPORT_BUNDLE_FIXTURE_STATUS="$COMPLETION_AUDIT_LOG.support-bundle-fixture-status"
python3 - "$SUPPORT_BUNDLE_FIXTURE_STATUS" <<'PY'
import json
import sys
from pathlib import Path

status_path = Path(sys.argv[1])
path = Path("dist/app-runtime-evidence.current.json")
rows = json.loads(path.read_text())
for row in rows:
    evidence = row.get("Evidence", "")
    if (
        ("support-bundle" in evidence or "support bundle" in evidence)
        and "Additional artifact: dist/app-runtime-artifacts/current-ui/support-bundle.json" in evidence
    ):
        row["Evidence"] = evidence.replace(
            " Additional artifact: dist/app-runtime-artifacts/current-ui/support-bundle.json",
            "",
        )
        path.write_text(json.dumps(rows, indent=2) + "\n")
        status_path.write_text("mutated\n")
        break
else:
    status_path.write_text("absent\n")
PY
if [[ "$(cat "$SUPPORT_BUNDLE_FIXTURE_STATUS")" == "mutated" ]]; then
  python3 qa/build_feature_status.py >/dev/null
  if python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.support-bundle-missing-raw-artifact" 2>&1; then
    echo "Expected completion audit to fail when support-bundle evidence omits the raw support bundle artifact."
    exit 1
  fi
  grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.support-bundle-missing-raw-artifact" >/dev/null
  grep -F "support-bundle evidence must cite dist/app-runtime-artifacts/current-ui/support-bundle.json as an Additional artifact" "$COMPLETION_AUDIT_LOG.support-bundle-missing-raw-artifact" >/dev/null
fi
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-evidence.current.json")
path.write_text(json.dumps({"ID": "UI-001"}, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.non-list-current-evidence" 2>&1; then
  echo "Expected completion audit to fail when current runtime evidence is not a JSON list."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.non-list-current-evidence" >/dev/null
grep -F "current runtime review artifact must contain a JSON list: dist/app-runtime-evidence.current.json" "$COMPLETION_AUDIT_LOG.non-list-current-evidence" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-evidence.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime evidence fixture must contain at least one row")
rows[0] = "not an object"
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.non-object-current-evidence-row" 2>&1; then
  echo "Expected completion audit to fail when current runtime evidence contains a non-object row."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.non-object-current-evidence-row" >/dev/null
grep -F "current runtime review artifact contains a non-object row: dist/app-runtime-evidence.current.json" "$COMPLETION_AUDIT_LOG.non-object-current-evidence-row" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-evidence.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime evidence fixture must contain at least one row")
rows.append(dict(rows[0]))
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.duplicate-current-evidence-row" 2>&1; then
  echo "Expected completion audit to fail when current runtime evidence duplicates a row."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.duplicate-current-evidence-row" >/dev/null
grep -F "dist/app-runtime-evidence.current.json: duplicate current runtime rows:" "$COMPLETION_AUDIT_LOG.duplicate-current-evidence-row" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-evidence.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime evidence fixture must contain at least one row")
rows[0]["ID"] = "UI-999"
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.unexpected-current-evidence-row" 2>&1; then
  echo "Expected completion audit to fail when current runtime evidence includes an unexpected row."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.unexpected-current-evidence-row" >/dev/null
grep -F "dist/app-runtime-evidence.current.json: UI-999 is not an expected current runtime row" "$COMPLETION_AUDIT_LOG.unexpected-current-evidence-row" >/dev/null
grep -F "dist/app-runtime-evidence.current.json: unexpected current runtime rows: UI-999" "$COMPLETION_AUDIT_LOG.unexpected-current-evidence-row" >/dev/null
restore_current_review_artifact
if [ "$(python3 qa/app_runtime_rows.py --count)" -gt 1 ]; then
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-evidence.current.json")
rows = json.loads(path.read_text())
if len(rows) < 2:
    raise SystemExit("current app-runtime evidence fixture must contain at least two rows")
rows[0], rows[1] = rows[1], rows[0]
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.out-of-order-current-evidence" 2>&1; then
  echo "Expected completion audit to fail when current runtime evidence rows are out of canonical order."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.out-of-order-current-evidence" >/dev/null
grep -F "dist/app-runtime-evidence.current.json: current runtime rows are not in canonical order" "$COMPLETION_AUDIT_LOG.out-of-order-current-evidence" >/dev/null
restore_current_review_artifact
fi
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-evidence.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime evidence fixture must contain at least one row")
rows[0]["Result"] = "blocked"
rows[0]["Errors"] = ""
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.missing-current-evidence-errors" 2>&1; then
  echo "Expected completion audit to fail when current runtime evidence omits blocked-row errors."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.missing-current-evidence-errors" >/dev/null
grep -F "dist/app-runtime-evidence.current.json: CORE-007 Errors is required when Result is fail or blocked" "$COMPLETION_AUDIT_LOG.missing-current-evidence-errors" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-evidence.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime evidence fixture must contain at least one row")
rows[0]["Evidence"] = rows[0]["Evidence"].replace("Result blocked", "Result pass", 1)
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.mismatched-current-evidence-result-text" 2>&1; then
  echo "Expected completion audit to fail when current runtime evidence text cites a mismatched Result."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.mismatched-current-evidence-result-text" >/dev/null
grep -F "dist/app-runtime-evidence.current.json: CORE-007 Evidence must cite Result blocked" "$COMPLETION_AUDIT_LOG.mismatched-current-evidence-result-text" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
import re
from pathlib import Path

path = Path("dist/app-runtime-evidence.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime evidence fixture must contain at least one row")
evidence = rows[0]["Evidence"]
rows[0]["Evidence"] = re.sub(r"\s+Rerun(?: command)?:\s*\S+(?:\s+\S+)*$", "", evidence, count=1)
if rows[0]["Evidence"] == evidence:
    rows[0]["Evidence"] = evidence.replace(" Rerun: qa/run_signed_app_direct_runtime_checks.sh --skip-notification-probe", "")
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.missing-current-evidence-rerun" 2>&1; then
  echo "Expected completion audit to fail when current blocked runtime evidence omits a rerun command."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.missing-current-evidence-rerun" >/dev/null
grep -F "dist/app-runtime-evidence.current.json: CORE-007 blocked Evidence must include a Rerun command" "$COMPLETION_AUDIT_LOG.missing-current-evidence-rerun" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
import re
from pathlib import Path

path = Path("dist/app-runtime-evidence.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime evidence fixture must contain at least one row")
evidence = rows[0]["Evidence"]
rows[0]["Evidence"] = re.sub(
    r"Rerun(?: command)?:\s*\S+",
    "Rerun: qa/missing-runtime-rerun-command.sh",
    evidence,
    count=1,
)
if rows[0]["Evidence"] == evidence:
    rows[0]["Evidence"] = evidence + " Rerun: qa/missing-runtime-rerun-command.sh"
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.missing-current-evidence-rerun-command" 2>&1; then
  echo "Expected completion audit to fail when current blocked runtime evidence cites a missing rerun command."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.missing-current-evidence-rerun-command" >/dev/null
grep -F "dist/app-runtime-evidence.current.json: CORE-007 Rerun command does not exist: qa/missing-runtime-rerun-command.sh" "$COMPLETION_AUDIT_LOG.missing-current-evidence-rerun-command" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
import re
from pathlib import Path

path = Path("dist/app-runtime-evidence.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime evidence fixture must contain at least one row")
artifact_match = re.search(r"\bArtifact:\s*(\S+)", rows[0]["Evidence"])
if not artifact_match:
    raise SystemExit("current app-runtime evidence fixture must cite an artifact")
artifact_ref = artifact_match.group(1).rstrip(".,;:)")
if artifact_ref not in rows[0]["Errors"]:
    raise SystemExit("current app-runtime Errors fixture must cite the evidence artifact")
rows[0]["Errors"] = rows[0]["Errors"].replace(artifact_ref, "dist/app-runtime-artifacts/direct-runtime/stale-error-artifact.log", 1)
path.write_text(json.dumps(rows, indent=2) + "\n")
tracker_path = Path("dist/app-runtime-tracker-update.current.json")
tracker_rows = json.loads(tracker_path.read_text())
tracker_rows[0]["Errors documented"] = rows[0]["Errors"]
tracker_path.write_text(json.dumps(tracker_rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.missing-current-evidence-errors-artifact" 2>&1; then
  echo "Expected completion audit to fail when current blocked runtime Errors omit the Evidence artifact."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.missing-current-evidence-errors-artifact" >/dev/null
grep -F "dist/app-runtime-evidence.current.json: CORE-007 Errors must mention the Evidence artifact" "$COMPLETION_AUDIT_LOG.missing-current-evidence-errors-artifact" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
import re
from pathlib import Path

path = Path("dist/app-runtime-evidence.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime evidence fixture must contain at least one row")
rerun_match = re.search(r"\bRerun(?: command)?:\s*(\S+)", rows[0]["Evidence"])
if not rerun_match:
    raise SystemExit("current app-runtime evidence fixture must cite a rerun command")
rerun_command = rerun_match.group(1).rstrip(".,;:)").strip("\"'")
if rerun_command not in rows[0]["Errors"]:
    raise SystemExit("current app-runtime Errors fixture must cite the rerun command")
rows[0]["Errors"] = rows[0]["Errors"].replace(rerun_command, "qa/stale-runtime-rerun-command.sh", 1)
path.write_text(json.dumps(rows, indent=2) + "\n")
tracker_path = Path("dist/app-runtime-tracker-update.current.json")
tracker_rows = json.loads(tracker_path.read_text())
tracker_rows[0]["Errors documented"] = rows[0]["Errors"]
tracker_path.write_text(json.dumps(tracker_rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.missing-current-evidence-errors-rerun" 2>&1; then
  echo "Expected completion audit to fail when current blocked runtime Errors omit the Rerun command."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.missing-current-evidence-errors-rerun" >/dev/null
grep -F "dist/app-runtime-evidence.current.json: CORE-007 Errors must mention the Rerun command" "$COMPLETION_AUDIT_LOG.missing-current-evidence-errors-rerun" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-evidence.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime evidence fixture must contain at least one row")
rows[0]["Evidence"] = rows[0]["Evidence"] + " Duplicate wording fixture with with native UI control."
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.duplicated-current-evidence-wording" 2>&1; then
  echo "Expected completion audit to fail when current runtime evidence contains duplicated wording."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.duplicated-current-evidence-wording" >/dev/null
grep -F "dist/app-runtime-evidence.current.json: CORE-007 Evidence contains duplicated wording: 'with with'" "$COMPLETION_AUDIT_LOG.duplicated-current-evidence-wording" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-evidence.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime evidence fixture must contain at least one row")
rows[0]["Evidence"] = "TODO placeholder runtime evidence for CORE-007 CLI symlink installation. Artifact: dist/app-runtime-artifacts/direct-runtime/current-direct-runtime-summary.log"
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.placeholder-current-evidence" 2>&1; then
  echo "Expected completion audit to fail when current runtime evidence uses placeholder text."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.placeholder-current-evidence" >/dev/null
grep -F "dist/app-runtime-evidence.current.json: CORE-007 Evidence must describe real runtime observations, not placeholder text" "$COMPLETION_AUDIT_LOG.placeholder-current-evidence" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-evidence.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime evidence fixture must contain at least one row")
story = rows[0]["User story"]
rows[0]["Evidence"] = rows[0]["Evidence"].replace(f" User story: {story}", "", 1)
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.missing-current-evidence-user-story-text" 2>&1; then
  echo "Expected completion audit to fail when current runtime evidence omits direct User story text."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.missing-current-evidence-user-story-text" >/dev/null
grep -F "dist/app-runtime-evidence.current.json: CORE-007 Evidence must mention the tracker User story" "$COMPLETION_AUDIT_LOG.missing-current-evidence-user-story-text" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-evidence.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime evidence fixture must contain at least one row")
test_instructions = rows[0]["Test instructions"]
rows[0]["Evidence"] = rows[0]["Evidence"].replace(f" Test instructions: {test_instructions}", "", 1)
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.missing-current-evidence-test-instructions-text" 2>&1; then
  echo "Expected completion audit to fail when current runtime evidence omits direct Test instructions text."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.missing-current-evidence-test-instructions-text" >/dev/null
grep -F "dist/app-runtime-evidence.current.json: CORE-007 Evidence must mention the tracker Test instructions" "$COMPLETION_AUDIT_LOG.missing-current-evidence-test-instructions-text" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-evidence.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime evidence fixture must contain at least one row")
row_id = rows[0].get("ID", "unknown")
feature = rows[0].get("Feature", "unknown")
rows[0]["Evidence"] = (
    f"{row_id} {feature}: Result blocked. Artifact: dist/app-runtime-artifacts/missing-current-evidence-artifact.log "
    "Rerun: qa/run_signed_app_direct_runtime_checks.sh --skip-notification-probe"
)
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.missing-current-evidence-artifact" 2>&1; then
  echo "Expected completion audit to fail when current runtime evidence cites a missing artifact."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.missing-current-evidence-artifact" >/dev/null
grep -F "dist/app-runtime-evidence.current.json: CORE-007 Evidence artifact does not exist: dist/app-runtime-artifacts/missing-current-evidence-artifact.log" "$COMPLETION_AUDIT_LOG.missing-current-evidence-artifact" >/dev/null
restore_current_review_artifact
WRONG_CURRENT_EVIDENCE_ARTIFACT="$(mktemp "$TMP_ROOT/bastion_wrong_current_evidence_artifact.XXXXXX")"
printf 'Result blocked. This artifact is intentionally unrelated to the first current runtime evidence row.\n' >"$WRONG_CURRENT_EVIDENCE_ARTIFACT"
WRONG_CURRENT_EVIDENCE_ARTIFACT="$WRONG_CURRENT_EVIDENCE_ARTIFACT" python3 - <<'PY'
import json
import os
from pathlib import Path

path = Path("dist/app-runtime-evidence.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime evidence fixture must contain at least one row")
row_id = rows[0].get("ID", "unknown")
feature = rows[0].get("Feature", "unknown")
rows[0]["Evidence"] = (
    f"{row_id} {feature}: Result blocked. Artifact: {os.environ['WRONG_CURRENT_EVIDENCE_ARTIFACT']} "
    "Rerun: qa/run_signed_app_direct_runtime_checks.sh --skip-notification-probe"
)
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" WRONG_CURRENT_EVIDENCE_ARTIFACT="$WRONG_CURRENT_EVIDENCE_ARTIFACT" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.wrong-current-evidence-artifact" 2>&1; then
  echo "Expected completion audit to fail when current runtime evidence cites an unrelated artifact."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.wrong-current-evidence-artifact" >/dev/null
grep -F "dist/app-runtime-evidence.current.json: CORE-007 Evidence artifact must mention the row ID: $WRONG_CURRENT_EVIDENCE_ARTIFACT" "$COMPLETION_AUDIT_LOG.wrong-current-evidence-artifact" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
import re
from pathlib import Path

path = Path("dist/app-runtime-evidence.current.json")
tracker_path = Path("dist/app-runtime-tracker-update.current.json")
rows = json.loads(path.read_text())
tracker_rows = json.loads(tracker_path.read_text())
if not rows:
    raise SystemExit("current app-runtime evidence fixture must contain at least one row")
evidence = rows[0]["Evidence"]
match = re.search(r"\bArtifact:\s*(\S+)", evidence)
if not match:
    raise SystemExit("current app-runtime evidence fixture must cite an Artifact")
artifact = match.group(1).rstrip(".,;:)")
punctuated_evidence = re.sub(r"\bArtifact:\s*\S+", f"Artifact: {artifact}.", evidence, count=1)
rows[0]["Evidence"] = punctuated_evidence
if not tracker_rows:
    raise SystemExit("current app-runtime tracker-update fixture must contain at least one row")
tracker_rows[0]["Retest status"] = tracker_rows[0]["Retest status"].replace(evidence, punctuated_evidence, 1)
path.write_text(json.dumps(rows, indent=2) + "\n")
tracker_path.write_text(json.dumps(tracker_rows, indent=2) + "\n")
PY
BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/build_feature_status.py >/dev/null
BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.punctuated-current-evidence-artifact" 2>&1
grep -F "Completion audit: not complete" "$COMPLETION_AUDIT_LOG.punctuated-current-evidence-artifact" >/dev/null
restore_current_review_artifact
python3 qa/build_feature_status.py >/dev/null
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-evidence.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime evidence fixture must contain at least one row")
rows[0]["Unexpected fixture key"] = "schema drift"
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.extra-current-evidence-key" 2>&1; then
  echo "Expected completion audit to fail when current runtime evidence has an unexpected key."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.extra-current-evidence-key" >/dev/null
grep -F "dist/app-runtime-evidence.current.json: row 1 has unexpected 'Unexpected fixture key' key" "$COMPLETION_AUDIT_LOG.extra-current-evidence-key" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-tracker-update.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime tracker-update fixture must contain at least one row")
path.write_text(json.dumps(rows[1:], indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.missing-current-tracker-update-row" 2>&1; then
  echo "Expected completion audit to fail when current tracker-update is missing a row."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.missing-current-tracker-update-row" >/dev/null
grep -F "dist/app-runtime-tracker-update.current.json: missing current runtime rows:" "$COMPLETION_AUDIT_LOG.missing-current-tracker-update-row" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-tracker-update.current.json")
path.write_text(json.dumps({"ID": "CORE-007"}, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.non-list-current-tracker-update" 2>&1; then
  echo "Expected completion audit to fail when current tracker-update is not a JSON list."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.non-list-current-tracker-update" >/dev/null
grep -F "current runtime review artifact must contain a JSON list: dist/app-runtime-tracker-update.current.json" "$COMPLETION_AUDIT_LOG.non-list-current-tracker-update" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-tracker-update.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime tracker-update fixture must contain at least one row")
rows[0] = "not an object"
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.non-object-current-tracker-update-row" 2>&1; then
  echo "Expected completion audit to fail when current tracker-update contains a non-object row."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.non-object-current-tracker-update-row" >/dev/null
grep -F "current runtime review artifact contains a non-object row: dist/app-runtime-tracker-update.current.json" "$COMPLETION_AUDIT_LOG.non-object-current-tracker-update-row" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-tracker-update.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime tracker-update fixture must contain at least one row")
rows.append(dict(rows[0]))
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.duplicate-current-tracker-update-row" 2>&1; then
  echo "Expected completion audit to fail when current tracker-update duplicates a row."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.duplicate-current-tracker-update-row" >/dev/null
grep -F "dist/app-runtime-tracker-update.current.json: duplicate current runtime rows:" "$COMPLETION_AUDIT_LOG.duplicate-current-tracker-update-row" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-tracker-update.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime tracker-update fixture must contain at least one row")
rows[0]["ID"] = "UI-999"
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.unexpected-current-tracker-update-row" 2>&1; then
  echo "Expected completion audit to fail when current tracker-update includes an unexpected row."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.unexpected-current-tracker-update-row" >/dev/null
grep -F "dist/app-runtime-tracker-update.current.json: UI-999 is not an expected current runtime row" "$COMPLETION_AUDIT_LOG.unexpected-current-tracker-update-row" >/dev/null
grep -F "dist/app-runtime-tracker-update.current.json: unexpected current runtime rows: UI-999" "$COMPLETION_AUDIT_LOG.unexpected-current-tracker-update-row" >/dev/null
restore_current_review_artifact
if [ "$(python3 qa/app_runtime_rows.py --count)" -gt 1 ]; then
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-tracker-update.current.json")
rows = json.loads(path.read_text())
if len(rows) < 2:
    raise SystemExit("current app-runtime tracker-update fixture must contain at least two rows")
rows[0], rows[1] = rows[1], rows[0]
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.out-of-order-current-tracker-update" 2>&1; then
  echo "Expected completion audit to fail when current tracker-update rows are out of canonical order."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.out-of-order-current-tracker-update" >/dev/null
grep -F "dist/app-runtime-tracker-update.current.json: current runtime rows are not in canonical order" "$COMPLETION_AUDIT_LOG.out-of-order-current-tracker-update" >/dev/null
restore_current_review_artifact
fi
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-tracker-update.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime tracker-update fixture must contain at least one row")
rows[0]["Unexpected fixture key"] = "schema drift"
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.extra-current-tracker-update-key" 2>&1; then
  echo "Expected completion audit to fail when current tracker-update evidence has an unexpected key."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.extra-current-tracker-update-key" >/dev/null
grep -F "dist/app-runtime-tracker-update.current.json: row 1 has unexpected 'Unexpected fixture key' key" "$COMPLETION_AUDIT_LOG.extra-current-tracker-update-key" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-tracker-update.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime tracker-update fixture must contain at least one row")
rows[0]["Errors documented"] = "TODO placeholder runtime state for CORE-007 CLI symlink installation."
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.placeholder-current-tracker-update" 2>&1; then
  echo "Expected completion audit to fail when current tracker-update lifecycle text is placeholder."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.placeholder-current-tracker-update" >/dev/null
grep -F "dist/app-runtime-tracker-update.current.json: CORE-007 Errors documented must describe real runtime state, not placeholder text" "$COMPLETION_AUDIT_LOG.placeholder-current-tracker-update" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-tracker-update.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime tracker-update fixture must contain at least one row")
rows[0]["Fix status"] = "Pending fix from signed-app runtime evidence for CORE-007 CLI symlink installation."
rows[0]["Retest status"] = rows[0]["Retest status"].replace(
    "Blocked pending runtime prerequisite retest for CORE-007 CLI symlink installation.",
    "Pending post-fix runtime retest for CORE-007 CLI symlink installation.",
    1,
)
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.mismatched-current-tracker-update-lifecycle-state" 2>&1; then
  echo "Expected completion audit to fail when blocked current tracker-update lifecycle text describes pending-fix state."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.mismatched-current-tracker-update-lifecycle-state" >/dev/null
grep -F "dist/app-runtime-tracker-update.current.json: CORE-007 Fix status must describe a blocked runtime state" "$COMPLETION_AUDIT_LOG.mismatched-current-tracker-update-lifecycle-state" >/dev/null
grep -F "dist/app-runtime-tracker-update.current.json: CORE-007 Retest status must describe a blocked runtime retest" "$COMPLETION_AUDIT_LOG.mismatched-current-tracker-update-lifecycle-state" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-tracker-update.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime tracker-update fixture must contain at least one row")
rows[0]["Result"] = "blocked"
rows[0]["Test status"] = "Pending"
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.invalid-current-tracker-update-status" 2>&1; then
  echo "Expected completion audit to fail when current tracker-update result/status values are inconsistent."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.invalid-current-tracker-update-status" >/dev/null
grep -F "dist/app-runtime-tracker-update.current.json: CORE-007 Result blocked must have Test status 'Blocked in this environment'" "$COMPLETION_AUDIT_LOG.invalid-current-tracker-update-status" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-tracker-update.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime tracker-update fixture must contain at least one row")
rows[0]["Result"] = "fail"
rows[0]["Test status"] = "Pending"
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.mismatched-current-tracker-update-result" 2>&1; then
  echo "Expected completion audit to fail when current tracker-update Result does not match current runtime evidence Result."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.mismatched-current-tracker-update-result" >/dev/null
grep -F "dist/app-runtime-tracker-update.current.json: CORE-007 Result 'fail' does not match dist/app-runtime-evidence.current.json Result 'blocked'" "$COMPLETION_AUDIT_LOG.mismatched-current-tracker-update-result" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/app-runtime-tracker-update.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime tracker-update fixture must contain at least one row")
rows[0]["Retest status"] = rows[0]["Retest status"].replace("Result blocked", "Result pass", 1)
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.mismatched-current-tracker-update-retest-result" 2>&1; then
  echo "Expected completion audit to fail when current tracker-update Retest status cites a mismatched Result."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.mismatched-current-tracker-update-retest-result" >/dev/null
grep -F "dist/app-runtime-tracker-update.current.json: CORE-007 Retest status must cite Result blocked" "$COMPLETION_AUDIT_LOG.mismatched-current-tracker-update-retest-result" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

evidence_path = Path("dist/app-runtime-evidence.current.json")
path = Path("dist/app-runtime-tracker-update.current.json")
evidence_rows = json.loads(evidence_path.read_text())
rows = json.loads(path.read_text())
if not evidence_rows or not rows:
    raise SystemExit("current app-runtime review fixtures must contain at least one row")
evidence_text = evidence_rows[0]["Evidence"]
if evidence_text not in rows[0]["Retest status"]:
    raise SystemExit("current app-runtime tracker-update fixture must carry paired Evidence text")
rows[0]["Retest status"] = rows[0]["Retest status"].replace(
    evidence_text,
    evidence_text.replace("Observed signed app runtime sweep", "Observed signed app runtime review sweep", 1),
    1,
)
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.mismatched-current-tracker-update-evidence-text" 2>&1; then
  echo "Expected completion audit to fail when current tracker-update Retest status does not include paired runtime Evidence text."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.mismatched-current-tracker-update-evidence-text" >/dev/null
grep -F "dist/app-runtime-tracker-update.current.json: CORE-007 Retest status must include dist/app-runtime-evidence.current.json Evidence text" "$COMPLETION_AUDIT_LOG.mismatched-current-tracker-update-evidence-text" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

evidence_path = Path("dist/app-runtime-evidence.current.json")
tracker_path = Path("dist/app-runtime-tracker-update.current.json")
evidence_rows = json.loads(evidence_path.read_text())
tracker_rows = json.loads(tracker_path.read_text())
if not evidence_rows or not tracker_rows:
    raise SystemExit("current app-runtime review fixtures must contain at least one row")
errors = evidence_rows[0]["Errors"]
if not errors or errors not in tracker_rows[0]["Errors documented"]:
    raise SystemExit("current app-runtime tracker-update fixture must carry paired Errors text")
tracker_rows[0]["Errors documented"] = (
    f"Current tracker update for {tracker_rows[0]['ID']} {tracker_rows[0]['Feature']} "
    "kept the row context but lost the paired runtime error details."
)
tracker_path.write_text(json.dumps(tracker_rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.mismatched-current-tracker-update-errors-text" 2>&1; then
  echo "Expected completion audit to fail when current tracker-update Errors documented does not include paired runtime Errors text."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.mismatched-current-tracker-update-errors-text" >/dev/null
grep -F "dist/app-runtime-tracker-update.current.json: CORE-007 Errors documented must include dist/app-runtime-evidence.current.json Errors text" "$COMPLETION_AUDIT_LOG.mismatched-current-tracker-update-errors-text" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
import re
from pathlib import Path

path = Path("dist/app-runtime-tracker-update.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime tracker-update fixture must contain at least one row")
rows[0]["Retest status"] = re.sub(
    r"\bRerun(?: command)?:\s*\S+",
    "Rerun: qa/missing-runtime-rerun-command.sh",
    rows[0]["Retest status"],
    1,
)
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.missing-current-tracker-update-rerun-command" 2>&1; then
  echo "Expected completion audit to fail when current tracker-update Retest status cites a missing Rerun command."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.missing-current-tracker-update-rerun-command" >/dev/null
grep -F "dist/app-runtime-tracker-update.current.json: CORE-007 Rerun command does not exist: qa/missing-runtime-rerun-command.sh" "$COMPLETION_AUDIT_LOG.missing-current-tracker-update-rerun-command" >/dev/null
restore_current_review_artifact
MISMATCH_CURRENT_TRACKER_UPDATE_ARTIFACT="$(mktemp "$TMP_ROOT/bastion_mismatch_current_tracker_update_artifact.XXXXXX")"
MISMATCH_CURRENT_TRACKER_UPDATE_ARTIFACT="$MISMATCH_CURRENT_TRACKER_UPDATE_ARTIFACT" python3 - <<'PY'
import json
import os
from pathlib import Path

path = Path("dist/app-runtime-tracker-update.current.json")
evidence_path = Path("dist/app-runtime-evidence.current.json")
rows = json.loads(path.read_text())
evidence_rows = json.loads(evidence_path.read_text())
if not rows or not evidence_rows:
    raise SystemExit("current app-runtime tracker-update fixture must contain at least one row")
row = rows[0]
evidence_row = evidence_rows[0]
artifact = Path(os.environ["MISMATCH_CURRENT_TRACKER_UPDATE_ARTIFACT"])
artifact.write_text(
    f"{evidence_row['ID']} {evidence_row['Feature']}: "
    f"User story: {evidence_row['User story']} "
    f"Expected behaviour: {evidence_row['Expected behaviour']} "
    f"Test instructions: {evidence_row['Test instructions']} "
    "Observed valid but intentionally mismatched tracker-update artifact.\n"
)
row_id = row.get("ID", "unknown")
feature = row.get("Feature", "unknown")
rows[0]["Retest status"] = (
    f"Blocked pending runtime prerequisite retest for {row_id} {feature}. "
    f"Evidence: {row_id} {feature}: Result blocked. User story: {evidence_row['User story']} Expected behaviour: {evidence_row['Expected behaviour']} Test instructions: {evidence_row['Test instructions']} Artifact: {artifact} "
    "Rerun: qa/run_signed_app_direct_runtime_checks.sh --skip-notification-probe"
)
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" MISMATCH_CURRENT_TRACKER_UPDATE_ARTIFACT="$MISMATCH_CURRENT_TRACKER_UPDATE_ARTIFACT" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.mismatched-current-tracker-update-artifact" 2>&1; then
  echo "Expected completion audit to fail when current tracker-update Retest artifact does not match current runtime evidence artifact."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.mismatched-current-tracker-update-artifact" >/dev/null
grep -F "dist/app-runtime-tracker-update.current.json: CORE-007 Retest artifact $MISMATCH_CURRENT_TRACKER_UPDATE_ARTIFACT does not match dist/app-runtime-evidence.current.json Evidence artifact" "$COMPLETION_AUDIT_LOG.mismatched-current-tracker-update-artifact" >/dev/null
restore_current_review_artifact
WRONG_CURRENT_TRACKER_UPDATE_ARTIFACT="$(mktemp "$TMP_ROOT/bastion_wrong_current_tracker_update_artifact.XXXXXX")"
printf 'Result blocked. This artifact is intentionally unrelated to the first current tracker-update row.\n' >"$WRONG_CURRENT_TRACKER_UPDATE_ARTIFACT"
WRONG_CURRENT_TRACKER_UPDATE_ARTIFACT="$WRONG_CURRENT_TRACKER_UPDATE_ARTIFACT" python3 - <<'PY'
import json
import os
from pathlib import Path

path = Path("dist/app-runtime-tracker-update.current.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current app-runtime tracker-update fixture must contain at least one row")
row_id = rows[0].get("ID", "unknown")
feature = rows[0].get("Feature", "unknown")
rows[0]["Retest status"] = (
    f"Blocked pending runtime prerequisite retest for {row_id} {feature}. "
    f"Evidence: {row_id} {feature}: Result blocked. Artifact: {os.environ['WRONG_CURRENT_TRACKER_UPDATE_ARTIFACT']} "
    "Rerun: qa/run_signed_app_direct_runtime_checks.sh --skip-notification-probe"
)
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" WRONG_CURRENT_TRACKER_UPDATE_ARTIFACT="$WRONG_CURRENT_TRACKER_UPDATE_ARTIFACT" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.wrong-current-tracker-update-artifact" 2>&1; then
  echo "Expected completion audit to fail when current tracker-update retest cites an unrelated artifact."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.wrong-current-tracker-update-artifact" >/dev/null
grep -F "dist/app-runtime-tracker-update.current.json: CORE-007 Retest artifact must mention the row ID: $WRONG_CURRENT_TRACKER_UPDATE_ARTIFACT" "$COMPLETION_AUDIT_LOG.wrong-current-tracker-update-artifact" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
import re
from pathlib import Path

path = Path("dist/app-runtime-tracker-update.current.json")
evidence_path = Path("dist/app-runtime-evidence.current.json")
rows = json.loads(path.read_text())
evidence_rows = json.loads(evidence_path.read_text())
if not rows:
    raise SystemExit("current app-runtime tracker-update fixture must contain at least one row")
if not evidence_rows:
    raise SystemExit("current app-runtime evidence fixture must contain at least one row")
retest_status = rows[0]["Retest status"]
match = re.search(r"\bArtifact:\s*(\S+)", retest_status)
if not match:
    raise SystemExit("current app-runtime tracker-update fixture must cite an Artifact")
artifact = match.group(1).rstrip(".,;:)")
rows[0]["Retest status"] = re.sub(r"\bArtifact:\s*\S+", f"Artifact: {artifact}.", retest_status, count=1)
evidence_rows[0]["Evidence"] = re.sub(
    r"\bArtifact:\s*\S+",
    f"Artifact: {artifact}.",
    evidence_rows[0]["Evidence"],
    count=1,
)
path.write_text(json.dumps(rows, indent=2) + "\n")
evidence_path.write_text(json.dumps(evidence_rows, indent=2) + "\n")
PY
BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/build_feature_status.py >/dev/null
BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.punctuated-current-tracker-update-artifact" 2>&1
grep -F "Completion audit: not complete" "$COMPLETION_AUDIT_LOG.punctuated-current-tracker-update-artifact" >/dev/null
restore_current_review_artifact
fi
python3 qa/build_feature_status.py >/dev/null
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-evidence.current-blocked.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current live-runtime evidence fixture must contain at least one row")
rows[0]["Result"] = "pass"
rows[0]["Evidence"] = f"{rows[0].get('ID', 'unknown')} live evidence missing its result marker."
rows[0]["Errors"] = ""
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.stale-current-live-evidence" 2>&1; then
  echo "Expected completion audit to fail when current live-runtime evidence omits required pass wording."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.stale-current-live-evidence" >/dev/null
grep -F "dist/live-runtime-evidence.current-blocked.json" "$COMPLETION_AUDIT_LOG.stale-current-live-evidence" >/dev/null
grep -F "Evidence must cite Result pass" "$COMPLETION_AUDIT_LOG.stale-current-live-evidence" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-evidence.current-blocked.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current live-runtime evidence fixture must contain at least one row")
path.write_text(json.dumps(rows[1:], indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.missing-current-live-evidence-row" 2>&1; then
  echo "Expected completion audit to fail when current live-runtime evidence is missing a row."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.missing-current-live-evidence-row" >/dev/null
grep -F "dist/live-runtime-evidence.current-blocked.json: missing current runtime rows:" "$COMPLETION_AUDIT_LOG.missing-current-live-evidence-row" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-evidence.current-blocked.json")
path.write_text(json.dumps({"ID": "CORE-003"}, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.non-list-current-live-evidence" 2>&1; then
  echo "Expected completion audit to fail when current live-runtime evidence is not a JSON list."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.non-list-current-live-evidence" >/dev/null
grep -F "current runtime review artifact must contain a JSON list: dist/live-runtime-evidence.current-blocked.json" "$COMPLETION_AUDIT_LOG.non-list-current-live-evidence" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-evidence.current-blocked.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current live-runtime evidence fixture must contain at least one row")
rows[0] = "not an object"
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.non-object-current-live-evidence-row" 2>&1; then
  echo "Expected completion audit to fail when current live-runtime evidence contains a non-object row."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.non-object-current-live-evidence-row" >/dev/null
grep -F "current runtime review artifact contains a non-object row: dist/live-runtime-evidence.current-blocked.json" "$COMPLETION_AUDIT_LOG.non-object-current-live-evidence-row" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-evidence.current-blocked.json")
rows = json.loads(path.read_text())
if len(rows) < 2:
    raise SystemExit("current live-runtime evidence fixture must contain at least two rows")
rows[1] = dict(rows[0])
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.duplicate-current-live-evidence-row" 2>&1; then
  echo "Expected completion audit to fail when current live-runtime evidence duplicates a row."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.duplicate-current-live-evidence-row" >/dev/null
grep -F "dist/live-runtime-evidence.current-blocked.json: duplicate current runtime rows:" "$COMPLETION_AUDIT_LOG.duplicate-current-live-evidence-row" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-evidence.current-blocked.json")
rows = json.loads(path.read_text())
if len(rows) < 2:
    raise SystemExit("current live-runtime evidence fixture must contain at least two rows")
rows[0]["ID"] = "CORE-999"
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.unexpected-current-live-evidence-row" 2>&1; then
  echo "Expected completion audit to fail when current live-runtime evidence includes an unexpected row."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.unexpected-current-live-evidence-row" >/dev/null
grep -F "dist/live-runtime-evidence.current-blocked.json: CORE-999 is not an expected current runtime row" "$COMPLETION_AUDIT_LOG.unexpected-current-live-evidence-row" >/dev/null
grep -F "dist/live-runtime-evidence.current-blocked.json: unexpected current runtime rows: CORE-999" "$COMPLETION_AUDIT_LOG.unexpected-current-live-evidence-row" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-evidence.current-blocked.json")
rows = json.loads(path.read_text())
if len(rows) < 2:
    raise SystemExit("current live-runtime evidence fixture must contain at least two rows")
rows[0], rows[1] = rows[1], rows[0]
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.out-of-order-current-live-evidence" 2>&1; then
  echo "Expected completion audit to fail when current live-runtime evidence rows are out of canonical order."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.out-of-order-current-live-evidence" >/dev/null
grep -F "dist/live-runtime-evidence.current-blocked.json: current runtime rows are not in canonical order" "$COMPLETION_AUDIT_LOG.out-of-order-current-live-evidence" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-evidence.current-blocked.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current live-runtime evidence fixture must contain at least one row")
rows[0]["Evidence"] = rows[0]["Evidence"].replace("Result pass", "Result fail", 1)
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.mismatched-current-live-evidence-result-text" 2>&1; then
  echo "Expected completion audit to fail when current live-runtime evidence text cites a mismatched Result."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.mismatched-current-live-evidence-result-text" >/dev/null
grep -F "dist/live-runtime-evidence.current-blocked.json: CORE-003 Evidence must cite Result pass" "$COMPLETION_AUDIT_LOG.mismatched-current-live-evidence-result-text" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-evidence.current-blocked.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current live-runtime evidence fixture must contain at least one row")
rows[0]["Unexpected fixture key"] = "schema drift"
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.extra-current-live-evidence-key" 2>&1; then
  echo "Expected completion audit to fail when current live-runtime evidence has an unexpected key."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.extra-current-live-evidence-key" >/dev/null
grep -F "dist/live-runtime-evidence.current-blocked.json: row 1 has unexpected 'Unexpected fixture key' key" "$COMPLETION_AUDIT_LOG.extra-current-live-evidence-key" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-evidence.current-blocked.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current live-runtime evidence fixture must contain at least one row")
rows[0]["Errors"] = "CORE-003 Secure Enclave signing and auth flow: stale pass-row error text."
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.missing-current-live-evidence-errors-artifact" 2>&1; then
  echo "Expected completion audit to fail when pass current live-runtime evidence has non-empty Errors."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.missing-current-live-evidence-errors-artifact" >/dev/null
grep -F "dist/live-runtime-evidence.current-blocked.json: CORE-003 Errors must be empty when Result is pass" "$COMPLETION_AUDIT_LOG.missing-current-live-evidence-errors-artifact" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

tracker_path = Path("dist/live-runtime-tracker-update.current-blocked.json")
tracker_rows = json.loads(tracker_path.read_text())
if not tracker_rows:
    raise SystemExit("current live-runtime tracker-update fixture must contain at least one row")
tracker_rows[0]["Errors documented"] = "todo"
tracker_path.write_text(json.dumps(tracker_rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.missing-current-live-evidence-errors-rerun" 2>&1; then
  echo "Expected completion audit to fail when live-runtime tracker Errors documented uses placeholder text."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.missing-current-live-evidence-errors-rerun" >/dev/null
grep -F "dist/live-runtime-tracker-update.current-blocked.json: CORE-003 Errors documented must describe real runtime state, not placeholder text" "$COMPLETION_AUDIT_LOG.missing-current-live-evidence-errors-rerun" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-evidence.current-blocked.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current live-runtime evidence fixture must contain at least one row")
rows[0]["Evidence"] = "TODO placeholder live-runtime evidence for CORE-003 Secure Enclave signing and auth flow. Artifact: dist/live-runtime-artifacts/live-runtime-current-blockers.log"
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.placeholder-current-live-evidence" 2>&1; then
  echo "Expected completion audit to fail when current live-runtime evidence uses placeholder text."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.placeholder-current-live-evidence" >/dev/null
grep -F "dist/live-runtime-evidence.current-blocked.json: CORE-003 Evidence must describe real runtime observations, not placeholder text" "$COMPLETION_AUDIT_LOG.placeholder-current-live-evidence" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-evidence.current-blocked.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current live-runtime evidence fixture must contain at least one row")
expected = rows[0]["Expected behaviour"]
rows[0]["Evidence"] = rows[0]["Evidence"].replace(f" Expected behaviour: {expected}", "", 1)
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.missing-current-live-evidence-expected-text" 2>&1; then
  echo "Expected completion audit to fail when current live-runtime evidence omits direct Expected behaviour text."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.missing-current-live-evidence-expected-text" >/dev/null
grep -F "dist/live-runtime-evidence.current-blocked.json: CORE-003 Evidence must mention the tracker Expected behaviour" "$COMPLETION_AUDIT_LOG.missing-current-live-evidence-expected-text" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-evidence.current-blocked.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current live-runtime evidence fixture must contain at least one row")
test_instructions = rows[0]["Test instructions"]
rows[0]["Evidence"] = rows[0]["Evidence"].replace(f" Test instructions: {test_instructions}", "", 1)
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.missing-current-live-evidence-test-instructions-text" 2>&1; then
  echo "Expected completion audit to fail when current live-runtime evidence omits direct Test instructions text."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.missing-current-live-evidence-test-instructions-text" >/dev/null
grep -F "dist/live-runtime-evidence.current-blocked.json: CORE-003 Evidence must mention the tracker Test instructions" "$COMPLETION_AUDIT_LOG.missing-current-live-evidence-test-instructions-text" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-tracker-update.current-blocked.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current live-runtime tracker-update fixture must contain at least one row")
path.write_text(json.dumps(rows[1:], indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.missing-current-live-tracker-update-row" 2>&1; then
  echo "Expected completion audit to fail when current live-runtime tracker-update is missing a row."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.missing-current-live-tracker-update-row" >/dev/null
grep -F "dist/live-runtime-tracker-update.current-blocked.json: missing current runtime rows:" "$COMPLETION_AUDIT_LOG.missing-current-live-tracker-update-row" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-tracker-update.current-blocked.json")
path.write_text(json.dumps({"ID": "CORE-003"}, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.non-list-current-live-tracker-update" 2>&1; then
  echo "Expected completion audit to fail when current live-runtime tracker-update is not a JSON list."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.non-list-current-live-tracker-update" >/dev/null
grep -F "current runtime review artifact must contain a JSON list: dist/live-runtime-tracker-update.current-blocked.json" "$COMPLETION_AUDIT_LOG.non-list-current-live-tracker-update" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-tracker-update.current-blocked.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current live-runtime tracker-update fixture must contain at least one row")
rows[0] = "not an object"
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.non-object-current-live-tracker-update-row" 2>&1; then
  echo "Expected completion audit to fail when current live-runtime tracker-update contains a non-object row."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.non-object-current-live-tracker-update-row" >/dev/null
grep -F "current runtime review artifact contains a non-object row: dist/live-runtime-tracker-update.current-blocked.json" "$COMPLETION_AUDIT_LOG.non-object-current-live-tracker-update-row" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-tracker-update.current-blocked.json")
rows = json.loads(path.read_text())
if len(rows) < 2:
    raise SystemExit("current live-runtime tracker-update fixture must contain at least two rows")
rows[1] = dict(rows[0])
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.duplicate-current-live-tracker-update-row" 2>&1; then
  echo "Expected completion audit to fail when current live-runtime tracker-update duplicates a row."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.duplicate-current-live-tracker-update-row" >/dev/null
grep -F "dist/live-runtime-tracker-update.current-blocked.json: duplicate current runtime rows:" "$COMPLETION_AUDIT_LOG.duplicate-current-live-tracker-update-row" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-tracker-update.current-blocked.json")
rows = json.loads(path.read_text())
if len(rows) < 2:
    raise SystemExit("current live-runtime tracker-update fixture must contain at least two rows")
rows[0]["ID"] = "CORE-999"
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.unexpected-current-live-tracker-update-row" 2>&1; then
  echo "Expected completion audit to fail when current live-runtime tracker-update includes an unexpected row."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.unexpected-current-live-tracker-update-row" >/dev/null
grep -F "dist/live-runtime-tracker-update.current-blocked.json: CORE-999 is not an expected current runtime row" "$COMPLETION_AUDIT_LOG.unexpected-current-live-tracker-update-row" >/dev/null
grep -F "dist/live-runtime-tracker-update.current-blocked.json: unexpected current runtime rows: CORE-999" "$COMPLETION_AUDIT_LOG.unexpected-current-live-tracker-update-row" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-tracker-update.current-blocked.json")
rows = json.loads(path.read_text())
if len(rows) < 2:
    raise SystemExit("current live-runtime tracker-update fixture must contain at least two rows")
rows[0], rows[1] = rows[1], rows[0]
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.out-of-order-current-live-tracker-update" 2>&1; then
  echo "Expected completion audit to fail when current live-runtime tracker-update rows are out of canonical order."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.out-of-order-current-live-tracker-update" >/dev/null
grep -F "dist/live-runtime-tracker-update.current-blocked.json: current runtime rows are not in canonical order" "$COMPLETION_AUDIT_LOG.out-of-order-current-live-tracker-update" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-tracker-update.current-blocked.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current live-runtime tracker-update fixture must contain at least one row")
rows[0]["Result"] = "fail"
rows[0]["Test status"] = "Pending"
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.mismatched-current-live-tracker-update-result" 2>&1; then
  echo "Expected completion audit to fail when current live-runtime tracker-update Result does not match current live-runtime evidence Result."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.mismatched-current-live-tracker-update-result" >/dev/null
grep -F "dist/live-runtime-tracker-update.current-blocked.json: CORE-003 Result 'fail' does not match dist/live-runtime-evidence.current-blocked.json Result 'pass'" "$COMPLETION_AUDIT_LOG.mismatched-current-live-tracker-update-result" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-tracker-update.current-blocked.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current live-runtime tracker-update fixture must contain at least one row")
rows[0]["Retest status"] = rows[0]["Retest status"].replace("Result pass", "Result fail", 1)
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.mismatched-current-live-tracker-update-retest-result" 2>&1; then
  echo "Expected completion audit to fail when current live-runtime tracker-update Retest status cites a mismatched Result."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.mismatched-current-live-tracker-update-retest-result" >/dev/null
grep -F "dist/live-runtime-tracker-update.current-blocked.json: CORE-003 Retest status must cite Result pass" "$COMPLETION_AUDIT_LOG.mismatched-current-live-tracker-update-retest-result" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

evidence_path = Path("dist/live-runtime-evidence.current-blocked.json")
path = Path("dist/live-runtime-tracker-update.current-blocked.json")
evidence_rows = json.loads(evidence_path.read_text())
rows = json.loads(path.read_text())
if not evidence_rows or not rows:
    raise SystemExit("current live-runtime review fixtures must contain at least one row")
evidence_text = evidence_rows[0]["Evidence"]
if evidence_text not in rows[0]["Retest status"]:
    raise SystemExit("current live-runtime tracker-update fixture must carry paired Evidence text")
rows[0]["Retest status"] = rows[0]["Retest status"].replace(
    evidence_text,
    evidence_text.replace("Artifact:", "Changed artifact:", 1),
    1,
)
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.mismatched-current-live-tracker-update-evidence-text" 2>&1; then
  echo "Expected completion audit to fail when current live-runtime tracker-update Retest status does not include paired runtime Evidence text."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.mismatched-current-live-tracker-update-evidence-text" >/dev/null
grep -F "dist/live-runtime-tracker-update.current-blocked.json: CORE-003 Retest status must include dist/live-runtime-evidence.current-blocked.json Evidence text" "$COMPLETION_AUDIT_LOG.mismatched-current-live-tracker-update-evidence-text" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

evidence_path = Path("dist/live-runtime-evidence.current-blocked.json")
tracker_path = Path("dist/live-runtime-tracker-update.current-blocked.json")
evidence_rows = json.loads(evidence_path.read_text())
tracker_rows = json.loads(tracker_path.read_text())
if not evidence_rows or not tracker_rows:
    raise SystemExit("current live-runtime review fixtures must contain at least one row")
tracker_rows[0]["Errors documented"] = "Signed-app live-runtime evidence closed the prior runtime proof gap."
tracker_path.write_text(json.dumps(tracker_rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.mismatched-current-live-tracker-update-errors-text" 2>&1; then
  echo "Expected completion audit to fail when current live-runtime tracker-update Errors documented loses row context."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.mismatched-current-live-tracker-update-errors-text" >/dev/null
grep -F "dist/live-runtime-tracker-update.current-blocked.json: CORE-003 Errors documented must mention the row ID" "$COMPLETION_AUDIT_LOG.mismatched-current-live-tracker-update-errors-text" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-tracker-update.current-blocked.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current live-runtime tracker-update fixture must contain at least one row")
rows[0]["Retest status"] = rows[0]["Retest status"].replace(
    "Artifact: dist/live-runtime-artifacts/live-runtime-row-pass-review.log",
    "Artifact: qa/missing-live-runtime-rerun-command.sh",
    1,
)
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.missing-current-live-tracker-update-rerun-command" 2>&1; then
  echo "Expected completion audit to fail when current live-runtime tracker-update Retest status cites a missing artifact."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.missing-current-live-tracker-update-rerun-command" >/dev/null
grep -F "dist/live-runtime-tracker-update.current-blocked.json: CORE-003 Retest artifact does not exist: qa/missing-live-runtime-rerun-command.sh" "$COMPLETION_AUDIT_LOG.missing-current-live-tracker-update-rerun-command" >/dev/null
restore_current_review_artifact
MISMATCH_CURRENT_LIVE_TRACKER_UPDATE_ARTIFACT="$(mktemp "$TMP_ROOT/bastion_mismatch_current_live_tracker_update_artifact.XXXXXX")"
MISMATCH_CURRENT_LIVE_TRACKER_UPDATE_ARTIFACT="$MISMATCH_CURRENT_LIVE_TRACKER_UPDATE_ARTIFACT" python3 - <<'PY'
import json
import os
from pathlib import Path

path = Path("dist/live-runtime-tracker-update.current-blocked.json")
evidence_path = Path("dist/live-runtime-evidence.current-blocked.json")
rows = json.loads(path.read_text())
evidence_rows = json.loads(evidence_path.read_text())
if not rows or not evidence_rows:
    raise SystemExit("current live-runtime tracker-update fixture must contain at least one row")
row = rows[0]
evidence_row = evidence_rows[0]
artifact = Path(os.environ["MISMATCH_CURRENT_LIVE_TRACKER_UPDATE_ARTIFACT"])
artifact.write_text(
    f"{evidence_row['ID']} {evidence_row['Feature']}: "
    f"User story: {evidence_row['User story']} "
    f"Expected behaviour: {evidence_row['Expected behaviour']} "
    f"Test instructions: {evidence_row['Test instructions']} "
    "Observed valid but intentionally mismatched live tracker-update artifact.\n"
)
row_id = row.get("ID", "unknown")
feature = row.get("Feature", "unknown")
rows[0]["Retest status"] = (
    f"Blocked pending current-source signed-app live-runtime retest for {row_id} {feature}. "
    f"Evidence: {row_id} {feature}: Result blocked. User story: {evidence_row['User story']} Expected behaviour: {evidence_row['Expected behaviour']} Test instructions: {evidence_row['Test instructions']} Artifact: {artifact}"
)
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" MISMATCH_CURRENT_LIVE_TRACKER_UPDATE_ARTIFACT="$MISMATCH_CURRENT_LIVE_TRACKER_UPDATE_ARTIFACT" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.mismatched-current-live-tracker-update-artifact" 2>&1; then
  echo "Expected completion audit to fail when current live-runtime tracker-update Retest artifact does not match current live-runtime evidence artifact."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.mismatched-current-live-tracker-update-artifact" >/dev/null
grep -F "dist/live-runtime-tracker-update.current-blocked.json: CORE-003 Retest artifact $MISMATCH_CURRENT_LIVE_TRACKER_UPDATE_ARTIFACT does not match dist/live-runtime-evidence.current-blocked.json Evidence artifact" "$COMPLETION_AUDIT_LOG.mismatched-current-live-tracker-update-artifact" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-tracker-update.current-blocked.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current live-runtime tracker-update fixture must contain at least one row")
rows[0]["Unexpected fixture key"] = "schema drift"
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.extra-current-live-tracker-update-key" 2>&1; then
  echo "Expected completion audit to fail when current live-runtime tracker-update evidence has an unexpected key."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.extra-current-live-tracker-update-key" >/dev/null
grep -F "dist/live-runtime-tracker-update.current-blocked.json: row 1 has unexpected 'Unexpected fixture key' key" "$COMPLETION_AUDIT_LOG.extra-current-live-tracker-update-key" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-tracker-update.current-blocked.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current live-runtime tracker-update fixture must contain at least one row")
rows[0]["Fix status"] = "TODO placeholder live-runtime state for CORE-003 Secure Enclave signing and auth flow."
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.placeholder-current-live-tracker-update" 2>&1; then
  echo "Expected completion audit to fail when current live-runtime tracker-update lifecycle text is placeholder."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.placeholder-current-live-tracker-update" >/dev/null
grep -F "dist/live-runtime-tracker-update.current-blocked.json: CORE-003 Fix status must describe real runtime state, not placeholder text" "$COMPLETION_AUDIT_LOG.placeholder-current-live-tracker-update" >/dev/null
restore_current_review_artifact
python3 - <<'PY'
import json
from pathlib import Path

path = Path("dist/live-runtime-tracker-update.current-blocked.json")
rows = json.loads(path.read_text())
if not rows:
    raise SystemExit("current live-runtime tracker-update fixture must contain at least one row")
rows[0]["Fix status"] = "Fixed after signed-app live-runtime pass."
path.write_text(json.dumps(rows, indent=2) + "\n")
PY
if BASTION_APP_PATH="${COMPLETION_AUDIT_LOG}.missing-app" python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.mismatched-current-live-tracker-update-lifecycle-state" 2>&1; then
  echo "Expected completion audit to fail when pass current live-runtime tracker-update Fix status loses row context."
  exit 1
fi
grep -F "Completion audit: invalid" "$COMPLETION_AUDIT_LOG.mismatched-current-live-tracker-update-lifecycle-state" >/dev/null
grep -F "dist/live-runtime-tracker-update.current-blocked.json: CORE-003 Fix status must mention the row ID" "$COMPLETION_AUDIT_LOG.mismatched-current-live-tracker-update-lifecycle-state" >/dev/null
restore_current_review_artifact
LIVE_REFRESH_SMOKE_DIR="$(mktemp -d "$TMP_ROOT/bastion_live_refresh_smoke.XXXXXX")"
python3 qa/refresh_live_runtime_current_blockers.py \
  --blocker-log "$LIVE_REFRESH_SMOKE_DIR/live-runtime-current-blockers.log" \
  --evidence-json "$LIVE_REFRESH_SMOKE_DIR/live-runtime-evidence.current-blocked.json" \
  >"$LIVE_REFRESH_SMOKE_DIR/refresh.log"
grep -F "Wrote" "$LIVE_REFRESH_SMOKE_DIR/refresh.log" >/dev/null
grep -F "== Latest notification-click diagnostic ==" "$LIVE_REFRESH_SMOKE_DIR/live-runtime-current-blockers.log" >/dev/null
grep -F "Latest notification diagnostic:" "$LIVE_REFRESH_SMOKE_DIR/live-runtime-evidence.current-blocked.json" >/dev/null
qa/run_live_runtime_checks.sh --audit-row-evidence "$LIVE_REFRESH_SMOKE_DIR/live-runtime-evidence.current-blocked.json" >"$LIVE_REFRESH_SMOKE_DIR/audit.log"
grep -F "Live-runtime row evidence audit passed for" "$LIVE_REFRESH_SMOKE_DIR/audit.log" >/dev/null
restore_original_current_review_artifact
trap cleanup_run_lock EXIT
if python3 qa/audit_goal_completion.py --workbook "${COMPLETION_AUDIT_LOG}.missing.xlsx" >"$COMPLETION_AUDIT_LOG.missing-workbook" 2>&1; then
  echo "Expected completion audit to fail when the canonical workbook is missing."
  exit 1
fi
grep -F "canonical workbook missing:" "$COMPLETION_AUDIT_LOG.missing-workbook" >/dev/null
STALE_WORKBOOK="${COMPLETION_AUDIT_LOG}.stale.xlsx"
python3 - "$STALE_WORKBOOK" <<'PY'
import sys
import zipfile
from pathlib import Path

source = Path("qa/feature_status.xlsx")
target = Path(sys.argv[1])
with zipfile.ZipFile(source) as in_workbook, zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as out_workbook:
    for item in in_workbook.infolist():
        data = in_workbook.read(item.filename)
        if item.filename == "xl/worksheets/sheet1.xml":
            text = data.decode()
            text = text.replace("<t>API-001</t>", "<t>STALE-001</t>", 1)
            if "STALE-001" not in text:
                raise SystemExit("stale workbook fixture did not mutate Feature Status")
            data = text.encode()
        out_workbook.writestr(item, data)
PY
if python3 qa/audit_goal_completion.py --workbook "$STALE_WORKBOOK" >"$COMPLETION_AUDIT_LOG.stale-workbook" 2>&1; then
  echo "Expected completion audit to fail when the canonical workbook content is stale."
  exit 1
fi
grep -F "Feature Status worksheet does not match canonical source rows" "$COMPLETION_AUDIT_LOG.stale-workbook" >/dev/null
STALE_SUMMARY_WORKBOOK="${COMPLETION_AUDIT_LOG}.stale-summary.xlsx"
python3 - "$STALE_SUMMARY_WORKBOOK" <<'PY'
import sys
import zipfile
from pathlib import Path

source = Path("qa/feature_status.xlsx")
target = Path(sys.argv[1])
with zipfile.ZipFile(source) as in_workbook, zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as out_workbook:
    for item in in_workbook.infolist():
        data = in_workbook.read(item.filename)
        if item.filename == "xl/worksheets/sheet2.xml":
            text = data.decode()
            text = text.replace("<t>Total tracker rows</t>", "<t>Stale tracker rows</t>", 1)
            if "Stale tracker rows" not in text:
                raise SystemExit("stale Summary fixture did not mutate sheet2")
            data = text.encode()
        out_workbook.writestr(item, data)
PY
if python3 qa/audit_goal_completion.py --workbook "$STALE_SUMMARY_WORKBOOK" >"$COMPLETION_AUDIT_LOG.stale-summary-workbook" 2>&1; then
  echo "Expected completion audit to fail when the Summary worksheet content is stale."
  exit 1
fi
grep -F "Summary worksheet does not match canonical summary rows" "$COMPLETION_AUDIT_LOG.stale-summary-workbook" >/dev/null
STALE_APP_RUNTIME_WORKBOOK="${COMPLETION_AUDIT_LOG}.stale-app-runtime.xlsx"
python3 - "$STALE_APP_RUNTIME_WORKBOOK" <<'PY'
import sys
import zipfile
from pathlib import Path

source = Path("qa/feature_status.xlsx")
target = Path(sys.argv[1])
with zipfile.ZipFile(source) as in_workbook, zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as out_workbook:
    for item in in_workbook.infolist():
        data = in_workbook.read(item.filename)
        if item.filename == "xl/worksheets/sheet3.xml":
            text = data.decode()
            text = text.replace("<t>CORE-007</t>", "<t>STALE-APP-009</t>", 1)
            if "STALE-APP-009" not in text:
                text = text.replace("<t>Result</t>", "<t>STALE-APP-RESULT</t>", 1)
            if "STALE-APP-009" not in text:
                if "STALE-APP-RESULT" in text:
                    data = text.encode()
                    out_workbook.writestr(item, data)
                    continue
                raise SystemExit("stale App Runtime Sweep fixture did not mutate sheet3")
            data = text.encode()
        out_workbook.writestr(item, data)
PY
if python3 qa/audit_goal_completion.py --workbook "$STALE_APP_RUNTIME_WORKBOOK" >"$COMPLETION_AUDIT_LOG.stale-app-runtime-workbook" 2>&1; then
  echo "Expected completion audit to fail when the App Runtime Sweep worksheet content is stale."
  exit 1
fi
grep -F "App Runtime Sweep worksheet does not match canonical app-runtime rows" "$COMPLETION_AUDIT_LOG.stale-app-runtime-workbook" >/dev/null
STALE_LIVE_RUNTIME_WORKBOOK="${COMPLETION_AUDIT_LOG}.stale-live-runtime.xlsx"
python3 - "$STALE_LIVE_RUNTIME_WORKBOOK" <<'PY'
import sys
import zipfile
from pathlib import Path

source = Path("qa/feature_status.xlsx")
target = Path(sys.argv[1])
with zipfile.ZipFile(source) as in_workbook, zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as out_workbook:
    for item in in_workbook.infolist():
        data = in_workbook.read(item.filename)
        if item.filename == "xl/worksheets/sheet4.xml":
            text = data.decode()
            text = text.replace("<t>CORE-003</t>", "<t>STALE-LIVE-003</t>", 1)
            if "STALE-LIVE-003" not in text:
                raise SystemExit("stale Live Runtime Sweep fixture did not mutate sheet4")
            data = text.encode()
        out_workbook.writestr(item, data)
PY
if python3 qa/audit_goal_completion.py --workbook "$STALE_LIVE_RUNTIME_WORKBOOK" >"$COMPLETION_AUDIT_LOG.stale-live-runtime-workbook" 2>&1; then
  echo "Expected completion audit to fail when the Live Runtime Sweep worksheet content is stale."
  exit 1
fi
grep -F "Live Runtime Sweep worksheet does not match canonical live-runtime rows" "$COMPLETION_AUDIT_LOG.stale-live-runtime-workbook" >/dev/null
STALE_CLOSURE_WORKBOOK="${COMPLETION_AUDIT_LOG}.stale-closure.xlsx"
python3 - "$STALE_CLOSURE_WORKBOOK" <<'PY'
import sys
import zipfile
from pathlib import Path

source = Path("qa/feature_status.xlsx")
target = Path(sys.argv[1])
with zipfile.ZipFile(source) as in_workbook, zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as out_workbook:
    for item in in_workbook.infolist():
        data = in_workbook.read(item.filename)
        if item.filename == "xl/worksheets/sheet5.xml":
            text = data.decode()
            text = text.replace("<t>Canonical tracker and deterministic gates</t>", "<t>Stale closure checklist</t>", 1)
            if "Stale closure checklist" not in text:
                raise SystemExit("stale Closure Checklist fixture did not mutate sheet5")
            data = text.encode()
        out_workbook.writestr(item, data)
PY
if python3 qa/audit_goal_completion.py --workbook "$STALE_CLOSURE_WORKBOOK" >"$COMPLETION_AUDIT_LOG.stale-closure-workbook" 2>&1; then
  echo "Expected completion audit to fail when the Closure Checklist worksheet content is stale."
  exit 1
fi
grep -F "Closure Checklist worksheet does not match canonical closure checklist rows" "$COMPLETION_AUDIT_LOG.stale-closure-workbook" >/dev/null
STALE_COMPLETION_WORKBOOK="${COMPLETION_AUDIT_LOG}.stale-completion.xlsx"
python3 - "$STALE_COMPLETION_WORKBOOK" <<'PY'
import sys
import zipfile
from pathlib import Path

source = Path("qa/feature_status.xlsx")
target = Path(sys.argv[1])
with zipfile.ZipFile(source) as in_workbook, zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as out_workbook:
    for item in in_workbook.infolist():
        data = in_workbook.read(item.filename)
        if item.filename == "xl/worksheets/sheet6.xml":
            text = data.decode()
            text = text.replace(
                "<t>Every app feature is mapped to a user story and expected behaviour</t>",
                "<t>Stale completion audit requirement</t>",
                1,
            )
            if "Stale completion audit requirement" not in text:
                raise SystemExit("stale Completion Audit fixture did not mutate sheet6")
            data = text.encode()
        out_workbook.writestr(item, data)
PY
if python3 qa/audit_goal_completion.py --workbook "$STALE_COMPLETION_WORKBOOK" >"$COMPLETION_AUDIT_LOG.stale-completion-workbook" 2>&1; then
  echo "Expected completion audit to fail when the Completion Audit worksheet content is stale."
  exit 1
fi
grep -F "Completion Audit worksheet does not match canonical completion audit rows" "$COMPLETION_AUDIT_LOG.stale-completion-workbook" >/dev/null
STALE_RUNTIME_PREREQS_WORKBOOK="${COMPLETION_AUDIT_LOG}.stale-runtime-prereqs.xlsx"
python3 - "$STALE_RUNTIME_PREREQS_WORKBOOK" <<'PY'
import sys
import zipfile
from pathlib import Path

source = Path("qa/feature_status.xlsx")
target = Path(sys.argv[1])
with zipfile.ZipFile(source) as in_workbook, zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as out_workbook:
    for item in in_workbook.infolist():
        data = in_workbook.read(item.filename)
        if item.filename == "xl/worksheets/sheet7.xml":
            text = data.decode()
            text = text.replace("<t>Signed stable app bundle</t>", "<t>Stale runtime prereq</t>", 1)
            if "Stale runtime prereq" not in text:
                raise SystemExit("stale Runtime Prereqs fixture did not mutate sheet7")
            data = text.encode()
        out_workbook.writestr(item, data)
PY
if python3 qa/audit_goal_completion.py --workbook "$STALE_RUNTIME_PREREQS_WORKBOOK" >"$COMPLETION_AUDIT_LOG.stale-runtime-prereqs-workbook" 2>&1; then
  echo "Expected completion audit to fail when the Runtime Prereqs worksheet content is stale."
  exit 1
fi
grep -F "Runtime Prereqs worksheet does not match current runtime prerequisite audit rows" "$COMPLETION_AUDIT_LOG.stale-runtime-prereqs-workbook" >/dev/null
STALE_OPEN_ISSUES_WORKBOOK="${COMPLETION_AUDIT_LOG}.stale-open-issues.xlsx"
python3 - "$STALE_OPEN_ISSUES_WORKBOOK" <<'PY'
import sys
import zipfile
from pathlib import Path

source = Path("qa/feature_status.xlsx")
target = Path(sys.argv[1])
with zipfile.ZipFile(source) as in_workbook, zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as out_workbook:
    for item in in_workbook.infolist():
        data = in_workbook.read(item.filename)
        if item.filename == "xl/worksheets/sheet8.xml":
            text = data.decode()
            text = text.replace("<t>CORE-007</t>", "<t>STALE-ISSUE-009</t>", 1)
            if "STALE-ISSUE-009" not in text:
                text = text.replace("<t>Issue type</t>", "<t>STALE-ISSUE-TYPE</t>", 1)
            if "STALE-ISSUE-009" not in text:
                if "STALE-ISSUE-TYPE" in text:
                    data = text.encode()
                    out_workbook.writestr(item, data)
                    continue
                raise SystemExit("stale Open Issues fixture did not mutate sheet8")
            data = text.encode()
        out_workbook.writestr(item, data)
PY
if python3 qa/audit_goal_completion.py --workbook "$STALE_OPEN_ISSUES_WORKBOOK" >"$COMPLETION_AUDIT_LOG.stale-open-issues-workbook" 2>&1; then
  echo "Expected completion audit to fail when the Open Issues worksheet content is stale."
  exit 1
fi
grep -F "Open Issues worksheet does not match canonical open issue rows" "$COMPLETION_AUDIT_LOG.stale-open-issues-workbook" >/dev/null
STALE_CODE_COVERAGE_WORKBOOK="${COMPLETION_AUDIT_LOG}.stale-code-coverage.xlsx"
python3 - "$STALE_CODE_COVERAGE_WORKBOOK" <<'PY'
import sys
import zipfile
from pathlib import Path

source = Path("qa/feature_status.xlsx")
target = Path(sys.argv[1])
with zipfile.ZipFile(source) as in_workbook, zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as out_workbook:
    for item in in_workbook.infolist():
        data = in_workbook.read(item.filename)
        if item.filename == "xl/worksheets/sheet9.xml":
            text = data.decode()
            text = text.replace("<t>BastionShared/", "<t>STALE-COVERAGE/", 1)
            if "STALE-COVERAGE/" not in text:
                raise SystemExit("stale Code Coverage fixture did not mutate sheet9")
            data = text.encode()
        out_workbook.writestr(item, data)
PY
if python3 qa/audit_goal_completion.py --workbook "$STALE_CODE_COVERAGE_WORKBOOK" >"$COMPLETION_AUDIT_LOG.stale-code-coverage-workbook" 2>&1; then
  echo "Expected completion audit to fail when the Code Coverage worksheet content is stale."
  exit 1
fi
grep -F "Code Coverage worksheet does not match canonical source-code mapping rows" "$COMPLETION_AUDIT_LOG.stale-code-coverage-workbook" >/dev/null
STALE_TEST_MATRIX_WORKBOOK="${COMPLETION_AUDIT_LOG}.stale-test-matrix.xlsx"
python3 - "$STALE_TEST_MATRIX_WORKBOOK" <<'PY'
import sys
import zipfile
from pathlib import Path

source = Path("qa/feature_status.xlsx")
target = Path(sys.argv[1])
with zipfile.ZipFile(source) as in_workbook, zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as out_workbook:
    for item in in_workbook.infolist():
        data = in_workbook.read(item.filename)
        if item.filename == "xl/worksheets/sheet10.xml":
            text = data.decode()
            text = text.replace("<t>UI-001</t>", "<t>STALE-MATRIX-001</t>", 1)
            if "STALE-MATRIX-001" not in text:
                raise SystemExit("stale Test Matrix fixture did not mutate sheet10")
            data = text.encode()
        out_workbook.writestr(item, data)
PY
if python3 qa/audit_goal_completion.py --workbook "$STALE_TEST_MATRIX_WORKBOOK" >"$COMPLETION_AUDIT_LOG.stale-test-matrix-workbook" 2>&1; then
  echo "Expected completion audit to fail when the Test Matrix worksheet content is stale."
  exit 1
fi
grep -F "Test Matrix worksheet does not match canonical user-story test matrix rows" "$COMPLETION_AUDIT_LOG.stale-test-matrix-workbook" >/dev/null
STALE_ERROR_LEDGER_WORKBOOK="${COMPLETION_AUDIT_LOG}.stale-error-ledger.xlsx"
python3 - "$STALE_ERROR_LEDGER_WORKBOOK" <<'PY'
import sys
import zipfile
from pathlib import Path

source = Path("qa/feature_status.xlsx")
target = Path(sys.argv[1])
with zipfile.ZipFile(source) as in_workbook, zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as out_workbook:
    for item in in_workbook.infolist():
        data = in_workbook.read(item.filename)
        if item.filename == "xl/worksheets/sheet11.xml":
            text = data.decode()
            text = text.replace("<t>UI-001</t>", "<t>STALE-LEDGER-001</t>", 1)
            if "STALE-LEDGER-001" not in text:
                raise SystemExit("stale Error Ledger fixture did not mutate sheet11")
            data = text.encode()
        out_workbook.writestr(item, data)
PY
if python3 qa/audit_goal_completion.py --workbook "$STALE_ERROR_LEDGER_WORKBOOK" >"$COMPLETION_AUDIT_LOG.stale-error-ledger-workbook" 2>&1; then
  echo "Expected completion audit to fail when the Error Ledger worksheet content is stale."
  exit 1
fi
grep -F "Error Ledger worksheet does not match canonical error/fix/retest rows" "$COMPLETION_AUDIT_LOG.stale-error-ledger-workbook" >/dev/null
NO_VALIDATION_WORKBOOK="${COMPLETION_AUDIT_LOG}.no-validation.xlsx"
python3 - "$NO_VALIDATION_WORKBOOK" <<'PY'
import sys
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

source = Path("qa/feature_status.xlsx")
target = Path(sys.argv[1])
namespace = {"main": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
with zipfile.ZipFile(source) as in_workbook, zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as out_workbook:
    for item in in_workbook.infolist():
        data = in_workbook.read(item.filename)
        if item.filename == "xl/worksheets/sheet1.xml":
            sheet = ET.fromstring(data)
            removed = False
            for child in list(sheet):
                if child.tag == f"{{{namespace['main']}}}dataValidations":
                    sheet.remove(child)
                    removed = True
            if not removed:
                raise SystemExit("no-validation workbook fixture did not remove Feature Status validations")
            data = ET.tostring(sheet, encoding="utf-8", xml_declaration=True)
        out_workbook.writestr(item, data)
PY
if python3 qa/audit_goal_completion.py --workbook "$NO_VALIDATION_WORKBOOK" >"$COMPLETION_AUDIT_LOG.no-validation-workbook" 2>&1; then
  echo "Expected completion audit to fail when canonical workbook validations are missing."
  exit 1
fi
grep -F "Feature Status worksheet data validations do not match canonical status lists" "$COMPLETION_AUDIT_LOG.no-validation-workbook" >/dev/null
PREREQ_INCONSISTENT_WORKBOOK="${COMPLETION_AUDIT_LOG}.prereq-inconsistent.xlsx"
if grep -Fx "Completion audit: complete" "$COMPLETION_AUDIT_LOG" >/dev/null; then
  PREREQ_INCONSISTENT_FINAL_STATE="Blocked"
  PREREQ_INCONSISTENT_EXPECTED="Runtime Prereqs row 'Final completion gate' is 'Blocked' after completion blockers closed"
else
  PREREQ_INCONSISTENT_FINAL_STATE="Complete"
  PREREQ_INCONSISTENT_EXPECTED="Runtime Prereqs row 'Final completion gate' is closed while completion blockers remain"
fi
PREREQ_INCONSISTENT_FINAL_STATE="$PREREQ_INCONSISTENT_FINAL_STATE" python3 - "$PREREQ_INCONSISTENT_WORKBOOK" <<'PY'
import os
import sys
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

source = Path("qa/feature_status.xlsx")
target = Path(sys.argv[1])
namespace = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
ET.register_namespace("", namespace)

def cell_text(cell: ET.Element) -> str:
    text_node = cell.find(f"{{{namespace}}}is/{{{namespace}}}t")
    return "" if text_node is None or text_node.text is None else text_node.text

def set_cell_text(cell: ET.Element, value: str) -> None:
    text_node = cell.find(f"{{{namespace}}}is/{{{namespace}}}t")
    if text_node is None:
        raise SystemExit("Runtime Prereqs fixture found a cell without inline string text")
    text_node.text = value

with zipfile.ZipFile(source) as in_workbook, zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as out_workbook:
    for item in in_workbook.infolist():
        data = in_workbook.read(item.filename)
        if item.filename == "xl/worksheets/sheet7.xml":
            sheet = ET.fromstring(data)
            changed = False
            for row in sheet.findall(f".//{{{namespace}}}sheetData/{{{namespace}}}row"):
                cells = row.findall(f"{{{namespace}}}c")
                if len(cells) >= 2 and cell_text(cells[0]) == "Final completion gate":
                    set_cell_text(cells[1], os.environ["PREREQ_INCONSISTENT_FINAL_STATE"])
                    changed = True
                    break
            if not changed:
                raise SystemExit("prereq-inconsistent fixture did not mutate Runtime Prereqs")
            data = ET.tostring(sheet, encoding="utf-8", xml_declaration=True)
        out_workbook.writestr(item, data)
PY
if python3 qa/audit_goal_completion.py --workbook "$PREREQ_INCONSISTENT_WORKBOOK" >"$COMPLETION_AUDIT_LOG.prereq-inconsistent-workbook" 2>&1; then
  echo "Expected completion audit to fail when Runtime Prereqs contradict completion state."
  exit 1
fi
grep -F "$PREREQ_INCONSISTENT_EXPECTED" "$COMPLETION_AUDIT_LOG.prereq-inconsistent-workbook" >/dev/null
test ! -e docs/feature_user_story_tracker.csv
grep -F "Archived UI TODO" ui_todo.md >/dev/null
grep -F "qa/feature_status_source.json" ui_todo.md >/dev/null
grep -F "[qa/README.md](qa/README.md)" README.md >/dev/null
grep -F "qa/feature_status_source.json" qa/README.md >/dev/null
grep -F "qa/feature_status.xlsx" qa/README.md >/dev/null
grep -F "Runtime Prereqs" qa/README.md >/dev/null
grep -F "Open Issues" qa/README.md >/dev/null
grep -F "Code Coverage" qa/README.md >/dev/null
grep -F "Test Matrix" qa/README.md >/dev/null
grep -F "Error Ledger" qa/README.md >/dev/null
grep -F "discovered app-bundle candidates" qa/README.md >/dev/null
grep -F "qa/run_app_runtime_user_story_checks.sh --write-template" qa/README.md >/dev/null
grep -F "qa/run_signed_app_direct_runtime_checks.sh" qa/README.md >/dev/null
grep -F "qa/run_seeded_paired_runtime_checks.sh" qa/README.md >/dev/null
grep -F "qa/run_app_runtime_user_story_checks.sh --audit-evidence" qa/README.md >/dev/null
grep -F "qa/run_app_runtime_user_story_checks.sh --write-tracker-update" qa/README.md >/dev/null
grep -F "qa/run_app_runtime_user_story_checks.sh --write-updated-source" qa/README.md >/dev/null
grep -F "qa/run_app_runtime_user_story_checks.sh --audit-evidence dist/app-runtime-evidence.json --require-pass" qa/README.md >/dev/null
grep -F "qa/run_live_runtime_checks.sh --write-template" qa/README.md >/dev/null
grep -F "qa/run_live_runtime_checks.sh --audit-row-evidence dist/live-runtime-evidence.json --require-pass" qa/README.md >/dev/null
grep -F "qa/run_live_runtime_checks.sh --write-tracker-update" qa/README.md >/dev/null
grep -F "qa/run_live_runtime_checks.sh --write-updated-source" qa/README.md >/dev/null
grep -F "qa/run_live_runtime_checks.sh --run-phase notification-click --require-notification-click" qa/README.md >/dev/null
grep -F "runtime_prereqs_satisfied" qa/run_signed_app_direct_runtime_checks.sh >/dev/null
grep -F "cannot be promoted to pass until signed-app/current-source prerequisites are satisfied" qa/run_signed_app_direct_runtime_checks.sh >/dev/null
grep -F "source_rows = tracker_rows()" qa/run_signed_app_direct_runtime_checks.sh >/dev/null
grep -F "runtime_evidence_template(source_rows)" qa/run_signed_app_direct_runtime_checks.sh >/dev/null
grep -F "runtime_test_instructions(row)" qa/run_signed_app_direct_runtime_checks.sh >/dev/null
grep -F '"Test instructions"' qa/run_signed_app_direct_runtime_checks.sh >/dev/null
grep -F "run_ui_probe_json" qa/run_signed_app_direct_runtime_checks.sh >/dev/null
grep -F "ui-probe \${target} did not produce non-empty JSON after retries" qa/run_signed_app_direct_runtime_checks.sh >/dev/null
grep -F "must mention ID, Feature, User story, Expected behaviour, and Test instructions" qa/run_app_runtime_user_story_checks.sh >/dev/null
grep -F "must mention ID, Feature, User story, Expected behaviour, and Test instructions" qa/run_live_runtime_checks.sh >/dev/null
grep -F "Artifact: path whose text also mentions Result, ID, Feature, User story, Expected behaviour, and Test instructions" qa/run_app_runtime_user_story_checks.sh >/dev/null
grep -F "Artifact: path whose text also mentions Result, ID, Feature, User story, Expected behaviour, and Test instructions" qa/run_live_runtime_checks.sh >/dev/null
if grep -F "pending app runtime" qa/run_signed_app_direct_runtime_checks.sh >/dev/null; then
  echo "qa/run_signed_app_direct_runtime_checks.sh must use explicit native signed-app runtime proof wording, not stale 'pending app runtime'."
  exit 1
fi
if grep -E '^## P[0-5]|^- \\*\\*P[0-5]\\*\\*' ui_todo.md >/dev/null; then
  echo "ui_todo.md must remain an archive pointer, not a second active UI backlog."
  exit 1
fi
unzip -t qa/feature_status.xlsx >/dev/null
python3 - <<'PY'
import json
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

sys.path.insert(0, "qa")
from build_feature_status import (
    FEATURE_STATUS_VALUES,
    RUNTIME_RESULT_VALUES,
    STALE_APP_RUNTIME_COUNT_RE,
    TEST_STATUS_VALUES,
    app_runtime_count_phrases,
    app_runtime_sweep_rows,
    code_coverage_rows,
    completion_audit_status,
    closure_checklist_rows,
    completion_audit_rows,
    display_path,
    error_ledger_rows,
    live_runtime_sweep_rows,
    open_issue_rows,
    runtime_prerequisite_rows,
    test_matrix_rows,
)
from app_runtime_rows import (
    LIVE_RUNTIME_BLOCKED_IDS,
    SEEDED_PAIRED_RUNTIME_IDS,
    live_runtime_evidence_template,
    runtime_evidence_template,
    runtime_pending_ids,
)

rows = json.loads(Path("qa/feature_status_source.json").read_text())
qa_rows = [row for row in rows if row.get("ID") == "QA-001"]
if len(qa_rows) != 1:
    raise SystemExit("canonical tracker must contain exactly one QA-001 row")
qa_tracker_text = " ".join(
    str(qa_rows[0].get(field, ""))
    for field in ("Test evidence", "Errors documented", "Fix status", "Retest status", "Notes")
)
app_runtime_row_count = len(runtime_pending_ids(rows))
stale_count_match = STALE_APP_RUNTIME_COUNT_RE.search(qa_tracker_text)
if stale_count_match:
    raise SystemExit(
        f"QA-001 tracker evidence still contains stale app-runtime row-count wording: {stale_count_match.group(0)}"
    )
for expected_phrase in app_runtime_count_phrases(app_runtime_row_count):
    if expected_phrase not in qa_tracker_text:
        raise SystemExit(f"QA-001 tracker evidence must cite current app-runtime count phrase: {expected_phrase}")
with zipfile.ZipFile("qa/feature_status.xlsx") as workbook:
    names = set(workbook.namelist())
    if "xl/worksheets/sheet2.xml" not in names:
        raise SystemExit("workbook missing Summary worksheet")
    if "xl/worksheets/sheet3.xml" not in names:
        raise SystemExit("workbook missing App Runtime Sweep worksheet")
    if "xl/worksheets/sheet4.xml" not in names:
        raise SystemExit("workbook missing Live Runtime Sweep worksheet")
    if "xl/worksheets/sheet5.xml" not in names:
        raise SystemExit("workbook missing Closure Checklist worksheet")
    if "xl/worksheets/sheet6.xml" not in names:
        raise SystemExit("workbook missing Completion Audit worksheet")
    if "xl/worksheets/sheet7.xml" not in names:
        raise SystemExit("workbook missing Runtime Prereqs worksheet")
    if "xl/worksheets/sheet8.xml" not in names:
        raise SystemExit("workbook missing Open Issues worksheet")
    if "xl/worksheets/sheet9.xml" not in names:
        raise SystemExit("workbook missing Code Coverage worksheet")
    if "xl/worksheets/sheet10.xml" not in names:
        raise SystemExit("workbook missing Test Matrix worksheet")
    if "xl/worksheets/sheet11.xml" not in names:
        raise SystemExit("workbook missing Error Ledger worksheet")
    workbook_xml = ET.fromstring(workbook.read("xl/workbook.xml"))
    feature_sheet = ET.fromstring(workbook.read("xl/worksheets/sheet1.xml"))
    summary_sheet = ET.fromstring(workbook.read("xl/worksheets/sheet2.xml"))
    runtime_sheet = ET.fromstring(workbook.read("xl/worksheets/sheet3.xml"))
    live_runtime_sheet = ET.fromstring(workbook.read("xl/worksheets/sheet4.xml"))
    closure_sheet = ET.fromstring(workbook.read("xl/worksheets/sheet5.xml"))
    completion_sheet = ET.fromstring(workbook.read("xl/worksheets/sheet6.xml"))
    runtime_prereq_sheet = ET.fromstring(workbook.read("xl/worksheets/sheet7.xml"))
    open_issues_sheet = ET.fromstring(workbook.read("xl/worksheets/sheet8.xml"))
    code_coverage_sheet = ET.fromstring(workbook.read("xl/worksheets/sheet9.xml"))
    test_matrix_sheet = ET.fromstring(workbook.read("xl/worksheets/sheet10.xml"))
    error_ledger_sheet = ET.fromstring(workbook.read("xl/worksheets/sheet11.xml"))

namespace = {"main": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
sheets = [sheet.attrib["name"] for sheet in workbook_xml.findall(".//main:sheets/main:sheet", namespace)]
if sheets != ["Feature Status", "Summary", "App Runtime Sweep", "Live Runtime Sweep", "Closure Checklist", "Completion Audit", "Runtime Prereqs", "Open Issues", "Code Coverage", "Test Matrix", "Error Ledger"]:
    raise SystemExit(f"unexpected workbook sheets: {sheets}")

dimension = feature_sheet.find("main:dimension", namespace).attrib["ref"]
sheet_rows = feature_sheet.findall(".//main:sheetData/main:row", namespace)
expected_dimension = f"A1:M{len(rows) + 1}"
if dimension != expected_dimension:
    raise SystemExit(f"unexpected feature workbook dimension {dimension}, expected {expected_dimension}")
if len(sheet_rows) != len(rows) + 1:
    raise SystemExit(f"unexpected feature workbook row count {len(sheet_rows)}, expected {len(rows) + 1}")

def col_index(ref: str) -> int:
    letters = re.match(r"[A-Z]+", ref).group(0)
    value = 0
    for letter in letters:
        value = value * 26 + ord(letter) - 64
    return value - 1

def cell_text(cell: ET.Element) -> str:
    text_node = cell.find("main:is/main:t", namespace)
    return "" if text_node is None or text_node.text is None else text_node.text

def matrix(sheet: ET.Element) -> list[list[str]]:
    out: list[list[str]] = []
    for row in sheet.findall(".//main:sheetData/main:row", namespace):
        values: list[str] = []
        for cell in row.findall("main:c", namespace):
            index = col_index(cell.attrib["r"])
            while len(values) <= index:
                values.append("")
            values[index] = cell_text(cell)
        out.append(values)
    return out

def validation_map(sheet: ET.Element) -> dict[str, dict[str, str]]:
    validations: dict[str, dict[str, str]] = {}
    for validation in sheet.findall(".//main:dataValidations/main:dataValidation", namespace):
        formula = validation.find("main:formula1", namespace)
        validations[validation.attrib.get("sqref", "")] = {
            "type": validation.attrib.get("type", ""),
            "allowBlank": validation.attrib.get("allowBlank", ""),
            "showErrorMessage": validation.attrib.get("showErrorMessage", ""),
            "formula1": "" if formula is None or formula.text is None else formula.text,
        }
    return validations

def list_formula(values: list[str]) -> str:
    return '"' + ",".join(values) + '"'

feature_validations = validation_map(feature_sheet)
expected_feature_validations = {
    f"G2:G{len(rows) + 1}": {
        "type": "list",
        "allowBlank": "1",
        "showErrorMessage": "1",
        "formula1": list_formula(FEATURE_STATUS_VALUES),
    },
    f"H2:H{len(rows) + 1}": {
        "type": "list",
        "allowBlank": "1",
        "showErrorMessage": "1",
        "formula1": list_formula(TEST_STATUS_VALUES),
    },
}
if feature_validations != expected_feature_validations:
    raise SystemExit(f"unexpected feature sheet data validations: {feature_validations}")

summary_dimension = summary_sheet.find("main:dimension", namespace).attrib["ref"]
if summary_dimension != "A1:C26":
    raise SystemExit(f"unexpected summary workbook dimension {summary_dimension}, expected A1:C26")
if validation_map(summary_sheet):
    raise SystemExit("Summary worksheet must not contain editable data validations")
summary_rows = matrix(summary_sheet)
if summary_rows[0] != ["Metric", "Value", "Notes"]:
    raise SystemExit(f"unexpected summary header: {summary_rows[0]}")
summary = {row[0]: row[1] for row in summary_rows[1:]}
test_statuses = Counter(row["Test status"] for row in rows)
feature_statuses = Counter(row["Feature status"] for row in rows)
expected_summary = {
    "Total tracker rows": str(len(rows)),
    "Passing rows": str(test_statuses["Pass"]),
    "Environment-blocked rows": str(test_statuses["Blocked in this environment"]),
    "Static-inspection-only rows": str(test_statuses["Pass by static inspection"]),
    "Pending rows": str(test_statuses["Pending"]),
    "App-runtime pending rows": str(len(runtime_pending_ids(rows))),
    "Feature code files": str(len(code_coverage_rows(rows)) - 1),
    "Unmapped feature code files": "0",
    "Open failure ledger rows": "0",
    "Runtime evidence pending ledger rows": str(len(runtime_evidence_template(rows))),
    "Implemented features": str(feature_statuses["Implemented"]),
    "Deferred UI features": str(feature_statuses["Deferred from UI"]),
    "Display-only management deferred": str(feature_statuses["Implemented for display; management deferred"]),
    "Live-runtime blocked IDs": ", ".join(sorted(LIVE_RUNTIME_BLOCKED_IDS)),
    "Live-runtime gate": "qa/run_live_runtime_checks.sh",
    "App-runtime gate": "qa/run_app_runtime_user_story_checks.sh",
    "Closure checklist": "Closure Checklist",
    "Completion audit sheet": "Completion Audit",
    "Runtime prerequisites sheet": "Runtime Prereqs",
    "Open issues sheet": "Open Issues",
    "Code coverage sheet": "Code Coverage",
    "Test matrix sheet": "Test Matrix",
    "Error ledger sheet": "Error Ledger",
    "Completion audit": completion_audit_status(rows),
}
for metric, expected in expected_summary.items():
    actual = summary.get(metric)
    if actual != expected:
        raise SystemExit(f"unexpected Summary value for {metric}: {actual!r}, expected {expected!r}")

runtime_template = runtime_evidence_template(rows)
runtime_dimension = runtime_sheet.find("main:dimension", namespace).attrib["ref"]
expected_runtime_dimension = f"A1:I{len(runtime_template) + 1}"
if runtime_dimension != expected_runtime_dimension:
    raise SystemExit(f"unexpected runtime sweep dimension {runtime_dimension}, expected {expected_runtime_dimension}")
runtime_rows = matrix(runtime_sheet)
runtime_header = ["ID", "Surface", "Feature", "User story", "Expected behaviour", "Test instructions", "Result", "Evidence", "Errors"]
if runtime_rows[0] != runtime_header:
    raise SystemExit(f"unexpected runtime sweep header: {runtime_rows[0]}")
if len(runtime_rows) != len(runtime_template) + 1:
    raise SystemExit(f"unexpected runtime sweep row count {len(runtime_rows)}, expected {len(runtime_template) + 1}")
expected_runtime_rows = app_runtime_sweep_rows(rows)
if runtime_rows != expected_runtime_rows:
    raise SystemExit("App Runtime Sweep worksheet does not match canonical hydrated app-runtime rows")
expected_runtime_validations = {
    f"G2:G{len(runtime_template) + 1}": {
        "type": "list",
        "allowBlank": "1",
        "showErrorMessage": "1",
        "formula1": list_formula(RUNTIME_RESULT_VALUES),
    },
} if runtime_template else {}
if validation_map(runtime_sheet) != expected_runtime_validations:
    raise SystemExit(f"unexpected app runtime sweep data validations: {validation_map(runtime_sheet)}")

live_runtime_template = live_runtime_evidence_template(rows)
live_runtime_dimension = live_runtime_sheet.find("main:dimension", namespace).attrib["ref"]
expected_live_runtime_dimension = f"A1:I{len(live_runtime_template) + 1}"
if live_runtime_dimension != expected_live_runtime_dimension:
    raise SystemExit(
        f"unexpected live runtime sweep dimension {live_runtime_dimension}, expected {expected_live_runtime_dimension}"
    )
live_runtime_rows = matrix(live_runtime_sheet)
if live_runtime_rows[0] != runtime_header:
    raise SystemExit(f"unexpected live runtime sweep header: {live_runtime_rows[0]}")
if len(live_runtime_rows) != len(live_runtime_template) + 1:
    raise SystemExit(
        f"unexpected live runtime sweep row count {len(live_runtime_rows)}, expected {len(live_runtime_template) + 1}"
    )
expected_live_runtime_rows = live_runtime_sweep_rows(rows)
if live_runtime_rows != expected_live_runtime_rows:
    raise SystemExit("Live Runtime Sweep worksheet does not match canonical hydrated live-runtime rows")
expected_live_runtime_validations = {
    f"G2:G{len(live_runtime_template) + 1}": {
        "type": "list",
        "allowBlank": "1",
        "showErrorMessage": "1",
        "formula1": list_formula(RUNTIME_RESULT_VALUES),
    },
} if live_runtime_template else {}
if validation_map(live_runtime_sheet) != expected_live_runtime_validations:
    raise SystemExit(f"unexpected live runtime sweep data validations: {validation_map(live_runtime_sheet)}")
seen_live_runtime_ids: set[str] = set()
for row_index, (workbook_row, expected_row) in enumerate(zip(live_runtime_rows[1:], live_runtime_template), start=2):
    row_id = expected_row["ID"]
    if row_id not in LIVE_RUNTIME_BLOCKED_IDS:
        raise SystemExit(f"unexpected live runtime row ID at row {row_index}: {row_id}")
    if row_id in seen_live_runtime_ids:
        raise SystemExit(f"duplicate live runtime row ID at row {row_index}: {row_id}")
    seen_live_runtime_ids.add(row_id)
if seen_live_runtime_ids != LIVE_RUNTIME_BLOCKED_IDS:
    raise SystemExit(f"live runtime sweep IDs do not match blocked row set: {sorted(seen_live_runtime_ids)}")

runtime_prereq_template = runtime_prerequisite_rows(rows)
runtime_prereq_by_name = {row[0]: row for row in runtime_prereq_template[1:] if row}
code_signing_prereq = runtime_prereq_by_name.get("Code-signing identities", [])
code_signing_blocked = len(code_signing_prereq) > 1 and code_signing_prereq[1] == "Blocked"

closure_template = closure_checklist_rows(rows)
closure_dimension = closure_sheet.find("main:dimension", namespace).attrib["ref"]
expected_closure_dimension = f"A1:E{len(closure_template)}"
if closure_dimension != expected_closure_dimension:
    raise SystemExit(f"unexpected closure checklist dimension {closure_dimension}, expected {expected_closure_dimension}")
closure_rows = matrix(closure_sheet)
if closure_rows != closure_template:
    raise SystemExit("Closure Checklist worksheet does not match canonical closure checklist rows")
external_closure_rows = [row for row in closure_rows if row and row[1] == "External runtime prerequisites"]
if len(external_closure_rows) != 1:
    raise SystemExit("Closure Checklist must include exactly one external runtime prerequisites row")
external_closure_row = external_closure_rows[0]
if code_signing_blocked and "Code-signing identities=Blocked" not in external_closure_row[2]:
    raise SystemExit("Closure Checklist external prerequisites row must summarize the code-signing blocker")
if not code_signing_blocked and "Code-signing identities=Blocked" in external_closure_row[2]:
    raise SystemExit("Closure Checklist external prerequisites row must not keep a stale code-signing blocker")
if "Notification click proof=Blocked" in external_closure_row[2]:
    raise SystemExit("Closure Checklist external prerequisites row must not use stale notification-click blocker wording")
if "Notification delivery and route proof=Blocked" in external_closure_row[2] and "notification" not in external_closure_row[2]:
    raise SystemExit("Closure Checklist external prerequisites row must summarize notification delivery blocker details")
if "Final completion gate" in external_closure_row[2]:
    raise SystemExit("Closure Checklist external prerequisites row must not treat the final audit as an external runtime prerequisite")
if "scripts/dev-enable-codesign-keychain-access.sh" not in external_closure_row[3]:
    raise SystemExit("Closure Checklist external prerequisites row must cite the keychain ACL repair command")
if "scripts/dev-rebuild-signed.sh" not in external_closure_row[3]:
    raise SystemExit("Closure Checklist external prerequisites row must cite the signed rebuild command")
if "notification-click" not in external_closure_row[3]:
    raise SystemExit("Closure Checklist external prerequisites row must cite notification-click closure")
if validation_map(closure_sheet):
    raise SystemExit("Closure Checklist worksheet must not contain editable data validations")

completion_template = completion_audit_rows(rows)
completion_dimension = completion_sheet.find("main:dimension", namespace).attrib["ref"]
expected_completion_dimension = f"A1:D{len(completion_template)}"
if completion_dimension != expected_completion_dimension:
    raise SystemExit(
        f"unexpected completion audit dimension {completion_dimension}, expected {expected_completion_dimension}"
    )
completion_rows = matrix(completion_sheet)
if completion_rows != completion_template:
    raise SystemExit("Completion Audit worksheet does not match canonical completion audit rows")
if validation_map(completion_sheet):
    raise SystemExit("Completion Audit worksheet must not contain editable data validations")

runtime_prereq_dimension = runtime_prereq_sheet.find("main:dimension", namespace).attrib["ref"]
expected_runtime_prereq_dimension = f"A1:E{len(runtime_prereq_template)}"
if runtime_prereq_dimension != expected_runtime_prereq_dimension:
    raise SystemExit(
        f"unexpected runtime prerequisite dimension {runtime_prereq_dimension}, expected {expected_runtime_prereq_dimension}"
    )
runtime_prereq_rows = matrix(runtime_prereq_sheet)
if runtime_prereq_rows != runtime_prereq_template:
    raise SystemExit("Runtime Prereqs worksheet does not match canonical runtime prerequisite rows")
candidate_rows = [row for row in runtime_prereq_rows if row and row[0] == "Discovered app bundle candidates"]
if len(candidate_rows) != 1:
    raise SystemExit("Runtime Prereqs worksheet must include exactly one discovered app-bundle candidates row")
release_candidate = Path("dist/release/Bastion.app")
if release_candidate.is_dir() and display_path(release_candidate.resolve()) not in candidate_rows[0][2]:
    raise SystemExit("Runtime Prereqs candidate row must report existing dist/release/Bastion.app candidate")
identity_rows = [row for row in runtime_prereq_rows if row and row[0] == "Code-signing identities"]
if len(identity_rows) != 1:
    raise SystemExit("Runtime Prereqs worksheet must include exactly one code-signing identities row")
if "scripts/dev-enable-codesign-keychain-access.sh" not in identity_rows[0][4]:
    raise SystemExit("Runtime Prereqs code-signing identities row must cite the keychain ACL repair command")
if "scripts/dev-enable-codesign-keychain-access.sh --check" not in identity_rows[0][4]:
    raise SystemExit("Runtime Prereqs code-signing identities row must cite the non-mutating codesign check command before repair")
if "scripts/dev-rebuild-signed.sh" not in identity_rows[0][4]:
    raise SystemExit("Runtime Prereqs code-signing identities row must cite the signed rebuild command")
if "codesign usability probe" not in identity_rows[0][2]:
    raise SystemExit("Runtime Prereqs code-signing identities row must include codesign usability probe evidence")
if identity_rows[0][1] == "Blocked" and "codesign usability probe failed" in identity_rows[0][2] and "matched private key label:" not in identity_rows[0][2]:
    raise SystemExit("Runtime Prereqs code-signing identities row must include the resolved private-key label when codesign is blocked")
if "/usr/bin/codesign can use the private key noninteractively" not in identity_rows[0][3]:
    raise SystemExit("Runtime Prereqs code-signing identities row must explain noninteractive private-key access")
if "non-mutating codesign check" not in identity_rows[0][3]:
    raise SystemExit("Runtime Prereqs code-signing identities row must explain the non-mutating codesign check")
seeded_pair_rows = [row for row in runtime_prereq_rows if row and row[0] == "Seeded paired-client runtime setup"]
if len(seeded_pair_rows) != 1:
    raise SystemExit("Runtime Prereqs worksheet must include exactly one seeded paired-client runtime setup row")
if "qa/run_seeded_paired_runtime_checks.sh" not in seeded_pair_rows[0][4]:
    raise SystemExit("Runtime Prereqs seeded paired-client row must cite the reversible seeded runtime gate")
if seeded_pair_rows[0][1] == "Blocked" and "non-mutating codesign check" not in seeded_pair_rows[0][3]:
    raise SystemExit("Runtime Prereqs seeded paired-client row must route blocked setup through the non-mutating codesign check")
if "paired-client" not in seeded_pair_rows[0][2] and seeded_pair_rows[0][1] != "Satisfied":
    raise SystemExit("Runtime Prereqs seeded paired-client row must describe paired-client runtime setup evidence")
app_runtime_result_by_id = {row[0]: row[6] for row in runtime_rows[1:] if len(row) >= 7}
queued_app_runtime_ids = set(app_runtime_result_by_id)
open_seeded_rows = sorted(
    row_id
    for row_id in SEEDED_PAIRED_RUNTIME_IDS
    if row_id in queued_app_runtime_ids
    and app_runtime_result_by_id.get(row_id) != "pass"
)
if open_seeded_rows and seeded_pair_rows[0][1] != "Blocked":
    raise SystemExit("Runtime Prereqs seeded paired-client row must be blocked while seeded target rows are not pass")
if open_seeded_rows and "seeded paired-client target rows" not in seeded_pair_rows[0][2]:
    raise SystemExit("Runtime Prereqs seeded paired-client row must cite seeded target row status")
seeded_runtime_evidence_path = Path("dist/app-runtime-evidence.current.json")
if open_seeded_rows and seeded_runtime_evidence_path.exists():
    seeded_runtime_evidence = json.loads(seeded_runtime_evidence_path.read_text())
    missing_seeded_preflight = sorted(
        item["ID"]
        for item in seeded_runtime_evidence
        if item.get("ID") in SEEDED_PAIRED_RUNTIME_IDS
        and "non-mutating codesign usability preflight failed" in item.get("Errors", "")
        and "Additional artifact: dist/app-runtime-artifacts/seeded-paired-runtime/codesign-preflight.log" not in item.get("Evidence", "")
    )
    if missing_seeded_preflight:
        raise SystemExit(
            "Seeded paired-client blocker evidence must cite the raw codesign preflight log: "
            + ", ".join(missing_seeded_preflight)
        )
if not open_seeded_rows and seeded_pair_rows[0][1] != "Satisfied":
    raise SystemExit("Runtime Prereqs seeded paired-client row must be satisfied when all seeded target rows pass")
freshness_rows = [row for row in runtime_prereq_rows if row and row[0] == "Current-source signed app rebuild"]
if len(freshness_rows) != 1:
    raise SystemExit("Runtime Prereqs worksheet must include exactly one current-source signed app rebuild row")
if "source" not in freshness_rows[0][2] or "runtime binary" not in freshness_rows[0][2]:
    raise SystemExit("Runtime Prereqs current-source row must compare source inputs with installed runtime binaries")
if "scripts/dev-rebuild-signed.sh" not in freshness_rows[0][4]:
    raise SystemExit("Runtime Prereqs current-source row must cite the signed rebuild command")
app_runtime_gate_rows = [row for row in runtime_prereq_rows if row and row[0] == "App Runtime Sweep prerequisite gate"]
if len(app_runtime_gate_rows) != 1:
    raise SystemExit("Runtime Prereqs worksheet must include exactly one app runtime gate row")
if "Current-source signed app rebuild=" not in app_runtime_gate_rows[0][2]:
    raise SystemExit("Runtime Prereqs app runtime gate row must summarize current-source freshness")
if "qa/run_app_runtime_user_story_checks.sh --check-prereqs --require-prereqs" not in app_runtime_gate_rows[0][4]:
    raise SystemExit("Runtime Prereqs app runtime gate row must cite the require-prereqs command")
live_runtime_gate_rows = [row for row in runtime_prereq_rows if row and row[0] == "Live Runtime Sweep prerequisite gate"]
if len(live_runtime_gate_rows) != 1:
    raise SystemExit("Runtime Prereqs worksheet must include exactly one live runtime gate row")
if "Current-source signed app rebuild=" not in live_runtime_gate_rows[0][2]:
    raise SystemExit("Runtime Prereqs live runtime gate row must summarize current-source freshness")
if "qa/run_live_runtime_checks.sh --check-prereqs --require-prereqs" not in live_runtime_gate_rows[0][4]:
    raise SystemExit("Runtime Prereqs live runtime gate row must cite the require-prereqs command")
notification_rows = [row for row in runtime_prereq_rows if row and row[0] == "Notification delivery and route proof"]
if len(notification_rows) != 1:
    raise SystemExit("Runtime Prereqs worksheet must include exactly one notification delivery and route proof row")
if "qa/run_live_runtime_checks.sh --run-phase notification-click --require-notification-click" not in notification_rows[0][4]:
    raise SystemExit("Runtime Prereqs notification delivery and route proof row must cite the notification-click closure command")
if notification_rows[0][1] != "Satisfied" and "notification" not in notification_rows[0][2]:
    raise SystemExit("Runtime Prereqs notification delivery and route proof row must describe notification proof state")
if validation_map(runtime_prereq_sheet):
    raise SystemExit("Runtime Prereqs worksheet must not contain editable data validations")

open_issue_template = open_issue_rows(rows)
open_issue_dimension = open_issues_sheet.find("main:dimension", namespace).attrib["ref"]
expected_open_issue_dimension = f"A1:F{len(open_issue_template)}"
if open_issue_dimension != expected_open_issue_dimension:
    raise SystemExit(f"unexpected open issues dimension {open_issue_dimension}, expected {expected_open_issue_dimension}")
open_issue_matrix = matrix(open_issues_sheet)
if open_issue_matrix != open_issue_template:
    raise SystemExit("Open Issues worksheet does not match canonical open issue rows")
issue_type_counts = Counter(row[0] for row in open_issue_matrix[1:])
if issue_type_counts["App-runtime evidence missing"] != len(runtime_template):
    raise SystemExit("Open Issues worksheet must include one app-runtime issue per runtime evidence row")
open_live_runtime_ids = {
    str(row.get("ID", ""))
    for row in rows
    if str(row.get("ID", "")) in LIVE_RUNTIME_BLOCKED_IDS
    and row.get("Test status") != "Pass"
}
if issue_type_counts["Live-runtime evidence missing"] != len(open_live_runtime_ids):
    raise SystemExit("Open Issues worksheet must include one live-runtime issue per unresolved live row")
expected_runtime_prereq_issue_count = sum(
    1
    for row in runtime_prereq_template[1:]
    if len(row) >= 2 and row[1] not in {"Satisfied", "Complete"}
)
if issue_type_counts["Runtime prerequisite blocker"] != expected_runtime_prereq_issue_count:
    raise SystemExit("Open Issues worksheet must include current runtime prerequisite blockers")
if validation_map(open_issues_sheet):
    raise SystemExit("Open Issues worksheet must not contain editable data validations")

code_coverage_template = code_coverage_rows(rows)
code_coverage_dimension = code_coverage_sheet.find("main:dimension", namespace).attrib["ref"]
expected_code_coverage_dimension = f"A1:F{len(code_coverage_template)}"
if code_coverage_dimension != expected_code_coverage_dimension:
    raise SystemExit(
        f"unexpected code coverage dimension {code_coverage_dimension}, expected {expected_code_coverage_dimension}"
    )
code_coverage_matrix = matrix(code_coverage_sheet)
if code_coverage_matrix != code_coverage_template:
    raise SystemExit("Code Coverage worksheet does not match canonical code coverage rows")
coverage_status_counts = Counter(row[4] for row in code_coverage_matrix[1:])
if coverage_status_counts["Missing tracker mapping"]:
    raise SystemExit("Code Coverage worksheet must not contain unmapped feature-code files")
if validation_map(code_coverage_sheet):
    raise SystemExit("Code Coverage worksheet must not contain editable data validations")

test_matrix_template = test_matrix_rows(rows)
test_matrix_dimension = test_matrix_sheet.find("main:dimension", namespace).attrib["ref"]
expected_test_matrix_dimension = f"A1:I{len(test_matrix_template)}"
if test_matrix_dimension != expected_test_matrix_dimension:
    raise SystemExit(f"unexpected test matrix dimension {test_matrix_dimension}, expected {expected_test_matrix_dimension}")
test_matrix_matrix = matrix(test_matrix_sheet)
if test_matrix_matrix != test_matrix_template:
    raise SystemExit("Test Matrix worksheet does not match canonical user-story test matrix rows")
lane_counts = Counter(row[3] for row in test_matrix_matrix[1:])
if lane_counts["App Runtime Sweep"] != len(runtime_template):
    raise SystemExit("Test Matrix must include one App Runtime Sweep lane per app-runtime evidence row")
if lane_counts["Live Runtime Sweep"] != len(open_live_runtime_ids):
    raise SystemExit("Test Matrix must include one Live Runtime Sweep lane per unresolved live row")
if lane_counts["Post-fix retest"]:
    raise SystemExit("Test Matrix should not contain Post-fix retest lanes while canonical tracker has no Pending rows")
if validation_map(test_matrix_sheet):
    raise SystemExit("Test Matrix worksheet must not contain editable data validations")

error_ledger_template = error_ledger_rows(rows)
error_ledger_dimension = error_ledger_sheet.find("main:dimension", namespace).attrib["ref"]
expected_error_ledger_dimension = f"A1:I{len(error_ledger_template)}"
if error_ledger_dimension != expected_error_ledger_dimension:
    raise SystemExit(f"unexpected error ledger dimension {error_ledger_dimension}, expected {expected_error_ledger_dimension}")
error_ledger_matrix = matrix(error_ledger_sheet)
if error_ledger_matrix != error_ledger_template:
    raise SystemExit("Error Ledger worksheet does not match canonical error/fix/retest rows")
error_state_counts = Counter(row[3] for row in error_ledger_matrix[1:])
if error_state_counts["Open failure"]:
    raise SystemExit("Error Ledger should not contain Open failure rows while canonical tracker has no Pending rows")
if error_state_counts["Runtime evidence pending"] != len(runtime_template):
    raise SystemExit("Error Ledger must include one Runtime evidence pending row per app-runtime evidence row")
if error_state_counts["Runtime environment blocked"] != len(open_live_runtime_ids):
    raise SystemExit("Error Ledger must include one Runtime environment blocked row per unresolved live row")
if validation_map(error_ledger_sheet):
    raise SystemExit("Error Ledger worksheet must not contain editable data validations")
PY
python3 - <<'PY'
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "qa")
import build_feature_status
from app_runtime_rows import LIVE_RUNTIME_BLOCKED_IDS, runtime_pending_ids

rows = json.loads(open("qa/feature_status_source.json").read())
app_runtime_row_count = len(runtime_pending_ids(rows))
live_runtime_context_artifact = "dist/live-runtime-artifacts/live-runtime-current-blockers.log"
fixture = [dict(row) for row in rows]
fixture[0]["Reviewer notes"] = "Out-of-contract tracker field"
try:
    build_feature_status.validate_entries(fixture)
except SystemExit as exc:
    message = str(exc)
    if "non-canonical fields:" not in message or "UI-001: Reviewer notes" not in message:
        raise
else:
    raise SystemExit("tracker builder must reject non-canonical source fields")

typed_fixture = [dict(row) for row in rows]
typed_fixture[0]["Notes"] = ["not", "a", "string"]
try:
    build_feature_status.validate_entries(typed_fixture)
except SystemExit as exc:
    message = str(exc)
    if "canonical fields must be strings:" not in message or "UI-001: Notes" not in message:
        raise
else:
    raise SystemExit("tracker builder must reject non-string canonical source fields")

whitespace_fixture = [dict(row) for row in rows]
whitespace_fixture[0]["ID"] = f"{whitespace_fixture[0]['ID']} "
try:
    build_feature_status.validate_entries(whitespace_fixture)
except SystemExit as exc:
    message = str(exc)
    if "canonical fields must not have leading or trailing whitespace:" not in message or "UI-001: ID" not in message:
        raise
else:
    raise SystemExit("tracker builder must reject whitespace-padded canonical source fields")

placeholder_fixture = [dict(row) for row in rows]
placeholder_fixture[0]["Retest status"] = (
    f"TODO unresolved canonical tracker placeholder for "
    f"{placeholder_fixture[0]['ID']} {placeholder_fixture[0]['Feature']}."
)
try:
    build_feature_status.validate_entries(placeholder_fixture)
except SystemExit as exc:
    message = str(exc)
    if "tracker source contains unresolved placeholder wording:" not in message or "UI-001: TODO" not in message:
        raise
else:
    raise SystemExit("tracker builder must reject unresolved canonical source placeholders")

deferred_ui_fixture = [dict(row) for row in rows]
for row in deferred_ui_fixture:
    if row["ID"] == "UI-026":
        row["Expected behaviour"] = "The wallet group panel must not render an Add agent control."
        row["Test evidence"] = "Deterministic no-fake-control coverage passed."
        row["Notes"] = ""
        break
else:
    raise SystemExit("canonical tracker must contain UI-026 for deferred UI fixture")
try:
    build_feature_status.validate_entries(deferred_ui_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "Deferred-from-UI rows must name the deferred UI scope and CLI/MCP/REST backend coverage" not in message
        or "UI-026" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject deferred UI rows without backend coverage context")

vague_retest_fixture = [dict(row) for row in rows]
vague_retest_fixture[0]["Test status"] = "Pass"
vague_retest_fixture[0]["Retest status"] = "Retest passed with no concrete gate"
try:
    build_feature_status.validate_entries(vague_retest_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "pass rows must describe concrete retest evidence" not in message
        or "UI-001: Retest passed with no concrete gate" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague pass-row Retest status text")

vague_fix_fixture = [dict(row) for row in rows]
vague_fix_fixture[0]["Test status"] = "Pass"
vague_fix_fixture[0]["Fix status"] = "Fixed"
try:
    build_feature_status.validate_entries(vague_fix_fixture)
except SystemExit as exc:
    message = str(exc)
    if "pass rows must describe the concrete fix state" not in message or "UI-001: Fixed" not in message:
        raise
else:
    raise SystemExit("tracker builder must reject vague pass-row Fix status text")

vague_runtime_pending_fix_fixture = [dict(row) for row in rows]
vague_runtime_pending_fix_fixture[0]["Test status"] = "Pass"
vague_runtime_pending_fix_fixture[0]["Fix status"] = (
    "Fixed deterministic coverage; live signing runtime pending."
)
try:
    build_feature_status.validate_entries(vague_runtime_pending_fix_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "pass rows must describe the concrete fix state" not in message
        or "UI-001: Fixed deterministic coverage; live signing runtime pending." not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague runtime-pending Fix status text")

vague_no_code_change_fix_fixture = [dict(row) for row in rows]
vague_no_code_change_fix_fixture[0]["Test status"] = "Pass"
vague_no_code_change_fix_fixture[0]["Fix status"] = (
    "No code change needed for deterministic coverage; runtime evidence remains pending."
)
try:
    build_feature_status.validate_entries(vague_no_code_change_fix_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "pass rows must describe the concrete fix state" not in message
        or "UI-001: No code change needed for deterministic coverage; runtime evidence remains pending." not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague no-code-change Fix status text")

vague_no_production_code_change_fix_fixture = [dict(row) for row in rows]
vague_no_production_code_change_fix_fixture[0]["Test status"] = "Pass"
vague_no_production_code_change_fix_fixture[0]["Fix status"] = (
    "No production code change needed; deterministic CLI argument smoke coverage added."
)
try:
    build_feature_status.validate_entries(vague_no_production_code_change_fix_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "pass rows must describe the concrete fix state" not in message
        or "UI-001: No production code change needed; deterministic CLI argument smoke coverage added." not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague no-production-code-change Fix status text")

stale_pass_runtime_gap_fixture = [dict(row) for row in rows]
for row in stale_pass_runtime_gap_fixture:
    if row["ID"] == "CLI-011":
        row["Fix status"] = row["Fix status"] + " Runtime proof gap: stale signed-app retest."
        break
else:
    raise SystemExit("canonical tracker must contain CLI-011 for stale pass-row runtime-gap fixture")
try:
    build_feature_status.validate_entries(stale_pass_runtime_gap_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "passed signed-app runtime rows must not retain Remaining/Runtime proof gap text" not in message
        or "CLI-011" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject stale proof-gap text on passed signed-app runtime rows")

vague_errors_fixture = [dict(row) for row in rows]
vague_errors_fixture[0]["Test status"] = "Pass"
vague_errors_fixture[0]["Errors documented"] = "None found in this pass."
try:
    build_feature_status.validate_entries(vague_errors_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "pass rows must describe reviewed errors or absence of defects" not in message
        or "UI-001: None found in this pass." not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague pass-row Errors documented text")

generic_no_issue_fixture = [dict(row) for row in rows]
generic_no_issue_fixture[0]["Test status"] = "Pass"
generic_no_issue_fixture[0]["Errors documented"] = "No source-level logistics or UX error found in static review."
try:
    build_feature_status.validate_entries(generic_no_issue_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "pass rows must describe reviewed errors or absence of defects" not in message
        or "UI-001: No source-level logistics or UX error found in static review." not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject generic no-source-level Errors documented text")

generic_no_new_fixture = [dict(row) for row in rows]
generic_no_new_fixture[0]["Test status"] = "Pass"
generic_no_new_fixture[0]["Errors documented"] = "Deterministic tests passed; no new logistics or UX error found in this pass."
try:
    build_feature_status.validate_entries(generic_no_new_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "pass rows must describe reviewed errors or absence of defects" not in message
        or "UI-001: Deterministic tests passed; no new logistics or UX error found in this pass." not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject generic no-new-error Errors documented text")

mcp_no_issue_fixture = [dict(row) for row in rows]
mcp_no_issue_fixture[0]["Test status"] = "Pass"
mcp_no_issue_fixture[0]["Errors documented"] = "No MCP wallet tool argument-contract error found after fake-CLI testing."
try:
    build_feature_status.validate_entries(mcp_no_issue_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "pass rows must describe reviewed errors or absence of defects" not in message
        or "UI-001: No MCP wallet tool argument-contract error found after fake-CLI testing." not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject generic MCP no-error Errors documented text")

reviewed_path_fixture = [dict(row) for row in rows]
reviewed_path_fixture[0]["Test status"] = "Pass"
reviewed_path_fixture[0]["Errors documented"] = "Ethereum message command path reviewed."
try:
    build_feature_status.validate_entries(reviewed_path_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "pass rows must describe reviewed errors or absence of defects" not in message
        or "UI-001: Ethereum message command path reviewed." not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague command-path reviewed Errors documented text")

stale_xcode_fix_fixture = [dict(row) for row in rows]
stale_xcode_fix_fixture[0]["Fix status"] = "No code change made; Xcode test blocked"
try:
    build_feature_status.validate_entries(stale_xcode_fix_fixture)
except SystemExit as exc:
    message = str(exc)
    if "tracker source contains stale Xcode/runtime blocker wording" not in message or "Xcode test blocked" not in message:
        raise
else:
    raise SystemExit("tracker builder must reject stale Xcode test blocked wording")

stale_static_mapping_fixture = [dict(row) for row in rows]
stale_static_mapping_fixture[0]["Errors documented"] = (
    "Static source/test mapping found coverage, but this fixture is intentionally stale."
)
try:
    build_feature_status.validate_entries(stale_static_mapping_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains stale static-inspection evidence wording" not in message
        or "UI-001: Static source/test mapping" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject stale static source/test mapping wording")

stale_static_only_fixture = [dict(row) for row in rows]
stale_static_only_fixture[0]["Errors documented"] = (
    "This pass replaced static-only menu evidence with deterministic coverage."
)
try:
    build_feature_status.validate_entries(stale_static_only_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains stale static-inspection evidence wording" not in message
        or "UI-001: static-only" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject stale static-only evidence wording")

stale_static_inspection_fixture = [dict(row) for row in rows]
stale_static_inspection_fixture[0]["Errors documented"] = (
    "The row previously relied on static inspection rather than deterministic coverage."
)
try:
    build_feature_status.validate_entries(stale_static_inspection_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains stale static-inspection evidence wording" not in message
        or "UI-001: static inspection" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject stale static inspection wording")

stale_statically_inspected_fixture = [dict(row) for row in rows]
stale_statically_inspected_fixture[0]["Errors documented"] = (
    "The option labels were only statically inspected."
)
try:
    build_feature_status.validate_entries(stale_statically_inspected_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains stale static-inspection evidence wording" not in message
        or "UI-001: statically inspected" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject stale statically-inspected evidence wording")

stale_static_evidence_fixture = [dict(row) for row in rows]
stale_static_evidence_fixture[0]["Errors documented"] = (
    "Signed JSON export behavior only had static evidence."
)
try:
    build_feature_status.validate_entries(stale_static_evidence_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains stale static-inspection evidence wording" not in message
        or "UI-001: static evidence" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject stale static-evidence wording")

stale_static_typecheck_fixture = [dict(row) for row in rows]
stale_static_typecheck_fixture[0]["Notes"] = (
    "The on-chain path remains covered by static/UI typecheck."
)
try:
    build_feature_status.validate_entries(stale_static_typecheck_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains stale static-inspection evidence wording" not in message
        or "UI-001: static/UI typecheck" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject stale static/UI typecheck wording")

vague_coverage_deflection_fixture = [dict(row) for row in rows]
vague_coverage_deflection_fixture[0]["Retest status"] = (
    "Passed for deterministic coverage; live provider submission remains covered by separate network/runtime blockers."
)
try:
    build_feature_status.validate_entries(vague_coverage_deflection_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains vague coverage deflection wording" not in message
        or "UI-001: remains covered" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague coverage deflection wording")

vague_future_feature_fixture = [dict(row) for row in rows]
vague_future_feature_fixture[0]["Notes"] = (
    "A real UI is still a future feature, tracked separately from this row."
)
try:
    build_feature_status.validate_entries(vague_future_feature_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains vague future-feature wording" not in message
        or "UI-001: future feature" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague future-feature wording")

vague_shell_unavailable_fixture = [dict(row) for row in rows]
vague_shell_unavailable_fixture[0]["Notes"] = (
    "Runtime visual verification is pending because screenshot inspection is unavailable from this shell."
)
try:
    build_feature_status.validate_entries(vague_shell_unavailable_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains vague shell-unavailable wording" not in message
        or "UI-001: unavailable from this shell" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague shell-unavailable wording")

vague_shell_cannot_fixture = [dict(row) for row in rows]
vague_shell_cannot_fixture[0]["Retest status"] = (
    "Revoke behavior remains pending because this shell cannot seed paired session state."
)
try:
    build_feature_status.validate_entries(vague_shell_cannot_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains vague shell-unavailable wording" not in message
        or "UI-001: because this shell cannot" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague shell-cannot wording")

vague_must_verify_fixture = [dict(row) for row in rows]
vague_must_verify_fixture[0]["Notes"] = (
    "Signed-app native UI automation still must verify target-add sheet rendering."
)
try:
    build_feature_status.validate_entries(vague_must_verify_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains vague must-verify wording" not in message
        or "UI-001: must verify" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague must-verify wording")

vague_not_yet_fixture = [dict(row) for row in rows]
vague_not_yet_fixture[0]["Errors documented"] = (
    "Notification remediation is printed if Bastion is not yet listed."
)
try:
    build_feature_status.validate_entries(vague_not_yet_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains vague not-yet wording" not in message
        or "UI-001: not yet" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague not-yet wording")

vague_partial_prefix_fixture = [dict(row) for row in rows]
vague_partial_prefix_fixture[0]["Retest status"] = (
    "Partial: deterministic checks passed and runtime closure remains separate."
)
try:
    build_feature_status.validate_entries(vague_partial_prefix_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains vague Partial-prefix wording" not in message
        or "UI-001: Partial:" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague Partial-prefix wording")

vague_partial_signed_app_runtime_fixture = [dict(row) for row in rows]
vague_partial_signed_app_runtime_fixture[0]["Retest status"] = (
    "Partial signed-app runtime: boundary check reached the service."
)
try:
    build_feature_status.validate_entries(vague_partial_signed_app_runtime_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains vague partial signed-app runtime wording" not in message
        or "UI-001: Partial signed-app runtime" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague partial signed-app runtime wording")

vague_pending_native_fixture = [dict(row) for row in rows]
vague_pending_native_fixture[0]["Retest status"] = (
    "Live menu-bar click/runtime behavior is still pending native signed-app UI automation."
)
try:
    build_feature_status.validate_entries(vague_pending_native_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains vague pending-native wording" not in message
        or "UI-001: still pending native signed-app UI automation" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague pending-native wording")

vague_remains_pending_native_fixture = [dict(row) for row in rows]
vague_remains_pending_native_fixture[0]["Retest status"] = (
    "Settings sidebar visual verification remains pending native signed-app UI automation."
)
try:
    build_feature_status.validate_entries(vague_remains_pending_native_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains vague pending-native wording" not in message
        or "UI-001: remains pending native signed-app UI automation" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague remains-pending-native wording")

vague_remain_pending_native_fixture = [dict(row) for row in rows]
vague_remain_pending_native_fixture[0]["Retest status"] = (
    "Settings sidebar visual checks remain pending native signed-app UI automation."
)
try:
    build_feature_status.validate_entries(vague_remain_pending_native_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains vague pending-native wording" not in message
        or "UI-001: remain pending native signed-app UI automation" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague remain-pending-native wording")

vague_pending_native_observation_fixture = [dict(row) for row in rows]
vague_pending_native_observation_fixture[0]["Notes"] = (
    "Signed-app visual verification remains pending native UI observation."
)
try:
    build_feature_status.validate_entries(vague_pending_native_observation_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains vague pending-native wording" not in message
        or "UI-001: pending native UI observation" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague pending-native-observation wording")

vague_still_pending_fixture = [dict(row) for row in rows]
vague_still_pending_fixture[0]["Retest status"] = (
    "Runtime prompt rendering is still pending signed-app native UI observation."
)
try:
    build_feature_status.validate_entries(vague_still_pending_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains vague still-pending wording" not in message
        or "UI-001: still pending" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague still-pending wording")

vague_remains_pending_fixture = [dict(row) for row in rows]
vague_remains_pending_fixture[0]["Retest status"] = (
    "Successful signature JSON remains pending."
)
try:
    build_feature_status.validate_entries(vague_remains_pending_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains vague remains-pending wording" not in message
        or "UI-001: remains pending" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague remains-pending wording")

vague_still_requires_fixture = [dict(row) for row in rows]
vague_still_requires_fixture[0]["Retest status"] = (
    "Successful signature JSON still require paired-client runtime evidence."
)
try:
    build_feature_status.validate_entries(vague_still_requires_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains vague still-requires wording" not in message
        or "UI-001: still require" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague still-requires wording")

vague_app_bundler_pending_fixture = [dict(row) for row in rows]
vague_app_bundler_pending_fixture[0]["Retest status"] = (
    "Real UserOperation signing/submission remains pending app/bundler runtime."
)
try:
    build_feature_status.validate_entries(vague_app_bundler_pending_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains vague runtime-placeholder wording" not in message
        or "UI-001: pending app/bundler runtime" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague app/bundler-pending wording")

vague_app_network_pending_fixture = [dict(row) for row in rows]
vague_app_network_pending_fixture[0]["Retest status"] = (
    "Live chain receipt polling remains pending app/network runtime."
)
try:
    build_feature_status.validate_entries(vague_app_network_pending_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains vague runtime-placeholder wording" not in message
        or "UI-001: pending app/network runtime" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague app/network-pending wording")

vague_app_runtime_testing_fixture = [dict(row) for row in rows]
vague_app_runtime_testing_fixture[0]["Retest status"] = (
    "Secure Enclave integration remains pending app/runtime testing."
)
try:
    build_feature_status.validate_entries(vague_app_runtime_testing_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains vague runtime-placeholder wording" not in message
        or "UI-001: pending app/runtime testing" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague app/runtime-testing wording")

vague_runtime_dependent_fixture = [dict(row) for row in rows]
vague_runtime_dependent_fixture[0]["Retest status"] = (
    "Final signed-app verification remains runtime dependent."
)
try:
    build_feature_status.validate_entries(vague_runtime_dependent_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains vague runtime-dependent wording" not in message
        or "UI-001: runtime dependent" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague runtime-dependent wording")

vague_runtime_ui_pending_fixture = [dict(row) for row in rows]
vague_runtime_ui_pending_fixture[0]["Retest status"] = (
    "Signed-app native click path remains pending runtime/UI automation."
)
try:
    build_feature_status.validate_entries(vague_runtime_ui_pending_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains vague runtime-placeholder wording" not in message
        or "UI-001: pending runtime/UI automation" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague runtime/UI-pending wording")

vague_signed_app_app_runtime_fixture = [dict(row) for row in rows]
vague_signed_app_app_runtime_fixture[0]["Retest status"] = (
    "Runtime service/XPC smoke remains pending signed-app app-runtime evidence."
)
try:
    build_feature_status.validate_entries(vague_signed_app_app_runtime_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains vague signed-app app-runtime wording" not in message
        or "UI-001: pending signed-app app-runtime evidence" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague signed-app app-runtime wording")

vague_signed_app_runtime_fixture = [dict(row) for row in rows]
vague_signed_app_runtime_fixture[0]["Retest status"] = (
    "Runtime service/XPC smoke remains pending signed-app runtime evidence."
)
try:
    build_feature_status.validate_entries(vague_signed_app_runtime_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains vague signed-app app-runtime wording" not in message
        or "UI-001: pending signed-app runtime evidence" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague signed-app runtime wording")

vague_requires_app_runtime_evidence_fixture = [dict(row) for row in rows]
vague_requires_app_runtime_evidence_fixture[0]["Fix status"] = (
    "Fixed deterministic coverage; live signing still requires app-runtime evidence."
)
try:
    build_feature_status.validate_entries(vague_requires_app_runtime_evidence_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains vague requires-app-runtime-evidence wording" not in message
        or "UI-001: requires app-runtime evidence" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague requires-app-runtime-evidence wording")

vague_pending_rebuild_fixture = [dict(row) for row in rows]
vague_pending_rebuild_fixture[0]["Fix status"] = (
    "Fixed parser validation; signed-app retest pending rebuild."
)
try:
    build_feature_status.validate_entries(vague_pending_rebuild_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains vague pending-rebuild wording" not in message
        or "UI-001: pending rebuild" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague pending-rebuild wording")

vague_xcode_only_blocker_fixture = [dict(row) for row in rows]
vague_xcode_only_blocker_fixture[0]["Notes"] = (
    "Deterministic Swift gate passes; no separate xcodebuild-only blocker remains for this row."
)
try:
    build_feature_status.validate_entries(vague_xcode_only_blocker_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "tracker source contains vague xcodebuild-only blocker wording" not in message
        or "UI-001: xcodebuild-only blocker" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject vague xcodebuild-only blocker wording")

wrong_retest_artifact = Path(tempfile.mkstemp(prefix="bastion_wrong_source_retest_artifact.")[1])
wrong_retest_artifact.write_text("Result pass. This artifact is intentionally unrelated to the first canonical tracker row.\n")
artifact_fixture = [dict(row) for row in rows]
artifact_fixture[0]["Retest status"] = (
    f"Passed fixture retest for {artifact_fixture[0]['ID']} {artifact_fixture[0]['Feature']}. "
    f"Evidence: {artifact_fixture[0]['ID']} {artifact_fixture[0]['Feature']}. Artifact: {wrong_retest_artifact}"
)
try:
    build_feature_status.validate_entries(artifact_fixture)
except SystemExit as exc:
    message = str(exc)
    if "Retest status artifact evidence is invalid:" not in message or "UI-001: Retest artifact must mention the row ID" not in message:
        raise
else:
    raise SystemExit("tracker builder must reject retest artifacts that do not support the tracker row")

signed_boundary_artifact_fixture = [dict(row) for row in rows]
for row in signed_boundary_artifact_fixture:
    if row["ID"] == "UI-001":
        row["Retest status"] = (
            f"Current signed-app boundary evidence for {row['ID']} {row['Feature']} lacks a clean artifact citation."
        )
        break
else:
    raise SystemExit("canonical tracker must contain UI-001 for signed-boundary artifact fixture")
try:
    build_feature_status.validate_entries(signed_boundary_artifact_fixture)
except SystemExit as exc:
    message = str(exc)
    if (
        "app-runtime rows with signed-app boundary evidence must cite Artifact: in the source row" not in message
        or "UI-001: Retest status" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject signed-app boundary source evidence without Artifact")

coverage_fixture = [dict(row) for row in rows]
for row in coverage_fixture:
    if row["ID"] == "CLI-009":
        row["Code evidence"] = row["Code evidence"].replace("; scripts/release-ci.sh", "")
        break
try:
    build_feature_status.validate_entries(coverage_fixture)
except SystemExit as exc:
    message = str(exc)
    if "feature code files missing from tracker evidence:" not in message or "scripts/release-ci.sh" not in message:
        raise
else:
    raise SystemExit("tracker builder must reject unmapped feature-code files")

stale_count_fixture = [dict(row) for row in rows]
current_template_phrase = f"{app_runtime_row_count}-row JSON runtime evidence template"
for row in stale_count_fixture:
    if row["ID"] == "QA-001":
        row["Test evidence"] = row["Test evidence"].replace(
            current_template_phrase,
            "66-row JSON runtime evidence template",
        )
        break
try:
    build_feature_status.validate_entries(stale_count_fixture)
except SystemExit as exc:
    message = str(exc)
    if "QA-001 tracker evidence contains stale app-runtime row-count wording: 66-row" not in message:
        raise
else:
    raise SystemExit("tracker builder must reject stale QA-001 app-runtime row-count evidence")

stale_non_core_fixture = [dict(row) for row in rows]
current_user_story_phrase = f"{app_runtime_row_count} app-runtime user-story rows"
for row in stale_non_core_fixture:
    if row["ID"] == "QA-001":
        row["Errors documented"] = row["Errors documented"].replace(
            current_user_story_phrase,
            "non-core runtime-pending user-story rows",
        )
        break
try:
    build_feature_status.validate_entries(stale_non_core_fixture)
except SystemExit as exc:
    message = str(exc)
    if "QA-001 tracker evidence contains stale app-runtime row-count wording: non-core runtime-pending" not in message:
        raise
else:
    raise SystemExit("tracker builder must reject stale QA-001 non-core runtime-pending wording")

stale_xcode_fixture = [dict(row) for row in rows]
for row in stale_xcode_fixture:
    if row["ID"] == "UI-006":
        row["Notes"] = "Full xcodebuild test still requires a full Xcode developer directory."
        break
try:
    build_feature_status.validate_entries(stale_xcode_fixture)
except SystemExit as exc:
    message = str(exc)
    if "tracker source contains stale Xcode/runtime blocker wording" not in message:
        raise
else:
    raise SystemExit("tracker builder must reject stale Xcode/runtime blocker wording")

stale_full_app_runtime_fixture = [dict(row) for row in rows]
for row in stale_full_app_runtime_fixture:
    if row["ID"] == "UI-002":
        row["Retest status"] = (
            "Passed through qa/run_available_checks.sh deterministic Swift runner; "
            "live menu-bar click/runtime behavior still pending full app runtime."
        )
        break
try:
    build_feature_status.validate_entries(stale_full_app_runtime_fixture)
except SystemExit as exc:
    message = str(exc)
    if "tracker source contains stale Xcode/runtime blocker wording" not in message or "full app runtime" not in message:
        raise
else:
    raise SystemExit("tracker builder must reject stale full app runtime wording")

stale_app_run_fixture = [dict(row) for row in rows]
for row in stale_app_run_fixture:
    if row["ID"] == "UI-001":
        row["Retest status"] = (
            "Passed through qa/run_available_checks.sh deterministic Swift runner; "
            "live menu-bar visual/runtime behavior still pending app run."
        )
        break
try:
    build_feature_status.validate_entries(stale_app_run_fixture)
except SystemExit as exc:
    message = str(exc)
    if "tracker source contains stale Xcode/runtime blocker wording" not in message or "pending app run" not in message:
        raise
else:
    raise SystemExit("tracker builder must reject stale pending app run wording")

stale_manual_ui_fixture = [dict(row) for row in rows]
for row in stale_manual_ui_fixture:
    if row["ID"] == "UI-008":
        row["Retest status"] = (
            "Passed through qa/run_available_checks.sh deterministic Swift runner; "
            "manual visual sidebar click verification remains pending."
        )
        break
try:
    build_feature_status.validate_entries(stale_manual_ui_fixture)
except SystemExit as exc:
    message = str(exc)
    if "tracker source contains stale manual UI-proof wording" not in message or "manual visual" not in message:
        raise
else:
    raise SystemExit("tracker builder must reject stale manual UI-proof wording")

all_pass_live = [dict(row) for row in rows]
for row in all_pass_live:
    if row["ID"] in LIVE_RUNTIME_BLOCKED_IDS:
        row["Test status"] = "Pass"
        row["Retest status"] = f"Passed signed-app live-runtime sweep for {row['ID']} {row['Feature']}. Evidence: Artifact: {live_runtime_context_artifact}"
build_feature_status.validate_entries(all_pass_live)

partial_live = [dict(row) for row in rows]
for row in partial_live:
    if row["ID"] == sorted(LIVE_RUNTIME_BLOCKED_IDS)[0]:
        row["Test status"] = "Pass"
        row["Retest status"] = f"Passed signed-app live-runtime sweep for {row['ID']} {row['Feature']}. Evidence: Artifact: {live_runtime_context_artifact}"
        break
build_feature_status.validate_entries(partial_live)

unexpected_blocked_live = [dict(row) for row in rows]
for row in unexpected_blocked_live:
    if row["ID"] == "UI-001":
        row["Test status"] = "Blocked in this environment"
        row["Retest status"] = (
            f"Blocked pending live-runtime prerequisite retest for {row['ID']} {row['Feature']}. "
            f"Evidence: {build_feature_status.LIVE_RUNTIME_GATE}. Artifact: {live_runtime_context_artifact}"
        )
        break
try:
    build_feature_status.validate_entries(unexpected_blocked_live)
except SystemExit as exc:
    message = str(exc)
    if (
        "Blocked-in-environment rows must be part of the canonical live-runtime gate until individually closed"
        not in message
        or "unexpected blocked rows: UI-001" not in message
    ):
        raise
else:
    raise SystemExit("tracker builder must reject non-live-runtime blocked rows")
PY

echo "== Address book validation UX regression guard =="
python3 - <<'PY'
from pathlib import Path

source = Path("bastion/UI/RulesSettingsView.swift").read_text()
if 'Button("Add") { addEntry() }' not in source:
    raise SystemExit("AddressBookPanel Add button must continue routing through addEntry validation")
if ".disabled(newAddress.isEmpty || newLabel.isEmpty)" in source:
    raise SystemExit("AddressBookPanel Add button must not silently disable blank-field validation")
if "addError = draft.validationMessage" not in source:
    raise SystemExit("AddressBookPanel addEntry must surface draft validation messages inline")
if 'Text("×")' in source:
    raise SystemExit("Settings remove controls must not expose bare x glyph labels")
for required in (
    "TargetAllowlistRowPresentation.make",
    "AddressBookRowPresentation.make",
    ".accessibilityLabel(presentation.removeAccessibilityLabel)",
    ".help(presentation.removeHelp)",
):
    if required not in source:
        raise SystemExit(f"Settings remove controls must retain labelled remove UX: {required}")
PY

echo "== Wallet group XPC auth regression guard =="
python3 - <<'PY'
from pathlib import Path

source = Path("bastion/IPC/XPCServer.swift").read_text()

def function_body(name: str) -> str:
    marker = f"nonisolated func {name}"
    start = source.find(marker)
    if start == -1:
        raise SystemExit(f"missing XPC handler: {name}")
    next_marker = source.find("\n    nonisolated func ", start + len(marker))
    if next_marker == -1:
        next_marker = source.find("\n    // MARK:", start + len(marker))
    if next_marker == -1:
        raise SystemExit(f"could not find end of XPC handler: {name}")
    return source[start:next_marker]

list_body = function_body("listWalletGroups")
if "AuthManager.shared.authenticate" in list_body:
    raise SystemExit("listWalletGroups must remain read-only and non-interactive")
if "ruleEngine.listWalletGroups()" not in list_body:
    raise SystemExit("listWalletGroups must read wallet groups from the rule engine")

show_body = function_body("getWalletGroup")
if "AuthManager.shared.authenticate" not in show_body:
    raise SystemExit("getWalletGroup must retain owner authentication")
if "Authenticate to view wallet group" not in show_body:
    raise SystemExit("getWalletGroup owner-auth reason changed unexpectedly")
PY

echo "== Approval panel chrome regression guard =="
python3 - <<'PY'
from pathlib import Path

source = Path("bastion/UI/SigningRequestView.swift").read_text()
if "backgroundDesktop" in source or "bastionDesktopTop" in source or "bastionDesktopBottom" in source:
    raise SystemExit("SigningRequestView must not draw a desktop backdrop inside the approval panel")
if "styleMask: chrome.styleMask" not in source or "styleMask: [.borderless, .nonactivatingPanel]" not in source:
    raise SystemExit("SigningRequestPanelManager must use a borderless nonactivating panel")
if ".titled" in source or ".closable" in source or ".fullSizeContentView" in source:
    raise SystemExit("SigningRequestPanelManager must not restore native titlebar/close chrome")
if "newPanel.hasShadow = chrome.hasNativeShadow" not in source or "hasNativeShadow: false" not in source:
    raise SystemExit("SigningRequestPanelManager must disable the transparent native panel shadow")
if "newPanel.backgroundColor = chrome.hasClearBackground ? .clear : .windowBackgroundColor" not in source or "hasClearBackground: true" not in source:
    raise SystemExit("SigningRequestPanelManager must keep the native panel background clear")
if "usesTransparentHostView: true" not in source or "hostingView.wantsLayer = true" not in source:
    raise SystemExit("SigningRequestPanelManager must keep the SwiftUI hosting view transparent")
if "hostingView.layer?.backgroundColor = NSColor.clear.cgColor" not in source or "hostingView.layer?.isOpaque = false" not in source:
    raise SystemExit("SigningRequestPanelManager must not let the hosting view paint a nested panel backing")
if "hostWidth" in source or "minimumHostWidth" in source or "minimumHostHeight" in source:
    raise SystemExit("SigningRequestView must not restore a larger host box around the approval card")
if "contentRect(fitting: fittingSize)" not in source or "hostingView.fittingSize.height" not in source:
    raise SystemExit("SigningRequestPanelManager must size the native panel from approval-card fitting height")
if "hostingView.frame = NSRect(origin: .zero, size: fittingSize)" not in source:
    raise SystemExit("SigningRequestPanelManager must size the hosting view exactly to the card content")
if "private var scrollableContent: some View" not in source or "ScrollView(.vertical)" not in source:
    raise SystemExit("SigningRequestView must keep variable approval details in a vertical scroll region")
if ".frame(maxHeight: SigningRequestPanelChrome.current.detailScrollMaxHeight)" not in source or "detailScrollMaxHeight: 392" not in source:
    raise SystemExit("SigningRequestView approval detail scroll region must stay bounded inside the panel")
PY

echo "== Swift app typecheck =="
SOURCE_LIST="$(mktemp "$TMP_ROOT/bastion_sources.XXXXXX")"
find BastionShared bastion -name '*.swift' \
  | sort \
  | sed '/BastionShared\/BastionXPCProtocol.swift/d' > "$SOURCE_LIST"
SOURCE_FILES=()
while IFS= read -r source_file; do
  SOURCE_FILES+=("$source_file")
done < "$SOURCE_LIST"
settle_swift_inputs
swiftc -typecheck \
  -DDEBUG \
  -import-objc-header bastion/Crypto/bastion-Bridging-Header.h \
  "${SOURCE_FILES[@]}"

echo "== Swift test target typecheck =="
TEST_MODULE_DIR="$(mktemp -d "$TMP_ROOT/bastion-testcheck.XXXXXX")"
TEST_SOURCE_LIST="$(mktemp "$TMP_ROOT/bastion_test_sources.XXXXXX")"

swiftc -emit-module -parse-as-library -enable-testing \
  -DDEBUG \
  -module-name bastion \
  -emit-module-path "$TEST_MODULE_DIR/bastion.swiftmodule" \
  -import-objc-header bastion/Crypto/bastion-Bridging-Header.h \
  "${SOURCE_FILES[@]}"

DEVELOPER_DIR_PATH="$(xcode-select -p)"
TESTING_FRAMEWORK="$DEVELOPER_DIR_PATH/Platforms/MacOSX.platform/Developer/Library/Frameworks/Testing.framework"
if [[ ! -d "$TESTING_FRAMEWORK" ]]; then
  TESTING_FRAMEWORK="$(find "$DEVELOPER_DIR_PATH" -name Testing.framework -type d -print -quit)"
fi
TESTING_MACROS="$(find "$DEVELOPER_DIR_PATH" -name libTestingMacros.dylib -type f -print -quit)"

if [[ -z "$TESTING_FRAMEWORK" || -z "$TESTING_MACROS" ]]; then
  echo "Swift Testing framework or macro plugin not found under $DEVELOPER_DIR_PATH."
  exit 1
fi

find bastionTests -name '*.swift' | sort > "$TEST_SOURCE_LIST"
TEST_SOURCE_FILES=()
while IFS= read -r test_source_file; do
  TEST_SOURCE_FILES+=("$test_source_file")
done < "$TEST_SOURCE_LIST"
settle_swift_inputs
swiftc -typecheck -enable-testing \
  -I "$TEST_MODULE_DIR" \
  -F "$(dirname "$TESTING_FRAMEWORK")" \
  -load-plugin-library "$TESTING_MACROS" \
  -import-objc-header bastionTests/Crypto/bastionTests-Bridging-Header.h \
  "${TEST_SOURCE_FILES[@]}"

echo "== Deterministic Swift tests =="
OPENSSL_ROOT="/opt/homebrew/opt/openssl@3"
if [ ! -f "$OPENSSL_ROOT/lib/libcrypto.a" ]; then
  echo "OpenSSL static library not found at $OPENSSL_ROOT/lib/libcrypto.a."
  exit 1
fi
if [ ! -f "$OPENSSL_ROOT/include/openssl/evp.h" ]; then
  echo "OpenSSL headers not found at $OPENSSL_ROOT/include/openssl/evp.h."
  exit 1
fi

TEST_RUN_DIR="$(mktemp -d "$TMP_ROOT/bastion-test-run.XXXXXX")"
cp qa/DeterministicRunner.swift "$TEST_RUN_DIR/Runner.swift"

clang -c bastion/Crypto/keccak256.c -o "$TEST_RUN_DIR/keccak256.o"
# The Swift driver rejects inputs whose mtimes appear newer than the build
# start. Pin generated object mtimes to a stable past timestamp.
touch -t 200001010000 "$TEST_RUN_DIR/keccak256.o"
swiftc -emit-library -parse-as-library -enable-testing \
  -DDEBUG \
  -module-name bastion \
  -emit-module-path "$TEST_RUN_DIR/bastion.swiftmodule" \
  -import-objc-header bastion/Crypto/bastion-Bridging-Header.h \
  -o "$TEST_RUN_DIR/libbastion.dylib" \
  "${SOURCE_FILES[@]}" "$TEST_RUN_DIR/keccak256.o"

clang -I"$OPENSSL_ROOT/include" -Wno-deprecated-declarations \
  -c bastionTests/Crypto/secp256k1_helper.c \
  -o "$TEST_RUN_DIR/secp256k1_helper.o"
touch -t 200001010000 "$TEST_RUN_DIR/secp256k1_helper.o"

settle_swift_inputs
swiftc \
  -DDEBUG \
  -I "$TEST_RUN_DIR" \
  -L "$TEST_RUN_DIR" \
  -l bastion \
  -F "$(dirname "$TESTING_FRAMEWORK")" \
  -load-plugin-library "$TESTING_MACROS" \
  -import-objc-header bastionTests/Crypto/bastionTests-Bridging-Header.h \
  "${TEST_SOURCE_FILES[@]}" \
  "$TEST_RUN_DIR/Runner.swift" \
  "$TEST_RUN_DIR/secp256k1_helper.o" \
  "$OPENSSL_ROOT/lib/libcrypto.a" \
  -Xlinker -rpath -Xlinker "$TEST_RUN_DIR" \
  -Xlinker -rpath -Xlinker "$(dirname "$TESTING_FRAMEWORK")" \
  -Xlinker -rpath -Xlinker "$DEVELOPER_DIR_PATH/Library/Developer/usr/lib" \
  -o "$TEST_RUN_DIR/bastion-tests"

DETERMINISTIC_TEST_FILTER="AuditFindingsRegressionTests|AuditLogHMACTests|AuditLogRedactionTests|AuditLogTests|BastionConfigMigrationTests|BundlerTrustResolverPrecedenceTests|CLIInstallerTests|CalldataDecoderTests|DataHexTests|ECDSAValidatorTests|EIP191Tests|EIP712Tests|Keccak256Tests|KernelEncodingTests|KernelModuleTests|MergedPolicyTests|P256CurveTests|P256SmartAccountTests|PermitClassifierTests|PreflightDebugExportTests|RLPTests|RawMessagePolicyTests|ReleaseUpdateTests|RequestExecutionModeTests|RequestFlowIntegrationTests|RiskScorerTests|RuleEngineConfigBackupTests|RuleEngineConfigTests|RuleEngineGroupLifecycleTests|RuleEngineValidationTests|RuleMergeTests|SecurityConfigurationTests|ServiceUIBridgeTests|SessionReconcilerTests|SessionStoreReconcileTests|SigningManagerAuthPolicyTests|SigningPostureTests|SilentBannerTests|SmartAccountTests|StateStoreRateLimitTests|StateStoreSpendingLimitTests|SubmissionStatusStoreTests|SupportBundleTests|TokenConfigTests|UserOpHashTests|UserOperationCodableTests|UserOperationFeeEstimationTests|UserOperationIntentEnvelopeTests|UserOperationSubmissionEnvelopeTests|WalletGroupModelTests|XPCSecurityTests|ZeroDevProviderResilienceTests"
DETERMINISTIC_TEST_SUMMARY="Test run with 444 tests in 53 suites passed"
BASTION_TEST_FILTER="$DETERMINISTIC_TEST_FILTER" "$TEST_RUN_DIR/bastion-tests" 2>&1 | tee "$TEST_RUN_DIR/test-output.log"
grep -F "$DETERMINISTIC_TEST_SUMMARY" "$TEST_RUN_DIR/test-output.log" >/dev/null

echo "== Service lifecycle diagnostic script =="
SERVICE_DIAG_DIR="$TMP_ROOT/bastion-service-diag"
rm -rf "$SERVICE_DIAG_DIR"
mkdir -p "$SERVICE_DIAG_DIR/home/Library/LaunchAgents"

VALID_APP="$SERVICE_DIAG_DIR/Valid/Bastion.app"
mkdir -p \
  "$VALID_APP/Contents/MacOS" \
  "$VALID_APP/Contents/Library/LaunchAgents"
printf '#!/bin/sh\nexit 0\n' > "$VALID_APP/Contents/MacOS/bastion"
printf '#!/bin/sh\nexit 1\n' > "$VALID_APP/Contents/MacOS/bastion-cli"
chmod +x "$VALID_APP/Contents/MacOS/bastion" "$VALID_APP/Contents/MacOS/bastion-cli"
cat > "$VALID_APP/Contents/Library/LaunchAgents/com.bastion.xpc.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.bastion.xpc</string>
  <key>BundleProgram</key>
  <string>Contents/MacOS/bastion</string>
  <key>MachServices</key>
  <dict>
    <key>com.bastion.xpc</key>
    <true/>
  </dict>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
</dict>
</plist>
EOF
VALID_LOG="$SERVICE_DIAG_DIR/valid.log"
HOME="$SERVICE_DIAG_DIR/home" scripts/diagnose-service-lifecycle.sh "$VALID_APP" >"$VALID_LOG" 2>&1
if grep -F "FAIL:" "$VALID_LOG" >/dev/null; then
  echo "Expected valid service lifecycle diagnostic fixture to have no failures."
  cat "$VALID_LOG"
  exit 1
fi

BROKEN_APP="$SERVICE_DIAG_DIR/Broken/Bastion.app"
mkdir -p \
  "$BROKEN_APP/Contents/MacOS" \
  "$BROKEN_APP/Contents/Library/LaunchAgents"
printf '#!/bin/sh\nexit 0\n' > "$BROKEN_APP/Contents/MacOS/bastion"
chmod +x "$BROKEN_APP/Contents/MacOS/bastion"
cat > "$BROKEN_APP/Contents/Library/LaunchAgents/com.bastion.xpc.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.example.wrong</string>
  <key>BundleProgram</key>
  <string>/tmp/bastion</string>
  <key>MachServices</key>
  <dict>
    <key>com.bastion.xpc</key>
    <false/>
  </dict>
</dict>
</plist>
EOF
BROKEN_LOG="$SERVICE_DIAG_DIR/broken.log"
if HOME="$SERVICE_DIAG_DIR/home" scripts/diagnose-service-lifecycle.sh "$BROKEN_APP" >"$BROKEN_LOG" 2>&1; then
  echo "Expected malformed service lifecycle diagnostic fixture to fail."
  exit 1
fi
grep -F "LaunchAgent Label is com.example.wrong" "$BROKEN_LOG" >/dev/null
grep -F "MachServices.com.bastion.xpc is not true" "$BROKEN_LOG" >/dev/null
grep -F "BundleProgram must be app-bundle relative" "$BROKEN_LOG" >/dev/null
grep -F "KeepAlive.SuccessfulExit must be false" "$BROKEN_LOG" >/dev/null

echo "== Release verifier prerequisite gate =="
RELEASE_GATE_DIR="$(mktemp -d "$TMP_ROOT/bastion-release-gate.XXXXXX")"
mkdir -p "$RELEASE_GATE_DIR/Bastion.app/Contents"
RELEASE_GATE_LOG="$RELEASE_GATE_DIR/missing-info.log"
if scripts/release-verify.sh "$RELEASE_GATE_DIR/Bastion.app" >"$RELEASE_GATE_LOG" 2>&1; then
  echo "Expected release verifier to fail for app bundle missing Info.plist."
  exit 1
fi
grep -F "Info.plist missing at ${RELEASE_GATE_DIR}/Bastion.app/Contents/Info.plist" "$RELEASE_GATE_LOG" >/dev/null

echo "== Live lifecycle verifier prerequisite gate =="
LIVE_GATE_DIR="$(mktemp -d "$TMP_ROOT/bastion-live-gate.XXXXXX")"
mkdir -p "$LIVE_GATE_DIR/home" "$LIVE_GATE_DIR/evidence"
LIVE_GATE_APP="$LIVE_GATE_DIR/home/Applications/Bastion Dev.app"
LIVE_GATE_LOG="$LIVE_GATE_DIR/missing-app.log"
if HOME="$LIVE_GATE_DIR/home" \
  BASTION_LIFECYCLE_EVIDENCE_DIR="$LIVE_GATE_DIR/evidence" \
  scripts/verify-service-lifecycle-live.sh --app "$LIVE_GATE_APP" --phase missing-runtime >"$LIVE_GATE_LOG" 2>&1; then
  echo "Expected live lifecycle verifier to fail without a stable signed app."
  exit 1
fi
grep -F "App bundle not found at ${LIVE_GATE_APP}" "$LIVE_GATE_LOG" >/dev/null
grep -F "Install a signed stable build, then rerun:" "$LIVE_GATE_LOG" >/dev/null
grep -F "scripts/verify-service-lifecycle-live.sh --phase fresh-install --register" "$LIVE_GATE_LOG" >/dev/null

echo "== Canonical live runtime gate prerequisite mapping =="
LIVE_RUNTIME_GATE_LOG="$LIVE_GATE_DIR/live-runtime-gate.log"
HOME="$LIVE_GATE_DIR/home" \
  BASTION_LIFECYCLE_EVIDENCE_DIR="$LIVE_GATE_DIR/evidence" \
  qa/run_live_runtime_checks.sh --check-prereqs >"$LIVE_RUNTIME_GATE_LOG" 2>&1
grep -F "Feature rows covered: CORE-003 CORE-005 CORE-006 CORE-009 CORE-011 CORE-017" "$LIVE_RUNTIME_GATE_LOG" >/dev/null
grep -F "qa/run_live_runtime_checks.sh --write-template dist/live-runtime-evidence.json" "$LIVE_RUNTIME_GATE_LOG" >/dev/null
grep -F "qa/run_live_runtime_checks.sh --audit-row-evidence dist/live-runtime-evidence.json --require-pass" "$LIVE_RUNTIME_GATE_LOG" >/dev/null
python3 - "$LIVE_RUNTIME_GATE_LOG" <<'PY'
import sys
from pathlib import Path

log = Path(sys.argv[1]).read_text()
if "Xcode " not in log and "Full xcodebuild tests remain blocked, but installed-app live runtime phases can run when a signed stable app is present." not in log:
    raise SystemExit("live runtime prerequisite output must report full-Xcode availability or the documented CommandLineTools warning")
PY
grep -F "App bundle not found at ${LIVE_GATE_APP}" "$LIVE_RUNTIME_GATE_LOG" >/dev/null
grep -F "== Current-source signed app rebuild ==" "$LIVE_RUNTIME_GATE_LOG" >/dev/null
grep -F "Current-source status: Blocked" "$LIVE_RUNTIME_GATE_LOG" >/dev/null
grep -F "== Discovered app bundle candidates ==" "$LIVE_RUNTIME_GATE_LOG" >/dev/null
grep -F "Candidate status:" "$LIVE_RUNTIME_GATE_LOG" >/dev/null
python3 - "$LIVE_RUNTIME_GATE_LOG" <<'PY'
import sys
from pathlib import Path

log = Path(sys.argv[1]).read_text()
release_candidate = Path("dist/release/Bastion.app").resolve()
if release_candidate.is_dir() and str(release_candidate) not in log:
    raise SystemExit("live runtime prerequisite output must report existing dist/release/Bastion.app candidate")
PY
grep -F "Prerequisite-only mode records the blocker" "$LIVE_RUNTIME_GATE_LOG" >/dev/null
LIVE_RUNTIME_STRICT_GATE_LOG="$LIVE_GATE_DIR/live-runtime-strict-gate.log"
if HOME="$LIVE_GATE_DIR/home" \
  BASTION_LIFECYCLE_EVIDENCE_DIR="$LIVE_GATE_DIR/evidence" \
  qa/run_live_runtime_checks.sh --check-prereqs --require-prereqs >"$LIVE_RUNTIME_STRICT_GATE_LOG" 2>&1; then
  echo "Expected strict live runtime prereq gate to fail without a stable signed app."
  exit 1
fi
grep -F "App bundle not found at ${LIVE_GATE_APP}" "$LIVE_RUNTIME_STRICT_GATE_LOG" >/dev/null
LIVE_RUNTIME_REFRESH_BAD_MODE_LOG="$LIVE_GATE_DIR/live-runtime-refresh-bad-mode.log"
if qa/run_live_runtime_checks.sh --allow-stale-app-for-blocker-refresh --check-prereqs >"$LIVE_RUNTIME_REFRESH_BAD_MODE_LOG" 2>&1; then
  echo "Expected stale-app blocker refresh flag to be accepted only with --run-phase."
  exit 1
fi
grep -F "Usage:" "$LIVE_RUNTIME_REFRESH_BAD_MODE_LOG" >/dev/null

MALFORMED_GATE_APP="$LIVE_GATE_DIR/home/Applications/Malformed Bastion.app"
mkdir -p "$MALFORMED_GATE_APP/Contents/MacOS"
printf '#!/bin/sh\nexit 0\n' > "$MALFORMED_GATE_APP/Contents/MacOS/bastion"
chmod +x "$MALFORMED_GATE_APP/Contents/MacOS/bastion"
MALFORMED_LIVE_RUNTIME_GATE_LOG="$LIVE_GATE_DIR/malformed-live-runtime-gate.log"
HOME="$LIVE_GATE_DIR/home" \
  BASTION_APP_PATH="$MALFORMED_GATE_APP" \
  BASTION_LIFECYCLE_EVIDENCE_DIR="$LIVE_GATE_DIR/evidence" \
  qa/run_live_runtime_checks.sh --check-prereqs >"$MALFORMED_LIVE_RUNTIME_GATE_LOG" 2>&1
grep -F "App bundle Info.plist missing at ${MALFORMED_GATE_APP}/Contents/Info.plist" "$MALFORMED_LIVE_RUNTIME_GATE_LOG" >/dev/null
grep -F "Prerequisite-only mode records the blocker" "$MALFORMED_LIVE_RUNTIME_GATE_LOG" >/dev/null

INVALID_GATE_APP="$LIVE_GATE_DIR/home/Applications/Unsigned Bastion.app"
mkdir -p "$INVALID_GATE_APP/Contents/MacOS"
printf '#!/bin/sh\nexit 0\n' > "$INVALID_GATE_APP/Contents/MacOS/bastion"
chmod +x "$INVALID_GATE_APP/Contents/MacOS/bastion"
cat > "$INVALID_GATE_APP/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>bastion</string>
  <key>CFBundleIdentifier</key>
  <string>com.bastion.fixture</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
</dict>
</plist>
EOF
INVALID_LIVE_RUNTIME_GATE_LOG="$LIVE_GATE_DIR/invalid-live-runtime-gate.log"
HOME="$LIVE_GATE_DIR/home" \
  BASTION_APP_PATH="$INVALID_GATE_APP" \
  BASTION_LIFECYCLE_EVIDENCE_DIR="$LIVE_GATE_DIR/evidence" \
  qa/run_live_runtime_checks.sh --check-prereqs >"$INVALID_LIVE_RUNTIME_GATE_LOG" 2>&1
grep -F "App codesign verification failed for ${INVALID_GATE_APP}" "$INVALID_LIVE_RUNTIME_GATE_LOG" >/dev/null
grep -F "Prerequisite-only mode records the blocker" "$INVALID_LIVE_RUNTIME_GATE_LOG" >/dev/null

LIVE_RUNTIME_EXPECTED_COUNT="$(python3 qa/app_runtime_rows.py --live-count)"
LIVE_RUNTIME_TEMPLATE="$LIVE_GATE_DIR/live-runtime-evidence-template.json"
LIVE_RUNTIME_TEMPLATE_LOG="$LIVE_GATE_DIR/live-runtime-evidence-template.log"
qa/run_live_runtime_checks.sh --write-template "$LIVE_RUNTIME_TEMPLATE" >"$LIVE_RUNTIME_TEMPLATE_LOG" 2>&1
grep -F "Wrote live-runtime evidence template for ${LIVE_RUNTIME_EXPECTED_COUNT} user-story rows" "$LIVE_RUNTIME_TEMPLATE_LOG" >/dev/null
LIVE_RUNTIME_EXPECTED_TEMPLATE="$LIVE_GATE_DIR/live-runtime-evidence-expected.json"
python3 qa/app_runtime_rows.py --live-template >"$LIVE_RUNTIME_EXPECTED_TEMPLATE"
diff -u "$LIVE_RUNTIME_EXPECTED_TEMPLATE" "$LIVE_RUNTIME_TEMPLATE"
test "$(python3 -c 'import json, sys; print(len(json.load(open(sys.argv[1]))))' "$LIVE_RUNTIME_TEMPLATE")" = "$LIVE_RUNTIME_EXPECTED_COUNT"

LIVE_RUNTIME_ARTIFACT="$LIVE_GATE_DIR/live-runtime-artifacts/live-runtime-sweep.log"
export LIVE_RUNTIME_ARTIFACT
mkdir -p "$(dirname "$LIVE_RUNTIME_ARTIFACT")"
python3 - <<'PY' >"$LIVE_RUNTIME_ARTIFACT"
from qa.app_runtime_rows import live_runtime_evidence_template, tracker_rows

print("Observed signed app live runtime sweep for canonical QA rows.")
print("Supported fixture result tokens: Result pass. Result blocked.")
for row in live_runtime_evidence_template(tracker_rows()):
    print(f"ROW {row['ID']}")
    print("Supported row result tokens: Result pass. Result blocked.")
    print(f"{row['Feature']}: Result pass. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Observed signed app live-runtime flow.")
    print(f"Test instructions: {row['Test instructions']}")
PY
LIVE_RUNTIME_EVIDENCE_PASS="$LIVE_GATE_DIR/live-runtime-evidence-pass.json"
python3 - <<'PY' >"$LIVE_RUNTIME_EVIDENCE_PASS"
import json
import os

from qa.app_runtime_rows import live_runtime_evidence_template, tracker_rows

artifact = os.environ["LIVE_RUNTIME_ARTIFACT"]
evidence = live_runtime_evidence_template(tracker_rows())
for row in evidence:
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app live runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
print(json.dumps(evidence, indent=2))
PY
LIVE_RUNTIME_EVIDENCE_PASS_LOG="$LIVE_GATE_DIR/live-runtime-evidence-pass.log"
qa/run_live_runtime_checks.sh --audit-row-evidence "$LIVE_RUNTIME_EVIDENCE_PASS" >"$LIVE_RUNTIME_EVIDENCE_PASS_LOG" 2>&1
grep -F "Live-runtime row evidence audit passed for ${LIVE_RUNTIME_EXPECTED_COUNT} user-story rows." "$LIVE_RUNTIME_EVIDENCE_PASS_LOG" >/dev/null
LIVE_RUNTIME_EVIDENCE_MISSING_DIRECT_EXPECTED="$LIVE_GATE_DIR/live-runtime-evidence-missing-direct-expected.json"
python3 - "$LIVE_RUNTIME_EVIDENCE_PASS" <<'PY' >"$LIVE_RUNTIME_EVIDENCE_MISSING_DIRECT_EXPECTED"
import json
import sys
from pathlib import Path

evidence = json.loads(Path(sys.argv[1]).read_text())
expected = evidence[0]["Expected behaviour"]
evidence[0]["Evidence"] = evidence[0]["Evidence"].replace(f" Expected behaviour: {expected}", "", 1)
print(json.dumps(evidence, indent=2))
PY
LIVE_RUNTIME_EVIDENCE_MISSING_DIRECT_EXPECTED_LOG="$LIVE_GATE_DIR/live-runtime-evidence-missing-direct-expected.log"
if qa/run_live_runtime_checks.sh --audit-row-evidence "$LIVE_RUNTIME_EVIDENCE_MISSING_DIRECT_EXPECTED" >"$LIVE_RUNTIME_EVIDENCE_MISSING_DIRECT_EXPECTED_LOG" 2>&1; then
  echo "Expected live-runtime evidence missing direct Expected behaviour text to fail."
  exit 1
fi
grep -F "CORE-003: Evidence must mention the tracker Expected behaviour" "$LIVE_RUNTIME_EVIDENCE_MISSING_DIRECT_EXPECTED_LOG" >/dev/null
LIVE_RUNTIME_EVIDENCE_MISSING_DIRECT_TEST_INSTRUCTIONS="$LIVE_GATE_DIR/live-runtime-evidence-missing-direct-test-instructions.json"
python3 - "$LIVE_RUNTIME_EVIDENCE_PASS" <<'PY' >"$LIVE_RUNTIME_EVIDENCE_MISSING_DIRECT_TEST_INSTRUCTIONS"
import json
import sys
from pathlib import Path

evidence = json.loads(Path(sys.argv[1]).read_text())
test_instructions = evidence[0]["Test instructions"]
evidence[0]["Evidence"] = evidence[0]["Evidence"].replace(f" Test instructions: {test_instructions}", "", 1)
print(json.dumps(evidence, indent=2))
PY
LIVE_RUNTIME_EVIDENCE_MISSING_DIRECT_TEST_INSTRUCTIONS_LOG="$LIVE_GATE_DIR/live-runtime-evidence-missing-direct-test-instructions.log"
if qa/run_live_runtime_checks.sh --audit-row-evidence "$LIVE_RUNTIME_EVIDENCE_MISSING_DIRECT_TEST_INSTRUCTIONS" >"$LIVE_RUNTIME_EVIDENCE_MISSING_DIRECT_TEST_INSTRUCTIONS_LOG" 2>&1; then
  echo "Expected live-runtime evidence missing direct Test instructions text to fail."
  exit 1
fi
grep -F "CORE-003: Evidence must mention the tracker Test instructions" "$LIVE_RUNTIME_EVIDENCE_MISSING_DIRECT_TEST_INSTRUCTIONS_LOG" >/dev/null
LIVE_RUNTIME_EVIDENCE_BLOCKED_NO_RERUN="$LIVE_GATE_DIR/live-runtime-evidence-blocked-no-rerun.json"
python3 - <<'PY' >"$LIVE_RUNTIME_EVIDENCE_BLOCKED_NO_RERUN"
import json
import os

from qa.app_runtime_rows import live_runtime_evidence_template, tracker_rows

artifact = os.environ["LIVE_RUNTIME_ARTIFACT"]
evidence = live_runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "blocked" if index == 0 else "pass"
    row["Evidence"] = f"Observed signed app live runtime sweep completed with Result {row['Result']} for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    row["Errors"] = f"{row['ID']} {row['Feature']}: signed-app prerequisite blocked this live runtime row." if index == 0 else ""
print(json.dumps(evidence, indent=2))
PY
LIVE_RUNTIME_EVIDENCE_BLOCKED_NO_RERUN_LOG="$LIVE_GATE_DIR/live-runtime-evidence-blocked-no-rerun.log"
if qa/run_live_runtime_checks.sh --audit-row-evidence "$LIVE_RUNTIME_EVIDENCE_BLOCKED_NO_RERUN" >"$LIVE_RUNTIME_EVIDENCE_BLOCKED_NO_RERUN_LOG" 2>&1; then
  echo "Expected blocked live-runtime evidence without a Rerun command to fail."
  exit 1
fi
grep -F "CORE-003: blocked Evidence must include a Rerun command" "$LIVE_RUNTIME_EVIDENCE_BLOCKED_NO_RERUN_LOG" >/dev/null
LIVE_RUNTIME_EVIDENCE_BLOCKED_MISSING_RERUN_COMMAND="$LIVE_GATE_DIR/live-runtime-evidence-blocked-missing-rerun-command.json"
python3 - <<'PY' >"$LIVE_RUNTIME_EVIDENCE_BLOCKED_MISSING_RERUN_COMMAND"
import json
import os

from qa.app_runtime_rows import live_runtime_evidence_template, tracker_rows

artifact = os.environ["LIVE_RUNTIME_ARTIFACT"]
evidence = live_runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "blocked" if index == 0 else "pass"
    row["Evidence"] = f"Observed signed app live runtime sweep completed with Result {row['Result']} for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    if index == 0:
        row["Evidence"] += " Rerun: qa/missing-live-runtime-rerun-command.sh"
    row["Errors"] = f"{row['ID']} {row['Feature']}: signed-app prerequisite blocked this live runtime row." if index == 0 else ""
print(json.dumps(evidence, indent=2))
PY
LIVE_RUNTIME_EVIDENCE_BLOCKED_MISSING_RERUN_COMMAND_LOG="$LIVE_GATE_DIR/live-runtime-evidence-blocked-missing-rerun-command.log"
if qa/run_live_runtime_checks.sh --audit-row-evidence "$LIVE_RUNTIME_EVIDENCE_BLOCKED_MISSING_RERUN_COMMAND" >"$LIVE_RUNTIME_EVIDENCE_BLOCKED_MISSING_RERUN_COMMAND_LOG" 2>&1; then
  echo "Expected blocked live-runtime evidence with a missing Rerun command to fail."
  exit 1
fi
grep -F "CORE-003: Rerun command does not exist: qa/missing-live-runtime-rerun-command.sh" "$LIVE_RUNTIME_EVIDENCE_BLOCKED_MISSING_RERUN_COMMAND_LOG" >/dev/null
LIVE_RUNTIME_EVIDENCE_ERRORS_MISSING_REFERENCES="$LIVE_GATE_DIR/live-runtime-evidence-errors-missing-references.json"
python3 - <<'PY' >"$LIVE_RUNTIME_EVIDENCE_ERRORS_MISSING_REFERENCES"
import json
import os

from qa.app_runtime_rows import live_runtime_evidence_template, tracker_rows

artifact = os.environ["LIVE_RUNTIME_ARTIFACT"]
evidence = live_runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "blocked" if index == 0 else "pass"
    row["Evidence"] = (
        f"Observed signed app live runtime sweep completed with Result {row['Result']} for {row['ID']} {row['Feature']}. "
        f"User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} "
        f"Test instructions: {row['Test instructions']} Artifact: {artifact}"
    )
    if index == 0:
        row["Evidence"] += " Rerun: qa/run_live_runtime_checks.sh --audit-row-evidence"
        row["Errors"] = f"{row['ID']} {row['Feature']}: signed-app prerequisite blocked this live runtime row."
    else:
        row["Errors"] = ""
print(json.dumps(evidence, indent=2))
PY
LIVE_RUNTIME_EVIDENCE_ERRORS_MISSING_REFERENCES_LOG="$LIVE_GATE_DIR/live-runtime-evidence-errors-missing-references.log"
if qa/run_live_runtime_checks.sh --audit-row-evidence "$LIVE_RUNTIME_EVIDENCE_ERRORS_MISSING_REFERENCES" >"$LIVE_RUNTIME_EVIDENCE_ERRORS_MISSING_REFERENCES_LOG" 2>&1; then
  echo "Expected blocked live-runtime evidence Errors without artifact/rerun references to fail."
  exit 1
fi
grep -F "CORE-003: Errors must mention the Evidence artifact" "$LIVE_RUNTIME_EVIDENCE_ERRORS_MISSING_REFERENCES_LOG" >/dev/null
grep -F "CORE-003: Errors must mention the Rerun command" "$LIVE_RUNTIME_EVIDENCE_ERRORS_MISSING_REFERENCES_LOG" >/dev/null
LIVE_RUNTIME_EVIDENCE_SHUFFLED="$LIVE_GATE_DIR/live-runtime-evidence-shuffled.json"
python3 - "$LIVE_RUNTIME_EVIDENCE_PASS" <<'PY' >"$LIVE_RUNTIME_EVIDENCE_SHUFFLED"
import json
import sys
from pathlib import Path

evidence = json.loads(Path(sys.argv[1]).read_text())
if len(evidence) < 2:
    raise SystemExit("live-runtime shuffled fixture needs at least two rows")
evidence[0], evidence[1] = evidence[1], evidence[0]
print(json.dumps(evidence, indent=2))
PY
LIVE_RUNTIME_EVIDENCE_SHUFFLED_LOG="$LIVE_GATE_DIR/live-runtime-evidence-shuffled.log"
if qa/run_live_runtime_checks.sh --audit-row-evidence "$LIVE_RUNTIME_EVIDENCE_SHUFFLED" >"$LIVE_RUNTIME_EVIDENCE_SHUFFLED_LOG" 2>&1; then
  echo "Expected shuffled live-runtime evidence rows to fail."
  exit 1
fi
grep -F "live-runtime row evidence rows are not in canonical order" "$LIVE_RUNTIME_EVIDENCE_SHUFFLED_LOG" >/dev/null
LIVE_RUNTIME_EVIDENCE_MISMATCHED_RESULT_TEXT="$LIVE_GATE_DIR/live-runtime-evidence-mismatched-result-text.json"
python3 - <<'PY' >"$LIVE_RUNTIME_EVIDENCE_MISMATCHED_RESULT_TEXT"
import json
import os

from qa.app_runtime_rows import live_runtime_evidence_template, tracker_rows

artifact = os.environ["LIVE_RUNTIME_ARTIFACT"]
evidence = live_runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app live runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    if index == 0:
        row["Evidence"] = row["Evidence"].replace("Result pass", "Result blocked", 1)
print(json.dumps(evidence, indent=2))
PY
LIVE_RUNTIME_EVIDENCE_MISMATCHED_RESULT_TEXT_LOG="$LIVE_GATE_DIR/live-runtime-evidence-mismatched-result-text.log"
if qa/run_live_runtime_checks.sh --audit-row-evidence "$LIVE_RUNTIME_EVIDENCE_MISMATCHED_RESULT_TEXT" >"$LIVE_RUNTIME_EVIDENCE_MISMATCHED_RESULT_TEXT_LOG" 2>&1; then
  echo "Expected live-runtime evidence with mismatched Result text to fail."
  exit 1
fi
grep -F "CORE-003: Evidence must cite Result pass" "$LIVE_RUNTIME_EVIDENCE_MISMATCHED_RESULT_TEXT_LOG" >/dev/null
LIVE_RUNTIME_EVIDENCE_PUNCTUATED_ARTIFACT="$LIVE_GATE_DIR/live-runtime-evidence-punctuated-artifact.json"
python3 - <<'PY' >"$LIVE_RUNTIME_EVIDENCE_PUNCTUATED_ARTIFACT"
import json
import os

from qa.app_runtime_rows import live_runtime_evidence_template, tracker_rows

artifact = os.environ["LIVE_RUNTIME_ARTIFACT"]
evidence = live_runtime_evidence_template(tracker_rows())
for row in evidence:
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app live runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}."
print(json.dumps(evidence, indent=2))
PY
LIVE_RUNTIME_EVIDENCE_PUNCTUATED_ARTIFACT_LOG="$LIVE_GATE_DIR/live-runtime-evidence-punctuated-artifact.log"
qa/run_live_runtime_checks.sh --audit-row-evidence "$LIVE_RUNTIME_EVIDENCE_PUNCTUATED_ARTIFACT" >"$LIVE_RUNTIME_EVIDENCE_PUNCTUATED_ARTIFACT_LOG" 2>&1
grep -F "Live-runtime row evidence audit passed for ${LIVE_RUNTIME_EXPECTED_COUNT} user-story rows." "$LIVE_RUNTIME_EVIDENCE_PUNCTUATED_ARTIFACT_LOG" >/dev/null
LIVE_RUNTIME_EVIDENCE_MISSING_ADDITIONAL_ARTIFACT="$LIVE_GATE_DIR/live-runtime-evidence-missing-additional-artifact.json"
python3 - <<'PY' >"$LIVE_RUNTIME_EVIDENCE_MISSING_ADDITIONAL_ARTIFACT"
import json
import os

from qa.app_runtime_rows import live_runtime_evidence_template, tracker_rows

artifact = os.environ["LIVE_RUNTIME_ARTIFACT"]
evidence = live_runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app live runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    if index == 0:
        row["Evidence"] += " Additional artifact: dist/live-runtime-artifacts/missing-supporting-log.log"
print(json.dumps(evidence, indent=2))
PY
LIVE_RUNTIME_EVIDENCE_MISSING_ADDITIONAL_ARTIFACT_LOG="$LIVE_GATE_DIR/live-runtime-evidence-missing-additional-artifact.log"
if qa/run_live_runtime_checks.sh --audit-row-evidence "$LIVE_RUNTIME_EVIDENCE_MISSING_ADDITIONAL_ARTIFACT" >"$LIVE_RUNTIME_EVIDENCE_MISSING_ADDITIONAL_ARTIFACT_LOG" 2>&1; then
  echo "Expected live-runtime evidence with a missing Additional artifact to fail."
  exit 1
fi
grep -F "CORE-003: Additional artifact does not exist: dist/live-runtime-artifacts/missing-supporting-log.log" "$LIVE_RUNTIME_EVIDENCE_MISSING_ADDITIONAL_ARTIFACT_LOG" >/dev/null
LIVE_RUNTIME_ARTIFACT_MISSING_RESULT="$LIVE_GATE_DIR/live-runtime-artifacts/live-runtime-missing-result.log"
export LIVE_RUNTIME_ARTIFACT_MISSING_RESULT
python3 - <<'PY' >"$LIVE_RUNTIME_ARTIFACT_MISSING_RESULT"
from qa.app_runtime_rows import live_runtime_evidence_template, tracker_rows

print("Observed signed app live runtime sweep with missing result support.")
for row in live_runtime_evidence_template(tracker_rows()):
    print(f"{row['ID']} {row['Feature']}: User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Observed signed app live-runtime flow.")
PY
LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_RESULT="$LIVE_GATE_DIR/live-runtime-evidence-artifact-missing-result.json"
python3 - <<'PY' >"$LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_RESULT"
import json
import os

from qa.app_runtime_rows import live_runtime_evidence_template, tracker_rows

artifact = os.environ["LIVE_RUNTIME_ARTIFACT_MISSING_RESULT"]
evidence = live_runtime_evidence_template(tracker_rows())
for row in evidence:
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app live runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
print(json.dumps(evidence, indent=2))
PY
LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_RESULT_LOG="$LIVE_GATE_DIR/live-runtime-evidence-artifact-missing-result.log"
if qa/run_live_runtime_checks.sh --audit-row-evidence "$LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_RESULT" >"$LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_RESULT_LOG" 2>&1; then
  echo "Expected live-runtime evidence artifact missing Result support to fail."
  exit 1
fi
grep -F "CORE-003: Evidence artifact must mention Result pass" "$LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_RESULT_LOG" >/dev/null
LIVE_RUNTIME_ARTIFACT_MISSING_ROW_SECTION="$LIVE_GATE_DIR/live-runtime-artifacts/live-runtime-missing-row-section.log"
export LIVE_RUNTIME_ARTIFACT_MISSING_ROW_SECTION
python3 - <<'PY' >"$LIVE_RUNTIME_ARTIFACT_MISSING_ROW_SECTION"
from qa.app_runtime_rows import live_runtime_evidence_template, tracker_rows

for index, row in enumerate(live_runtime_evidence_template(tracker_rows())):
    marker = "CORE-999" if index == 0 else row["ID"]
    print(f"ROW {marker}")
    print(f"{row['ID']} {row['Feature']}: Result pass. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Observed signed app live-runtime flow.")
PY
LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_ROW_SECTION="$LIVE_GATE_DIR/live-runtime-evidence-artifact-missing-row-section.json"
python3 - <<'PY' >"$LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_ROW_SECTION"
import json
import os

from qa.app_runtime_rows import live_runtime_evidence_template, tracker_rows

artifact = os.environ["LIVE_RUNTIME_ARTIFACT_MISSING_ROW_SECTION"]
evidence = live_runtime_evidence_template(tracker_rows())
for row in evidence:
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app live runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
print(json.dumps(evidence, indent=2))
PY
LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_ROW_SECTION_LOG="$LIVE_GATE_DIR/live-runtime-evidence-artifact-missing-row-section.log"
if qa/run_live_runtime_checks.sh --audit-row-evidence "$LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_ROW_SECTION" >"$LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_ROW_SECTION_LOG" 2>&1; then
  echo "Expected live-runtime evidence artifact missing a cited row section to fail."
  exit 1
fi
grep -F "CORE-003: Evidence artifact must include a row section for CORE-003" "$LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_ROW_SECTION_LOG" >/dev/null
LIVE_RUNTIME_EVIDENCE_PASS_REQUIRED_LOG="$LIVE_GATE_DIR/live-runtime-evidence-pass-required.log"
if BASTION_APP_PATH="$LIVE_GATE_DIR/missing-prereq.app" qa/run_live_runtime_checks.sh --audit-row-evidence "$LIVE_RUNTIME_EVIDENCE_PASS" --require-pass >"$LIVE_RUNTIME_EVIDENCE_PASS_REQUIRED_LOG" 2>&1; then
  echo "Expected final live-runtime require-pass audit to fail while runtime prerequisites are blocked."
  exit 1
fi
grep -F "Live-runtime row evidence audit passed for ${LIVE_RUNTIME_EXPECTED_COUNT} user-story rows." "$LIVE_RUNTIME_EVIDENCE_PASS_REQUIRED_LOG" >/dev/null
grep -F "Current-source signed app rebuild: Blocked" "$LIVE_RUNTIME_EVIDENCE_PASS_REQUIRED_LOG" >/dev/null
grep -F "Final live-runtime require-pass evidence needs satisfied runtime prerequisites" "$LIVE_RUNTIME_EVIDENCE_PASS_REQUIRED_LOG" >/dev/null
LIVE_RUNTIME_TRACKER_UPDATE_PASS="$LIVE_GATE_DIR/live-runtime-tracker-update-pass.json"
LIVE_RUNTIME_TRACKER_UPDATE_PASS_LOG="$LIVE_GATE_DIR/live-runtime-tracker-update-pass.log"
if BASTION_APP_PATH="$LIVE_GATE_DIR/missing-prereq.app" qa/run_live_runtime_checks.sh --write-tracker-update "$LIVE_RUNTIME_EVIDENCE_PASS" "$LIVE_RUNTIME_TRACKER_UPDATE_PASS" >"$LIVE_RUNTIME_TRACKER_UPDATE_PASS_LOG" 2>&1; then
  echo "Expected all-pass live-runtime tracker-update generation to fail while runtime prerequisites are blocked."
  exit 1
fi
grep -F "Current-source signed app rebuild: Blocked" "$LIVE_RUNTIME_TRACKER_UPDATE_PASS_LOG" >/dev/null
grep -F "Final live-runtime require-pass evidence needs satisfied runtime prerequisites" "$LIVE_RUNTIME_TRACKER_UPDATE_PASS_LOG" >/dev/null
LIVE_RUNTIME_EVIDENCE_STALE_CONTEXT="$LIVE_GATE_DIR/live-runtime-evidence-stale-context.json"
python3 - <<'PY' >"$LIVE_RUNTIME_EVIDENCE_STALE_CONTEXT"
import json
import os

from qa.app_runtime_rows import live_runtime_evidence_template, tracker_rows

artifact = os.environ["LIVE_RUNTIME_ARTIFACT"]
evidence = live_runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app live runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    if index == 0:
        row["Feature"] = "Stale live-runtime feature context"
print(json.dumps(evidence, indent=2))
PY
LIVE_RUNTIME_EVIDENCE_STALE_CONTEXT_LOG="$LIVE_GATE_DIR/live-runtime-evidence-stale-context.log"
if qa/run_live_runtime_checks.sh --audit-row-evidence "$LIVE_RUNTIME_EVIDENCE_STALE_CONTEXT" >"$LIVE_RUNTIME_EVIDENCE_STALE_CONTEXT_LOG" 2>&1; then
  echo "Expected stale live-runtime evidence context to fail."
  exit 1
fi
grep -F "CORE-003: Feature does not match qa/feature_status_source.json" "$LIVE_RUNTIME_EVIDENCE_STALE_CONTEXT_LOG" >/dev/null
LIVE_RUNTIME_ARTIFACT_MISSING_EXPECTED="$LIVE_GATE_DIR/live-runtime-artifacts/live-runtime-missing-expected.log"
export LIVE_RUNTIME_ARTIFACT_MISSING_EXPECTED
python3 - <<'PY' >"$LIVE_RUNTIME_ARTIFACT_MISSING_EXPECTED"
from qa.app_runtime_rows import live_runtime_evidence_template, tracker_rows

print("Observed signed app live runtime sweep with one incomplete artifact row.")
for index, row in enumerate(live_runtime_evidence_template(tracker_rows())):
    if index == 0:
        print(f"{row['ID']} {row['Feature']}: Result pass. User story: {row['User story']} Observed signed app live-runtime flow without expected-behaviour support.")
    else:
        print(f"{row['ID']} {row['Feature']}: Result pass. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Observed signed app live-runtime flow.")
PY
LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_EXPECTED="$LIVE_GATE_DIR/live-runtime-evidence-artifact-missing-expected.json"
python3 - <<'PY' >"$LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_EXPECTED"
import json
import os

from qa.app_runtime_rows import live_runtime_evidence_template, tracker_rows

artifact = os.environ["LIVE_RUNTIME_ARTIFACT_MISSING_EXPECTED"]
evidence = live_runtime_evidence_template(tracker_rows())
for row in evidence:
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app live runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
print(json.dumps(evidence, indent=2))
PY
LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_EXPECTED_LOG="$LIVE_GATE_DIR/live-runtime-evidence-artifact-missing-expected.log"
if qa/run_live_runtime_checks.sh --audit-row-evidence "$LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_EXPECTED" >"$LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_EXPECTED_LOG" 2>&1; then
  echo "Expected live-runtime evidence artifact missing Expected behaviour support to fail."
  exit 1
fi
grep -F "CORE-003: Evidence artifact must mention the tracker Expected behaviour" "$LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_EXPECTED_LOG" >/dev/null
LIVE_RUNTIME_ARTIFACT_MISSING_USER_STORY="$LIVE_GATE_DIR/live-runtime-artifacts/live-runtime-missing-user-story.log"
export LIVE_RUNTIME_ARTIFACT_MISSING_USER_STORY
python3 - <<'PY' >"$LIVE_RUNTIME_ARTIFACT_MISSING_USER_STORY"
from qa.app_runtime_rows import live_runtime_evidence_template, tracker_rows

print("Observed signed app live runtime sweep with one incomplete user-story artifact row.")
for index, row in enumerate(live_runtime_evidence_template(tracker_rows())):
    if index == 0:
        print(f"{row['ID']} {row['Feature']}: Result pass. Expected behaviour: {row['Expected behaviour']} Observed signed app live-runtime flow without user-story support.")
    else:
        print(f"{row['ID']} {row['Feature']}: Result pass. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Observed signed app live-runtime flow.")
PY
LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_USER_STORY="$LIVE_GATE_DIR/live-runtime-evidence-artifact-missing-user-story.json"
python3 - <<'PY' >"$LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_USER_STORY"
import json
import os

from qa.app_runtime_rows import live_runtime_evidence_template, tracker_rows

artifact = os.environ["LIVE_RUNTIME_ARTIFACT_MISSING_USER_STORY"]
evidence = live_runtime_evidence_template(tracker_rows())
for row in evidence:
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app live runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
print(json.dumps(evidence, indent=2))
PY
LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_USER_STORY_LOG="$LIVE_GATE_DIR/live-runtime-evidence-artifact-missing-user-story.log"
if qa/run_live_runtime_checks.sh --audit-row-evidence "$LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_USER_STORY" >"$LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_USER_STORY_LOG" 2>&1; then
  echo "Expected live-runtime evidence artifact missing User story support to fail."
  exit 1
fi
grep -F "CORE-003: Evidence artifact must mention the tracker User story" "$LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_USER_STORY_LOG" >/dev/null
LIVE_RUNTIME_ARTIFACT_MISSING_TEST_INSTRUCTIONS="$LIVE_GATE_DIR/live-runtime-artifacts/live-runtime-missing-test-instructions.log"
export LIVE_RUNTIME_ARTIFACT_MISSING_TEST_INSTRUCTIONS
python3 - <<'PY' >"$LIVE_RUNTIME_ARTIFACT_MISSING_TEST_INSTRUCTIONS"
from qa.app_runtime_rows import live_runtime_evidence_template, tracker_rows

print("Observed signed app live runtime sweep with one incomplete test-instructions artifact row.")
for index, row in enumerate(live_runtime_evidence_template(tracker_rows())):
    if index == 0:
        print(f"{row['ID']} {row['Feature']}: Result pass. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Observed signed app live-runtime flow without test-instructions support.")
    else:
        print(f"{row['ID']} {row['Feature']}: Result pass. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Observed signed app live-runtime flow.")
PY
LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_TEST_INSTRUCTIONS="$LIVE_GATE_DIR/live-runtime-evidence-artifact-missing-test-instructions.json"
python3 - <<'PY' >"$LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_TEST_INSTRUCTIONS"
import json
import os

from qa.app_runtime_rows import live_runtime_evidence_template, tracker_rows

artifact = os.environ["LIVE_RUNTIME_ARTIFACT_MISSING_TEST_INSTRUCTIONS"]
evidence = live_runtime_evidence_template(tracker_rows())
for row in evidence:
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app live runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
print(json.dumps(evidence, indent=2))
PY
LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_TEST_INSTRUCTIONS_LOG="$LIVE_GATE_DIR/live-runtime-evidence-artifact-missing-test-instructions.log"
if qa/run_live_runtime_checks.sh --audit-row-evidence "$LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_TEST_INSTRUCTIONS" >"$LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_TEST_INSTRUCTIONS_LOG" 2>&1; then
  echo "Expected live-runtime evidence artifact missing Test instructions support to fail."
  exit 1
fi
grep -F "CORE-003: Evidence artifact must mention the tracker Test instructions: ${LIVE_RUNTIME_ARTIFACT_MISSING_TEST_INSTRUCTIONS}" "$LIVE_RUNTIME_EVIDENCE_ARTIFACT_MISSING_TEST_INSTRUCTIONS_LOG" >/dev/null
LIVE_RUNTIME_EVIDENCE_PLACEHOLDER="$LIVE_GATE_DIR/live-runtime-evidence-placeholder.json"
python3 - <<'PY' >"$LIVE_RUNTIME_EVIDENCE_PLACEHOLDER"
import json
import os

from qa.app_runtime_rows import live_runtime_evidence_template, tracker_rows

artifact = os.environ["LIVE_RUNTIME_ARTIFACT"]
evidence = live_runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app live runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    if index == 0:
        row["Evidence"] = "TODO placeholder live-runtime evidence"
print(json.dumps(evidence, indent=2))
PY
LIVE_RUNTIME_EVIDENCE_PLACEHOLDER_LOG="$LIVE_GATE_DIR/live-runtime-evidence-placeholder.log"
if qa/run_live_runtime_checks.sh --audit-row-evidence "$LIVE_RUNTIME_EVIDENCE_PLACEHOLDER" >"$LIVE_RUNTIME_EVIDENCE_PLACEHOLDER_LOG" 2>&1; then
  echo "Expected live-runtime evidence with placeholder text to fail."
  exit 1
fi
grep -F "CORE-003: Evidence must describe real live-runtime observations, not placeholder text" "$LIVE_RUNTIME_EVIDENCE_PLACEHOLDER_LOG" >/dev/null
LIVE_RUNTIME_UPDATED_SOURCE="$LIVE_GATE_DIR/live-runtime-updated-source.json"
LIVE_RUNTIME_UPDATED_SOURCE_LOG="$LIVE_GATE_DIR/live-runtime-updated-source.log"
if BASTION_APP_PATH="$LIVE_GATE_DIR/missing-prereq.app" qa/run_live_runtime_checks.sh --write-updated-source "$LIVE_RUNTIME_EVIDENCE_PASS" "$LIVE_RUNTIME_UPDATED_SOURCE" >"$LIVE_RUNTIME_UPDATED_SOURCE_LOG" 2>&1; then
  echo "Expected all-pass live-runtime updated-source generation to fail while runtime prerequisites are blocked."
  exit 1
fi
grep -F "Current-source signed app rebuild: Blocked" "$LIVE_RUNTIME_UPDATED_SOURCE_LOG" >/dev/null
grep -F "Final live-runtime require-pass evidence needs satisfied runtime prerequisites" "$LIVE_RUNTIME_UPDATED_SOURCE_LOG" >/dev/null

LIVE_RUNTIME_EVIDENCE_DOCUMENTED_BLOCKER="$LIVE_GATE_DIR/live-runtime-evidence-documented-blocker.json"
python3 - <<'PY' >"$LIVE_RUNTIME_EVIDENCE_DOCUMENTED_BLOCKER"
import json
import os

from qa.app_runtime_rows import live_runtime_evidence_template, tracker_rows

artifact = os.environ["LIVE_RUNTIME_ARTIFACT"]
evidence = live_runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "blocked" if index == 0 else "pass"
    row["Evidence"] = f"Observed signed app live runtime sweep completed with Result {row['Result']} for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    if index == 0:
        row["Evidence"] += " Rerun: qa/run_live_runtime_checks.sh --audit-row-evidence"
        row["Errors"] = (
            f"{row['ID']} {row['Feature']}: signed-app prerequisite blocked this live runtime row. "
            f"Artifact: {artifact}. Rerun: qa/run_live_runtime_checks.sh."
        )
    else:
        row["Errors"] = ""
print(json.dumps(evidence, indent=2))
PY
LIVE_RUNTIME_EVIDENCE_DOCUMENTED_BLOCKER_LOG="$LIVE_GATE_DIR/live-runtime-evidence-documented-blocker.log"
qa/run_live_runtime_checks.sh --audit-row-evidence "$LIVE_RUNTIME_EVIDENCE_DOCUMENTED_BLOCKER" >"$LIVE_RUNTIME_EVIDENCE_DOCUMENTED_BLOCKER_LOG" 2>&1
grep -F "Live-runtime row evidence audit passed for ${LIVE_RUNTIME_EXPECTED_COUNT} user-story rows." "$LIVE_RUNTIME_EVIDENCE_DOCUMENTED_BLOCKER_LOG" >/dev/null
LIVE_RUNTIME_EVIDENCE_REQUIRE_PASS_FAILURE_LOG="$LIVE_GATE_DIR/live-runtime-evidence-require-pass-failure.log"
if qa/run_live_runtime_checks.sh --audit-row-evidence "$LIVE_RUNTIME_EVIDENCE_DOCUMENTED_BLOCKER" --require-pass >"$LIVE_RUNTIME_EVIDENCE_REQUIRE_PASS_FAILURE_LOG" 2>&1; then
  echo "Expected final live-runtime evidence closure to fail when any row is not pass."
  exit 1
fi
grep -F "CORE-003: Result must be pass for final post-fix live-runtime closure" "$LIVE_RUNTIME_EVIDENCE_REQUIRE_PASS_FAILURE_LOG" >/dev/null
LIVE_RUNTIME_TRACKER_UPDATE="$LIVE_GATE_DIR/live-runtime-tracker-update.json"
LIVE_RUNTIME_TRACKER_UPDATE_LOG="$LIVE_GATE_DIR/live-runtime-tracker-update.log"
BASTION_APP_PATH="$LIVE_GATE_DIR/missing-prereq.app" qa/run_live_runtime_checks.sh --write-tracker-update "$LIVE_RUNTIME_EVIDENCE_DOCUMENTED_BLOCKER" "$LIVE_RUNTIME_TRACKER_UPDATE" >"$LIVE_RUNTIME_TRACKER_UPDATE_LOG" 2>&1
grep -F "Wrote live-runtime tracker update review artifact for ${LIVE_RUNTIME_EXPECTED_COUNT} row evidence rows" "$LIVE_RUNTIME_TRACKER_UPDATE_LOG" >/dev/null
python3 qa/assert_live_runtime_tracker_update.py "$LIVE_RUNTIME_TRACKER_UPDATE" "$LIVE_RUNTIME_EXPECTED_COUNT" "$LIVE_RUNTIME_EVIDENCE_DOCUMENTED_BLOCKER"
LIVE_RUNTIME_DIRECT_TRACKER_UPDATE_LOG="$LIVE_GATE_DIR/live-runtime-direct-tracker-update.log"
cp qa/feature_status_source.json "$LIVE_GATE_DIR/feature_status_source.before-live-direct-tracker-update.json"
if qa/run_live_runtime_checks.sh --write-tracker-update "$LIVE_RUNTIME_EVIDENCE_DOCUMENTED_BLOCKER" qa/feature_status_source.json >"$LIVE_RUNTIME_DIRECT_TRACKER_UPDATE_LOG" 2>&1; then
  echo "Expected live-runtime tracker update generation to reject the canonical source path."
  exit 1
fi
grep -F "live-runtime tracker update must be written as a review artifact, not directly over qa/feature_status_source.json" "$LIVE_RUNTIME_DIRECT_TRACKER_UPDATE_LOG" >/dev/null
cmp -s qa/feature_status_source.json "$LIVE_GATE_DIR/feature_status_source.before-live-direct-tracker-update.json"
LIVE_RUNTIME_DIRECT_UPDATED_SOURCE_LOG="$LIVE_GATE_DIR/live-runtime-direct-updated-source.log"
cp qa/feature_status_source.json "$LIVE_GATE_DIR/feature_status_source.before-live-direct-updated-source.json"
if qa/run_live_runtime_checks.sh --write-updated-source "$LIVE_RUNTIME_EVIDENCE_PASS" qa/feature_status_source.json >"$LIVE_RUNTIME_DIRECT_UPDATED_SOURCE_LOG" 2>&1; then
  echo "Expected live-runtime updated-source generation to reject the canonical source path."
  exit 1
fi
grep -F "live-runtime updated source must be written as a review artifact, not directly over qa/feature_status_source.json" "$LIVE_RUNTIME_DIRECT_UPDATED_SOURCE_LOG" >/dev/null
cmp -s qa/feature_status_source.json "$LIVE_GATE_DIR/feature_status_source.before-live-direct-updated-source.json"
LIVE_RUNTIME_PARTIAL_UPDATED_SOURCE="$LIVE_GATE_DIR/live-runtime-partial-updated-source.json"
LIVE_RUNTIME_PARTIAL_UPDATED_SOURCE_LOG="$LIVE_GATE_DIR/live-runtime-partial-updated-source.log"
if BASTION_APP_PATH="$LIVE_GATE_DIR/missing-prereq.app" qa/run_live_runtime_checks.sh --write-updated-source "$LIVE_RUNTIME_EVIDENCE_DOCUMENTED_BLOCKER" "$LIVE_RUNTIME_PARTIAL_UPDATED_SOURCE" >"$LIVE_RUNTIME_PARTIAL_UPDATED_SOURCE_LOG" 2>&1; then
  echo "Expected partial live-runtime pass promotion to fail while runtime prerequisites are blocked."
  exit 1
fi
grep -F "Current-source signed app rebuild: Blocked" "$LIVE_RUNTIME_PARTIAL_UPDATED_SOURCE_LOG" >/dev/null
grep -F "Final live-runtime require-pass evidence needs satisfied runtime prerequisites" "$LIVE_RUNTIME_PARTIAL_UPDATED_SOURCE_LOG" >/dev/null
test ! -e "$LIVE_RUNTIME_PARTIAL_UPDATED_SOURCE"

echo "== App-runtime user-story gate prerequisite mapping =="
APP_RUNTIME_GATE_LOG="$LIVE_GATE_DIR/app-runtime-gate.log"
APP_RUNTIME_EXPECTED_COUNT="$(python3 qa/app_runtime_rows.py --count)"
python3 qa/assert_app_runtime_derivation.py
HOME="$LIVE_GATE_DIR/home" \
  qa/run_app_runtime_user_story_checks.sh --check-prereqs >"$APP_RUNTIME_GATE_LOG" 2>&1
grep -F "Runtime-pending user-story rows covered (${APP_RUNTIME_EXPECTED_COUNT}):" "$APP_RUNTIME_GATE_LOG" >/dev/null
if [[ "$APP_RUNTIME_EXPECTED_COUNT" -gt 0 ]]; then
  grep -F "CORE-007" "$APP_RUNTIME_GATE_LOG" >/dev/null
fi
grep -F "App bundle not found at ${LIVE_GATE_APP}" "$APP_RUNTIME_GATE_LOG" >/dev/null
grep -F "== Current-source signed app rebuild ==" "$APP_RUNTIME_GATE_LOG" >/dev/null
grep -F "Current-source status: Blocked" "$APP_RUNTIME_GATE_LOG" >/dev/null
grep -F "== Discovered app bundle candidates ==" "$APP_RUNTIME_GATE_LOG" >/dev/null
grep -F "Candidate status:" "$APP_RUNTIME_GATE_LOG" >/dev/null
python3 - "$APP_RUNTIME_GATE_LOG" <<'PY'
import sys
from pathlib import Path

log = Path(sys.argv[1]).read_text()
release_candidate = Path("dist/release/Bastion.app").resolve()
if release_candidate.is_dir() and str(release_candidate) not in log:
    raise SystemExit("app-runtime prerequisite output must report existing dist/release/Bastion.app candidate")
PY
grep -F "Prerequisite-only mode records the blocker" "$APP_RUNTIME_GATE_LOG" >/dev/null
APP_RUNTIME_STRICT_GATE_LOG="$LIVE_GATE_DIR/app-runtime-strict-gate.log"
if HOME="$LIVE_GATE_DIR/home" \
  qa/run_app_runtime_user_story_checks.sh --check-prereqs --require-prereqs >"$APP_RUNTIME_STRICT_GATE_LOG" 2>&1; then
  echo "Expected strict app-runtime prereq gate to fail without a stable signed app."
  exit 1
fi
grep -F "App bundle not found at ${LIVE_GATE_APP}" "$APP_RUNTIME_STRICT_GATE_LOG" >/dev/null

APP_RUNTIME_MALFORMED_GATE_LOG="$LIVE_GATE_DIR/app-runtime-malformed-gate.log"
HOME="$LIVE_GATE_DIR/home" \
  BASTION_APP_PATH="$MALFORMED_GATE_APP" \
  qa/run_app_runtime_user_story_checks.sh --check-prereqs >"$APP_RUNTIME_MALFORMED_GATE_LOG" 2>&1
grep -F "App bundle Info.plist missing at ${MALFORMED_GATE_APP}/Contents/Info.plist" "$APP_RUNTIME_MALFORMED_GATE_LOG" >/dev/null
grep -F "Prerequisite-only mode records the blocker" "$APP_RUNTIME_MALFORMED_GATE_LOG" >/dev/null

APP_RUNTIME_INVALID_GATE_LOG="$LIVE_GATE_DIR/app-runtime-invalid-gate.log"
HOME="$LIVE_GATE_DIR/home" \
  BASTION_APP_PATH="$INVALID_GATE_APP" \
  qa/run_app_runtime_user_story_checks.sh --check-prereqs >"$APP_RUNTIME_INVALID_GATE_LOG" 2>&1
grep -F "App codesign verification failed for ${INVALID_GATE_APP}" "$APP_RUNTIME_INVALID_GATE_LOG" >/dev/null
grep -F "Prerequisite-only mode records the blocker" "$APP_RUNTIME_INVALID_GATE_LOG" >/dev/null

APP_RUNTIME_TEMPLATE="$LIVE_GATE_DIR/app-runtime-evidence-template.json"
APP_RUNTIME_TEMPLATE_LOG="$LIVE_GATE_DIR/app-runtime-evidence-template.log"
qa/run_app_runtime_user_story_checks.sh --write-template "$APP_RUNTIME_TEMPLATE" >"$APP_RUNTIME_TEMPLATE_LOG" 2>&1
grep -F "Wrote app-runtime evidence template for ${APP_RUNTIME_EXPECTED_COUNT} user-story rows" "$APP_RUNTIME_TEMPLATE_LOG" >/dev/null
python3 - "$APP_RUNTIME_TEMPLATE" "$APP_RUNTIME_EXPECTED_COUNT" <<'PY'
import json
import sys
from pathlib import Path

template = json.loads(Path(sys.argv[1]).read_text())
expected_count = int(sys.argv[2])
if len(template) != expected_count:
    raise SystemExit(f"unexpected app-runtime template row count {len(template)}")
required = {"ID", "Surface", "Feature", "User story", "Expected behaviour", "Test instructions", "Result", "Evidence", "Errors"}
for index, row in enumerate(template, start=1):
    missing = required - set(row)
    if missing:
        raise SystemExit(f"template row {index} missing keys: {', '.join(sorted(missing))}")
    if not row["ID"] or not row["Surface"] or not row["Feature"] or not row["User story"] or not row["Expected behaviour"] or not row["Test instructions"]:
        raise SystemExit(f"template row {index} is missing tracker context")
    if row["Result"] or row["Evidence"] or row["Errors"]:
        raise SystemExit(f"template row {row['ID']} must start with blank result/evidence/errors fields")
PY

APP_RUNTIME_EVIDENCE_PASS="$LIVE_GATE_DIR/app-runtime-evidence-pass.json"
APP_RUNTIME_ARTIFACT="$LIVE_GATE_DIR/app-runtime-artifacts/runtime-sweep.log"
export APP_RUNTIME_ARTIFACT
mkdir -p "$(dirname "$APP_RUNTIME_ARTIFACT")"
python3 - <<'PY' >"$APP_RUNTIME_ARTIFACT"
from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

print("Observed signed app runtime sweep artifact for canonical QA fixtures.")
print("Supported fixture result tokens: Result pass. Result fail. Result blocked.")
for row in runtime_evidence_template(tracker_rows()):
    print(f"ROW {row['ID']}")
    print("Supported row result tokens: Result pass. Result fail. Result blocked.")
    print(f"{row['Feature']}: Result pass. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Observed signed app runtime user-story flow.")
    print(f"Test instructions: {row['Test instructions']}")
PY
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_PASS"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
evidence = runtime_evidence_template(tracker_rows())
for row in evidence:
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_PASS_LOG="$LIVE_GATE_DIR/app-runtime-evidence-pass.log"
qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_PASS" >"$APP_RUNTIME_EVIDENCE_PASS_LOG" 2>&1
grep -F "App-runtime evidence audit passed for ${APP_RUNTIME_EXPECTED_COUNT} user-story rows." "$APP_RUNTIME_EVIDENCE_PASS_LOG" >/dev/null
if [[ "$APP_RUNTIME_EXPECTED_COUNT" -gt 0 ]]; then
APP_RUNTIME_EVIDENCE_MISSING_DIRECT_USER_STORY="$LIVE_GATE_DIR/app-runtime-evidence-missing-direct-user-story.json"
python3 - "$APP_RUNTIME_EVIDENCE_PASS" <<'PY' >"$APP_RUNTIME_EVIDENCE_MISSING_DIRECT_USER_STORY"
import json
import sys
from pathlib import Path

evidence = json.loads(Path(sys.argv[1]).read_text())
story = evidence[0]["User story"]
evidence[0]["Evidence"] = evidence[0]["Evidence"].replace(f" User story: {story}", "", 1)
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_MISSING_DIRECT_USER_STORY_LOG="$LIVE_GATE_DIR/app-runtime-evidence-missing-direct-user-story.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_MISSING_DIRECT_USER_STORY" >"$APP_RUNTIME_EVIDENCE_MISSING_DIRECT_USER_STORY_LOG" 2>&1; then
  echo "Expected app-runtime evidence missing direct User story text to fail."
  exit 1
fi
grep -F "CORE-007: Evidence must mention the tracker User story" "$APP_RUNTIME_EVIDENCE_MISSING_DIRECT_USER_STORY_LOG" >/dev/null
APP_RUNTIME_EVIDENCE_MISSING_DIRECT_TEST_INSTRUCTIONS="$LIVE_GATE_DIR/app-runtime-evidence-missing-direct-test-instructions.json"
python3 - "$APP_RUNTIME_EVIDENCE_PASS" <<'PY' >"$APP_RUNTIME_EVIDENCE_MISSING_DIRECT_TEST_INSTRUCTIONS"
import json
import sys
from pathlib import Path

evidence = json.loads(Path(sys.argv[1]).read_text())
test_instructions = evidence[0]["Test instructions"]
evidence[0]["Evidence"] = evidence[0]["Evidence"].replace(f" Test instructions: {test_instructions}", "", 1)
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_MISSING_DIRECT_TEST_INSTRUCTIONS_LOG="$LIVE_GATE_DIR/app-runtime-evidence-missing-direct-test-instructions.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_MISSING_DIRECT_TEST_INSTRUCTIONS" >"$APP_RUNTIME_EVIDENCE_MISSING_DIRECT_TEST_INSTRUCTIONS_LOG" 2>&1; then
  echo "Expected app-runtime evidence missing direct Test instructions text to fail."
  exit 1
fi
grep -F "CORE-007: Evidence must mention the tracker Test instructions" "$APP_RUNTIME_EVIDENCE_MISSING_DIRECT_TEST_INSTRUCTIONS_LOG" >/dev/null
APP_RUNTIME_EVIDENCE_BLOCKED_NO_RERUN="$LIVE_GATE_DIR/app-runtime-evidence-blocked-no-rerun.json"
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_BLOCKED_NO_RERUN"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
evidence = runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "blocked" if index == 0 else "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result {row['Result']} for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    row["Errors"] = f"{row['ID']} {row['Feature']}: signed-app prerequisite blocked this runtime row." if index == 0 else ""
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_BLOCKED_NO_RERUN_LOG="$LIVE_GATE_DIR/app-runtime-evidence-blocked-no-rerun.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_BLOCKED_NO_RERUN" >"$APP_RUNTIME_EVIDENCE_BLOCKED_NO_RERUN_LOG" 2>&1; then
  echo "Expected blocked app-runtime evidence without a Rerun command to fail."
  exit 1
fi
grep -F "CORE-007: blocked Evidence must include a Rerun command" "$APP_RUNTIME_EVIDENCE_BLOCKED_NO_RERUN_LOG" >/dev/null
APP_RUNTIME_EVIDENCE_BLOCKED_MISSING_RERUN_COMMAND="$LIVE_GATE_DIR/app-runtime-evidence-blocked-missing-rerun-command.json"
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_BLOCKED_MISSING_RERUN_COMMAND"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
evidence = runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "blocked" if index == 0 else "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result {row['Result']} for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    if index == 0:
        row["Evidence"] += " Rerun: qa/missing-app-runtime-rerun-command.sh"
    row["Errors"] = f"{row['ID']} {row['Feature']}: signed-app prerequisite blocked this runtime row." if index == 0 else ""
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_BLOCKED_MISSING_RERUN_COMMAND_LOG="$LIVE_GATE_DIR/app-runtime-evidence-blocked-missing-rerun-command.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_BLOCKED_MISSING_RERUN_COMMAND" >"$APP_RUNTIME_EVIDENCE_BLOCKED_MISSING_RERUN_COMMAND_LOG" 2>&1; then
  echo "Expected blocked app-runtime evidence with a missing Rerun command to fail."
  exit 1
fi
grep -F "CORE-007: Rerun command does not exist: qa/missing-app-runtime-rerun-command.sh" "$APP_RUNTIME_EVIDENCE_BLOCKED_MISSING_RERUN_COMMAND_LOG" >/dev/null
if [ "$APP_RUNTIME_EXPECTED_COUNT" -gt 1 ]; then
APP_RUNTIME_EVIDENCE_SHUFFLED="$LIVE_GATE_DIR/app-runtime-evidence-shuffled.json"
python3 - "$APP_RUNTIME_EVIDENCE_PASS" <<'PY' >"$APP_RUNTIME_EVIDENCE_SHUFFLED"
import json
import sys
from pathlib import Path

evidence = json.loads(Path(sys.argv[1]).read_text())
if len(evidence) < 2:
    raise SystemExit("app-runtime shuffled fixture needs at least two rows")
evidence[0], evidence[1] = evidence[1], evidence[0]
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_SHUFFLED_LOG="$LIVE_GATE_DIR/app-runtime-evidence-shuffled.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_SHUFFLED" >"$APP_RUNTIME_EVIDENCE_SHUFFLED_LOG" 2>&1; then
  echo "Expected shuffled app-runtime evidence rows to fail."
  exit 1
fi
grep -F "runtime evidence rows are not in canonical order" "$APP_RUNTIME_EVIDENCE_SHUFFLED_LOG" >/dev/null
fi
APP_RUNTIME_EVIDENCE_MISMATCHED_RESULT_TEXT="$LIVE_GATE_DIR/app-runtime-evidence-mismatched-result-text.json"
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_MISMATCHED_RESULT_TEXT"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
evidence = runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    if index == 0:
        row["Evidence"] = row["Evidence"].replace("Result pass", "Result blocked", 1)
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_MISMATCHED_RESULT_TEXT_LOG="$LIVE_GATE_DIR/app-runtime-evidence-mismatched-result-text.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_MISMATCHED_RESULT_TEXT" >"$APP_RUNTIME_EVIDENCE_MISMATCHED_RESULT_TEXT_LOG" 2>&1; then
  echo "Expected app-runtime evidence with mismatched Result text to fail."
  exit 1
fi
grep -F "CORE-007: Evidence must cite Result pass" "$APP_RUNTIME_EVIDENCE_MISMATCHED_RESULT_TEXT_LOG" >/dev/null
APP_RUNTIME_EVIDENCE_PUNCTUATED_ARTIFACT="$LIVE_GATE_DIR/app-runtime-evidence-punctuated-artifact.json"
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_PUNCTUATED_ARTIFACT"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
evidence = runtime_evidence_template(tracker_rows())
for row in evidence:
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}."
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_PUNCTUATED_ARTIFACT_LOG="$LIVE_GATE_DIR/app-runtime-evidence-punctuated-artifact.log"
qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_PUNCTUATED_ARTIFACT" >"$APP_RUNTIME_EVIDENCE_PUNCTUATED_ARTIFACT_LOG" 2>&1
grep -F "App-runtime evidence audit passed for ${APP_RUNTIME_EXPECTED_COUNT} user-story rows." "$APP_RUNTIME_EVIDENCE_PUNCTUATED_ARTIFACT_LOG" >/dev/null
APP_RUNTIME_EVIDENCE_MISSING_ADDITIONAL_ARTIFACT="$LIVE_GATE_DIR/app-runtime-evidence-missing-additional-artifact.json"
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_MISSING_ADDITIONAL_ARTIFACT"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
evidence = runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    if index == 0:
        row["Evidence"] += " Additional artifact: dist/app-runtime-artifacts/missing-supporting-log.log"
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_MISSING_ADDITIONAL_ARTIFACT_LOG="$LIVE_GATE_DIR/app-runtime-evidence-missing-additional-artifact.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_MISSING_ADDITIONAL_ARTIFACT" >"$APP_RUNTIME_EVIDENCE_MISSING_ADDITIONAL_ARTIFACT_LOG" 2>&1; then
  echo "Expected app-runtime evidence with a missing Additional artifact to fail."
  exit 1
fi
grep -F "CORE-007: Additional artifact does not exist: dist/app-runtime-artifacts/missing-supporting-log.log" "$APP_RUNTIME_EVIDENCE_MISSING_ADDITIONAL_ARTIFACT_LOG" >/dev/null
APP_RUNTIME_ARTIFACT_MISSING_RESULT="$LIVE_GATE_DIR/app-runtime-artifacts/runtime-sweep-missing-result.log"
export APP_RUNTIME_ARTIFACT_MISSING_RESULT
python3 - <<'PY' >"$APP_RUNTIME_ARTIFACT_MISSING_RESULT"
from qa.app_runtime_rows import runtime_pending_rows, tracker_rows

print("Observed signed app runtime sweep artifact with missing result support.")
for row in runtime_pending_rows(tracker_rows()):
    print(f"{row['ID']} {row['Feature']}: User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Observed signed app runtime user-story flow.")
PY
APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_RESULT="$LIVE_GATE_DIR/app-runtime-evidence-artifact-missing-result.json"
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_RESULT"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT_MISSING_RESULT"]
evidence = runtime_evidence_template(tracker_rows())
for row in evidence:
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_RESULT_LOG="$LIVE_GATE_DIR/app-runtime-evidence-artifact-missing-result.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_RESULT" >"$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_RESULT_LOG" 2>&1; then
  echo "Expected app-runtime evidence artifact missing Result support to fail."
  exit 1
fi
grep -F "CORE-007: Evidence artifact must mention Result pass" "$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_RESULT_LOG" >/dev/null
APP_RUNTIME_ARTIFACT_MISSING_ROW_SECTION="$LIVE_GATE_DIR/app-runtime-artifacts/runtime-sweep-missing-row-section.log"
export APP_RUNTIME_ARTIFACT_MISSING_ROW_SECTION
python3 - <<'PY' >"$APP_RUNTIME_ARTIFACT_MISSING_ROW_SECTION"
from qa.app_runtime_rows import runtime_pending_rows, tracker_rows

for index, row in enumerate(runtime_pending_rows(tracker_rows())):
    marker = "UI-999" if index == 0 else row["ID"]
    print(f"ROW {marker}")
    print(f"{row['ID']} {row['Feature']}: Result pass. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Observed signed app runtime user-story flow.")
PY
APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_ROW_SECTION="$LIVE_GATE_DIR/app-runtime-evidence-artifact-missing-row-section.json"
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_ROW_SECTION"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT_MISSING_ROW_SECTION"]
evidence = runtime_evidence_template(tracker_rows())
for row in evidence:
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_ROW_SECTION_LOG="$LIVE_GATE_DIR/app-runtime-evidence-artifact-missing-row-section.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_ROW_SECTION" >"$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_ROW_SECTION_LOG" 2>&1; then
  echo "Expected app-runtime evidence artifact missing a cited row section to fail."
  exit 1
fi
grep -F "CORE-007: Evidence artifact must include a row section for CORE-007" "$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_ROW_SECTION_LOG" >/dev/null
APP_RUNTIME_EVIDENCE_PASS_REQUIRED_LOG="$LIVE_GATE_DIR/app-runtime-evidence-pass-required.log"
if BASTION_APP_PATH="$LIVE_GATE_DIR/missing-prereq.app" qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_PASS" --require-pass >"$APP_RUNTIME_EVIDENCE_PASS_REQUIRED_LOG" 2>&1; then
  echo "Expected final app-runtime require-pass audit to fail while runtime prerequisites are blocked."
  exit 1
fi
grep -F "App-runtime evidence audit passed for ${APP_RUNTIME_EXPECTED_COUNT} user-story rows." "$APP_RUNTIME_EVIDENCE_PASS_REQUIRED_LOG" >/dev/null
grep -F "Current-source signed app rebuild: Blocked" "$APP_RUNTIME_EVIDENCE_PASS_REQUIRED_LOG" >/dev/null
grep -F "Final app-runtime require-pass evidence needs satisfied runtime prerequisites" "$APP_RUNTIME_EVIDENCE_PASS_REQUIRED_LOG" >/dev/null
APP_RUNTIME_TRACKER_UPDATE_PASS="$LIVE_GATE_DIR/app-runtime-tracker-update-pass.json"
APP_RUNTIME_TRACKER_UPDATE_PASS_LOG="$LIVE_GATE_DIR/app-runtime-tracker-update-pass.log"
if BASTION_APP_PATH="$LIVE_GATE_DIR/missing-prereq.app" qa/run_app_runtime_user_story_checks.sh --write-tracker-update "$APP_RUNTIME_EVIDENCE_PASS" "$APP_RUNTIME_TRACKER_UPDATE_PASS" >"$APP_RUNTIME_TRACKER_UPDATE_PASS_LOG" 2>&1; then
  echo "Expected all-pass app-runtime tracker-update generation to fail while runtime prerequisites are blocked."
  exit 1
fi
grep -F "Current-source signed app rebuild: Blocked" "$APP_RUNTIME_TRACKER_UPDATE_PASS_LOG" >/dev/null
grep -F "Final app-runtime require-pass evidence needs satisfied runtime prerequisites" "$APP_RUNTIME_TRACKER_UPDATE_PASS_LOG" >/dev/null
APP_RUNTIME_UPDATED_SOURCE_PASS="$LIVE_GATE_DIR/app-runtime-updated-source-pass.json"
APP_RUNTIME_UPDATED_SOURCE_PASS_LOG="$LIVE_GATE_DIR/app-runtime-updated-source-pass.log"
if BASTION_APP_PATH="$LIVE_GATE_DIR/missing-prereq.app" qa/run_app_runtime_user_story_checks.sh --write-updated-source "$APP_RUNTIME_EVIDENCE_PASS" "$APP_RUNTIME_UPDATED_SOURCE_PASS" >"$APP_RUNTIME_UPDATED_SOURCE_PASS_LOG" 2>&1; then
  echo "Expected all-pass app-runtime updated-source generation to fail while runtime prerequisites are blocked."
  exit 1
fi
grep -F "Current-source signed app rebuild: Blocked" "$APP_RUNTIME_UPDATED_SOURCE_PASS_LOG" >/dev/null
grep -F "Final app-runtime require-pass evidence needs satisfied runtime prerequisites" "$APP_RUNTIME_UPDATED_SOURCE_PASS_LOG" >/dev/null

APP_RUNTIME_EVIDENCE_DOCUMENTED_FAILURE="$LIVE_GATE_DIR/app-runtime-evidence-documented-failure.json"
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_DOCUMENTED_FAILURE"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
evidence = runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "fail" if index == 0 else "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result {row['Result']} for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    row["Errors"] = f"{row['ID']} {row['Feature']}: observed runtime mismatch that must be fixed and retested. Artifact: {artifact}." if index == 0 else ""
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_DOCUMENTED_FAILURE_LOG="$LIVE_GATE_DIR/app-runtime-evidence-documented-failure.log"
qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_DOCUMENTED_FAILURE" >"$APP_RUNTIME_EVIDENCE_DOCUMENTED_FAILURE_LOG" 2>&1
grep -F "App-runtime evidence audit passed for ${APP_RUNTIME_EXPECTED_COUNT} user-story rows." "$APP_RUNTIME_EVIDENCE_DOCUMENTED_FAILURE_LOG" >/dev/null
APP_RUNTIME_EVIDENCE_REQUIRE_PASS_FAILURE_LOG="$LIVE_GATE_DIR/app-runtime-evidence-require-pass-failure.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_DOCUMENTED_FAILURE" --require-pass >"$APP_RUNTIME_EVIDENCE_REQUIRE_PASS_FAILURE_LOG" 2>&1; then
  echo "Expected final app-runtime evidence closure to fail when any row is not pass."
  exit 1
fi
grep -F "CORE-007: Result must be pass for final post-fix runtime closure" "$APP_RUNTIME_EVIDENCE_REQUIRE_PASS_FAILURE_LOG" >/dev/null

APP_RUNTIME_TRACKER_UPDATE="$LIVE_GATE_DIR/app-runtime-tracker-update.json"
APP_RUNTIME_TRACKER_UPDATE_LOG="$LIVE_GATE_DIR/app-runtime-tracker-update.log"
BASTION_APP_PATH="$LIVE_GATE_DIR/missing-prereq.app" qa/run_app_runtime_user_story_checks.sh --write-tracker-update "$APP_RUNTIME_EVIDENCE_DOCUMENTED_FAILURE" "$APP_RUNTIME_TRACKER_UPDATE" >"$APP_RUNTIME_TRACKER_UPDATE_LOG" 2>&1
grep -F "Wrote tracker update review artifact for ${APP_RUNTIME_EXPECTED_COUNT} runtime evidence rows" "$APP_RUNTIME_TRACKER_UPDATE_LOG" >/dev/null
python3 - "$APP_RUNTIME_TRACKER_UPDATE" "$APP_RUNTIME_EXPECTED_COUNT" "$APP_RUNTIME_EVIDENCE_DOCUMENTED_FAILURE" <<'PY'
import json
import sys
from pathlib import Path

updates = json.loads(Path(sys.argv[1]).read_text())
expected_count = int(sys.argv[2])
evidence = json.loads(Path(sys.argv[3]).read_text())
expected_keys = {
    "ID",
    "Feature",
    "Result",
    "Test status",
    "Errors documented",
    "Fix status",
    "Retest status",
}
if len(updates) != expected_count:
    raise SystemExit(f"unexpected tracker update row count {len(updates)}")
for index, row in enumerate(updates, start=1):
    if set(row) != expected_keys:
        raise SystemExit(f"app-runtime tracker update row {index} has non-canonical keys: {sorted(row)}")
by_id = {row["ID"]: row for row in updates}
evidence_by_id = {row["ID"]: row for row in evidence}
row = by_id["CORE-007"]
if row["Result"] != "fail" or row["Test status"] != "Pending":
    raise SystemExit("failed runtime row must become Pending in tracker update")
if "CORE-007" not in row["Errors documented"] or "CLI symlink installation" not in row["Errors documented"]:
    raise SystemExit("failed runtime row must carry row-specific Errors documented text")
if "Pending fix from signed-app runtime evidence for CORE-007 CLI symlink installation." != row["Fix status"]:
    raise SystemExit("failed runtime row must request a pending fix")
if "Pending post-fix runtime retest for CORE-007 CLI symlink installation." not in row["Retest status"]:
    raise SystemExit("failed runtime row must request post-fix retest")
if evidence_by_id["CORE-007"]["Evidence"] not in row["Retest status"]:
    raise SystemExit("failed runtime row must carry exact Evidence text into Retest status")
if "Artifact:" not in row["Retest status"]:
    raise SystemExit("failed runtime row Retest status must preserve Artifact citation")
PY
APP_RUNTIME_DIRECT_TRACKER_UPDATE_LOG="$LIVE_GATE_DIR/app-runtime-direct-tracker-update.log"
cp qa/feature_status_source.json "$LIVE_GATE_DIR/feature_status_source.before-app-direct-tracker-update.json"
if qa/run_app_runtime_user_story_checks.sh --write-tracker-update "$APP_RUNTIME_EVIDENCE_DOCUMENTED_FAILURE" qa/feature_status_source.json >"$APP_RUNTIME_DIRECT_TRACKER_UPDATE_LOG" 2>&1; then
  echo "Expected app-runtime tracker update generation to reject the canonical source path."
  exit 1
fi
grep -F "app-runtime tracker update must be written as a review artifact, not directly over qa/feature_status_source.json" "$APP_RUNTIME_DIRECT_TRACKER_UPDATE_LOG" >/dev/null
cmp -s qa/feature_status_source.json "$LIVE_GATE_DIR/feature_status_source.before-app-direct-tracker-update.json"
APP_RUNTIME_DIRECT_UPDATED_SOURCE_LOG="$LIVE_GATE_DIR/app-runtime-direct-updated-source.log"
cp qa/feature_status_source.json "$LIVE_GATE_DIR/feature_status_source.before-app-direct-updated-source.json"
if qa/run_app_runtime_user_story_checks.sh --write-updated-source "$APP_RUNTIME_EVIDENCE_PASS" qa/feature_status_source.json >"$APP_RUNTIME_DIRECT_UPDATED_SOURCE_LOG" 2>&1; then
  echo "Expected app-runtime updated-source generation to reject the canonical source path."
  exit 1
fi
grep -F "app-runtime updated source must be written as a review artifact, not directly over qa/feature_status_source.json" "$APP_RUNTIME_DIRECT_UPDATED_SOURCE_LOG" >/dev/null
cmp -s qa/feature_status_source.json "$LIVE_GATE_DIR/feature_status_source.before-app-direct-updated-source.json"
APP_RUNTIME_UPDATED_SOURCE="$LIVE_GATE_DIR/app-runtime-updated-source.json"
APP_RUNTIME_UPDATED_SOURCE_LOG="$LIVE_GATE_DIR/app-runtime-updated-source.log"
if qa/run_app_runtime_user_story_checks.sh --write-updated-source "$APP_RUNTIME_EVIDENCE_DOCUMENTED_FAILURE" "$APP_RUNTIME_UPDATED_SOURCE" >"$APP_RUNTIME_UPDATED_SOURCE_LOG" 2>&1; then
  echo "Expected partial app-runtime failure evidence to fail canonical updated-source generation."
  exit 1
fi
grep -F "app-runtime updated-source artifacts cannot include failed runtime evidence." "$APP_RUNTIME_UPDATED_SOURCE_LOG" >/dev/null
grep -F "Use --write-tracker-update for fail or blocked evidence while documenting the fix/retest loop." "$APP_RUNTIME_UPDATED_SOURCE_LOG" >/dev/null
test ! -e "$APP_RUNTIME_UPDATED_SOURCE"

APP_RUNTIME_EVIDENCE_VAGUE_FAILURE="$LIVE_GATE_DIR/app-runtime-evidence-vague-failure.json"
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_VAGUE_FAILURE"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
evidence = runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "fail" if index == 0 else "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    row["Errors"] = "Observed runtime mismatch that must be fixed and retested." if index == 0 else ""
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_VAGUE_FAILURE_LOG="$LIVE_GATE_DIR/app-runtime-evidence-vague-failure.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_VAGUE_FAILURE" >"$APP_RUNTIME_EVIDENCE_VAGUE_FAILURE_LOG" 2>&1; then
  echo "Expected vague app-runtime failure evidence to fail without row-specific Errors text."
  exit 1
fi
grep -F "CORE-007: Errors must mention the row ID" "$APP_RUNTIME_EVIDENCE_VAGUE_FAILURE_LOG" >/dev/null
grep -F "CORE-007: Errors must mention the tracker Feature" "$APP_RUNTIME_EVIDENCE_VAGUE_FAILURE_LOG" >/dev/null

APP_RUNTIME_EVIDENCE_ERRORS_MISSING_REFERENCES="$LIVE_GATE_DIR/app-runtime-evidence-errors-missing-references.json"
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_ERRORS_MISSING_REFERENCES"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
evidence = runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "blocked" if index == 0 else "pass"
    row["Evidence"] = (
        f"Observed signed app runtime sweep completed with Result {row['Result']} for {row['ID']} {row['Feature']}. "
        f"User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} "
        f"Test instructions: {row['Test instructions']} Artifact: {artifact}"
    )
    if index == 0:
        row["Evidence"] += " Rerun: qa/run_app_runtime_user_story_checks.sh --audit-evidence"
        row["Errors"] = f"{row['ID']} {row['Feature']}: signed-app prerequisite blocked this runtime row."
    else:
        row["Errors"] = ""
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_ERRORS_MISSING_REFERENCES_LOG="$LIVE_GATE_DIR/app-runtime-evidence-errors-missing-references.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_ERRORS_MISSING_REFERENCES" >"$APP_RUNTIME_EVIDENCE_ERRORS_MISSING_REFERENCES_LOG" 2>&1; then
  echo "Expected blocked app-runtime evidence Errors without artifact/rerun references to fail."
  exit 1
fi
grep -F "CORE-007: Errors must mention the Evidence artifact" "$APP_RUNTIME_EVIDENCE_ERRORS_MISSING_REFERENCES_LOG" >/dev/null
grep -F "CORE-007: Errors must mention the Rerun command" "$APP_RUNTIME_EVIDENCE_ERRORS_MISSING_REFERENCES_LOG" >/dev/null

APP_RUNTIME_EVIDENCE_MISSING="$LIVE_GATE_DIR/app-runtime-evidence-missing.json"
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_MISSING"
import json
import os

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
print(json.dumps([
    {
        "ID": "CORE-007",
        "Surface": "Stale surface text",
        "Feature": "Stale feature text",
        "User story": "Stale user story text",
        "Expected behaviour": "Stale expected behaviour text",
        "Test instructions": "Stale test instruction text",
        "Result": "pass",
        "Evidence": f"Observed signed app runtime sweep covered one row. User story: Stale user story text Expected behaviour: Stale expected behaviour text Artifact: {artifact}",
        "Errors": "",
    }
], indent=2))
PY
APP_RUNTIME_EVIDENCE_MISSING_LOG="$LIVE_GATE_DIR/app-runtime-evidence-missing.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_MISSING" >"$APP_RUNTIME_EVIDENCE_MISSING_LOG" 2>&1; then
  echo "Expected incomplete app-runtime evidence audit fixture to fail."
  exit 1
fi
grep -F "CORE-007: Surface does not match qa/feature_status_source.json" "$APP_RUNTIME_EVIDENCE_MISSING_LOG" >/dev/null
grep -F "CORE-007: Feature does not match qa/feature_status_source.json" "$APP_RUNTIME_EVIDENCE_MISSING_LOG" >/dev/null
grep -F "CORE-007: Test instructions does not match qa/feature_status_source.json" "$APP_RUNTIME_EVIDENCE_MISSING_LOG" >/dev/null

APP_RUNTIME_EVIDENCE_BLOCKED_NO_ERRORS="$LIVE_GATE_DIR/app-runtime-evidence-blocked-no-errors.json"
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_BLOCKED_NO_ERRORS"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
evidence = runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "blocked" if index == 0 else "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    row["Errors"] = ""
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_BLOCKED_NO_ERRORS_LOG="$LIVE_GATE_DIR/app-runtime-evidence-blocked-no-errors.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_BLOCKED_NO_ERRORS" >"$APP_RUNTIME_EVIDENCE_BLOCKED_NO_ERRORS_LOG" 2>&1; then
  echo "Expected blocked app-runtime evidence without Errors to fail."
  exit 1
fi
grep -F "CORE-007: Errors is required when Result is fail or blocked" "$APP_RUNTIME_EVIDENCE_BLOCKED_NO_ERRORS_LOG" >/dev/null

APP_RUNTIME_EVIDENCE_BLOCKED_PLACEHOLDER_ERRORS="$LIVE_GATE_DIR/app-runtime-evidence-blocked-placeholder-errors.json"
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_BLOCKED_PLACEHOLDER_ERRORS"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
evidence = runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "blocked" if index == 0 else "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    row["Errors"] = "TODO placeholder runtime failure" if index == 0 else ""
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_BLOCKED_PLACEHOLDER_ERRORS_LOG="$LIVE_GATE_DIR/app-runtime-evidence-blocked-placeholder-errors.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_BLOCKED_PLACEHOLDER_ERRORS" >"$APP_RUNTIME_EVIDENCE_BLOCKED_PLACEHOLDER_ERRORS_LOG" 2>&1; then
  echo "Expected blocked app-runtime evidence with placeholder Errors to fail."
  exit 1
fi
grep -F "CORE-007: Errors must describe real runtime failures, not placeholder text" "$APP_RUNTIME_EVIDENCE_BLOCKED_PLACEHOLDER_ERRORS_LOG" >/dev/null

APP_RUNTIME_EVIDENCE_PASS_WITH_ERRORS="$LIVE_GATE_DIR/app-runtime-evidence-pass-with-errors.json"
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_PASS_WITH_ERRORS"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
evidence = runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    row["Errors"] = "Stale error that should have been cleared" if index == 0 else ""
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_PASS_WITH_ERRORS_LOG="$LIVE_GATE_DIR/app-runtime-evidence-pass-with-errors.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_PASS_WITH_ERRORS" >"$APP_RUNTIME_EVIDENCE_PASS_WITH_ERRORS_LOG" 2>&1; then
  echo "Expected passed app-runtime evidence with stale Errors to fail."
  exit 1
fi
grep -F "CORE-007: Errors must be empty when Result is pass" "$APP_RUNTIME_EVIDENCE_PASS_WITH_ERRORS_LOG" >/dev/null

APP_RUNTIME_EVIDENCE_PASS_MISSING_ERRORS="$LIVE_GATE_DIR/app-runtime-evidence-pass-missing-errors.json"
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_PASS_MISSING_ERRORS"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
evidence = runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    if index == 0:
        del row["Errors"]
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_PASS_MISSING_ERRORS_LOG="$LIVE_GATE_DIR/app-runtime-evidence-pass-missing-errors.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_PASS_MISSING_ERRORS" >"$APP_RUNTIME_EVIDENCE_PASS_MISSING_ERRORS_LOG" 2>&1; then
  echo "Expected passed app-runtime evidence without the Errors key to fail."
  exit 1
fi
grep -F "row 1: Errors key is required" "$APP_RUNTIME_EVIDENCE_PASS_MISSING_ERRORS_LOG" >/dev/null

APP_RUNTIME_EVIDENCE_EXTRA_KEY="$LIVE_GATE_DIR/app-runtime-evidence-extra-key.json"
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_EXTRA_KEY"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
evidence = runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    if index == 0:
        row["Reviewer notes"] = "Out-of-contract field"
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_EXTRA_KEY_LOG="$LIVE_GATE_DIR/app-runtime-evidence-extra-key.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_EXTRA_KEY" >"$APP_RUNTIME_EVIDENCE_EXTRA_KEY_LOG" 2>&1; then
  echo "Expected app-runtime evidence with an extra key to fail."
  exit 1
fi
grep -F "row 1: unexpected Reviewer notes key" "$APP_RUNTIME_EVIDENCE_EXTRA_KEY_LOG" >/dev/null

APP_RUNTIME_EVIDENCE_PADDED_RESULT="$LIVE_GATE_DIR/app-runtime-evidence-padded-result.json"
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_PADDED_RESULT"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
evidence = runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = " pass " if index == 0 else "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_PADDED_RESULT_LOG="$LIVE_GATE_DIR/app-runtime-evidence-padded-result.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_PADDED_RESULT" >"$APP_RUNTIME_EVIDENCE_PADDED_RESULT_LOG" 2>&1; then
  echo "Expected app-runtime evidence with padded Result to fail."
  exit 1
fi
grep -F "CORE-007: Result must be one of pass, fail, blocked" "$APP_RUNTIME_EVIDENCE_PADDED_RESULT_LOG" >/dev/null

APP_RUNTIME_EVIDENCE_PADDED_ID="$LIVE_GATE_DIR/app-runtime-evidence-padded-id.json"
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_PADDED_ID"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
evidence = runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    if index == 0:
        row["ID"] = f" {row['ID']} "
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_PADDED_ID_LOG="$LIVE_GATE_DIR/app-runtime-evidence-padded-id.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_PADDED_ID" >"$APP_RUNTIME_EVIDENCE_PADDED_ID_LOG" 2>&1; then
  echo "Expected app-runtime evidence with padded ID to fail."
  exit 1
fi
grep -F "CORE-007: ID must not contain leading or trailing whitespace" "$APP_RUNTIME_EVIDENCE_PADDED_ID_LOG" >/dev/null

APP_RUNTIME_EVIDENCE_NON_STRING="$LIVE_GATE_DIR/app-runtime-evidence-non-string.json"
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_NON_STRING"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
evidence = runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    if index == 0:
        row["Evidence"] = ["not", "a", "string"]
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_NON_STRING_LOG="$LIVE_GATE_DIR/app-runtime-evidence-non-string.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_NON_STRING" >"$APP_RUNTIME_EVIDENCE_NON_STRING_LOG" 2>&1; then
  echo "Expected app-runtime evidence with non-string fields to fail."
  exit 1
fi
grep -F "row 1: Evidence must be a string" "$APP_RUNTIME_EVIDENCE_NON_STRING_LOG" >/dev/null

APP_RUNTIME_EVIDENCE_PLACEHOLDER="$LIVE_GATE_DIR/app-runtime-evidence-placeholder.json"
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_PLACEHOLDER"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
evidence = runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    if index == 0:
        row["Evidence"] = "TODO placeholder runtime evidence"
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_PLACEHOLDER_LOG="$LIVE_GATE_DIR/app-runtime-evidence-placeholder.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_PLACEHOLDER" >"$APP_RUNTIME_EVIDENCE_PLACEHOLDER_LOG" 2>&1; then
  echo "Expected app-runtime evidence with placeholder text to fail."
  exit 1
fi
grep -F "CORE-007: Evidence must describe real runtime observations, not placeholder text" "$APP_RUNTIME_EVIDENCE_PLACEHOLDER_LOG" >/dev/null

APP_RUNTIME_EVIDENCE_MISSING_ROW_ID="$LIVE_GATE_DIR/app-runtime-evidence-missing-row-id.json"
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_MISSING_ROW_ID"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
evidence = runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    if index == 0:
        row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for the first tracker row. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_MISSING_ROW_ID_LOG="$LIVE_GATE_DIR/app-runtime-evidence-missing-row-id.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_MISSING_ROW_ID" >"$APP_RUNTIME_EVIDENCE_MISSING_ROW_ID_LOG" 2>&1; then
  echo "Expected app-runtime evidence without a row ID mention to fail."
  exit 1
fi
grep -F "CORE-007: Evidence must mention the row ID" "$APP_RUNTIME_EVIDENCE_MISSING_ROW_ID_LOG" >/dev/null

APP_RUNTIME_EVIDENCE_MISSING_FEATURE="$LIVE_GATE_DIR/app-runtime-evidence-missing-feature.json"
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_MISSING_FEATURE"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
evidence = runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    if index == 0:
        row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_MISSING_FEATURE_LOG="$LIVE_GATE_DIR/app-runtime-evidence-missing-feature.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_MISSING_FEATURE" >"$APP_RUNTIME_EVIDENCE_MISSING_FEATURE_LOG" 2>&1; then
  echo "Expected app-runtime evidence without tracker Feature text to fail."
  exit 1
fi
grep -F "CORE-007: Evidence must mention the tracker Feature" "$APP_RUNTIME_EVIDENCE_MISSING_FEATURE_LOG" >/dev/null

APP_RUNTIME_ARTIFACT_MISSING_ROW_ID="$LIVE_GATE_DIR/app-runtime-artifacts/runtime-sweep-missing-row-id.log"
printf '%s\n' "Result pass. Observed signed app runtime sweep artifact without the first row ID." >"$APP_RUNTIME_ARTIFACT_MISSING_ROW_ID"
APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_ROW_ID="$LIVE_GATE_DIR/app-runtime-evidence-artifact-missing-row-id.json"
export APP_RUNTIME_ARTIFACT_MISSING_ROW_ID
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_ROW_ID"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
missing_row_artifact = os.environ["APP_RUNTIME_ARTIFACT_MISSING_ROW_ID"]
evidence = runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    if index == 0:
        row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. Artifact: {missing_row_artifact}"
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_ROW_ID_LOG="$LIVE_GATE_DIR/app-runtime-evidence-artifact-missing-row-id.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_ROW_ID" >"$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_ROW_ID_LOG" 2>&1; then
  echo "Expected app-runtime evidence with an artifact missing the row ID to fail."
  exit 1
fi
grep -F "CORE-007: Evidence artifact must mention the row ID: ${APP_RUNTIME_ARTIFACT_MISSING_ROW_ID}" "$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_ROW_ID_LOG" >/dev/null

APP_RUNTIME_ARTIFACT_MISSING_FEATURE="$LIVE_GATE_DIR/app-runtime-artifacts/runtime-sweep-missing-feature.log"
python3 - <<'PY' >"$APP_RUNTIME_ARTIFACT_MISSING_FEATURE"
from qa.app_runtime_rows import runtime_pending_rows, tracker_rows

print("Observed signed app runtime sweep artifact with the first row feature omitted.")
for index, row in enumerate(runtime_pending_rows(tracker_rows())):
    if index == 0:
        print(f"{row['ID']}: Result pass. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Observed signed app runtime user-story flow.")
    else:
        print(f"{row['ID']} {row['Feature']}: Result pass. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Observed signed app runtime user-story flow.")
PY
APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_FEATURE="$LIVE_GATE_DIR/app-runtime-evidence-artifact-missing-feature.json"
export APP_RUNTIME_ARTIFACT_MISSING_FEATURE
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_FEATURE"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
missing_feature_artifact = os.environ["APP_RUNTIME_ARTIFACT_MISSING_FEATURE"]
evidence = runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    if index == 0:
        row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. Artifact: {missing_feature_artifact}"
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_FEATURE_LOG="$LIVE_GATE_DIR/app-runtime-evidence-artifact-missing-feature.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_FEATURE" >"$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_FEATURE_LOG" 2>&1; then
  echo "Expected app-runtime evidence with an artifact missing tracker Feature text to fail."
  exit 1
fi
grep -F "CORE-007: Evidence artifact must mention the tracker Feature: ${APP_RUNTIME_ARTIFACT_MISSING_FEATURE}" "$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_FEATURE_LOG" >/dev/null

APP_RUNTIME_ARTIFACT_MISSING_EXPECTED="$LIVE_GATE_DIR/app-runtime-artifacts/runtime-sweep-missing-expected.log"
python3 - <<'PY' >"$APP_RUNTIME_ARTIFACT_MISSING_EXPECTED"
from qa.app_runtime_rows import runtime_pending_rows, tracker_rows

print("Observed signed app runtime sweep artifact with the first row expected behaviour omitted.")
for index, row in enumerate(runtime_pending_rows(tracker_rows())):
    if index == 0:
        print(f"{row['ID']} {row['Feature']}: Result pass. User story: {row['User story']} observed signed app runtime user-story flow.")
    else:
        print(f"{row['ID']} {row['Feature']}: Result pass. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Observed signed app runtime user-story flow.")
PY
APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_EXPECTED="$LIVE_GATE_DIR/app-runtime-evidence-artifact-missing-expected.json"
export APP_RUNTIME_ARTIFACT_MISSING_EXPECTED
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_EXPECTED"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
missing_expected_artifact = os.environ["APP_RUNTIME_ARTIFACT_MISSING_EXPECTED"]
evidence = runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    if index == 0:
        row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. Artifact: {missing_expected_artifact}"
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_EXPECTED_LOG="$LIVE_GATE_DIR/app-runtime-evidence-artifact-missing-expected.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_EXPECTED" >"$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_EXPECTED_LOG" 2>&1; then
  echo "Expected app-runtime evidence with an artifact missing tracker Expected behaviour text to fail."
  exit 1
fi
grep -F "CORE-007: Evidence artifact must mention the tracker Expected behaviour: ${APP_RUNTIME_ARTIFACT_MISSING_EXPECTED}" "$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_EXPECTED_LOG" >/dev/null

APP_RUNTIME_ARTIFACT_MISSING_USER_STORY="$LIVE_GATE_DIR/app-runtime-artifacts/runtime-sweep-missing-user-story.log"
python3 - <<'PY' >"$APP_RUNTIME_ARTIFACT_MISSING_USER_STORY"
from qa.app_runtime_rows import runtime_pending_rows, tracker_rows

print("Observed signed app runtime sweep artifact with the first row user story omitted.")
for index, row in enumerate(runtime_pending_rows(tracker_rows())):
    if index == 0:
        print(f"{row['ID']} {row['Feature']}: Result pass. Expected behaviour: {row['Expected behaviour']} Observed signed app runtime flow without user-story support.")
    else:
        print(f"{row['ID']} {row['Feature']}: Result pass. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Observed signed app runtime user-story flow.")
PY
APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_USER_STORY="$LIVE_GATE_DIR/app-runtime-evidence-artifact-missing-user-story.json"
export APP_RUNTIME_ARTIFACT_MISSING_USER_STORY
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_USER_STORY"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
missing_user_story_artifact = os.environ["APP_RUNTIME_ARTIFACT_MISSING_USER_STORY"]
evidence = runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    if index == 0:
        row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. Artifact: {missing_user_story_artifact}"
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_USER_STORY_LOG="$LIVE_GATE_DIR/app-runtime-evidence-artifact-missing-user-story.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_USER_STORY" >"$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_USER_STORY_LOG" 2>&1; then
  echo "Expected app-runtime evidence with an artifact missing tracker User story text to fail."
  exit 1
fi
grep -F "CORE-007: Evidence artifact must mention the tracker User story: ${APP_RUNTIME_ARTIFACT_MISSING_USER_STORY}" "$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_USER_STORY_LOG" >/dev/null

APP_RUNTIME_ARTIFACT_MISSING_TEST_INSTRUCTIONS="$LIVE_GATE_DIR/app-runtime-artifacts/runtime-sweep-missing-test-instructions.log"
python3 - <<'PY' >"$APP_RUNTIME_ARTIFACT_MISSING_TEST_INSTRUCTIONS"
from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

print("Observed signed app runtime sweep artifact with the first row test instructions omitted.")
for index, row in enumerate(runtime_evidence_template(tracker_rows())):
    if index == 0:
        print(f"{row['ID']} {row['Feature']}: Result pass. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Observed signed app runtime flow without test-instructions support.")
    else:
        print(f"{row['ID']} {row['Feature']}: Result pass. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Observed signed app runtime user-story flow.")
PY
APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_TEST_INSTRUCTIONS="$LIVE_GATE_DIR/app-runtime-evidence-artifact-missing-test-instructions.json"
export APP_RUNTIME_ARTIFACT_MISSING_TEST_INSTRUCTIONS
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_TEST_INSTRUCTIONS"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
missing_test_instructions_artifact = os.environ["APP_RUNTIME_ARTIFACT_MISSING_TEST_INSTRUCTIONS"]
evidence = runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    if index == 0:
        row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. Artifact: {missing_test_instructions_artifact}"
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_TEST_INSTRUCTIONS_LOG="$LIVE_GATE_DIR/app-runtime-evidence-artifact-missing-test-instructions.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_TEST_INSTRUCTIONS" >"$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_TEST_INSTRUCTIONS_LOG" 2>&1; then
  echo "Expected app-runtime evidence with an artifact missing tracker Test instructions text to fail."
  exit 1
fi
grep -F "CORE-007: Evidence artifact must mention the tracker Test instructions: ${APP_RUNTIME_ARTIFACT_MISSING_TEST_INSTRUCTIONS}" "$APP_RUNTIME_EVIDENCE_ARTIFACT_MISSING_TEST_INSTRUCTIONS_LOG" >/dev/null

APP_RUNTIME_EVIDENCE_MISSING_ARTIFACT="$LIVE_GATE_DIR/app-runtime-evidence-missing-artifact.json"
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_MISSING_ARTIFACT"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
missing_artifact = f"{artifact}.missing"
evidence = runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    if index == 0:
        row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. Artifact: {missing_artifact}"
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_MISSING_ARTIFACT_LOG="$LIVE_GATE_DIR/app-runtime-evidence-missing-artifact.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_MISSING_ARTIFACT" >"$APP_RUNTIME_EVIDENCE_MISSING_ARTIFACT_LOG" 2>&1; then
  echo "Expected app-runtime evidence with a missing artifact path to fail."
  exit 1
fi
grep -F "CORE-007: Evidence artifact does not exist: ${APP_RUNTIME_ARTIFACT}.missing" "$APP_RUNTIME_EVIDENCE_MISSING_ARTIFACT_LOG" >/dev/null

APP_RUNTIME_EMPTY_ARTIFACT="$LIVE_GATE_DIR/app-runtime-artifacts/empty-runtime-sweep.log"
: >"$APP_RUNTIME_EMPTY_ARTIFACT"
APP_RUNTIME_EVIDENCE_EMPTY_ARTIFACT="$LIVE_GATE_DIR/app-runtime-evidence-empty-artifact.json"
export APP_RUNTIME_EMPTY_ARTIFACT
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_EMPTY_ARTIFACT"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
empty_artifact = os.environ["APP_RUNTIME_EMPTY_ARTIFACT"]
evidence = runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    if index == 0:
        row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. Artifact: {empty_artifact}"
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_EMPTY_ARTIFACT_LOG="$LIVE_GATE_DIR/app-runtime-evidence-empty-artifact.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_EMPTY_ARTIFACT" >"$APP_RUNTIME_EVIDENCE_EMPTY_ARTIFACT_LOG" 2>&1; then
  echo "Expected app-runtime evidence with an empty artifact file to fail."
  exit 1
fi
grep -F "CORE-007: Evidence artifact must not be empty: ${APP_RUNTIME_EMPTY_ARTIFACT}" "$APP_RUNTIME_EVIDENCE_EMPTY_ARTIFACT_LOG" >/dev/null

APP_RUNTIME_DIRECTORY_ARTIFACT="$LIVE_GATE_DIR/app-runtime-artifacts/directory-runtime-sweep"
mkdir -p "$APP_RUNTIME_DIRECTORY_ARTIFACT"
APP_RUNTIME_EVIDENCE_DIRECTORY_ARTIFACT="$LIVE_GATE_DIR/app-runtime-evidence-directory-artifact.json"
export APP_RUNTIME_DIRECTORY_ARTIFACT
python3 - <<'PY' >"$APP_RUNTIME_EVIDENCE_DIRECTORY_ARTIFACT"
import json
import os

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

artifact = os.environ["APP_RUNTIME_ARTIFACT"]
directory_artifact = os.environ["APP_RUNTIME_DIRECTORY_ARTIFACT"]
evidence = runtime_evidence_template(tracker_rows())
for index, row in enumerate(evidence):
    row["Result"] = "pass"
    row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} Test instructions: {row['Test instructions']} Artifact: {artifact}"
    if index == 0:
        row["Evidence"] = f"Observed signed app runtime sweep completed with Result pass for {row['ID']} {row['Feature']}. Artifact: {directory_artifact}"
print(json.dumps(evidence, indent=2))
PY
APP_RUNTIME_EVIDENCE_DIRECTORY_ARTIFACT_LOG="$LIVE_GATE_DIR/app-runtime-evidence-directory-artifact.log"
if qa/run_app_runtime_user_story_checks.sh --audit-evidence "$APP_RUNTIME_EVIDENCE_DIRECTORY_ARTIFACT" >"$APP_RUNTIME_EVIDENCE_DIRECTORY_ARTIFACT_LOG" 2>&1; then
  echo "Expected app-runtime evidence with a directory artifact to fail."
  exit 1
fi
grep -F "CORE-007: Evidence artifact must be a regular file: ${APP_RUNTIME_DIRECTORY_ARTIFACT}" "$APP_RUNTIME_EVIDENCE_DIRECTORY_ARTIFACT_LOG" >/dev/null
fi

echo "== Lifecycle evidence audit fixtures =="
write_lifecycle_log() {
  local dir="$1"
  local phase="$2"
  local app="$3"
  local domain="$4"
  local team_id="$5"
  local recorded_phase="${6:-$phase}"
  local safe_phase
  safe_phase="$(printf '%s' "$phase" | tr -c 'A-Za-z0-9_.-' '_')"
  local log_path="$dir/20200101T000000Z-${safe_phase}.log"

  cat > "$log_path" <<EOF
==> Bastion live service lifecycle verification
Phase: ${recorded_phase}
App: ${app}
Domain: ${domain}
Evidence: ${log_path}
TeamIdentifier: ${team_id}
==> CLI status
{"executablePath":"${app}/Contents/MacOS/bastion","bundlePath":"${app}","launchMode":"service","machServiceName":"com.bastion.xpc"}
==> XPC UI open auditHistory
{
  "opened" : true,
  "target" : "auditHistory"
}
EOF
  if [[ "$phase" == "notification-click" ]]; then
    printf '%s\n' 'Matched delivery diagnostic: {"event":"notification_delivered","bastionProbeID":"fixture"}' >> "$log_path"
    printf '%s\n' 'Matched click route diagnostic: {"event":"notification_click_local_open","bastionProbeID":"fixture","context":{"target":"auditHistory"}}' >> "$log_path"
  fi
  printf '%s\n' '==> Live lifecycle verification complete' >> "$log_path"
}

AUDIT_PASS_DIR="$LIVE_GATE_DIR/audit-pass"
mkdir -p "$AUDIT_PASS_DIR"
for phase in fresh-install reinstall post-reboot post-login notification-click; do
  write_lifecycle_log "$AUDIT_PASS_DIR" "$phase" "/Applications/Bastion.app" "gui/501/com.bastion.xpc" "926A27BQ7W"
done
if ! scripts/audit-service-lifecycle-evidence.sh --evidence-dir "$AUDIT_PASS_DIR" >"$LIVE_GATE_DIR/audit-pass.log" 2>&1; then
  cat "$LIVE_GATE_DIR/audit-pass.log"
  exit 1
fi

AUDIT_MISMATCH_DIR="$LIVE_GATE_DIR/audit-mismatch"
mkdir -p "$AUDIT_MISMATCH_DIR"
for phase in fresh-install reinstall post-reboot post-login notification-click; do
  app="/Applications/Bastion.app"
  if [[ "$phase" == "post-login" ]]; then
    app="/tmp/Bastion.app"
  fi
  write_lifecycle_log "$AUDIT_MISMATCH_DIR" "$phase" "$app" "gui/501/com.bastion.xpc" "926A27BQ7W"
done
if scripts/audit-service-lifecycle-evidence.sh --evidence-dir "$AUDIT_MISMATCH_DIR" >"$LIVE_GATE_DIR/audit-mismatch.log" 2>&1; then
  echo "Expected lifecycle evidence audit to fail when phase app paths differ."
  exit 1
fi
grep -F "Phase post-login app path /tmp/Bastion.app does not match /Applications/Bastion.app" "$LIVE_GATE_DIR/audit-mismatch.log" >/dev/null

AUDIT_PHASE_MISMATCH_DIR="$LIVE_GATE_DIR/audit-phase-mismatch"
mkdir -p "$AUDIT_PHASE_MISMATCH_DIR"
for phase in fresh-install reinstall post-reboot post-login notification-click; do
  recorded_phase="$phase"
  if [[ "$phase" == "post-login" ]]; then
    recorded_phase="reinstall"
  fi
  write_lifecycle_log "$AUDIT_PHASE_MISMATCH_DIR" "$phase" "/Applications/Bastion.app" "gui/501/com.bastion.xpc" "926A27BQ7W" "$recorded_phase"
done
if scripts/audit-service-lifecycle-evidence.sh --evidence-dir "$AUDIT_PHASE_MISMATCH_DIR" >"$LIVE_GATE_DIR/audit-phase-mismatch.log" 2>&1; then
  echo "Expected lifecycle evidence audit to fail when a phase log records the wrong phase."
  exit 1
fi
grep -F "Phase post-login log records Phase: reinstall" "$LIVE_GATE_DIR/audit-phase-mismatch.log" >/dev/null

echo "== Shell script syntax =="
python3 -m py_compile qa/refresh_live_runtime_current_blockers.py
bash -n qa/run_available_checks.sh
bash -n qa/run_app_runtime_user_story_checks.sh
bash -n qa/run_bastion_mcp_smoke.sh
bash -n qa/run_live_runtime_checks.sh
bash -n qa/run_mcp_cli_wrapper_smoke.sh
bash -n qa/run_native_cli_smoke.sh
bash -n qa/run_rest_wrapper_smoke.sh
bash -n qa/run_signed_app_direct_runtime_checks.sh
bash -n qa/run_seeded_paired_runtime_checks.sh
for script in scripts/*.sh; do
  echo "sh -n $script"
  sh -n "$script"
done
grep -F "scripts/dev-enable-codesign-keychain-access.sh" scripts/dev-rebuild-signed.sh >/dev/null
grep -F "security set-key-partition-list -S apple-tool:,apple:,codesign: -s -t private" scripts/dev-rebuild-signed.sh >/dev/null
grep -F 'PARTITION_LIST="apple-tool:,apple:,codesign:"' scripts/dev-enable-codesign-keychain-access.sh >/dev/null
grep -F "Apple signing and codesign tools" scripts/dev-enable-codesign-keychain-access.sh >/dev/null
grep -F "resolve_private_key_label" scripts/dev-enable-codesign-keychain-access.sh >/dev/null
grep -F -- "--check" scripts/dev-enable-codesign-keychain-access.sh >/dev/null
grep -F "without changing keychain access" scripts/dev-enable-codesign-keychain-access.sh >/dev/null
grep -F "The non-mutating codesign usability probe failed; keychain access was not changed." scripts/dev-enable-codesign-keychain-access.sh >/dev/null
grep -F "Code-signing keychain access was updated, but /usr/bin/codesign still cannot" scripts/dev-enable-codesign-keychain-access.sh >/dev/null
grep -F "Detected nested private-key label matched" scripts/dev-enable-codesign-keychain-access.sh >/dev/null
grep -F "Matched private signing key" scripts/dev-enable-codesign-keychain-access.sh >/dev/null
grep -F "resolve_private_key_label" scripts/dev-rebuild-signed.sh >/dev/null
grep -F "nested private key labeled" scripts/dev-rebuild-signed.sh >/dev/null
grep -F "codesign --force --sign" scripts/dev-enable-codesign-keychain-access.sh >/dev/null
grep -F "Run this from an interactive terminal" scripts/dev-enable-codesign-keychain-access.sh >/dev/null
grep -F "Access Control" scripts/dev-enable-codesign-keychain-access.sh >/dev/null
grep -F "private key can have an older" scripts/dev-enable-codesign-keychain-access.sh >/dev/null
grep -F "scripts/dev-rebuild-signed.sh" scripts/dev-enable-codesign-keychain-access.sh >/dev/null
scripts/dev-enable-codesign-keychain-access.sh --help | grep -F "Mac login/keychain password" >/dev/null
scripts/dev-enable-codesign-keychain-access.sh --help | grep -F "throwaway codesign probe result without changing the keychain" >/dev/null
grep -F "CODESIGN_PREFLIGHT_LOG" qa/run_seeded_paired_runtime_checks.sh >/dev/null
grep -F "scripts/dev-enable-codesign-keychain-access.sh --check" qa/run_seeded_paired_runtime_checks.sh >/dev/null
grep -F "non-mutating codesign usability preflight failed" qa/run_seeded_paired_runtime_checks.sh >/dev/null
grep -F "ROW_ID_PREFIX_RE" qa/run_signed_app_direct_runtime_checks.sh >/dev/null
grep -F "lower_first_word_unless_row_id" qa/run_signed_app_direct_runtime_checks.sh >/dev/null
grep -F "Alternatively, open Keychain Access" scripts/dev-rebuild-signed.sh >/dev/null
grep -F "Do not add a -l identity-name" scripts/dev-rebuild-signed.sh >/dev/null
grep -F "filter; Apple certificate names" scripts/dev-rebuild-signed.sh >/dev/null
grep -F "do not add a" qa/README.md >/dev/null
grep -F -- "\`-l\` identity-name filter" qa/README.md >/dev/null
grep -F "./scripts/dev-enable-codesign-keychain-access.sh --check" qa/README.md >/dev/null
grep -F "non-mutating" qa/README.md >/dev/null
grep -F "explicit \`codesign:\` partitions" qa/README.md >/dev/null
grep -F "unsafe -l identity filters" qa/feature_status_source.json >/dev/null
grep -F "certificate names and private-key labels can differ" qa/feature_status_source.json >/dev/null
grep -F "codesign: partition" qa/feature_status_source.json >/dev/null
grep -F "Then rerun:" scripts/dev-rebuild-signed.sh >/dev/null
grep -F "System Settings > Notifications" scripts/verify-service-lifecycle-live.sh >/dev/null
grep -F "qa/run_live_runtime_checks.sh --run-phase notification-click --require-notification-click" scripts/verify-service-lifecycle-live.sh >/dev/null
grep -F -- "--allow-stale-app-for-blocker-refresh" qa/run_live_runtime_checks.sh >/dev/null
grep -F "Final closure still requires --require-pass evidence" qa/run_live_runtime_checks.sh >/dev/null
grep -F 'STATUS_PROCESS_IDENTIFIER="$(json_value processIdentifier' scripts/verify-service-lifecycle-live.sh >/dev/null
grep -F 'Bastion service process ${STATUS_PROCESS_IDENTIFIER}' scripts/verify-service-lifecycle-live.sh >/dev/null
grep -F 'Contents/MacOS/${basename}' scripts/verify-service-lifecycle-live.sh >/dev/null
grep -F "BASTION_RELAY_EXIT_TIMEOUT" scripts/verify-service-lifecycle-live.sh >/dev/null
grep -F "Waiting for LaunchServices relay handoff to exit" scripts/verify-service-lifecycle-live.sh >/dev/null

echo "== CLI symlink installer helper =="
CLI_SYMLINK_HELPER_DIR="$(mktemp -d "$TMP_ROOT/bastion_cli_symlink_helper.XXXXXX")"
CLI_SYMLINK_FIXTURE="$CLI_SYMLINK_HELPER_DIR/Bastion Dev.app/Contents/MacOS/bastion-cli"
CLI_SYMLINK_LINK="$CLI_SYMLINK_HELPER_DIR/bin/bastion"
mkdir -p "$(dirname "$CLI_SYMLINK_FIXTURE")"
printf '#!/bin/sh\nexit 0\n' >"$CLI_SYMLINK_FIXTURE"
chmod +x "$CLI_SYMLINK_FIXTURE"
scripts/install-cli-symlink.sh --cli "$CLI_SYMLINK_FIXTURE" --link "$CLI_SYMLINK_LINK" --sudo-if-interactive >"$CLI_SYMLINK_HELPER_DIR/install.log"
grep -F "Installed CLI symlink: $CLI_SYMLINK_LINK -> $CLI_SYMLINK_FIXTURE" "$CLI_SYMLINK_HELPER_DIR/install.log" >/dev/null
[[ "$(readlink "$CLI_SYMLINK_LINK")" == "$CLI_SYMLINK_FIXTURE" ]]
if scripts/install-cli-symlink.sh --sudo --no-sudo >"$CLI_SYMLINK_HELPER_DIR/conflict.log" 2>&1; then
  echo "Expected install-cli-symlink.sh to reject conflicting sudo modes."
  exit 1
fi
grep -F "Use only one of --sudo, --no-sudo, or --sudo-if-interactive" "$CLI_SYMLINK_HELPER_DIR/conflict.log" >/dev/null
grep -F -- "--sudo-if-interactive" scripts/dev-rebuild-signed.sh >/dev/null
grep -F "bastion-mcp" scripts/release-install.sh >/dev/null
if grep -F -- "--sudo-if-interactive" scripts/release-install.sh >/dev/null; then
  echo "release-install.sh should verify XPC through bastion-mcp, not install the CLI symlink."
  exit 1
fi

echo "== Native CLI typecheck =="
swiftc -typecheck \
  bastion-cli/main.swift \
  bastion/Utilities/ReleaseUpdate.swift \
  bastion/Utilities/ReleaseUpdateInstaller.swift

echo "== Native CLI argument smoke =="
bash qa/run_native_cli_smoke.sh

echo "== Swift MCP/REST bridge smoke =="
bash qa/run_bastion_mcp_smoke.sh

echo "== MCP CLI wrapper smoke =="
bash qa/run_mcp_cli_wrapper_smoke.sh

echo "== REST wrapper smoke =="
bash qa/run_rest_wrapper_smoke.sh

echo "== MCP typecheck =="
(cd mcp && bun run typecheck)

echo "== Xcode environment =="
xcode-select -p
if xcodebuild -version >/dev/null 2>&1; then
  echo "== Xcode test action =="
  xcodebuild \
    -project bastion.xcodeproj \
    -scheme bastion \
    -configuration Debug \
    -derivedDataPath build/XcodeDerivedData \
    test \
    CODE_SIGNING_ALLOWED=NO
else
  echo "xcodebuild unavailable: active developer directory is CommandLineTools, not full Xcode."
  echo "Full xcodebuild tests remain blocked in this environment."
fi

echo "== Final tracker workbook audit =="
python3 qa/build_feature_status.py
python3 qa/audit_goal_completion.py >"$COMPLETION_AUDIT_LOG.final"
if grep -Fx "Completion audit: complete" "$COMPLETION_AUDIT_LOG.final" >/dev/null; then
  python3 qa/audit_goal_completion.py --require-complete >"$COMPLETION_AUDIT_LOG.final.require"
  grep -Fx "Completion audit: complete" "$COMPLETION_AUDIT_LOG.final.require" >/dev/null
else
  grep -F "Completion audit: not complete" "$COMPLETION_AUDIT_LOG.final" >/dev/null
  grep -F "signed-app app-runtime user-story rows still require runtime evidence:" "$COMPLETION_AUDIT_LOG.final" >/dev/null
fi
if grep -F "signed-app live-runtime rows still require installed-app lifecycle evidence:" "$COMPLETION_AUDIT_LOG.final" >/dev/null; then
  echo "Final completion audit contains stale live-runtime blocker wording."
  exit 1
fi
if grep -F "runtime prerequisite blockers remain:" "$COMPLETION_AUDIT_LOG.final" >/dev/null; then
  grep -F "Blocked:" "$COMPLETION_AUDIT_LOG.final" >/dev/null
fi
if grep -F "Code-signing identities=Blocked:" "$COMPLETION_AUDIT_LOG.final" >/dev/null; then
  grep -F "matched private key label:" "$COMPLETION_AUDIT_LOG.final" >/dev/null
fi
if grep -F "Seeded paired-client runtime setup=Blocked:" "$COMPLETION_AUDIT_LOG.final" >/dev/null; then
  grep -F "seeded paired-client target rows" "$COMPLETION_AUDIT_LOG.final" >/dev/null
fi
if grep -F "Notification click proof=Blocked:" "$COMPLETION_AUDIT_LOG.final" >/dev/null; then
  echo "Final completion audit contains stale notification-click blocker wording."
  exit 1
fi

echo "Available checks passed."
