#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

APP_PATH="${BASTION_APP_PATH:-${HOME}/Applications/Bastion Dev.app}"
EVIDENCE_DIR="${BASTION_LIFECYCLE_EVIDENCE_DIR:-${ROOT}/dist/lifecycle}"

CHECK_PREREQS_ONLY=0
REQUIRE_PREREQS=0
AUDIT_ONLY=0
REQUIRE_PASS=0
PHASE=""
ALLOW_STALE_APP_FOR_BLOCKER_REFRESH=0
WRITE_TEMPLATE_PATH=""
ROW_EVIDENCE_PATH=""
WRITE_TRACKER_UPDATE_PATH=""
WRITE_UPDATED_SOURCE_PATH=""
REGISTER_ARGS=()
PASSTHROUGH_ARGS=()

usage() {
  cat <<'USAGE'
Usage:
  qa/run_live_runtime_checks.sh --check-prereqs
  qa/run_live_runtime_checks.sh --check-prereqs --require-prereqs
  qa/run_live_runtime_checks.sh --write-template <json>
  qa/run_live_runtime_checks.sh --audit-row-evidence <json>
  qa/run_live_runtime_checks.sh --audit-row-evidence <json> --require-pass
  qa/run_live_runtime_checks.sh --write-tracker-update <evidence-json> <update-json>
  qa/run_live_runtime_checks.sh --write-updated-source <evidence-json> <source-json>
  qa/run_live_runtime_checks.sh --run-phase <phase> [verifier options]
  qa/run_live_runtime_checks.sh --audit-evidence

Purpose:
  Canonical live-runtime gate for feature rows that cannot be completed with
  CommandLineTools-only deterministic checks:
    CORE-003 Secure Enclave signing and auth flow
    CORE-005 Keychain config/state/session storage
    CORE-006 Background release update monitor
    CORE-009 Menu bar app launch and runtime mode selection
    CORE-011 XPC caller verification and profile gating
    CORE-017 Service registration and lifecycle diagnostics

Environment:
  BASTION_APP_PATH                    Default: ~/Applications/Bastion Dev.app
  BASTION_LIFECYCLE_EVIDENCE_DIR      Default: dist/lifecycle

Options:
  --require-prereqs   Make --check-prereqs fail when the signed stable app
                      prerequisite is not satisfied.
  --require-pass      Make --audit-row-evidence fail unless every row Result is pass.
  --allow-stale-app-for-blocker-refresh
                      With --run-phase only, continue past a current-source
                      freshness blocker so the phase can refresh blocker logs.
                      Final closure still requires --require-pass evidence and
                      satisfied current-source signed-app prerequisites.

Row evidence JSON schema:
  [
    {
      "ID": "CORE-003",
      "Surface": "Surface from the canonical tracker",
      "Feature": "Feature name from the canonical tracker",
      "User story": "User story from the canonical tracker",
      "Expected behaviour": "Expected behaviour from the canonical tracker",
      "Test instructions": "Generated signed-app live-runtime phase checklist",
      "Result": "pass | fail | blocked",
      "Evidence": "What was exercised and observed; must mention ID, Feature, User story, Expected behaviour, and Test instructions, and cite an existing Artifact: path whose text also mentions Result, ID, Feature, User story, Expected behaviour, and Test instructions; optional Additional artifact: paths must exist and be non-empty",
      "Errors": "Required when Result is fail or blocked and must mention ID and Feature; empty when Result is pass"
    }
  ]

Examples:
  qa/run_live_runtime_checks.sh --check-prereqs
  qa/run_live_runtime_checks.sh --check-prereqs --require-prereqs
  qa/run_live_runtime_checks.sh --write-template dist/live-runtime-evidence.json
  qa/run_live_runtime_checks.sh --audit-row-evidence dist/live-runtime-evidence.json
  qa/run_live_runtime_checks.sh --write-tracker-update dist/live-runtime-evidence.json dist/live-runtime-tracker-update.json
  qa/run_live_runtime_checks.sh --write-updated-source dist/live-runtime-evidence.json dist/feature_status_source.live-runtime.json
  qa/run_live_runtime_checks.sh --run-phase fresh-install --register
  qa/run_live_runtime_checks.sh --run-phase notification-click --require-notification-click
  qa/run_live_runtime_checks.sh --audit-evidence
USAGE
}

note() {
  printf '%s\n' "$*"
}

fail() {
  printf 'FAIL: %s\n' "$*" >&2
}

write_template() {
  local output_path="$1"

  python3 - "$output_path" <<'PY'
import json
import sys
from pathlib import Path

from qa.app_runtime_rows import live_runtime_evidence_template, tracker_rows

output_path = Path(sys.argv[1])
template = live_runtime_evidence_template(tracker_rows())

output_path.parent.mkdir(parents=True, exist_ok=True)
output_path.write_text(json.dumps(template, indent=2) + "\n")
print(f"Wrote live-runtime evidence template for {len(template)} user-story rows to {output_path}")
PY
}

reject_canonical_output_path() {
  local output_path="$1"
  local artifact_kind="$2"

  python3 - "$output_path" "$artifact_kind" <<'PY'
import sys
from pathlib import Path

output_path = Path(sys.argv[1]).resolve()
artifact_kind = sys.argv[2]
canonical_source = (Path.cwd() / "qa" / "feature_status_source.json").resolve()
if output_path == canonical_source:
    raise SystemExit(
        f"{artifact_kind} must be written as a review artifact, not directly over qa/feature_status_source.json"
    )
PY
}

audit_row_evidence() {
  local evidence_path="$1"
  local require_pass="$2"

python3 - "$evidence_path" "$require_pass" <<'PY'
import json
import os
import re
import sys
from pathlib import Path

from qa.app_runtime_rows import LIVE_RUNTIME_BLOCKED_IDS, live_runtime_evidence_template, tracker_rows

evidence_path = Path(sys.argv[1])
require_pass = sys.argv[2] == "1"
if not evidence_path.exists():
    raise SystemExit(f"live-runtime row evidence file not found: {evidence_path}")

rows = tracker_rows()
template = live_runtime_evidence_template(rows)
expected = [row["ID"] for row in template]
expected_context = {
    row["ID"]: {
        "Surface": row["Surface"],
        "Feature": row["Feature"],
        "User story": row["User story"],
        "Expected behaviour": row["Expected behaviour"],
        "Test instructions": row["Test instructions"],
    }
    for row in template
}

payload = json.loads(evidence_path.read_text())
if not isinstance(payload, list):
    raise SystemExit("live-runtime row evidence must be a JSON list")

seen: set[str] = set()
duplicates: set[str] = set()
observed_order: list[str] = []
bad_rows: list[str] = []
allowed_results = {"pass", "fail", "blocked"}
required_keys = {"ID", "Surface", "Feature", "User story", "Expected behaviour", "Test instructions", "Result", "Evidence", "Errors"}
string_keys = required_keys
placeholder_evidence_re = re.compile(r"\b(?:fixture|placeholder|todo|tbd|example|dummy)\b", re.IGNORECASE)
artifact_re = re.compile(r"\bArtifact:\s*(\S+)")
additional_artifact_re = re.compile(r"\bAdditional artifact:\s*(\S+)")
artifact_row_marker_re = re.compile(r"(?m)^.*\bROW\s+([A-Z]+-\d+)\b.*$")
rerun_hint_re = re.compile(r"\bRerun(?: command)?:\s*(\S+)")


def clean_artifact_ref(raw_path: str) -> str:
    return raw_path.rstrip(".,;:)")


def artifact_path(raw_path: str) -> Path:
    path = Path(clean_artifact_ref(raw_path))
    if path.is_absolute():
        return path
    candidate = evidence_path.parent / path
    if candidate.exists():
        return candidate
    return Path.cwd() / path


def artifact_section_text(artifact_text: str, row_id: str):
    markers = list(artifact_row_marker_re.finditer(artifact_text))
    if not markers:
        return artifact_text
    for marker_index, marker in enumerate(markers):
        if marker.group(1) != row_id:
            continue
        section_end = markers[marker_index + 1].start() if marker_index + 1 < len(markers) else len(artifact_text)
        return artifact_text[marker.start():section_end]
    return None


def artifact_mentions_feature(row_artifact_text: str, row_id: str, feature: str) -> bool:
    return any(
        marker in row_artifact_text
        for marker in (
            f"{row_id} {feature}",
            f"| {feature}",
            f"Feature: {feature}",
            f"{feature}:",
        )
    )


def validate_additional_artifacts(evidence: str, row_id: str, bad_rows: list[str]) -> None:
    for match in additional_artifact_re.finditer(evidence):
        artifact_ref = clean_artifact_ref(match.group(1))
        resolved_artifact = artifact_path(artifact_ref)
        if not resolved_artifact.exists():
            bad_rows.append(f"{row_id}: Additional artifact does not exist: {artifact_ref}")
        elif not resolved_artifact.is_file():
            bad_rows.append(f"{row_id}: Additional artifact must be a regular file: {artifact_ref}")
        elif resolved_artifact.stat().st_size == 0:
            bad_rows.append(f"{row_id}: Additional artifact must not be empty: {artifact_ref}")


def validate_rerun_command(evidence: str, row_id: str, bad_rows: list[str]) -> None:
    match = rerun_hint_re.search(evidence)
    if not match:
        bad_rows.append(f"{row_id}: blocked Evidence must include a Rerun command")
        return
    command = clean_artifact_ref(match.group(1)).strip("\"'")
    if command.startswith("./"):
        command_path = Path.cwd() / command[2:]
    elif command.startswith(("qa/", "scripts/")):
        command_path = Path.cwd() / command
    else:
        return
    if not command_path.exists():
        bad_rows.append(f"{row_id}: Rerun command does not exist: {command}")
    elif not command_path.is_file():
        bad_rows.append(f"{row_id}: Rerun command must be a file: {command}")
    elif not os.access(command_path, os.X_OK):
        bad_rows.append(f"{row_id}: Rerun command must be executable: {command}")


for index, item in enumerate(payload, start=1):
    if not isinstance(item, dict):
        bad_rows.append(f"row {index}: must be an object")
        continue

    missing_keys = sorted(required_keys - set(item))
    for key in missing_keys:
        bad_rows.append(f"row {index}: {key} key is required")
    extra_keys = sorted(set(item) - required_keys)
    for key in extra_keys:
        bad_rows.append(f"row {index}: unexpected {key} key")

    for key in sorted(string_keys & set(item)):
        if not isinstance(item[key], str):
            bad_rows.append(f"row {index}: {key} must be a string")

    row_id_value = item.get("ID", "")
    result_value = item.get("Result", "")
    evidence_value = item.get("Evidence", "")
    errors_value = item.get("Errors", "")
    row_id = row_id_value.strip() if isinstance(row_id_value, str) else ""
    result = result_value if isinstance(result_value, str) else ""
    evidence = evidence_value.strip() if isinstance(evidence_value, str) else ""
    errors = errors_value.strip() if isinstance(errors_value, str) else ""

    if not row_id:
        bad_rows.append(f"row {index}: missing ID")
        continue
    if isinstance(row_id_value, str) and row_id_value != row_id:
        bad_rows.append(f"{row_id}: ID must not contain leading or trailing whitespace")
    if row_id in seen:
        duplicates.add(row_id)
    seen.add(row_id)
    observed_order.append(row_id)

    if row_id not in LIVE_RUNTIME_BLOCKED_IDS:
        bad_rows.append(f"{row_id}: unexpected live-runtime row ID")
    elif row_id in expected_context:
        for key, expected_value in expected_context[row_id].items():
            actual_value = str(item.get(key, "")).strip()
            if not actual_value:
                bad_rows.append(f"{row_id}: {key} is required")
            elif actual_value != expected_value:
                bad_rows.append(f"{row_id}: {key} does not match qa/feature_status_source.json")

    if result not in allowed_results:
        bad_rows.append(f"{row_id}: Result must be one of pass, fail, blocked")
    elif result_value != result:
        bad_rows.append(f"{row_id}: Result must be lowercase with no leading or trailing whitespace")
    elif require_pass and result != "pass":
        bad_rows.append(f"{row_id}: Result must be pass for final post-fix live-runtime closure")
    if not evidence:
        bad_rows.append(f"{row_id}: Evidence is required")
    elif placeholder_evidence_re.search(evidence):
        bad_rows.append(f"{row_id}: Evidence must describe real live-runtime observations, not placeholder text")
    else:
        if result in allowed_results and f"Result {result}" not in evidence:
            bad_rows.append(f"{row_id}: Evidence must cite Result {result}")
        if row_id not in evidence:
            bad_rows.append(f"{row_id}: Evidence must mention the row ID")
        if row_id in expected_context:
            expected_feature = expected_context[row_id]["Feature"]
            if expected_feature and f"{row_id} {expected_feature}" not in evidence:
                bad_rows.append(f"{row_id}: Evidence must mention the tracker Feature")
            expected_user_story = expected_context[row_id]["User story"]
            if expected_user_story and f"User story: {expected_user_story}" not in evidence:
                bad_rows.append(f"{row_id}: Evidence must mention the tracker User story")
            expected_behaviour = expected_context[row_id]["Expected behaviour"]
            if expected_behaviour and f"Expected behaviour: {expected_behaviour}" not in evidence:
                bad_rows.append(f"{row_id}: Evidence must mention the tracker Expected behaviour")
            expected_test_instructions = expected_context[row_id]["Test instructions"]
            if expected_test_instructions and f"Test instructions: {expected_test_instructions}" not in evidence:
                bad_rows.append(f"{row_id}: Evidence must mention the tracker Test instructions")
        artifact_match = artifact_re.search(evidence)
        if not artifact_match:
            bad_rows.append(f"{row_id}: Evidence must cite an Artifact: path")
        else:
            artifact_ref = clean_artifact_ref(artifact_match.group(1))
            resolved_artifact = artifact_path(artifact_ref)
            if not resolved_artifact.exists():
                bad_rows.append(f"{row_id}: Evidence artifact does not exist: {artifact_ref}")
            elif not resolved_artifact.is_file():
                bad_rows.append(f"{row_id}: Evidence artifact must be a regular file: {artifact_ref}")
            elif resolved_artifact.stat().st_size == 0:
                bad_rows.append(f"{row_id}: Evidence artifact must not be empty: {artifact_ref}")
            else:
                artifact_text = resolved_artifact.read_text(errors="replace")
                row_artifact_text = artifact_section_text(artifact_text, row_id)
                if row_artifact_text is None:
                    bad_rows.append(f"{row_id}: Evidence artifact must include a row section for {row_id}: {artifact_ref}")
                    continue
                if result in allowed_results and f"Result {result}" not in row_artifact_text:
                    bad_rows.append(f"{row_id}: Evidence artifact must mention Result {result}: {artifact_ref}")
                if row_id not in row_artifact_text:
                    bad_rows.append(f"{row_id}: Evidence artifact must mention the row ID: {artifact_ref}")
                if row_id in expected_context:
                    expected_feature = expected_context[row_id]["Feature"]
                    if expected_feature and not artifact_mentions_feature(row_artifact_text, row_id, expected_feature):
                        bad_rows.append(f"{row_id}: Evidence artifact must mention the tracker Feature: {artifact_ref}")
                    expected_user_story = expected_context[row_id]["User story"]
                    if expected_user_story and f"User story: {expected_user_story}" not in row_artifact_text:
                        bad_rows.append(f"{row_id}: Evidence artifact must mention the tracker User story: {artifact_ref}")
                    expected_behaviour = expected_context[row_id]["Expected behaviour"]
                    if expected_behaviour and f"Expected behaviour: {expected_behaviour}" not in row_artifact_text:
                        bad_rows.append(f"{row_id}: Evidence artifact must mention the tracker Expected behaviour: {artifact_ref}")
                    expected_test_instructions = expected_context[row_id]["Test instructions"]
                    if expected_test_instructions and f"Test instructions: {expected_test_instructions}" not in row_artifact_text:
                        bad_rows.append(f"{row_id}: Evidence artifact must mention the tracker Test instructions: {artifact_ref}")
        validate_additional_artifacts(evidence, row_id, bad_rows)
        if result == "blocked":
            validate_rerun_command(evidence, row_id, bad_rows)
    if result in {"fail", "blocked"} and not errors:
        bad_rows.append(f"{row_id}: Errors is required when Result is fail or blocked")
    elif result in {"fail", "blocked"} and placeholder_evidence_re.search(errors):
        bad_rows.append(f"{row_id}: Errors must describe real live-runtime failures, not placeholder text")
    elif result in {"fail", "blocked"}:
        if row_id not in errors:
            bad_rows.append(f"{row_id}: Errors must mention the row ID")
        if row_id in expected_context:
            expected_feature = expected_context[row_id]["Feature"]
            if expected_feature and expected_feature not in errors:
                bad_rows.append(f"{row_id}: Errors must mention the tracker Feature")
        artifact_match = artifact_re.search(evidence)
        if artifact_match:
            artifact_ref = clean_artifact_ref(artifact_match.group(1))
            if artifact_ref not in errors:
                bad_rows.append(f"{row_id}: Errors must mention the Evidence artifact")
        rerun_match = rerun_hint_re.search(evidence)
        if result == "blocked" and rerun_match:
            rerun_command = clean_artifact_ref(rerun_match.group(1)).strip("\"'")
            if rerun_command not in errors:
                bad_rows.append(f"{row_id}: Errors must mention the Rerun command")
    elif result == "pass" and errors:
        bad_rows.append(f"{row_id}: Errors must be empty when Result is pass")

expected_set = set(expected)
missing = sorted(expected_set - seen)
unexpected = sorted(seen - expected_set)

errors_out: list[str] = []
if missing:
    errors_out.append("missing live-runtime row evidence rows:\n  " + "\n  ".join(missing))
if unexpected:
    errors_out.append("unexpected live-runtime row evidence rows:\n  " + "\n  ".join(unexpected))
if duplicates:
    errors_out.append("duplicate live-runtime row evidence rows:\n  " + "\n  ".join(sorted(duplicates)))
if not missing and not unexpected and not duplicates and observed_order != expected:
    errors_out.append("live-runtime row evidence rows are not in canonical order")
if bad_rows:
    errors_out.append("invalid live-runtime row evidence rows:\n  " + "\n  ".join(bad_rows))

if errors_out:
    raise SystemExit("\n\n".join(errors_out))

print(f"Live-runtime row evidence audit passed for {len(expected)} user-story rows.")
PY

  if [[ "$require_pass" == "1" ]]; then
    require_final_runtime_prereqs
  fi
}

write_tracker_update() {
  local evidence_path="$1"
  local output_path="$2"

  reject_canonical_output_path "$output_path" "live-runtime tracker update"
  audit_row_evidence "$evidence_path" 0 >/dev/null
  if evidence_all_pass "$evidence_path"; then
    require_final_runtime_prereqs
  fi
  local prerequisite_status="blocked"
  if runtime_prereqs_satisfied; then
    prerequisite_status="satisfied"
  fi

python3 - "$evidence_path" "$output_path" "$prerequisite_status" <<'PY'
import json
import sys
from pathlib import Path

from qa.app_runtime_rows import live_runtime_rows, tracker_rows

sys.path.insert(0, str(Path.cwd() / "qa"))
import build_feature_status

evidence_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])
runtime_prereqs_satisfied = sys.argv[3] == "satisfied"

rows = tracker_rows()
tracker_by_id = {row["ID"]: row for row in rows}
live_ids = {row["ID"] for row in live_runtime_rows(rows)}
evidence = json.loads(evidence_path.read_text())

updates: list[dict[str, str]] = []
for item in evidence:
    row_id = item["ID"]
    if row_id not in live_ids:
        continue

    tracker = tracker_by_id[row_id]
    result = item["Result"]
    feature = item["Feature"]
    evidence_text = item["Evidence"]
    errors = item["Errors"]

    if result == "pass" and runtime_prereqs_satisfied:
        test_status = "Pass"
        errors_documented = (
            f"{row_id} {feature}: signed-app live-runtime evidence closed the prior runtime proof gap; "
            "no current live-runtime errors remain. See Retest status for evidence."
        )
        fix_status = f"Fixed after signed-app live-runtime pass for {row_id} {feature}."
        retest_status = f"Passed signed-app live-runtime sweep for {row_id} {feature}. Evidence: {evidence_text}"
    elif result == "pass":
        test_status = "Blocked in this environment"
        errors_documented = (
            f"{tracker['Errors documented']} Live-runtime prerequisite blocker for {row_id} {feature}: "
            "pass evidence was recorded, but code-signature/current-source signed-app prerequisites "
            "were not satisfied, so this row cannot be promoted to Pass from the review artifact."
        ).strip()
        fix_status = f"Blocked pending current-source signed-app live-runtime prerequisite for {row_id} {feature}."
        retest_status = f"Blocked pending current-source signed-app live-runtime retest for {row_id} {feature}. Evidence: {evidence_text}"
    elif result == "fail":
        test_status = "Pending"
        errors_documented = f"{tracker['Errors documented']} Live-runtime failure: {errors}".strip()
        fix_status = f"Pending fix from signed-app live-runtime evidence for {row_id} {feature}."
        retest_status = f"Pending post-fix live-runtime retest for {row_id} {feature}. Evidence: {evidence_text}"
    else:
        test_status = "Blocked in this environment"
        errors_documented = f"{tracker['Errors documented']} Live-runtime blocker: {errors}".strip()
        fix_status = f"Blocked pending live-runtime prerequisite for {row_id} {feature}."
        retest_status = f"Blocked pending live-runtime prerequisite retest for {row_id} {feature}. Evidence: {evidence_text}"

    updates.append(
        {
            "ID": row_id,
            "Feature": feature,
            "Result": result,
            "Test status": test_status,
            "Errors documented": errors_documented,
            "Fix status": fix_status,
            "Retest status": retest_status,
        }
    )

output_path.parent.mkdir(parents=True, exist_ok=True)
output_path.write_text(json.dumps(updates, indent=2) + "\n")
print(f"Wrote live-runtime tracker update review artifact for {len(updates)} row evidence rows to {output_path}")
PY
}

write_updated_source() {
  local evidence_path="$1"
  local output_path="$2"

  reject_canonical_output_path "$output_path" "live-runtime updated source"
  audit_row_evidence "$evidence_path" 0 >/dev/null
  if evidence_has_pass "$evidence_path"; then
    require_final_runtime_prereqs
  fi

python3 - "$evidence_path" "$output_path" <<'PY'
import json
import sys
from pathlib import Path

from qa.app_runtime_rows import live_runtime_rows, tracker_rows

sys.path.insert(0, str(Path.cwd() / "qa"))
import build_feature_status

evidence_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])

rows = tracker_rows()
live_ids = {row["ID"] for row in live_runtime_rows(rows)}
evidence = json.loads(evidence_path.read_text())
evidence_by_id = {
    item["ID"]: item
    for item in evidence
    if item["ID"] in live_ids
}

updated_rows: list[dict[str, object]] = []
for tracker in rows:
    row = dict(tracker)
    row_id = str(row["ID"])
    item = evidence_by_id.get(row_id)
    if item is None:
        updated_rows.append(row)
        continue

    result = item["Result"]
    feature = item["Feature"]
    evidence_text = item["Evidence"]
    errors = item["Errors"]

    if result == "pass":
        row["Test status"] = "Pass"
        row["Errors documented"] = (
            f"{row_id} {feature}: signed-app live-runtime evidence closed the prior runtime proof gap; "
            "no current live-runtime errors remain. See Retest status for evidence."
        )
        row["Fix status"] = f"Fixed after signed-app live-runtime pass for {row_id} {feature}."
        row["Retest status"] = f"Passed signed-app live-runtime sweep for {row_id} {feature}. Evidence: {evidence_text}"
    elif result == "fail":
        row["Test status"] = "Pending"
        row["Errors documented"] = f"{row['Errors documented']} Live-runtime failure: {errors}".strip()
        row["Fix status"] = f"Pending fix from signed-app live-runtime evidence for {row_id} {feature}."
        row["Retest status"] = f"Pending post-fix live-runtime retest for {row_id} {feature}. Evidence: {evidence_text}"
    else:
        row["Test status"] = "Blocked in this environment"
        row["Errors documented"] = f"{row['Errors documented']} Live-runtime blocker: {errors}".strip()
        row["Fix status"] = f"Blocked pending live-runtime prerequisite for {row_id} {feature}."
        row["Retest status"] = f"Blocked pending live-runtime prerequisite retest for {row_id} {feature}. Evidence: {evidence_text}"

    updated_rows.append(row)

output_path.parent.mkdir(parents=True, exist_ok=True)
build_feature_status.validate_entries(updated_rows)
output_path.write_text(json.dumps(updated_rows, indent=2) + "\n")
print(f"Wrote live-runtime updated tracker source review artifact for {len(updated_rows)} feature rows to {output_path}")
PY
}

print_mapping() {
  note "== Bastion live runtime feature gate =="
  note "App: ${APP_PATH}"
  note "Evidence: ${EVIDENCE_DIR}"
  note "Feature rows covered: CORE-003 CORE-005 CORE-006 CORE-009 CORE-011 CORE-017"
}

print_required_commands() {
  python3 - <<'PY'
from qa.app_runtime_rows import LIVE_RUNTIME_PHASE_COMMANDS

for index, command in enumerate(LIVE_RUNTIME_PHASE_COMMANDS, start=1):
    print(f"{index}. {command}")
PY
}

print_candidate_apps() {
  python3 - "$APP_PATH" <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, "qa")
import build_feature_status

status, evidence = build_feature_status.candidate_app_summary(Path(sys.argv[1]))
print("== Discovered app bundle candidates ==")
print(f"Candidate status: {status}")
print(evidence)
PY
}

print_current_source_freshness() {
  python3 - "$APP_PATH" <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, "qa")
import build_feature_status

status, evidence = build_feature_status.app_source_freshness_status(Path(sys.argv[1]))
print("== Current-source signed app rebuild ==")
print(f"Current-source status: {status}")
print(evidence)
raise SystemExit(0 if status == "Satisfied" else 1)
PY
}

record_current_source_freshness() {
  if print_current_source_freshness; then
    return 0
  fi
  if [[ "$ALLOW_STALE_APP_FOR_BLOCKER_REFRESH" -eq 1 ]]; then
    note "WARN: Current-source signed app rebuild is blocked; continuing only to refresh blocker evidence."
    note "WARN: Do not treat this phase as final pass evidence until qa/run_live_runtime_checks.sh --check-prereqs --require-prereqs passes."
    return 0
  fi
  return 1
}

require_final_runtime_prereqs() {
  python3 - "$APP_PATH" <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, "qa")
import build_feature_status

app_path = Path(sys.argv[1])
checks = [
    ("Code signature and TeamIdentifier", *build_feature_status.signed_app_status(app_path)),
    ("Current-source signed app rebuild", *build_feature_status.app_source_freshness_status(app_path)),
]
failures = []
for label, status, evidence in checks:
    print(f"{label}: {status} - {evidence}")
    if status != "Satisfied":
        failures.append(label)
if failures:
    raise SystemExit(
        "Final live-runtime require-pass evidence needs satisfied runtime prerequisites: "
        + ", ".join(failures)
    )
PY
}

evidence_all_pass() {
  python3 - "$1" <<'PY'
import json
import sys

evidence = json.loads(open(sys.argv[1]).read())
if evidence and all(item.get("Result") == "pass" for item in evidence):
    raise SystemExit(0)
raise SystemExit(1)
PY
}

evidence_has_pass() {
  python3 - "$1" <<'PY'
import json
import sys

evidence = json.loads(open(sys.argv[1]).read())
if any(item.get("Result") == "pass" for item in evidence):
    raise SystemExit(0)
raise SystemExit(1)
PY
}

runtime_prereqs_satisfied() {
  python3 - "$APP_PATH" <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, "qa")
import build_feature_status

app_path = Path(sys.argv[1])
checks = [
    build_feature_status.signed_app_status(app_path),
    build_feature_status.app_source_freshness_status(app_path),
]
raise SystemExit(0 if all(status == "Satisfied" for status, _ in checks) else 1)
PY
}

check_prereqs() {
  local failures=0

  print_mapping

  note "== Full Xcode build/test availability =="
  if /usr/bin/xcodebuild -version >/dev/null 2>&1; then
    /usr/bin/xcodebuild -version
  else
    note "WARN: xcodebuild is unavailable from active developer directory: $(/usr/bin/xcode-select -p 2>/dev/null || printf '<unknown>')"
    note "Full xcodebuild tests remain blocked, but installed-app live runtime phases can run when a signed stable app is present."
  fi

  note "== Stable signed app runtime =="
  if [[ ! -d "$APP_PATH" ]]; then
    fail "App bundle not found at ${APP_PATH}"
    failures=$((failures + 1))
  elif [[ "$APP_PATH" == *DerivedData* ]]; then
    fail "App path is under DerivedData; install to a stable app path before live runtime testing."
    failures=$((failures + 1))
  elif [[ ! -f "$APP_PATH/Contents/Info.plist" ]]; then
    fail "App bundle Info.plist missing at ${APP_PATH}/Contents/Info.plist"
    failures=$((failures + 1))
  elif [[ ! -x "$APP_PATH/Contents/MacOS/bastion" ]]; then
    fail "App executable missing or not executable at ${APP_PATH}/Contents/MacOS/bastion"
    failures=$((failures + 1))
  else
    if ! /usr/bin/codesign --verify --deep --strict --verbose=2 "$APP_PATH"; then
      fail "App codesign verification failed for ${APP_PATH}"
      failures=$((failures + 1))
    else
      local team_id
      team_id="$(/usr/bin/codesign -dv "$APP_PATH" 2>&1 | /usr/bin/awk -F= '/^TeamIdentifier=/{ print $2 }')"
      if [[ -z "$team_id" ]]; then
        fail "Signed stable install must have a TeamIdentifier; ad hoc signatures are not enough for this gate."
        failures=$((failures + 1))
      else
        note "TeamIdentifier: ${team_id}"
      fi
    fi
  fi

  if ! record_current_source_freshness; then
    failures=$((failures + 1))
  fi

  print_candidate_apps

  note "== Required live phases =="
  print_required_commands

  if [[ "$failures" -gt 0 ]]; then
    note "== Installed-app live runtime prerequisites blocked with ${failures} issue(s) =="
    return 1
  fi

  note "== Installed-app live runtime prerequisites satisfied =="
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --check-prereqs)
      CHECK_PREREQS_ONLY=1
      ;;
    --require-prereqs)
      REQUIRE_PREREQS=1
      ;;
    --write-template)
      shift
      [[ "$#" -gt 0 ]] || { usage >&2; exit 2; }
      WRITE_TEMPLATE_PATH="$1"
      ;;
    --audit-row-evidence)
      shift
      [[ "$#" -gt 0 ]] || { usage >&2; exit 2; }
      ROW_EVIDENCE_PATH="$1"
      ;;
    --write-tracker-update)
      shift
      [[ "$#" -ge 2 ]] || { usage >&2; exit 2; }
      ROW_EVIDENCE_PATH="$1"
      shift
      WRITE_TRACKER_UPDATE_PATH="$1"
      ;;
    --write-updated-source)
      shift
      [[ "$#" -ge 2 ]] || { usage >&2; exit 2; }
      ROW_EVIDENCE_PATH="$1"
      shift
      WRITE_UPDATED_SOURCE_PATH="$1"
      ;;
    --require-pass)
      REQUIRE_PASS=1
      ;;
    --run-phase)
      shift
      [[ "$#" -gt 0 ]] || { usage >&2; exit 2; }
      PHASE="$1"
      ;;
    --allow-stale-app-for-blocker-refresh)
      ALLOW_STALE_APP_FOR_BLOCKER_REFRESH=1
      ;;
    --audit-evidence)
      AUDIT_ONLY=1
      ;;
    --register)
      REGISTER_ARGS+=(--register)
      ;;
    --skip-relay-open|--require-notification-click)
      PASSTHROUGH_ARGS+=("$1")
      ;;
    --notification-timeout)
      PASSTHROUGH_ARGS+=("$1")
      shift
      [[ "$#" -gt 0 ]] || { usage >&2; exit 2; }
      PASSTHROUGH_ARGS+=("$1")
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
  shift
done

mode_count=0
[[ "$CHECK_PREREQS_ONLY" -eq 1 ]] && mode_count=$((mode_count + 1))
[[ "$AUDIT_ONLY" -eq 1 ]] && mode_count=$((mode_count + 1))
[[ -n "$PHASE" ]] && mode_count=$((mode_count + 1))
[[ -n "$WRITE_TEMPLATE_PATH" ]] && mode_count=$((mode_count + 1))
[[ -n "$ROW_EVIDENCE_PATH" && -z "$WRITE_TRACKER_UPDATE_PATH" && -z "$WRITE_UPDATED_SOURCE_PATH" ]] && mode_count=$((mode_count + 1))
[[ -n "$WRITE_TRACKER_UPDATE_PATH" ]] && mode_count=$((mode_count + 1))
[[ -n "$WRITE_UPDATED_SOURCE_PATH" ]] && mode_count=$((mode_count + 1))
if [[ "$mode_count" -ne 1 ]]; then
  usage >&2
  exit 2
fi
if [[ "$ALLOW_STALE_APP_FOR_BLOCKER_REFRESH" -eq 1 && -z "$PHASE" ]]; then
  usage >&2
  exit 2
fi
if [[ "$REQUIRE_PASS" -eq 1 && -z "$ROW_EVIDENCE_PATH" ]]; then
  usage >&2
  exit 2
fi

if [[ "$CHECK_PREREQS_ONLY" -eq 1 ]]; then
  if check_prereqs; then
    exit 0
  fi
  if [[ "$REQUIRE_PREREQS" -eq 1 ]]; then
    exit 1
  fi
  note "Prerequisite-only mode records the blocker but does not fail the deterministic QA harness."
  exit 0
fi

if [[ -n "$WRITE_TEMPLATE_PATH" ]]; then
  write_template "$WRITE_TEMPLATE_PATH"
  exit 0
fi

if [[ -n "$WRITE_TRACKER_UPDATE_PATH" ]]; then
  write_tracker_update "$ROW_EVIDENCE_PATH" "$WRITE_TRACKER_UPDATE_PATH"
  exit 0
fi

if [[ -n "$WRITE_UPDATED_SOURCE_PATH" ]]; then
  write_updated_source "$ROW_EVIDENCE_PATH" "$WRITE_UPDATED_SOURCE_PATH"
  exit 0
fi

if [[ -n "$ROW_EVIDENCE_PATH" ]]; then
  audit_row_evidence "$ROW_EVIDENCE_PATH" "$REQUIRE_PASS"
  exit 0
fi

if [[ "$AUDIT_ONLY" -eq 1 ]]; then
  print_mapping
  exec scripts/audit-service-lifecycle-evidence.sh --evidence-dir "$EVIDENCE_DIR"
fi

if [[ -n "$PHASE" ]]; then
  check_prereqs
  exec scripts/verify-service-lifecycle-live.sh \
    --app "$APP_PATH" \
    --phase "$PHASE" \
    ${REGISTER_ARGS+"${REGISTER_ARGS[@]}"} \
    ${PASSTHROUGH_ARGS+"${PASSTHROUGH_ARGS[@]}"}
fi

usage >&2
exit 2
