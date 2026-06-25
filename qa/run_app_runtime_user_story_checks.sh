#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

APP_PATH="${BASTION_APP_PATH:-${HOME}/Applications/Bastion Dev.app}"

usage() {
  cat <<'USAGE'
Usage:
  qa/run_app_runtime_user_story_checks.sh --check-prereqs
  qa/run_app_runtime_user_story_checks.sh --check-prereqs --require-prereqs
  qa/run_app_runtime_user_story_checks.sh --write-template <json>
  qa/run_app_runtime_user_story_checks.sh --audit-evidence <json>
  qa/run_app_runtime_user_story_checks.sh --audit-evidence <json> --require-pass
  qa/run_app_runtime_user_story_checks.sh --write-tracker-update <evidence-json> <update-json>
  qa/run_app_runtime_user_story_checks.sh --write-updated-source <evidence-json> <source-json>

Purpose:
  Canonical app-runtime gate for user-story rows whose current tracker evidence
  is static/deterministic but still calls out pending live UI, CLI, API, network,
  or app-runtime behaviour. The row set is derived from
  qa/feature_status_source.json so newly documented runtime-pending rows are
  automatically pulled into this gate.

Environment:
  BASTION_APP_PATH    Default: ~/Applications/Bastion Dev.app

Options:
  --require-prereqs   Make --check-prereqs fail when the signed stable app
                      prerequisite is not satisfied.
  --require-pass      Make --audit-evidence fail unless every row Result is pass.

Evidence JSON schema:
  [
    {
      "ID": "UI-001",
      "Surface": "Surface from the canonical tracker",
      "Feature": "Feature name from the canonical tracker",
      "User story": "User story from the canonical tracker",
      "Expected behaviour": "Expected behaviour from the canonical tracker",
      "Test instructions": "Generated row-specific signed-app test instructions",
      "Result": "pass | fail | blocked",
      "Evidence": "What was exercised and observed; must mention ID, Feature, User story, Expected behaviour, and Test instructions, and cite an existing Artifact: path whose text also mentions Result, ID, Feature, User story, Expected behaviour, and Test instructions; optional Additional artifact: paths must exist and be non-empty",
      "Errors": "Required when Result is fail or blocked and must mention ID and Feature; empty when Result is pass"
    }
  ]

Tracker update JSON:
  A generated review artifact with one row per runtime evidence row. Use it to
  copy signed-app results back into qa/feature_status_source.json after a sweep.

Updated source JSON:
  A complete qa/feature_status_source.json-shaped review artifact with runtime
  evidence applied to Test status, Errors documented, Fix status, and Retest status.
USAGE
}

write_template() {
  local output_path="$1"

  python3 - "$output_path" <<'PY'
import json
import os
import re
import sys
from pathlib import Path

from qa.app_runtime_rows import runtime_evidence_template, tracker_rows

output_path = Path(sys.argv[1])
template = runtime_evidence_template(tracker_rows())

output_path.parent.mkdir(parents=True, exist_ok=True)
output_path.write_text(json.dumps(template, indent=2) + "\n")
print(f"Wrote app-runtime evidence template for {len(template)} user-story rows to {output_path}")
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

runtime_pending_rows() {
  python3 qa/app_runtime_rows.py --ids
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
        "Final app-runtime require-pass evidence needs satisfied runtime prerequisites: "
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

evidence_has_fail() {
  python3 - "$1" <<'PY'
import json
import sys

evidence = json.loads(open(sys.argv[1]).read())
if any(item.get("Result") == "fail" for item in evidence):
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
  local ids
  local count
  local failures=0

  ids="$(runtime_pending_rows)"
  count="$(wc -w <<<"$ids" | tr -d ' ')"

  printf '%s\n' "== Bastion app-runtime user-story gate =="
  printf 'App: %s\n' "$APP_PATH"
  printf 'Runtime-pending user-story rows covered (%s): %s\n' "$count" "$ids"

  printf '%s\n' "== Required runtime sweep =="
  printf '%s\n' "1. Launch the signed stable app from ${APP_PATH}."
  printf '%s\n' "2. Exercise the menu bar, settings, pairing, signing approval, audit history, diagnostics, CLI, MCP, REST, provider, and policy flows listed above."
  printf '%s\n' "3. Record each failure back into qa/feature_status_source.json, fix logistical/UX defects, rebuild qa/feature_status.xlsx, and rerun this gate plus qa/run_available_checks.sh."

  printf '%s\n' "== Stable signed app runtime =="
  if [[ ! -d "$APP_PATH" ]]; then
    printf 'FAIL: App bundle not found at %s\n' "$APP_PATH" >&2
    failures=$((failures + 1))
  elif [[ "$APP_PATH" == *DerivedData* ]]; then
    printf '%s\n' "FAIL: App path is under DerivedData; install to a stable app path before app-runtime user-story testing." >&2
    failures=$((failures + 1))
  elif [[ ! -f "$APP_PATH/Contents/Info.plist" ]]; then
    printf 'FAIL: App bundle Info.plist missing at %s\n' "$APP_PATH/Contents/Info.plist" >&2
    failures=$((failures + 1))
  elif [[ ! -x "$APP_PATH/Contents/MacOS/bastion" ]]; then
    printf 'FAIL: App executable missing or not executable at %s\n' "$APP_PATH/Contents/MacOS/bastion" >&2
    failures=$((failures + 1))
  elif ! /usr/bin/codesign --verify --deep --strict --verbose=2 "$APP_PATH"; then
    printf 'FAIL: App codesign verification failed for %s\n' "$APP_PATH" >&2
    failures=$((failures + 1))
  else
    local team_id
    team_id="$(/usr/bin/codesign -dv "$APP_PATH" 2>&1 | /usr/bin/awk -F= '/^TeamIdentifier=/{ print $2 }')"
    if [[ -z "$team_id" ]]; then
      printf '%s\n' "FAIL: Signed stable install must have a TeamIdentifier; ad hoc signatures are not enough for this gate." >&2
      failures=$((failures + 1))
    else
      printf 'TeamIdentifier: %s\n' "$team_id"
    fi
  fi

  if ! print_current_source_freshness; then
    failures=$((failures + 1))
  fi

  print_candidate_apps

  if [[ "$failures" -gt 0 ]]; then
    printf '== App-runtime user-story prerequisites blocked with %s issue(s) ==\n' "$failures"
    return 1
  fi

  printf '%s\n' "== App-runtime user-story prerequisites satisfied =="
}

audit_evidence() {
  local evidence_path="$1"
  local require_pass="$2"

python3 - "$evidence_path" "$require_pass" <<'PY'
import json
import os
import re
import sys
from pathlib import Path

from qa.app_runtime_rows import runtime_evidence_template, runtime_pending_ids, tracker_rows

evidence_path = Path(sys.argv[1])
require_pass = sys.argv[2] == "1"
if not evidence_path.exists():
    raise SystemExit(f"app-runtime evidence file not found: {evidence_path}")

rows = tracker_rows()
expected = runtime_pending_ids(rows)
expected_context = {
    row["ID"]: {
        "Surface": row["Surface"],
        "Feature": row["Feature"],
        "User story": row["User story"],
        "Expected behaviour": row["Expected behaviour"],
        "Test instructions": row["Test instructions"],
    }
    for row in runtime_evidence_template(rows)
}

payload = json.loads(evidence_path.read_text())
if not isinstance(payload, list):
    raise SystemExit("app-runtime evidence must be a JSON list")

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

    if row_id in expected_context:
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
        bad_rows.append(f"{row_id}: Result must be pass for final post-fix runtime closure")
    if not evidence:
        bad_rows.append(f"{row_id}: Evidence is required")
    elif placeholder_evidence_re.search(evidence):
        bad_rows.append(f"{row_id}: Evidence must describe real runtime observations, not placeholder text")
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
            elif resolved_artifact.is_file() and resolved_artifact.stat().st_size == 0:
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
        bad_rows.append(f"{row_id}: Errors must describe real runtime failures, not placeholder text")
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
    errors_out.append("missing runtime evidence rows:\n  " + "\n  ".join(missing))
if unexpected:
    errors_out.append("unexpected runtime evidence rows:\n  " + "\n  ".join(unexpected))
if duplicates:
    errors_out.append("duplicate runtime evidence rows:\n  " + "\n  ".join(sorted(duplicates)))
if not missing and not unexpected and not duplicates and observed_order != expected:
    errors_out.append("runtime evidence rows are not in canonical order")
if bad_rows:
    errors_out.append("invalid runtime evidence rows:\n  " + "\n  ".join(bad_rows))

if errors_out:
    raise SystemExit("\n\n".join(errors_out))

print(f"App-runtime evidence audit passed for {len(expected)} user-story rows.")
PY

  if [[ "$require_pass" == "1" ]]; then
    require_final_runtime_prereqs
  fi
}

write_tracker_update() {
  local evidence_path="$1"
  local output_path="$2"

  reject_canonical_output_path "$output_path" "app-runtime tracker update"
  audit_evidence "$evidence_path" 0 >/dev/null
  if evidence_all_pass "$evidence_path"; then
    require_final_runtime_prereqs
  fi
  local prerequisite_status="blocked"
  if runtime_prereqs_satisfied; then
    prerequisite_status="satisfied"
  fi

python3 - "$evidence_path" "$output_path" "$prerequisite_status" <<'PY'
import json
import re
import sys
from pathlib import Path

from qa.app_runtime_rows import runtime_pending_ids, tracker_rows

sys.path.insert(0, str(Path.cwd() / "qa"))
import build_feature_status

evidence_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])
runtime_prereqs_satisfied = sys.argv[3] == "satisfied"

rows = tracker_rows()
tracker_by_id = {row["ID"]: row for row in rows}
runtime_ids = set(runtime_pending_ids(rows))
evidence = json.loads(evidence_path.read_text())

def lower_first_word_unless_row_id(text: str) -> str:
    if re.match(r"^[A-Z]+-\d+\b", text):
        return text
    return text[:1].lower() + text[1:]

def normalize_blocker_text(text: str) -> str:
    normalized = text
    normalized = normalized.replace(" because this shell cannot capture/control native UI or required runtime interactions", " with native UI control and required runtime interactions")
    normalized = normalized.replace(" because this shell cannot capture/control native UI", " with native UI control")
    normalized = normalized.replace(" because this shell cannot capture or inspect native windows", " with native window inspection")
    normalized = normalized.replace(" because this shell cannot control native UI", " with native UI control")
    normalized = normalized.replace(" because this shell cannot inspect/control native UI", " with native UI inspection/control")
    normalized = normalized.replace(" because screenshot and Accessibility inspection are unavailable from this shell", " with screenshot or Accessibility inspection")
    normalized = normalized.replace(" because native UI observation/control is unavailable from this shell", " with native UI observation/control")
    normalized = normalized.replace(" because native UI/auth interaction is unavailable from this shell", " with native UI/auth interaction")
    normalized = normalized.replace(" because configured RPC/network interaction is unavailable in this shell-only sweep", " with configured RPC/network interaction")
    normalized = re.sub(
        r"(, but |; )([a-z][^.;]*?) remains? pending because ([^.;]+)",
        lambda match: f". Remaining proof gap: {match.group(2)} with {match.group(3)}",
        normalized,
    )
    normalized = re.sub(
        r"([A-Z][^.;]*?) remains? pending because ([^.;]+)",
        lambda match: f"Remaining proof gap: {lower_first_word_unless_row_id(match.group(1))} with {match.group(2)}",
        normalized,
    )
    normalized = re.sub(
        r"([A-Za-z][^.;]*?) remains? pending(?: with ([^.;]+))?\.",
        lambda match: (
            f"Remaining proof gap: {lower_first_word_unless_row_id(match.group(1))}"
            + (f" with {match.group(2)}" if match.group(2) else "")
            + "."
        ),
        normalized,
    )
    normalized = re.sub(
        r"([A-Za-z][^.;]*?) remain pending(?: with ([^.;]+))?\.",
        lambda match: (
            f"Remaining proof gap: {lower_first_word_unless_row_id(match.group(1))}"
            + (f" with {match.group(2)}" if match.group(2) else "")
            + "."
        ),
        normalized,
    )
    normalized = re.sub(r"\bwith\s+with\b", "with", normalized, flags=re.IGNORECASE)
    return normalized

updates: list[dict[str, str]] = []
for item in evidence:
    row_id = item["ID"]
    if row_id not in runtime_ids:
        continue

    tracker = tracker_by_id[row_id]
    result = item["Result"]
    feature = item["Feature"]
    evidence_text = item["Evidence"]
    errors = item["Errors"]

    if result == "pass" and runtime_prereqs_satisfied:
        test_status = "Pass"
        errors_documented = (
            f"Runtime pass for {row_id} {feature}: "
            "current signed-app runtime evidence recorded no runtime errors for this row."
        )
        fix_status = (
            f"Runtime evidence passed for {row_id} {feature}; "
            "no signed-app runtime fix is pending from this sweep."
        )
        retest_status = f"Passed signed-app runtime sweep for {row_id} {feature}. Evidence: {evidence_text}"
    elif result == "pass":
        test_status = "Blocked in this environment"
        errors_documented = (
            f"{tracker['Errors documented']} Runtime prerequisite blocker for {row_id} {feature}: "
            "pass evidence was recorded, but code-signature/current-source signed-app prerequisites "
            "were not satisfied, so this row cannot be promoted to Pass from the review artifact."
        ).strip()
        fix_status = f"Blocked pending current-source signed-app runtime prerequisite for {row_id} {feature}."
        retest_status = f"Blocked pending current-source signed-app runtime retest for {row_id} {feature}. Evidence: {evidence_text}"
    elif result == "fail":
        test_status = "Pending"
        errors_documented = f"{tracker['Errors documented']} Runtime failure from signed-app sweep: {errors}".strip()
        fix_status = f"Pending fix from signed-app runtime evidence for {row_id} {feature}."
        retest_status = f"Pending post-fix runtime retest for {row_id} {feature}. Evidence: {evidence_text}"
    else:
        test_status = "Blocked in this environment"
        errors_documented = f"{tracker['Errors documented']} Runtime blocker from signed-app sweep: {errors}".strip()
        fix_status = f"Blocked pending runtime prerequisite for {row_id} {feature}."
        retest_status = f"Blocked pending runtime prerequisite retest for {row_id} {feature}. Evidence: {evidence_text}"

    updates.append(
        {
            "ID": row_id,
            "Feature": feature,
            "Result": result,
            "Test status": test_status,
            "Errors documented": normalize_blocker_text(errors_documented),
            "Fix status": normalize_blocker_text(fix_status),
            "Retest status": normalize_blocker_text(retest_status),
        }
    )

output_path.parent.mkdir(parents=True, exist_ok=True)
output_path.write_text(json.dumps(updates, indent=2) + "\n")
print(f"Wrote tracker update review artifact for {len(updates)} runtime evidence rows to {output_path}")
PY
}

write_updated_source() {
  local evidence_path="$1"
  local output_path="$2"

  reject_canonical_output_path "$output_path" "app-runtime updated source"
  audit_evidence "$evidence_path" 0 >/dev/null
  if evidence_has_fail "$evidence_path"; then
    echo "app-runtime updated-source artifacts cannot include failed runtime evidence." >&2
    echo "Use --write-tracker-update for fail or blocked evidence while documenting the fix/retest loop." >&2
    exit 1
  fi
  if ! evidence_has_pass "$evidence_path"; then
    echo "app-runtime updated-source artifacts require at least one pass row to promote." >&2
    exit 1
  fi
  require_final_runtime_prereqs

python3 - "$evidence_path" "$output_path" <<'PY'
import json
import re
import sys
from pathlib import Path

from qa.app_runtime_rows import runtime_pending_ids, tracker_rows

sys.path.insert(0, str(Path.cwd() / "qa"))
import build_feature_status

evidence_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])

rows = tracker_rows()
runtime_ids = set(runtime_pending_ids(rows))
evidence = json.loads(evidence_path.read_text())
evidence_by_id = {
    item["ID"]: item
    for item in evidence
    if item["ID"] in runtime_ids
}

PROOF_GAP_RE = re.compile(r"Remaining proof gap:|Runtime proof gap:|Signed-app boundary evidence:", re.IGNORECASE)


def remove_runtime_proof_gap_text(text: str) -> str:
    cleaned = re.sub(r"\s*(?:Remaining proof gap|Runtime proof gap):[^.]*\.", "", text, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*Signed-app boundary evidence:[^.]*\.", "", cleaned, flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", cleaned).strip()


def sync_qa_runtime_count_text(text: str, pending_count: int) -> str:
    phrases = build_feature_status.app_runtime_count_phrases(pending_count)
    replacements = [
        (r"\b\d+ app-runtime user-story rows\b", phrases[0]),
        (r"\b\d+-row JSON runtime evidence template\b", phrases[1]),
        (r"\b\d+ app-runtime pending rows\b", phrases[2]),
        (r"\bthose \d+ rows\b", phrases[3]),
    ]
    updated = text
    for pattern, replacement in replacements:
        updated = re.sub(pattern, replacement, updated)
    return updated


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
        row["Test evidence"] = remove_runtime_proof_gap_text(str(row.get("Test evidence", "")))
        row["Errors documented"] = (
            f"Runtime pass for {row_id} {feature}: "
            "current signed-app runtime evidence recorded no runtime errors for this row."
        )
        row["Fix status"] = (
            f"Runtime evidence passed for {row_id} {feature}; "
            "no signed-app runtime fix is pending from this sweep."
        )
        row["Retest status"] = f"Passed signed-app runtime sweep for {row_id} {feature}. Evidence: {evidence_text}"
        row["Notes"] = remove_runtime_proof_gap_text(str(row.get("Notes", "")))
    elif result == "fail":
        row["Test status"] = "Pending"
        row["Errors documented"] = f"{row['Errors documented']} Runtime failure from signed-app sweep: {errors}".strip()
        row["Fix status"] = f"Pending fix from signed-app runtime evidence for {row_id} {feature}."
        row["Retest status"] = f"Pending post-fix runtime retest for {row_id} {feature}. Evidence: {evidence_text}"
    else:
        pass

    updated_rows.append(row)

pending_count = len(runtime_pending_ids(updated_rows))
for row in updated_rows:
    if row.get("ID") != "QA-001":
        continue
    for field in ("Test evidence", "Errors documented", "Retest status"):
        row[field] = sync_qa_runtime_count_text(str(row.get(field, "")), pending_count)
    break

output_path.parent.mkdir(parents=True, exist_ok=True)
build_feature_status.validate_entries(updated_rows)
output_path.write_text(json.dumps(updated_rows, indent=2) + "\n")
print(f"Wrote updated tracker source review artifact for {len(updated_rows)} feature rows to {output_path}")
PY
}

REQUIRE_PREREQS=0
REQUIRE_PASS=0

case "${1:-}" in
  --check-prereqs)
    shift
    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --require-prereqs)
          REQUIRE_PREREQS=1
          ;;
        *)
          usage >&2
          exit 2
          ;;
      esac
      shift
    done
    if check_prereqs; then
      exit 0
    fi
    if [[ "$REQUIRE_PREREQS" -eq 1 ]]; then
      exit 1
    fi
    printf '%s\n' "Prerequisite-only mode records the blocker but does not fail the deterministic QA harness."
    ;;
  --write-template)
    shift
    [[ "$#" -eq 1 ]] || { usage >&2; exit 2; }
    write_template "$1"
    ;;
  --audit-evidence)
    shift
    [[ "$#" -ge 1 ]] || { usage >&2; exit 2; }
    evidence_path="$1"
    shift
    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        --require-pass)
          REQUIRE_PASS=1
          ;;
        *)
          usage >&2
          exit 2
          ;;
      esac
      shift
    done
    audit_evidence "$evidence_path" "$REQUIRE_PASS"
    ;;
  --write-tracker-update)
    shift
    [[ "$#" -eq 2 ]] || { usage >&2; exit 2; }
    write_tracker_update "$1" "$2"
    ;;
  --write-updated-source)
    shift
    [[ "$#" -eq 2 ]] || { usage >&2; exit 2; }
    write_updated_source "$1" "$2"
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
