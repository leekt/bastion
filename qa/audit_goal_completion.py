#!/usr/bin/env python3
"""Audit whether the full feature/user-story QA objective is closable."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import build_feature_status
from app_runtime_rows import (
    SEEDED_PAIRED_RUNTIME_IDS,
    live_runtime_evidence_template,
    runtime_evidence_template,
)


NAMESPACE = {"main": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
ARTIFACT_REF_RE = re.compile(r"\bArtifact:\s*(\S+)")
ADDITIONAL_ARTIFACT_REF_RE = re.compile(r"\bAdditional artifact:\s*(\S+)")
ARTIFACT_ROW_MARKER_RE = re.compile(r"(?m)^.*\bROW\s+([A-Z]+-\d+)\b.*$")
RERUN_HINT_RE = re.compile(r"\bRerun(?: command)?:\s*(\S+)")
PLACEHOLDER_TEXT_RE = re.compile(r"\b(?:fixture|todo|tbd|example|dummy)\b", re.IGNORECASE)
DUPLICATED_WITH_RE = re.compile(r"\bwith\s+with\b", re.IGNORECASE)
CURRENT_REVIEW_ARTIFACTS = [
    (Path("dist/app-runtime-evidence.current.json"), "runtime evidence"),
    (Path("dist/live-runtime-evidence.current-blocked.json"), "runtime evidence"),
    (Path("dist/app-runtime-tracker-update.current.json"), "tracker update"),
    (Path("dist/live-runtime-tracker-update.current-blocked.json"), "tracker update"),
]
CURRENT_REVIEW_ARTIFACT_PAIRS = [
    (
        Path("dist/app-runtime-evidence.current.json"),
        Path("dist/app-runtime-tracker-update.current.json"),
    ),
    (
        Path("dist/live-runtime-evidence.current-blocked.json"),
        Path("dist/live-runtime-tracker-update.current-blocked.json"),
    ),
]
CURRENT_RUNTIME_EVIDENCE_KEYS = {
    "ID",
    "Surface",
    "Feature",
    "User story",
    "Expected behaviour",
    "Test instructions",
    "Result",
    "Evidence",
    "Errors",
}
CURRENT_TRACKER_UPDATE_KEYS = {
    "ID",
    "Feature",
    "Result",
    "Test status",
    "Errors documented",
    "Fix status",
    "Retest status",
}
SEEDED_CODESIGN_PREFLIGHT_ARTIFACT = (
    "Additional artifact: dist/app-runtime-artifacts/seeded-paired-runtime/codesign-preflight.log"
)
UI039_NOTIFICATION_ARTIFACTS = (
    "Additional artifact: dist/app-runtime-artifacts/direct-runtime/notification-probe.json",
    "Additional artifact: dist/app-runtime-artifacts/direct-runtime/notification-probe.json.status",
    "Additional artifact: dist/app-runtime-artifacts/direct-runtime/notification-click-probe.json",
    "Additional artifact: dist/app-runtime-artifacts/direct-runtime/notification-click-probe.json.status",
    "Additional artifact: dist/app-runtime-artifacts/direct-runtime/userop-notification-probe.json",
    "Additional artifact: dist/app-runtime-artifacts/direct-runtime/userop-notification-probe.json.status",
    "Additional artifact: dist/app-runtime-artifacts/direct-runtime/userop-notification-click-probe.json",
    "Additional artifact: dist/app-runtime-artifacts/direct-runtime/userop-notification-click-probe.json.status",
    "Additional artifact: dist/app-runtime-artifacts/direct-runtime/diagnostics-tail.jsonl",
)
UI042_OPEN_UI_ARTIFACTS = (
    "Additional artifact: dist/app-runtime-artifacts/direct-runtime/open-ui-settings.json",
    "Additional artifact: dist/app-runtime-artifacts/direct-runtime/open-ui-auditHistory.json",
    "Additional artifact: dist/app-runtime-artifacts/direct-runtime/open-ui-diagnostics.json",
)
SUPPORT_BUNDLE_ARTIFACT = (
    "Additional artifact: dist/app-runtime-artifacts/current-ui/support-bundle.json"
)


def col_index(ref: str) -> int:
    value = 0
    for letter in ref:
        if not letter.isalpha():
            break
        value = value * 26 + ord(letter.upper()) - 64
    return value - 1


def cell_text(cell: ET.Element) -> str:
    text_node = cell.find("main:is/main:t", NAMESPACE)
    return "" if text_node is None or text_node.text is None else text_node.text


def matrix(sheet: ET.Element) -> list[list[str]]:
    out: list[list[str]] = []
    for row in sheet.findall(".//main:sheetData/main:row", NAMESPACE):
        values: list[str] = []
        for cell in row.findall("main:c", NAMESPACE):
            index = col_index(cell.attrib["r"])
            while len(values) <= index:
                values.append("")
            values[index] = cell_text(cell)
        out.append(values)
    return out


def string_rows(rows: list[list[object]]) -> list[list[str]]:
    return [["" if value is None else str(value) for value in row] for row in rows]


def list_formula(values: list[str]) -> str:
    return '"' + ",".join(values) + '"'


def clean_artifact_ref(raw_path: str) -> str:
    return raw_path.rstrip(".,;:)")


def resolve_artifact_path(raw_path: str, evidence_path: Path) -> Path:
    path = Path(clean_artifact_ref(raw_path))
    if path.is_absolute():
        return path
    candidate = evidence_path.parent / path
    if candidate.exists():
        return candidate
    return Path.cwd() / path


def artifact_section_text(artifact_text: str, row_id: str) -> str | None:
    markers = list(ARTIFACT_ROW_MARKER_RE.finditer(artifact_text))
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


def validate_additional_artifacts(evidence: str, row_id_text: str, artifact: Path) -> list[str]:
    issues: list[str] = []
    for match in ADDITIONAL_ARTIFACT_REF_RE.finditer(evidence):
        artifact_ref = clean_artifact_ref(match.group(1))
        resolved_artifact = resolve_artifact_path(artifact_ref, artifact)
        if not resolved_artifact.exists():
            issues.append(f"{artifact}: {row_id_text} Additional artifact does not exist: {artifact_ref}")
        elif not resolved_artifact.is_file():
            issues.append(f"{artifact}: {row_id_text} Additional artifact must be a regular file: {artifact_ref}")
        elif resolved_artifact.stat().st_size == 0:
            issues.append(f"{artifact}: {row_id_text} Additional artifact must not be empty: {artifact_ref}")
    return issues


def validate_rerun_command(evidence: str, row_id_text: str, artifact: Path) -> list[str]:
    match = RERUN_HINT_RE.search(evidence)
    if not match:
        return [f"{artifact}: {row_id_text} blocked Evidence must include a Rerun command"]
    command = clean_artifact_ref(match.group(1)).strip("\"'")
    if command.startswith("./"):
        command_path = Path.cwd() / command[2:]
    elif command.startswith(("qa/", "scripts/")):
        command_path = Path.cwd() / command
    else:
        return []
    if not command_path.exists():
        return [f"{artifact}: {row_id_text} Rerun command does not exist: {command}"]
    if not command_path.is_file():
        return [f"{artifact}: {row_id_text} Rerun command must be a file: {command}"]
    if not os.access(command_path, os.X_OK):
        return [f"{artifact}: {row_id_text} Rerun command must be executable: {command}"]
    return []


def validation_map(sheet: ET.Element) -> dict[str, dict[str, str]]:
    validations: dict[str, dict[str, str]] = {}
    for validation in sheet.findall(".//main:dataValidations/main:dataValidation", NAMESPACE):
        formula = validation.find("main:formula1", NAMESPACE)
        validations[validation.attrib.get("sqref", "")] = {
            "type": validation.attrib.get("type", ""),
            "allowBlank": validation.attrib.get("allowBlank", ""),
            "showErrorMessage": validation.attrib.get("showErrorMessage", ""),
            "formula1": "" if formula is None or formula.text is None else formula.text,
        }
    return validations


def runtime_prerequisite_consistency_blockers(
    rows: list[dict[str, object]], runtime_prereq_rows: list[list[object]]
) -> list[str]:
    blockers = build_feature_status.completion_blockers(rows)
    runtime_pending = runtime_evidence_template(rows)
    live_pending = live_runtime_evidence_template(rows)
    prereqs = {
        str(row[0]): str(row[1])
        for row in runtime_prereq_rows[1:]
        if len(row) >= 2
    }
    issues: list[str] = []

    if blockers:
        if prereqs.get("Final completion gate") in {"Satisfied", "Complete"}:
            issues.append("Runtime Prereqs row 'Final completion gate' is closed while completion blockers remain")
    else:
        for prereq, status in prereqs.items():
            if prereq == "Full Xcode developer directory":
                continue
            if status != "Satisfied" and not (prereq == "Final completion gate" and status == "Complete"):
                issues.append(f"Runtime Prereqs row {prereq!r} is {status!r} after completion blockers closed")

    return issues


def current_runtime_artifact_expected_context(rows: list[dict[str, object]]) -> dict[Path, dict[str, dict[str, str]]]:
    evidence_context: dict[Path, dict[str, dict[str, str]]] = {
        Path("dist/app-runtime-evidence.current.json"): {},
        Path("dist/live-runtime-evidence.current-blocked.json"): {},
    }
    tracker_context: dict[Path, dict[str, dict[str, str]]] = {
        Path("dist/app-runtime-tracker-update.current.json"): {},
        Path("dist/live-runtime-tracker-update.current-blocked.json"): {},
    }

    for path, template in (
        (Path("dist/app-runtime-evidence.current.json"), runtime_evidence_template(rows)),
        (Path("dist/live-runtime-evidence.current-blocked.json"), live_runtime_evidence_template(rows)),
    ):
        evidence_context[path] = {
            item["ID"]: {
                "Surface": item["Surface"],
                "Feature": item["Feature"],
                "User story": item["User story"],
                "Expected behaviour": item["Expected behaviour"],
                "Test instructions": item["Test instructions"],
            }
            for item in template
        }

    for path, evidence_path in (
        (Path("dist/app-runtime-tracker-update.current.json"), Path("dist/app-runtime-evidence.current.json")),
        (Path("dist/live-runtime-tracker-update.current-blocked.json"), Path("dist/live-runtime-evidence.current-blocked.json")),
    ):
        tracker_context[path] = {
            row_id: {"Feature": context["Feature"]}
            for row_id, context in evidence_context[evidence_path].items()
        }

    return {**evidence_context, **tracker_context}


def current_runtime_review_artifact_blockers(rows: list[dict[str, object]]) -> list[str]:
    app_path = Path(os.environ.get("BASTION_APP_PATH", str(Path.home() / "Applications/Bastion Dev.app")))
    prereq_checks = [
        build_feature_status.signed_app_status(app_path),
        build_feature_status.app_source_freshness_status(app_path),
    ]
    runtime_prereqs_blocked = not all(status == "Satisfied" for status, _ in prereq_checks)
    canonical_pass_ids = {
        str(row.get("ID", ""))
        for row in rows
        if row.get("Test status") == "Pass"
    }

    issues: list[str] = []
    expected_context_by_artifact = current_runtime_artifact_expected_context(rows)
    full_context_by_id = {
        item["ID"]: item
        for item in [*runtime_evidence_template(rows), *live_runtime_evidence_template(rows)]
    }
    current_rows_by_artifact: dict[Path, dict[str, dict[str, object]]] = {}
    for artifact, artifact_kind in CURRENT_REVIEW_ARTIFACTS:
        required_keys = (
            CURRENT_RUNTIME_EVIDENCE_KEYS if artifact_kind == "runtime evidence" else CURRENT_TRACKER_UPDATE_KEYS
        )
        if not artifact.exists():
            issues.append(f"current runtime review artifact is missing: {artifact}")
            continue
        try:
            payload = json.loads(artifact.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            issues.append(f"current runtime review artifact is unreadable: {artifact} ({exc})")
            continue
        if not isinstance(payload, list):
            issues.append(f"current runtime review artifact must contain a JSON list: {artifact}")
            continue
        expected_context = expected_context_by_artifact[artifact]
        expected_ids = set(expected_context)
        expected_order = list(expected_context)
        observed_order: list[str] = []
        seen_ids: set[str] = set()
        duplicate_ids: set[str] = set()
        valid_rows_by_id: dict[str, dict[str, object]] = {}
        for index, row in enumerate(payload, start=1):
            if not isinstance(row, dict):
                issues.append(f"current runtime review artifact contains a non-object row: {artifact}")
                continue
            missing_keys = sorted(required_keys - set(row))
            extra_keys = sorted(set(row) - required_keys)
            for key in missing_keys:
                issues.append(f"{artifact}: row {index} is missing required {key!r} key")
            for key in extra_keys:
                issues.append(f"{artifact}: row {index} has unexpected {key!r} key")
            for key in sorted(required_keys & set(row)):
                if not isinstance(row[key], str):
                    issues.append(f"{artifact}: row {index} {key!r} must be a string")
            row_id = row.get("ID")
            if not isinstance(row_id, str) or not row_id.strip():
                issues.append(f"{artifact}: row {index} is missing a string ID")
                continue
            if row_id != row_id.strip():
                issues.append(f"{artifact}: {row_id!r} has leading or trailing whitespace in ID")
            if row_id in seen_ids:
                duplicate_ids.add(row_id)
            seen_ids.add(row_id)
            observed_order.append(row_id)
            valid_rows_by_id[row_id] = row
            for key in sorted(required_keys & set(row)):
                value = row.get(key)
                if isinstance(value, str) and DUPLICATED_WITH_RE.search(value):
                    issues.append(f"{artifact}: {row_id} {key} contains duplicated wording: 'with with'")
            if row_id not in expected_context:
                issues.append(f"{artifact}: {row_id} is not an expected current runtime row")
            else:
                for key, expected_value in expected_context[row_id].items():
                    if row.get(key) != expected_value:
                        issues.append(f"{artifact}: {row_id} {key} does not match the canonical tracker")
            is_canonical_pass = isinstance(row_id, str) and row_id in canonical_pass_ids
            promotes_pass = runtime_prereqs_blocked and not is_canonical_pass and row.get("Result") == "pass" and (
                artifact_kind == "runtime evidence" or row.get("Test status") == "Pass"
            )
            if promotes_pass:
                issues.append(
                    f"{artifact}: {row.get('ID')} promotes pass evidence while runtime prerequisites are blocked"
                )
            if artifact_kind == "runtime evidence":
                result = row.get("Result")
                row_id_text = row_id if isinstance(row_id, str) else f"row {index}"
                feature = row.get("Feature")
                evidence = row.get("Evidence")
                errors = row.get("Errors")
                if result not in build_feature_status.RUNTIME_RESULT_VALUES:
                    issues.append(f"{artifact}: {row_id_text} Result must be one of pass, fail, blocked")
                if not isinstance(evidence, str) or not evidence.strip():
                    issues.append(f"{artifact}: {row_id_text} Evidence is required")
                elif PLACEHOLDER_TEXT_RE.search(evidence):
                    issues.append(f"{artifact}: {row_id_text} Evidence must describe real runtime observations, not placeholder text")
                else:
                    if (
                        result in build_feature_status.RUNTIME_RESULT_VALUES
                        and f"Result {result}" not in evidence
                    ):
                        issues.append(f"{artifact}: {row_id_text} Evidence must cite Result {result}")
                    if result == "blocked":
                        issues.extend(validate_rerun_command(evidence, row_id_text, artifact))
                    if row_id not in evidence:
                        issues.append(f"{artifact}: {row_id_text} Evidence must mention the row ID")
                    if isinstance(row_id, str) and isinstance(feature, str) and feature and f"{row_id} {feature}" not in evidence:
                        issues.append(f"{artifact}: {row_id_text} Evidence must mention the tracker Feature")
                    if isinstance(row_id, str) and row_id in expected_context:
                        expected_user_story = expected_context[row_id]["User story"]
                        if expected_user_story and f"User story: {expected_user_story}" not in evidence:
                            issues.append(f"{artifact}: {row_id_text} Evidence must mention the tracker User story")
                        expected_behaviour = expected_context[row_id]["Expected behaviour"]
                        if expected_behaviour and f"Expected behaviour: {expected_behaviour}" not in evidence:
                            issues.append(f"{artifact}: {row_id_text} Evidence must mention the tracker Expected behaviour")
                        expected_test_instructions = expected_context[row_id]["Test instructions"]
                        if expected_test_instructions and f"Test instructions: {expected_test_instructions}" not in evidence:
                            issues.append(f"{artifact}: {row_id_text} Evidence must mention the tracker Test instructions")
                    artifact_match = ARTIFACT_REF_RE.search(evidence)
                    if not artifact_match:
                        issues.append(f"{artifact}: {row_id_text} Evidence must cite Artifact:")
                    else:
                        artifact_ref = clean_artifact_ref(artifact_match.group(1))
                        resolved_artifact = resolve_artifact_path(artifact_ref, artifact)
                        if not resolved_artifact.exists():
                            issues.append(
                                f"{artifact}: {row_id_text} Evidence artifact does not exist: {artifact_ref}"
                            )
                        elif not resolved_artifact.is_file():
                            issues.append(
                                f"{artifact}: {row_id_text} Evidence artifact must be a regular file: {artifact_ref}"
                            )
                        elif resolved_artifact.stat().st_size == 0:
                            issues.append(
                                f"{artifact}: {row_id_text} Evidence artifact must not be empty: {artifact_ref}"
                            )
                        else:
                            artifact_text = resolved_artifact.read_text(errors="replace")
                            row_artifact_text = artifact_section_text(artifact_text, row_id)
                            if row_artifact_text is None:
                                issues.append(
                                    f"{artifact}: {row_id_text} Evidence artifact must include a row section for {row_id}: {artifact_ref}"
                                )
                                continue
                            if (
                                result in build_feature_status.RUNTIME_RESULT_VALUES
                                and f"Result {result}" not in row_artifact_text
                            ):
                                issues.append(
                                    f"{artifact}: {row_id_text} Evidence artifact must mention Result {result}: {artifact_ref}"
                                )
                            if row_id not in row_artifact_text:
                                issues.append(
                                    f"{artifact}: {row_id_text} Evidence artifact must mention the row ID: {artifact_ref}"
                                )
                            if row_id in expected_context:
                                expected_feature = expected_context[row_id]["Feature"]
                                if expected_feature and not artifact_mentions_feature(row_artifact_text, row_id, expected_feature):
                                    issues.append(
                                        f"{artifact}: {row_id_text} Evidence artifact must mention the tracker Feature: {artifact_ref}"
                                    )
                                expected_user_story = expected_context[row_id]["User story"]
                                if expected_user_story and f"User story: {expected_user_story}" not in row_artifact_text:
                                    issues.append(
                                        f"{artifact}: {row_id_text} Evidence artifact must mention the tracker User story: {artifact_ref}"
                                    )
                                expected_behaviour = expected_context[row_id]["Expected behaviour"]
                                if expected_behaviour and f"Expected behaviour: {expected_behaviour}" not in row_artifact_text:
                                    issues.append(
                                        f"{artifact}: {row_id_text} Evidence artifact must mention the tracker Expected behaviour: {artifact_ref}"
                                    )
                                expected_test_instructions = expected_context[row_id]["Test instructions"]
                                if expected_test_instructions and f"Test instructions: {expected_test_instructions}" not in row_artifact_text:
                                    issues.append(
                                        f"{artifact}: {row_id_text} Evidence artifact must mention the tracker Test instructions: {artifact_ref}"
                                    )
                    issues.extend(validate_additional_artifacts(evidence, row_id_text, artifact))
                    if (
                        artifact == Path("dist/app-runtime-evidence.current.json")
                        and row_id in SEEDED_PAIRED_RUNTIME_IDS
                        and isinstance(errors, str)
                        and "non-mutating codesign usability preflight failed" in errors
                        and SEEDED_CODESIGN_PREFLIGHT_ARTIFACT not in evidence
                    ):
                        issues.append(
                            f"{artifact}: {row_id_text} seeded paired-client preflight blocker "
                            "must cite raw codesign-preflight.log as an Additional artifact"
                        )
                    if (
                        artifact == Path("dist/app-runtime-evidence.current.json")
                        and row_id == "UI-039"
                        and "notification probe" in evidence
                    ):
                        for notification_artifact in UI039_NOTIFICATION_ARTIFACTS:
                            if notification_artifact not in evidence:
                                issues.append(
                                    f"{artifact}: {row_id_text} notification probe evidence must cite "
                                    f"{notification_artifact.removeprefix('Additional artifact: ')} "
                                    "as an Additional artifact"
                                )
                    if (
                        artifact == Path("dist/app-runtime-evidence.current.json")
                        and row_id == "UI-042"
                        and "open-ui" in evidence
                    ):
                        for open_ui_artifact in UI042_OPEN_UI_ARTIFACTS:
                            if open_ui_artifact not in evidence:
                                issues.append(
                                    f"{artifact}: {row_id_text} open-ui evidence must cite "
                                    f"{open_ui_artifact.removeprefix('Additional artifact: ')} "
                                    "as an Additional artifact"
                                )
                    if (
                        artifact == Path("dist/app-runtime-evidence.current.json")
                        and ("support-bundle" in evidence or "support bundle" in evidence)
                        and SUPPORT_BUNDLE_ARTIFACT not in evidence
                    ):
                        issues.append(
                            f"{artifact}: {row_id_text} support-bundle evidence must cite "
                            "dist/app-runtime-artifacts/current-ui/support-bundle.json as an Additional artifact"
                        )
                if result in {"fail", "blocked"}:
                    if not isinstance(errors, str) or not errors.strip():
                        issues.append(f"{artifact}: {row_id_text} Errors is required when Result is fail or blocked")
                    elif PLACEHOLDER_TEXT_RE.search(errors):
                        issues.append(f"{artifact}: {row_id_text} Errors must describe real runtime failures, not placeholder text")
                    else:
                        if row_id not in errors:
                            issues.append(f"{artifact}: {row_id_text} Errors must mention the row ID")
                        if isinstance(feature, str) and feature and feature not in errors:
                            issues.append(f"{artifact}: {row_id_text} Errors must mention the tracker Feature")
                        if isinstance(evidence, str):
                            artifact_match = ARTIFACT_REF_RE.search(evidence)
                            if artifact_match:
                                artifact_ref = clean_artifact_ref(artifact_match.group(1))
                                if artifact_ref not in errors:
                                    issues.append(f"{artifact}: {row_id_text} Errors must mention the Evidence artifact")
                            rerun_match = RERUN_HINT_RE.search(evidence)
                            if result == "blocked" and rerun_match:
                                rerun_command = clean_artifact_ref(rerun_match.group(1)).strip("\"'")
                                if rerun_command not in errors:
                                    issues.append(f"{artifact}: {row_id_text} Errors must mention the Rerun command")
                elif result == "pass" and isinstance(errors, str) and errors.strip():
                    issues.append(f"{artifact}: {row_id_text} Errors must be empty when Result is pass")
            if artifact_kind == "tracker update":
                result = row.get("Result")
                test_status = row.get("Test status")
                row_id_text = row_id if isinstance(row_id, str) else f"row {index}"
                feature = row.get("Feature")
                if result not in build_feature_status.RUNTIME_RESULT_VALUES:
                    issues.append(f"{artifact}: {row_id_text} Result must be one of pass, fail, blocked")
                if test_status not in build_feature_status.TEST_STATUS_VALUES:
                    issues.append(f"{artifact}: {row_id_text} Test status is not canonical: {test_status!r}")
                if result == "blocked" and test_status != "Blocked in this environment":
                    issues.append(
                        f"{artifact}: {row_id_text} Result blocked must have Test status 'Blocked in this environment'"
                    )
                elif result == "fail" and test_status != "Pending":
                    issues.append(f"{artifact}: {row_id_text} Result fail must have Test status 'Pending'")
                elif (
                    result == "pass"
                    and runtime_prereqs_blocked
                    and not is_canonical_pass
                    and test_status != "Blocked in this environment"
                ):
                    issues.append(
                        f"{artifact}: {row_id_text} Result pass must remain 'Blocked in this environment' while runtime prerequisites are blocked"
                    )
                elif result == "pass" and (not runtime_prereqs_blocked or is_canonical_pass) and test_status != "Pass":
                    issues.append(f"{artifact}: {row_id_text} Result pass must have Test status 'Pass'")

                lifecycle_fields = ("Errors documented", "Fix status", "Retest status")
                for key in lifecycle_fields:
                    value = row.get(key)
                    if not isinstance(value, str) or not value.strip():
                        issues.append(f"{artifact}: {row_id_text} {key} is required")
                    elif PLACEHOLDER_TEXT_RE.search(value):
                        issues.append(f"{artifact}: {row_id_text} {key} must describe real runtime state, not placeholder text")
                    else:
                        if isinstance(row_id, str) and row_id not in value:
                            issues.append(f"{artifact}: {row_id_text} {key} must mention the row ID")
                        if isinstance(feature, str) and feature and feature not in value:
                            issues.append(f"{artifact}: {row_id_text} {key} must mention the tracker Feature")
                retest_status = row.get("Retest status")
                fix_status = row.get("Fix status")
                if isinstance(fix_status, str) and isinstance(retest_status, str):
                    if result == "blocked":
                        if not fix_status.startswith("Blocked pending"):
                            issues.append(f"{artifact}: {row_id_text} Fix status must describe a blocked runtime state")
                        if not retest_status.startswith("Blocked pending"):
                            issues.append(f"{artifact}: {row_id_text} Retest status must describe a blocked runtime retest")
                    elif result == "fail":
                        if not fix_status.startswith("Pending fix"):
                            issues.append(f"{artifact}: {row_id_text} Fix status must describe a pending fix")
                        if not retest_status.startswith("Pending post-fix"):
                            issues.append(f"{artifact}: {row_id_text} Retest status must describe a pending post-fix retest")
                    elif result == "pass" and runtime_prereqs_blocked and not is_canonical_pass:
                        if not fix_status.startswith("Blocked pending current-source"):
                            issues.append(
                                f"{artifact}: {row_id_text} Fix status must describe the blocked current-source prerequisite"
                            )
                        if not retest_status.startswith("Blocked pending current-source"):
                            issues.append(
                                f"{artifact}: {row_id_text} Retest status must describe the blocked current-source retest"
                            )
                if isinstance(retest_status, str) and retest_status.strip() and "Evidence:" not in retest_status:
                    issues.append(f"{artifact}: {row_id_text} Retest status must cite Evidence:")
                if (
                    isinstance(retest_status, str)
                    and retest_status.strip()
                    and result in build_feature_status.RUNTIME_RESULT_VALUES
                    and f"Result {result}" not in retest_status
                ):
                    issues.append(f"{artifact}: {row_id_text} Retest status must cite Result {result}")
                if isinstance(retest_status, str) and retest_status.strip():
                    artifact_match = ARTIFACT_REF_RE.search(retest_status)
                    if not artifact_match:
                        issues.append(f"{artifact}: {row_id_text} Retest status must cite Artifact:")
                    else:
                        artifact_ref = clean_artifact_ref(artifact_match.group(1))
                        resolved_artifact = resolve_artifact_path(artifact_ref, artifact)
                        if not resolved_artifact.exists():
                            issues.append(
                                f"{artifact}: {row_id_text} Retest artifact does not exist: {artifact_ref}"
                            )
                        elif not resolved_artifact.is_file():
                            issues.append(
                                f"{artifact}: {row_id_text} Retest artifact must be a regular file: {artifact_ref}"
                            )
                        elif resolved_artifact.stat().st_size == 0:
                            issues.append(
                                f"{artifact}: {row_id_text} Retest artifact must not be empty: {artifact_ref}"
                            )
                        else:
                            artifact_text = resolved_artifact.read_text(errors="replace")
                            row_artifact_text = (
                                artifact_section_text(artifact_text, row_id)
                                if isinstance(row_id, str)
                                else artifact_text
                            )
                            if row_artifact_text is None:
                                issues.append(
                                    f"{artifact}: {row_id_text} Retest artifact must include a row section for {row_id}: {artifact_ref}"
                                )
                                continue
                            if (
                                result in build_feature_status.RUNTIME_RESULT_VALUES
                                and f"Result {result}" not in row_artifact_text
                            ):
                                issues.append(
                                    f"{artifact}: {row_id_text} Retest artifact must mention Result {result}: {artifact_ref}"
                                )
                            if isinstance(row_id, str) and row_id not in row_artifact_text:
                                issues.append(
                                    f"{artifact}: {row_id_text} Retest artifact must mention the row ID: {artifact_ref}"
                                )
                            context = full_context_by_id.get(row_id if isinstance(row_id, str) else "")
                            if context:
                                expected_feature = context["Feature"]
                                if expected_feature and isinstance(row_id, str) and not artifact_mentions_feature(row_artifact_text, row_id, expected_feature):
                                    issues.append(
                                        f"{artifact}: {row_id_text} Retest artifact must mention the tracker Feature: {artifact_ref}"
                                    )
                                expected_user_story = context["User story"]
                                if expected_user_story and f"User story: {expected_user_story}" not in row_artifact_text:
                                    issues.append(
                                        f"{artifact}: {row_id_text} Retest artifact must mention the tracker User story: {artifact_ref}"
                                    )
                                expected_behaviour = context["Expected behaviour"]
                                if expected_behaviour and f"Expected behaviour: {expected_behaviour}" not in row_artifact_text:
                                    issues.append(
                                        f"{artifact}: {row_id_text} Retest artifact must mention the tracker Expected behaviour: {artifact_ref}"
                                    )
                                expected_test_instructions = context["Test instructions"]
                                if expected_test_instructions and f"Test instructions: {expected_test_instructions}" not in row_artifact_text:
                                    issues.append(
                                        f"{artifact}: {row_id_text} Retest artifact must mention the tracker Test instructions: {artifact_ref}"
                                    )
                    if isinstance(retest_status, str):
                        issues.extend(validate_additional_artifacts(retest_status, row_id_text, artifact))
                        if result == "blocked":
                            issues.extend(validate_rerun_command(retest_status, row_id_text, artifact))
        missing_ids = sorted(expected_ids - seen_ids)
        extra_ids = sorted(seen_ids - expected_ids)
        if missing_ids:
            issues.append(f"{artifact}: missing current runtime rows: {', '.join(missing_ids)}")
        if extra_ids:
            issues.append(f"{artifact}: unexpected current runtime rows: {', '.join(extra_ids)}")
        if duplicate_ids:
            issues.append(f"{artifact}: duplicate current runtime rows: {', '.join(sorted(duplicate_ids))}")
        if not missing_ids and not extra_ids and not duplicate_ids and observed_order != expected_order:
            issues.append(f"{artifact}: current runtime rows are not in canonical order")
        current_rows_by_artifact[artifact] = valid_rows_by_id
    for evidence_artifact, tracker_artifact in CURRENT_REVIEW_ARTIFACT_PAIRS:
        evidence_rows = current_rows_by_artifact.get(evidence_artifact, {})
        tracker_rows = current_rows_by_artifact.get(tracker_artifact, {})
        for row_id in sorted(set(evidence_rows) & set(tracker_rows)):
            evidence_result = evidence_rows[row_id].get("Result")
            tracker_result = tracker_rows[row_id].get("Result")
            if evidence_result != tracker_result:
                issues.append(
                    f"{tracker_artifact}: {row_id} Result {tracker_result!r} does not match "
                    f"{evidence_artifact} Result {evidence_result!r}"
                )
            evidence_text = evidence_rows[row_id].get("Evidence")
            evidence_errors = evidence_rows[row_id].get("Errors")
            errors_documented = tracker_rows[row_id].get("Errors documented")
            if isinstance(evidence_errors, str) and evidence_errors.strip() and isinstance(errors_documented, str):
                if evidence_errors not in errors_documented:
                    issues.append(
                        f"{tracker_artifact}: {row_id} Errors documented must include "
                        f"{evidence_artifact} Errors text"
                    )
            retest_status = tracker_rows[row_id].get("Retest status")
            if isinstance(evidence_text, str) and isinstance(retest_status, str):
                if evidence_text and evidence_text not in retest_status:
                    issues.append(
                        f"{tracker_artifact}: {row_id} Retest status must include "
                        f"{evidence_artifact} Evidence text"
                    )
                evidence_match = ARTIFACT_REF_RE.search(evidence_text)
                retest_match = ARTIFACT_REF_RE.search(retest_status)
                if evidence_match and retest_match:
                    evidence_ref = clean_artifact_ref(evidence_match.group(1))
                    retest_ref = clean_artifact_ref(retest_match.group(1))
                    if evidence_ref != retest_ref:
                        issues.append(
                            f"{tracker_artifact}: {row_id} Retest artifact {retest_ref} does not match "
                            f"{evidence_artifact} Evidence artifact {evidence_ref}"
                        )
    return issues


def workbook_blockers(rows: list[dict[str, object]], workbook_path: Path) -> list[str]:
    if not workbook_path.exists():
        return [f"canonical workbook missing: {workbook_path}"]

    blockers: list[str] = []
    expected_sheets = [
        "Feature Status",
        "Summary",
        "App Runtime Sweep",
        "Live Runtime Sweep",
        "Closure Checklist",
        "Completion Audit",
        "Runtime Prereqs",
        "Open Issues",
        "Code Coverage",
        "Test Matrix",
        "Error Ledger",
    ]
    try:
        with zipfile.ZipFile(workbook_path) as workbook:
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
    except (KeyError, ET.ParseError, zipfile.BadZipFile) as exc:
        return [f"canonical workbook is unreadable or missing required sheets: {workbook_path} ({exc})"]

    sheets = [sheet.attrib["name"] for sheet in workbook_xml.findall(".//main:sheets/main:sheet", NAMESPACE)]
    if sheets != expected_sheets:
        blockers.append(f"canonical workbook sheets are stale: {sheets}")

    expected_feature_dimension = f"A1:M{len(rows) + 1}"
    feature_dimension = feature_sheet.find("main:dimension", NAMESPACE).attrib["ref"]
    if feature_dimension != expected_feature_dimension:
        blockers.append(f"Feature Status dimension {feature_dimension} does not match {expected_feature_dimension}")
    feature_rows = [build_feature_status.HEADERS]
    for row in rows:
        feature_rows.append([row.get(header, "") for header in build_feature_status.HEADERS])
    if matrix(feature_sheet) != string_rows(feature_rows):
        blockers.append("Feature Status worksheet does not match canonical source rows")
    expected_feature_validations = {
        f"G2:G{len(rows) + 1}": {
            "type": "list",
            "allowBlank": "1",
            "showErrorMessage": "1",
            "formula1": list_formula(build_feature_status.FEATURE_STATUS_VALUES),
        },
        f"H2:H{len(rows) + 1}": {
            "type": "list",
            "allowBlank": "1",
            "showErrorMessage": "1",
            "formula1": list_formula(build_feature_status.TEST_STATUS_VALUES),
        },
    }
    if validation_map(feature_sheet) != expected_feature_validations:
        blockers.append("Feature Status worksheet data validations do not match canonical status lists")

    summary = {row[0]: row[1] for row in matrix(summary_sheet)[1:] if row}
    expected_summary_rows = build_feature_status.summary_rows(rows)
    if matrix(summary_sheet) != string_rows(expected_summary_rows):
        blockers.append("Summary worksheet does not match canonical summary rows")
    expected_completion = build_feature_status.completion_audit_status(rows)
    if summary.get("Completion audit") != expected_completion:
        blockers.append(
            "Summary worksheet Completion audit value "
            f"{summary.get('Completion audit')!r} does not match {expected_completion!r}"
        )
    if validation_map(summary_sheet):
        blockers.append("Summary worksheet must not contain editable data validations")

    runtime_dimension = runtime_sheet.find("main:dimension", NAMESPACE).attrib["ref"]
    expected_runtime_dimension = f"A1:I{len(runtime_evidence_template(rows)) + 1}"
    if runtime_dimension != expected_runtime_dimension:
        blockers.append(f"App Runtime Sweep dimension {runtime_dimension} does not match {expected_runtime_dimension}")
    if matrix(runtime_sheet) != string_rows(build_feature_status.app_runtime_sweep_rows(rows)):
        blockers.append("App Runtime Sweep worksheet does not match canonical app-runtime rows")
    expected_runtime_validations = {}
    if runtime_evidence_template(rows):
        expected_runtime_validations = {
            f"G2:G{len(runtime_evidence_template(rows)) + 1}": {
                "type": "list",
                "allowBlank": "1",
                "showErrorMessage": "1",
                "formula1": list_formula(build_feature_status.RUNTIME_RESULT_VALUES),
            },
        }
    if validation_map(runtime_sheet) != expected_runtime_validations:
        blockers.append("App Runtime Sweep worksheet data validations do not match canonical result list")

    live_runtime_dimension = live_runtime_sheet.find("main:dimension", NAMESPACE).attrib["ref"]
    expected_live_runtime_dimension = f"A1:I{len(live_runtime_evidence_template(rows)) + 1}"
    if live_runtime_dimension != expected_live_runtime_dimension:
        blockers.append(f"Live Runtime Sweep dimension {live_runtime_dimension} does not match {expected_live_runtime_dimension}")
    if matrix(live_runtime_sheet) != string_rows(build_feature_status.live_runtime_sweep_rows(rows)):
        blockers.append("Live Runtime Sweep worksheet does not match canonical live-runtime rows")
    expected_live_runtime_validations = {}
    if live_runtime_evidence_template(rows):
        expected_live_runtime_validations = {
            f"G2:G{len(live_runtime_evidence_template(rows)) + 1}": {
                "type": "list",
                "allowBlank": "1",
                "showErrorMessage": "1",
                "formula1": list_formula(build_feature_status.RUNTIME_RESULT_VALUES),
            },
        }
    if validation_map(live_runtime_sheet) != expected_live_runtime_validations:
        blockers.append("Live Runtime Sweep worksheet data validations do not match canonical result list")

    closure_dimension = closure_sheet.find("main:dimension", NAMESPACE).attrib["ref"]
    closure_rows = build_feature_status.closure_checklist_rows(rows)
    expected_closure_dimension = f"A1:E{len(closure_rows)}"
    if closure_dimension != expected_closure_dimension:
        blockers.append(f"Closure Checklist dimension {closure_dimension} does not match {expected_closure_dimension}")
    if matrix(closure_sheet) != string_rows(closure_rows):
        blockers.append("Closure Checklist worksheet does not match canonical closure checklist rows")
    if validation_map(closure_sheet):
        blockers.append("Closure Checklist worksheet must not contain editable data validations")

    completion_rows = build_feature_status.completion_audit_rows(rows)
    completion_dimension = completion_sheet.find("main:dimension", NAMESPACE).attrib["ref"]
    expected_completion_dimension = f"A1:D{len(completion_rows)}"
    if completion_dimension != expected_completion_dimension:
        blockers.append(
            f"Completion Audit dimension {completion_dimension} does not match {expected_completion_dimension}"
        )
    elif matrix(completion_sheet) != string_rows(completion_rows):
        blockers.append("Completion Audit worksheet does not match canonical completion audit rows")
    if validation_map(completion_sheet):
        blockers.append("Completion Audit worksheet must not contain editable data validations")

    runtime_prereq_rows = build_feature_status.runtime_prerequisite_rows(rows)
    workbook_runtime_prereq_rows = matrix(runtime_prereq_sheet)
    runtime_prereq_dimension = runtime_prereq_sheet.find("main:dimension", NAMESPACE).attrib["ref"]
    expected_runtime_prereq_dimension = f"A1:E{len(runtime_prereq_rows)}"
    if runtime_prereq_dimension != expected_runtime_prereq_dimension:
        blockers.append(
            f"Runtime Prereqs dimension {runtime_prereq_dimension} does not match {expected_runtime_prereq_dimension}"
        )
    elif workbook_runtime_prereq_rows != string_rows(runtime_prereq_rows):
        blockers.append("Runtime Prereqs worksheet does not match current runtime prerequisite audit rows")
    if validation_map(runtime_prereq_sheet):
        blockers.append("Runtime Prereqs worksheet must not contain editable data validations")
    blockers.extend(runtime_prerequisite_consistency_blockers(rows, workbook_runtime_prereq_rows))

    open_issue_rows = build_feature_status.open_issue_rows(rows)
    open_issue_dimension = open_issues_sheet.find("main:dimension", NAMESPACE).attrib["ref"]
    expected_open_issue_dimension = f"A1:F{len(open_issue_rows)}"
    if open_issue_dimension != expected_open_issue_dimension:
        blockers.append(f"Open Issues dimension {open_issue_dimension} does not match {expected_open_issue_dimension}")
    elif matrix(open_issues_sheet) != string_rows(open_issue_rows):
        blockers.append("Open Issues worksheet does not match canonical open issue rows")
    if validation_map(open_issues_sheet):
        blockers.append("Open Issues worksheet must not contain editable data validations")

    code_coverage_rows = build_feature_status.code_coverage_rows(rows)
    code_coverage_dimension = code_coverage_sheet.find("main:dimension", NAMESPACE).attrib["ref"]
    expected_code_coverage_dimension = f"A1:F{len(code_coverage_rows)}"
    if code_coverage_dimension != expected_code_coverage_dimension:
        blockers.append(
            f"Code Coverage dimension {code_coverage_dimension} does not match {expected_code_coverage_dimension}"
        )
    elif matrix(code_coverage_sheet) != string_rows(code_coverage_rows):
        blockers.append("Code Coverage worksheet does not match canonical source-code mapping rows")
    if validation_map(code_coverage_sheet):
        blockers.append("Code Coverage worksheet must not contain editable data validations")
    missing_coverage = [
        row[0]
        for row in code_coverage_rows[1:]
        if len(row) >= 5 and row[4] == "Missing tracker mapping"
    ]
    if missing_coverage:
        blockers.append("Code Coverage worksheet has unmapped feature-code files: " + ", ".join(missing_coverage))

    test_matrix_rows = build_feature_status.test_matrix_rows(rows)
    test_matrix_dimension = test_matrix_sheet.find("main:dimension", NAMESPACE).attrib["ref"]
    expected_test_matrix_dimension = f"A1:I{len(test_matrix_rows)}"
    if test_matrix_dimension != expected_test_matrix_dimension:
        blockers.append(f"Test Matrix dimension {test_matrix_dimension} does not match {expected_test_matrix_dimension}")
    elif matrix(test_matrix_sheet) != string_rows(test_matrix_rows):
        blockers.append("Test Matrix worksheet does not match canonical user-story test matrix rows")
    if validation_map(test_matrix_sheet):
        blockers.append("Test Matrix worksheet must not contain editable data validations")

    error_ledger_rows = build_feature_status.error_ledger_rows(rows)
    error_ledger_dimension = error_ledger_sheet.find("main:dimension", NAMESPACE).attrib["ref"]
    expected_error_ledger_dimension = f"A1:I{len(error_ledger_rows)}"
    if error_ledger_dimension != expected_error_ledger_dimension:
        blockers.append(f"Error Ledger dimension {error_ledger_dimension} does not match {expected_error_ledger_dimension}")
    elif matrix(error_ledger_sheet) != string_rows(error_ledger_rows):
        blockers.append("Error Ledger worksheet does not match canonical error/fix/retest rows")
    if validation_map(error_ledger_sheet):
        blockers.append("Error Ledger worksheet must not contain editable data validations")

    return blockers


def runtime_prerequisite_blockers(rows: list[dict[str, object]]) -> list[str]:
    blockers: list[str] = []
    for prereq in build_feature_status.runtime_prerequisite_rows(rows)[1:]:
        if len(prereq) < 3:
            continue
        name = str(prereq[0])
        status = str(prereq[1])
        if status in {"Satisfied", "Complete"} or name == "Final completion gate":
            continue
        evidence = build_feature_status.one_line(str(prereq[2]))
        if len(evidence) > 500:
            evidence = evidence[:497] + "..."
        blockers.append(f"{name}={status}: {evidence}")
    return blockers


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="exit non-zero unless every canonical tracker row is fully closed",
    )
    parser.add_argument(
        "--workbook",
        type=Path,
        default=build_feature_status.OUTPUT,
        help="path to the generated canonical workbook",
    )
    args = parser.parse_args()

    rows = build_feature_status.validate_entries(json.loads(build_feature_status.SOURCE.read_text()))
    workbook_issues = workbook_blockers(rows, args.workbook)
    workbook_issues.extend(current_runtime_review_artifact_blockers(rows))
    if workbook_issues:
        print("Completion audit: invalid")
        for issue in workbook_issues:
            print(f"- {issue}")
        raise SystemExit(1)

    blockers = build_feature_status.completion_blockers(rows)
    prereq_blockers = runtime_prerequisite_blockers(rows)

    if blockers:
        print("Completion audit: not complete")
        for blocker in blockers:
            print(f"- {blocker}")
        if prereq_blockers:
            print("- runtime prerequisite blockers remain:")
            for blocker in prereq_blockers:
                print(f"  - {blocker}")
        if args.require_complete:
            raise SystemExit(1)
        return

    print("Completion audit: complete")


if __name__ == "__main__":
    main()
