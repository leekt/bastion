#!/usr/bin/env python3
"""Shared app-runtime user-story row derivation for Bastion QA gates."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "feature_status_source.json"

LIVE_RUNTIME_BLOCKED_IDS = {
    "CORE-003",
    "CORE-005",
    "CORE-006",
    "CORE-009",
    "CORE-011",
    "CORE-017",
}

SEEDED_PAIRED_RUNTIME_IDS = {
    "API-001",
    "API-002",
    "API-004",
    "API-005",
    "CLI-001",
    "CLI-002",
    "CLI-003",
    "CLI-004",
    "CLI-005",
    "CLI-007",
    "CORE-001",
    "CORE-002",
    "CORE-004",
    "CORE-016",
    "CORE-019",
    "CORE-020",
    "UI-007",
    "UI-024",
    "UI-028",
    "UI-029",
    "UI-030",
    "UI-031",
    "UI-041",
}

LIVE_RUNTIME_PHASE_COMMANDS = [
    "qa/run_live_runtime_checks.sh --write-template dist/live-runtime-evidence.json",
    "qa/run_live_runtime_checks.sh --check-prereqs --require-prereqs",
    "qa/run_live_runtime_checks.sh --run-phase fresh-install --register",
    "qa/run_live_runtime_checks.sh --run-phase reinstall",
    "qa/run_live_runtime_checks.sh --run-phase post-reboot",
    "qa/run_live_runtime_checks.sh --run-phase post-login",
    "qa/run_live_runtime_checks.sh --run-phase notification-click --require-notification-click",
    "qa/run_live_runtime_checks.sh --audit-evidence",
    "qa/run_live_runtime_checks.sh --audit-row-evidence dist/live-runtime-evidence.json --require-pass",
    "qa/run_live_runtime_checks.sh --write-tracker-update dist/live-runtime-evidence.json dist/live-runtime-tracker-update.json",
    "qa/run_live_runtime_checks.sh --write-updated-source dist/live-runtime-evidence.json dist/feature_status_source.live-runtime.json",
]

RUNTIME_PENDING_RE = re.compile(
    r"\bruntime\b.*\bpending\b"
    r"|\bpending\b.*\bruntime\b"
    r"|Remaining proof gap:"
    r"|Runtime proof gap:"
    r"|live visual"
    r"|app runtime"
    r"|Signed-app boundary evidence",
    re.IGNORECASE,
)


def tracker_rows() -> list[dict[str, Any]]:
    rows = json.loads(SOURCE.read_text())
    if not isinstance(rows, list):
        raise SystemExit(f"{SOURCE} must contain a JSON list")
    return rows


def is_runtime_pending_row(row: dict[str, Any]) -> bool:
    row_id = str(row.get("ID", ""))
    if row_id == "QA-001" or row_id in LIVE_RUNTIME_BLOCKED_IDS:
        return False
    retest_status = str(row.get("Retest status", ""))
    if f"Passed signed-app runtime sweep for {row_id} " in retest_status:
        return False
    evidence_text = " ".join(
        str(row.get(header, ""))
        for header in ("Test evidence", "Retest status", "Notes", "Fix status", "Errors documented")
    )
    return bool(RUNTIME_PENDING_RE.search(evidence_text))


def runtime_pending_rows(rows: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    source_rows = rows if rows is not None else tracker_rows()
    return [row for row in source_rows if is_runtime_pending_row(row)]


def runtime_pending_ids(rows: list[dict[str, Any]] | None = None) -> list[str]:
    return [str(row.get("ID", "")) for row in runtime_pending_rows(rows)]


def runtime_test_instructions(row: dict[str, Any]) -> str:
    """Return stable per-row instructions for the signed-app runtime sweep."""

    return (
        f"Launch the signed stable app and exercise {row.get('Surface', '')} / {row.get('Feature', '')}. "
        f"Scenario: {row.get('User story', '')} "
        f"Verify: {row.get('Expected behaviour', '')} "
        f"Runtime proof needed: {runtime_proof_focus(row)}"
    )


def contains_runtime_api_term(searchable: str) -> bool:
    return bool(re.search(r"\b(?:rest|mcp|https?)\b", searchable))


def runtime_proof_focus(row: dict[str, Any]) -> str:
    """Classify the missing signed-app proof so blockers are row-specific."""

    row_id = str(row.get("ID", ""))
    surface = str(row.get("Surface", ""))
    feature = str(row.get("Feature", ""))
    expected = str(row.get("Expected behaviour", ""))
    searchable = f"{surface} {feature} {expected}".lower()

    focus: list[str] = []
    if row_id.startswith("UI-") or surface in {"Menu bar", "Settings", "Signing UI", "Audit UI", "Diagnostics"}:
        focus.append("native signed-app UI automation visual/click observation")
    if row_id.startswith("CLI-") or re.search(r"\bcli\b", searchable) or "command" in searchable:
        focus.append("bundled CLI command output from the signed app")
    if row_id.startswith("API-") or contains_runtime_api_term(searchable):
        focus.append("authenticated REST/MCP runtime response")
    if "notification" in searchable:
        focus.append("macOS notification authorization, delivery, and XPC route diagnostics")
    if "pair" in searchable or "profile" in searchable or "client" in searchable:
        focus.append("paired-client profile setup and success-path read/sign behavior")
    if "auth" in searchable or "approve" in searchable or "owner" in searchable or "biometric" in searchable:
        focus.append("owner approval/authentication runtime behavior")
    if "rpc" in searchable or "provider" in searchable or "zerodev" in searchable or "chain" in searchable or "network" in searchable:
        focus.append("configured provider/RPC/network runtime behavior")
    if "keychain" in searchable or "secure enclave" in searchable or "session" in searchable:
        focus.append("persistence across Keychain/Secure Enclave/session state")
    if "rebuild" in searchable or "symlink" in searchable or surface in {"App lifecycle", "Service lifecycle", "Install/runtime"}:
        focus.append("freshly rebuilt signed app/service lifecycle state")

    deduped = list(dict.fromkeys(focus))
    if not deduped:
        deduped.append("row-specific signed-app runtime observation")
    return "; ".join(deduped)


def runtime_evidence_template(rows: list[dict[str, Any]] | None = None) -> list[dict[str, str]]:
    return [
        {
            "ID": str(row.get("ID", "")),
            "Surface": str(row.get("Surface", "")),
            "Feature": str(row.get("Feature", "")),
            "User story": str(row.get("User story", "")),
            "Expected behaviour": str(row.get("Expected behaviour", "")),
            "Test instructions": runtime_test_instructions(row),
            "Result": "",
            "Evidence": "",
            "Errors": "",
        }
        for row in runtime_pending_rows(rows)
    ]


def live_runtime_rows(rows: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    source_rows = rows if rows is not None else tracker_rows()
    rows_by_id = {str(row.get("ID", "")): row for row in source_rows}
    missing = sorted(LIVE_RUNTIME_BLOCKED_IDS - set(rows_by_id))
    if missing:
        raise SystemExit("missing live-runtime blocked rows: " + ", ".join(missing))
    return [rows_by_id[row_id] for row_id in sorted(LIVE_RUNTIME_BLOCKED_IDS)]


def live_runtime_test_instructions(row: dict[str, Any]) -> str:
    commands = "; ".join(LIVE_RUNTIME_PHASE_COMMANDS)
    return (
        f"Install a signed stable app, run: {commands}. "
        f"Verify for {row.get('ID', '')} / {row.get('Feature', '')}: {row.get('Expected behaviour', '')}"
    )


def live_runtime_evidence_template(rows: list[dict[str, Any]] | None = None) -> list[dict[str, str]]:
    return [
        {
            "ID": str(row.get("ID", "")),
            "Surface": str(row.get("Surface", "")),
            "Feature": str(row.get("Feature", "")),
            "User story": str(row.get("User story", "")),
            "Expected behaviour": str(row.get("Expected behaviour", "")),
            "Test instructions": live_runtime_test_instructions(row),
            "Result": "",
            "Evidence": "",
            "Errors": "",
        }
        for row in live_runtime_rows(rows)
    ]


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ids", action="store_true", help="print runtime-pending row IDs")
    parser.add_argument("--count", action="store_true", help="print runtime-pending row count")
    parser.add_argument("--template", action="store_true", help="print runtime evidence template JSON")
    parser.add_argument("--live-ids", action="store_true", help="print live-runtime blocked row IDs")
    parser.add_argument("--live-count", action="store_true", help="print live-runtime blocked row count")
    parser.add_argument("--live-template", action="store_true", help="print live-runtime evidence template JSON")
    args = parser.parse_args()

    rows = tracker_rows()
    if args.count:
        print(len(runtime_pending_rows(rows)))
    elif args.template:
        print(json.dumps(runtime_evidence_template(rows), indent=2))
    elif args.live_count:
        print(len(live_runtime_rows(rows)))
    elif args.live_template:
        print(json.dumps(live_runtime_evidence_template(rows), indent=2))
    elif args.live_ids:
        print(" ".join(row["ID"] for row in live_runtime_rows(rows)))
    else:
        print(" ".join(runtime_pending_ids(rows)))


if __name__ == "__main__":
    main()
