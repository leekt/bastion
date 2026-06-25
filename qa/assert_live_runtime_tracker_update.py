#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 4:
        raise SystemExit("usage: assert_live_runtime_tracker_update.py <update-json> <expected-count> <evidence-json>")

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
        raise SystemExit(f"unexpected live-runtime tracker update row count {len(updates)}")

    for index, row in enumerate(updates, start=1):
        if set(row) != expected_keys:
            raise SystemExit(f"live-runtime tracker update row {index} has non-canonical keys: {sorted(row)}")

    by_id = {row["ID"]: row for row in updates}
    evidence_by_id = {row["ID"]: row for row in evidence}
    first = by_id["CORE-003"]
    if first["Result"] != "blocked" or first["Test status"] != "Blocked in this environment":
        raise SystemExit("blocked live-runtime row must remain environment-blocked in tracker update")
    if "CORE-003" not in first["Errors documented"] or "Secure Enclave signing and auth flow" not in first["Errors documented"]:
        raise SystemExit("blocked live-runtime row must carry row-specific Errors documented text")
    if "Blocked pending live-runtime prerequisite for CORE-003 Secure Enclave signing and auth flow." != first["Fix status"]:
        raise SystemExit("blocked live-runtime row must carry row-specific Fix status")
    first_evidence = evidence_by_id["CORE-003"]["Evidence"]
    if first_evidence not in first["Retest status"]:
        raise SystemExit("blocked live-runtime row must carry exact Evidence text into Retest status")
    if "Artifact:" not in first["Retest status"]:
        raise SystemExit("blocked live-runtime row Retest status must preserve Artifact citation")

    passed = by_id["CORE-005"]
    if passed["Result"] != "pass" or passed["Test status"] != "Blocked in this environment":
        raise SystemExit("passed live-runtime row must remain prerequisite-blocked in tracker update while runtime prerequisites are blocked")
    if "Live-runtime prerequisite blocker for CORE-005 Keychain config/state/session storage" not in passed["Errors documented"]:
        raise SystemExit("passed live-runtime row must record the final prerequisite blocker")
    expected_fix = "Blocked pending current-source signed-app live-runtime prerequisite for CORE-005 Keychain config/state/session storage."
    if expected_fix != passed["Fix status"]:
        raise SystemExit("passed live-runtime row must carry row-specific current-source Fix status")
    expected_retest = "Blocked pending current-source signed-app live-runtime retest for CORE-005 Keychain config/state/session storage."
    if expected_retest not in passed["Retest status"]:
        raise SystemExit("passed live-runtime row must require current-source signed-app live-runtime retest")
    passed_evidence = evidence_by_id["CORE-005"]["Evidence"]
    if passed_evidence not in passed["Retest status"]:
        raise SystemExit("passed live-runtime row must carry exact Evidence text into Retest status")
    if "Artifact:" not in passed["Retest status"]:
        raise SystemExit("passed live-runtime row Retest status must preserve Artifact citation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
