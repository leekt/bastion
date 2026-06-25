#!/usr/bin/env python3
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))

from app_runtime_rows import runtime_pending_ids, tracker_rows


def main() -> int:
    rows = tracker_rows()
    fixture = dict(rows[0])
    fixture.update(
        {
            "ID": "UI-999",
            "Test evidence": "Deterministic fixture evidence only.",
            "Retest status": "Deterministic fixture retest only.",
            "Fix status": "No code change needed.",
            "Notes": "",
            "Errors documented": "Runtime pending from error documentation only.",
        }
    )
    if "UI-999" not in runtime_pending_ids(rows + [fixture]):
        raise SystemExit("app-runtime derivation must include runtime blockers from Errors documented")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
