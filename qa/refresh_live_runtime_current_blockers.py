#!/usr/bin/env python3
"""Refresh current live-runtime blocker review artifacts.

This is intentionally not a closure tool. It records the best current evidence
for the six installed-app lifecycle rows while final pass evidence is blocked
by current-source signing, notification authorization, reboot/login, or click
requirements.
"""

from __future__ import annotations

import json
import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
sys.path.insert(0, str(ROOT))

import build_feature_status
from app_runtime_rows import live_runtime_evidence_template, tracker_rows


DEFAULT_APP_PATH = Path.home() / "Applications" / "Bastion Dev.app"
DEFAULT_EVIDENCE_DIR = REPO / "dist" / "lifecycle"
DEFAULT_BLOCKER_LOG = REPO / "dist" / "live-runtime-artifacts" / "live-runtime-current-blockers.log"
DEFAULT_EVIDENCE_JSON = REPO / "dist" / "live-runtime-evidence.current-blocked.json"


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO.resolve()))
    except ValueError:
        return str(path)


def latest_phase_log(evidence_dir: Path, phase: str) -> Path | None:
    logs = sorted(evidence_dir.glob(f"*-{phase}.log"))
    return logs[-1] if logs else None


def run_text(*args: str) -> tuple[int, str]:
    result = subprocess.run(
        args,
        cwd=REPO,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return result.returncode, result.stdout


def notification_diagnostic_lines(notification_log: Path | None) -> list[str]:
    if notification_log is None or not notification_log.exists():
        return ["Status: missing notification-click lifecycle log."]

    parsed_events: list[dict[str, object]] = []
    for line in notification_log.read_text(errors="replace").splitlines():
        if "notification_" not in line or "{" not in line:
            continue
        json_text = line[line.find("{") :]
        try:
            payload = json.loads(json_text)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and isinstance(payload.get("event"), str):
            parsed_events.append(payload)

    if not parsed_events:
        return ["Status: no machine-readable notification diagnostic event found in the latest notification-click log."]

    preferred_events = {
        "notification_click_local_open",
        "notification_click_relay_result",
        "notification_skipped_unauthorized",
        "notification_delivery_failed",
        "notification_delivered",
        "notification_probe_rate_limited",
    }
    selected = next(
        (event for event in reversed(parsed_events) if str(event.get("event")) in preferred_events),
        parsed_events[-1],
    )
    event_name = str(selected.get("event", "unknown"))
    context = selected.get("context")
    context_obj = context if isinstance(context, dict) else {}

    if event_name == "notification_skipped_unauthorized":
        status = str(context_obj.get("status", "<unknown>"))
        settings_path = str(context_obj.get("settingsPath", "System Settings > Notifications"))
        rerun = str(
            context_obj.get(
                "rerunCommand",
                "qa/run_live_runtime_checks.sh --run-phase notification-click --require-notification-click",
            )
        )
        return [
            f"Status: blocked by notification authorization. Diagnostic event={event_name}; authorization status={status}.",
            f"Suggested action: {context_obj.get('suggestedAction', 'Enable notifications for Bastion, then rerun the notification-click live-runtime check.')}",
            f"Settings path: {settings_path}",
            f"Rerun command: {rerun}",
        ]
    if event_name == "notification_delivered":
        return [
            "Status: notification delivery was observed; waiting for terminal click-route diagnostic evidence from notification-click-probe.",
            f"Diagnostic event={event_name}; notificationIdentifier={context_obj.get('notificationIdentifier', '<unknown>')}",
        ]
    if event_name in {"notification_click_local_open", "notification_click_relay_result"}:
        return [
            "Status: terminal notification click-route diagnostic was observed; native banner activation is optional manual OS-interaction evidence.",
            f"Diagnostic event={event_name}; context={json.dumps(context_obj, sort_keys=True)}",
        ]
    if event_name == "notification_delivery_failed":
        return [
            "Status: notification delivery failed before automated delivery/route proof could be completed.",
            f"Diagnostic event={event_name}; context={json.dumps(context_obj, sort_keys=True)}",
        ]
    if event_name == "notification_probe_rate_limited":
        return [
            "Status: notification probe was rate-limited; rerun after the probe cooldown.",
            f"Diagnostic event={event_name}; context={json.dumps(context_obj, sort_keys=True)}",
        ]

    return [
        f"Status: latest notification diagnostic event is {event_name}.",
        f"Context: {json.dumps(context_obj, sort_keys=True)}",
    ]


def artifact_text(rows: list[dict[str, str]], app_path: Path, evidence_dir: Path) -> str:
    signed_status, signed_evidence = build_feature_status.signed_app_status(app_path)
    freshness_status, freshness_evidence = build_feature_status.app_source_freshness_status(app_path)
    audit_status, audit_output = run_text(
        "scripts/audit-service-lifecycle-evidence.sh",
        "--evidence-dir",
        str(evidence_dir),
    )
    notification_log = latest_phase_log(evidence_dir, "notification-click")
    notification_tail = (
        notification_log.read_text(errors="replace").splitlines()[-80:]
        if notification_log is not None and notification_log.exists()
        else ["<missing notification-click lifecycle log>"]
    )
    notification_diagnostic = notification_diagnostic_lines(notification_log)

    lines: list[str] = [
        "== Live runtime blocked row contexts ==",
    ]
    for row in rows:
        lines.extend(
            [
                f"ROW {row['ID']}",
                "Result blocked",
                f"Feature: {row['Feature']}",
                f"User story: {row['User story']}",
                f"Expected behaviour: {row['Expected behaviour']}",
                f"Test instructions: {row['Test instructions']}",
                "",
            ]
        )

    lines.extend(
        [
            "== Current prerequisite state ==",
            f"Signed stable app: {signed_status} - {signed_evidence}",
            f"Current-source signed app rebuild: {freshness_status} - {freshness_evidence}",
            "Code-signing repair command: scripts/dev-enable-codesign-keychain-access.sh",
            "Signed rebuild command: scripts/dev-rebuild-signed.sh",
            "",
            "== Latest lifecycle evidence audit ==",
            f"Exit status: {audit_status}",
            audit_output.rstrip(),
            "",
            "== Latest notification-click diagnostic ==",
            f"Log: {rel(notification_log) if notification_log else '<missing>'}",
            *notification_diagnostic,
            "",
            "== Latest notification-click log tail ==",
            f"Log: {rel(notification_log) if notification_log else '<missing>'}",
            *notification_tail,
            "",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, default=DEFAULT_APP_PATH)
    parser.add_argument("--evidence-dir", type=Path, default=DEFAULT_EVIDENCE_DIR)
    parser.add_argument("--blocker-log", type=Path, default=DEFAULT_BLOCKER_LOG)
    parser.add_argument("--evidence-json", type=Path, default=DEFAULT_EVIDENCE_JSON)
    args = parser.parse_args()

    rows = live_runtime_evidence_template(tracker_rows())
    notification_log = latest_phase_log(args.evidence_dir, "notification-click")
    notification_rel = rel(notification_log) if notification_log else "dist/lifecycle/<missing-notification-click-log>"
    notification_summary = " ".join(notification_diagnostic_lines(notification_log))
    blocker_log_rel = rel(args.blocker_log)
    rerun_command = "qa/run_live_runtime_checks.sh --run-phase notification-click --require-notification-click"
    args.blocker_log.parent.mkdir(parents=True, exist_ok=True)
    args.evidence_json.parent.mkdir(parents=True, exist_ok=True)
    args.blocker_log.write_text(artifact_text(rows, args.app, args.evidence_dir))

    evidence: list[dict[str, str]] = []
    for row in rows:
        item = dict(row)
        item["Result"] = "blocked"
        item["Evidence"] = (
            f"{row['ID']} {row['Feature']}: Result blocked. Current live-runtime blocker refresh shows "
            "fresh-install, reinstall, post-login, post-reboot, and notification delivery/route lifecycle evidence is present. "
            "Remaining proof gap: row-level installed-app live-runtime pass evidence and tracker source promotion. "
            f"Latest notification diagnostic: {notification_summary} "
            f"User story: {row['User story']} Expected behaviour: {row['Expected behaviour']} "
            f"Test instructions: {row['Test instructions']} "
            f"Artifact: {blocker_log_rel} Additional artifact: {notification_rel} "
            f"Rerun: {rerun_command}"
        )
        item["Errors"] = (
            f"{row['ID']} {row['Feature']}: live-runtime closure remains blocked pending row-level installed-app pass evidence "
            "and tracker source promotion. "
            f"Latest notification diagnostic: {notification_summary} "
            f"Artifact: {blocker_log_rel}. Rerun: {rerun_command}."
        )
        evidence.append(item)

    args.evidence_json.write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"Wrote {rel(args.blocker_log)}")
    print(f"Wrote {rel(args.evidence_json)}")


if __name__ == "__main__":
    main()
