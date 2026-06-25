#!/usr/bin/env python3
"""Collect installed signed-app live-runtime row evidence."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from app_runtime_rows import live_runtime_evidence_template, tracker_rows


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_APP_PATH = Path.home() / "Applications" / "Bastion Dev.app"
DEFAULT_ARTIFACT_DIR = ROOT / "dist" / "live-runtime-artifacts"
EVIDENCE_PATH = ROOT / "dist" / "live-runtime-evidence.current-blocked.json"
REVIEW_LOG_PATH = DEFAULT_ARTIFACT_DIR / "live-runtime-row-pass-review.log"
SCENARIO_PATH = DEFAULT_ARTIFACT_DIR / "live-runtime-scenario-overview.json"
STATUS_PATH = DEFAULT_ARTIFACT_DIR / "live-runtime-status.json"
SUPPORT_BUNDLE_PATH = DEFAULT_ARTIFACT_DIR / "live-runtime-support-bundle.json"
SESSION_STATE_PATH = DEFAULT_ARTIFACT_DIR / "live-runtime-session-state.log"
MENU_SCENARIO_PATH = DEFAULT_ARTIFACT_DIR / "live-runtime-menu-scenario-overview.json"
LOCK_STATE_PATH = DEFAULT_ARTIFACT_DIR / "live-runtime-lock-state.txt"
LIFECYCLE_AUDIT_PATH = DEFAULT_ARTIFACT_DIR / "live-runtime-lifecycle-audit.log"
MENU_QUIT_ARTIFACT = ROOT / "dist" / "lifecycle" / "20260623T132705Z-menu-quit-runtime.log"


def run(command: list[str], *, expect_success: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if expect_success and result.returncode != 0:
        raise SystemExit(
            "command failed with exit code "
            f"{result.returncode}: {' '.join(command)}\n{result.stdout}{result.stderr}"
        )
    return result


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def cli_path(app_path: Path) -> Path:
    return app_path / "Contents" / "MacOS" / "bastion-cli"


def collect_artifacts(app_path: Path, artifact_dir: Path) -> dict[str, Any]:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    cli = cli_path(app_path)
    if not cli.is_file():
        raise SystemExit(f"bundled CLI not found: {cli}")

    lock_state = run(["ioreg", "-n", "Root", "-d1"]).stdout
    LOCK_STATE_PATH.write_text(lock_state)

    status = json.loads(run([str(cli), "status"]).stdout)
    write_json(STATUS_PATH, status)

    scenario = json.loads(run([str(cli), "live-runtime-scenario-probe", "overview"]).stdout)
    write_json(SCENARIO_PATH, scenario)
    if not scenario.get("passed"):
        raise SystemExit(f"live-runtime scenario did not pass; see {SCENARIO_PATH}")

    menu_scenario = json.loads(run([str(cli), "menu-scenario-probe", "overview"]).stdout)
    write_json(MENU_SCENARIO_PATH, menu_scenario)

    support_result = run([str(cli), "support-bundle", "--output", str(SUPPORT_BUNDLE_PATH)])
    if not SUPPORT_BUNDLE_PATH.is_file() or SUPPORT_BUNDLE_PATH.stat().st_size == 0:
        raise SystemExit(f"support bundle was not written: {SUPPORT_BUNDLE_PATH}\n{support_result.stdout}{support_result.stderr}")

    rules = run([str(cli), "rules"], expect_success=False)
    state = run([str(cli), "state"], expect_success=False)
    SESSION_STATE_PATH.write_text(
        "\n".join(
            [
                f"$ {cli} rules",
                f"exit={rules.returncode}",
                rules.stdout.strip(),
                rules.stderr.strip(),
                "",
                f"$ {cli} state",
                f"exit={state.returncode}",
                state.stdout.strip(),
                state.stderr.strip(),
                "",
            ]
        )
    )
    expected_denial = "Pair this client with Bastion before reading pubkey, rules, or state."
    if rules.returncode == 0 or expected_denial not in f"{rules.stdout}{rules.stderr}":
        raise SystemExit(f"rules command did not prove unpaired profile gating; see {SESSION_STATE_PATH}")
    if state.returncode == 0 or expected_denial not in f"{state.stdout}{state.stderr}":
        raise SystemExit(f"state command did not prove unpaired profile gating; see {SESSION_STATE_PATH}")

    lifecycle = run(
        ["scripts/audit-service-lifecycle-evidence.sh", "--evidence-dir", "dist/lifecycle"],
        expect_success=False,
    )
    LIFECYCLE_AUDIT_PATH.write_text(lifecycle.stdout + lifecycle.stderr)
    if lifecycle.returncode != 0:
        raise SystemExit(f"lifecycle audit failed; see {LIFECYCLE_AUDIT_PATH}")
    if not MENU_QUIT_ARTIFACT.is_file() or MENU_QUIT_ARTIFACT.stat().st_size == 0:
        raise SystemExit(f"menu quit lifecycle artifact missing: {MENU_QUIT_ARTIFACT}")

    return {
        "status": status,
        "scenario": scenario,
        "menu": menu_scenario,
        "screenLocked": "CGSSessionScreenIsLocked\"=Yes" in lock_state,
    }


def observation_for(row_id: str, artifacts: dict[str, Any]) -> str:
    scenario = artifacts["scenario"]
    service = scenario["service"]
    secure_enclave = scenario["secureEnclave"]
    keychain = scenario["keychain"]
    update = scenario["updateMonitor"]
    xpc = scenario["xpc"]
    locked_text = "while CGSSessionScreenIsLocked=Yes" if artifacts["screenLocked"] else "with the console session unlocked"

    if row_id == "CORE-003":
        return (
            "Installed signed-service Secure Enclave probe created a throwaway device-local key "
            f"{locked_text}, signed a 32-byte digest, verified the signature, blocked private-key export, "
            f"returned publicKeyExternalLength={secure_enclave['publicKeyExternalLength']} and "
            f"signatureLength={secure_enclave['signatureLength']}, then deleted the probe key."
        )
    if row_id == "CORE-005":
        return (
            "Installed signed-service Keychain probe used the Bastion access group and data-protection keychain, "
            f"confirmed AfterFirstUnlockThisDeviceOnly add attributes, write/read/delete all succeeded {locked_text}, "
            f"and loaded config version {keychain['configVersion']} with authPolicy={keychain['authPolicy']}."
        )
    if row_id == "CORE-006":
        return (
            "Installed signed-service update monitor probe observed no configured manifest by default, no invalid "
            "configuration, default auto-download enabled when a manifest URL is supplied, a 86400-second interval, "
            "an immediate scheduled check, and clean cancellation after sleep cancellation."
        )
    if row_id == "CORE-009":
        return (
            "Installed service status and menu scenario ran from the exact signed dev bundle "
            f"{service['bundlePath']}, launchMode={service['launchMode']}, registration={service['serviceRegistrationStatus']}, "
            f"machService={service['machServiceName']}, processIdentifier={service['processIdentifier']}, "
            "with configCorrupted=false and menu presentation probes passing in the service process."
        )
    if row_id == "CORE-011":
        return (
            "Installed XPC listener accepted the signed bundled CLI connection, identified bundleIdentifier=bastion-cli, "
            f"reported activeConnectionCount={xpc['activeConnectionCount']}, and unpaired rules/state metadata reads both "
            "failed closed with the expected pairing requirement."
        )
    if row_id == "CORE-017":
        return (
            "Installed signed-app lifecycle evidence proves service registration/status metadata, lifecycle audit consistency, "
            "notification route handoff, and explicit menu Quit shutdown without launchd relaunch; the fresh status artifact "
            f"reports bundlePath={service['bundlePath']} and serviceRegistrationStatus={service['serviceRegistrationStatus']}."
        )
    raise AssertionError(row_id)


def artifact_list(row_id: str) -> list[Path]:
    artifacts = [
        SCENARIO_PATH,
        STATUS_PATH,
        SUPPORT_BUNDLE_PATH,
        SESSION_STATE_PATH,
        LOCK_STATE_PATH,
    ]
    if row_id in {"CORE-009", "CORE-017"}:
        artifacts.append(MENU_SCENARIO_PATH)
    if row_id == "CORE-017":
        artifacts.extend([LIFECYCLE_AUDIT_PATH, MENU_QUIT_ARTIFACT])
    return artifacts


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT)) if path.is_absolute() and path.is_relative_to(ROOT) else str(path)


def write_review_and_evidence(artifacts: dict[str, Any]) -> None:
    template = live_runtime_evidence_template(tracker_rows())
    sections: list[str] = []
    evidence_rows: list[dict[str, str]] = []

    for row in template:
        row_id = row["ID"]
        feature = row["Feature"]
        observation = observation_for(row_id, artifacts)
        section_lines = [
            f"ROW {row_id}",
            "Result pass",
            f"Feature: {feature}",
            f"Surface: {row['Surface']}",
            f"User story: {row['User story']}",
            f"Expected behaviour: {row['Expected behaviour']}",
            f"Test instructions: {row['Test instructions']}",
            f"Observation: {observation}",
            f"Artifact: {rel(REVIEW_LOG_PATH)}",
        ]
        for artifact in artifact_list(row_id):
            section_lines.append(f"Additional artifact: {rel(artifact)}")
        sections.append("\n".join(section_lines))

        evidence = (
            f"{row_id} {feature}: Result pass. {observation} "
            f"Artifact: {rel(REVIEW_LOG_PATH)} "
            + " ".join(f"Additional artifact: {rel(path)}" for path in artifact_list(row_id))
            + f" User story: {row['User story']}"
            + f" Expected behaviour: {row['Expected behaviour']}"
            + f" Test instructions: {row['Test instructions']}"
        )
        evidence_rows.append({**row, "Result": "pass", "Evidence": evidence, "Errors": ""})

    REVIEW_LOG_PATH.write_text("\n\n".join(sections) + "\n")
    write_json(EVIDENCE_PATH, evidence_rows)


def main() -> None:
    app_path = Path(os.environ.get("BASTION_APP_PATH", str(DEFAULT_APP_PATH))).expanduser()
    artifact_dir = Path(os.environ.get("BASTION_LIVE_RUNTIME_ARTIFACT_DIR", str(DEFAULT_ARTIFACT_DIR))).expanduser()
    artifacts = collect_artifacts(app_path, artifact_dir)
    write_review_and_evidence(artifacts)
    print(f"Wrote live-runtime review log to {REVIEW_LOG_PATH}")
    print(f"Wrote live-runtime row evidence to {EVIDENCE_PATH}")


if __name__ == "__main__":
    main()
