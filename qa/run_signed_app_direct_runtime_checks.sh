#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

APP_PATH="${BASTION_APP_PATH:-${HOME}/Applications/Bastion Dev.app}"
OUTPUT_DIR="dist/app-runtime-artifacts/direct-runtime"
EVIDENCE_PATH="dist/app-runtime-evidence.current.json"
SUPPORT_BUNDLE_PATH="dist/app-runtime-artifacts/current-ui/support-bundle.json"
UPDATE_EVIDENCE=1
RUN_NOTIFICATION_PROBE=1
WAIT_FOR_PAIR_APPROVAL=0
PAIR_APPROVAL_TIMEOUT=8

usage() {
  cat <<'USAGE'
Usage:
  qa/run_signed_app_direct_runtime_checks.sh [options]

Options:
  --app <app-bundle>               Signed app bundle to exercise.
                                   Default: ~/Applications/Bastion Dev.app
  --output-dir <dir>               Artifact directory.
                                   Default: dist/app-runtime-artifacts/direct-runtime
  --evidence <json>                App-runtime evidence JSON to refresh.
                                   Default: dist/app-runtime-evidence.current.json
  --support-bundle <json>          Support bundle artifact path.
                                   Default: dist/app-runtime-artifacts/current-ui/support-bundle.json
  --wait-for-pair-approval         Keep the pairing CLI alive so the owner can
                                   click Accept in the menu-bar prompt. When
                                   accepted, paired-client read checks run
                                   afterward and can turn CLI-005/CLI-007 green.
  --pair-approval-timeout <sec>    Seconds to wait for owner approval.
                                   Default: 8 without --wait-for-pair-approval;
                                   use 60-300 for manual acceptance runs.
  --skip-evidence-update           Collect artifacts without editing evidence JSON.
  --skip-notification-probe        Avoid notification probe rate-limit side effects.
  -h, --help                       Show this help.

Purpose:
  Refresh the signed-app runtime evidence that can be observed from a shell:
  bundled CLI reads, REST/MCP wrapper behavior, XPC UI probes,
  diagnostics support export, notification probe diagnostics, and CLI symlink
  diagnostics. This script writes review artifacts only; it never writes
  qa/feature_status_source.json.
USAGE
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --app)
      shift
      [[ "$#" -gt 0 ]] || { echo "--app requires a path" >&2; exit 2; }
      APP_PATH="$1"
      ;;
    --output-dir)
      shift
      [[ "$#" -gt 0 ]] || { echo "--output-dir requires a path" >&2; exit 2; }
      OUTPUT_DIR="$1"
      ;;
    --evidence)
      shift
      [[ "$#" -gt 0 ]] || { echo "--evidence requires a path" >&2; exit 2; }
      EVIDENCE_PATH="$1"
      ;;
    --support-bundle)
      shift
      [[ "$#" -gt 0 ]] || { echo "--support-bundle requires a path" >&2; exit 2; }
      SUPPORT_BUNDLE_PATH="$1"
      ;;
    --wait-for-pair-approval)
      WAIT_FOR_PAIR_APPROVAL=1
      if [[ "$PAIR_APPROVAL_TIMEOUT" -lt 60 ]]; then
        PAIR_APPROVAL_TIMEOUT=120
      fi
      ;;
    --pair-approval-timeout)
      shift
      [[ "$#" -gt 0 ]] || { echo "--pair-approval-timeout requires seconds" >&2; exit 2; }
      [[ "$1" =~ ^[0-9]+$ ]] || { echo "--pair-approval-timeout must be an integer number of seconds" >&2; exit 2; }
      PAIR_APPROVAL_TIMEOUT="$1"
      ;;
    --skip-evidence-update)
      UPDATE_EVIDENCE=0
      ;;
    --skip-notification-probe)
      RUN_NOTIFICATION_PROBE=0
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

APP_BIN="${APP_PATH}/Contents/MacOS/bastion"
CLI_BIN="${APP_PATH}/Contents/MacOS/bastion-cli"
SUMMARY_PATH="${OUTPUT_DIR}/current-direct-runtime-summary.log"
DIAGNOSTICS_LOG="${HOME}/Library/Application Support/Bastion/diagnostics.jsonl"
TOKEN="VNSq8yXf9L2mR7pT4cK6zJ1bH5wD3eQ0uA8sG9nP2vC7xY4rM6tZ1kL5hF3dB0qW"

mkdir -p "$OUTPUT_DIR" "$(dirname "$SUPPORT_BUNDLE_PATH")"

if [[ ! -d "$APP_PATH" ]]; then
  echo "Signed app bundle not found: $APP_PATH" >&2
  exit 1
fi
if [[ ! -x "$APP_BIN" ]]; then
  echo "Signed app executable missing or not executable: $APP_BIN" >&2
  exit 1
fi
if [[ ! -x "$CLI_BIN" ]]; then
  echo "Bundled CLI missing or not executable: $CLI_BIN" >&2
  exit 1
fi
if [[ "$UPDATE_EVIDENCE" -eq 1 && ! -f "$EVIDENCE_PATH" ]]; then
  echo "Evidence JSON not found: $EVIDENCE_PATH" >&2
  exit 1
fi

/usr/bin/codesign --verify --deep --strict --verbose=2 "$APP_PATH" >/dev/null
CLI_CODE_ID="$(/usr/bin/codesign -dv "$CLI_BIN" 2>&1 | /usr/bin/sed -n 's/^Identifier=//p')"
if [[ -z "$CLI_CODE_ID" ]]; then
  CLI_CODE_ID="bastion-cli"
fi

capture_allow_failure() {
  local output="$1"
  shift
  set +e
  "$@" >"$output" 2>&1
  local status=$?
  set -e
  printf '%s\n' "$status" >"${output}.status"
}

"$CLI_BIN" status >"${OUTPUT_DIR}/cli-status.json"
python3 - "$APP_PATH" "${OUTPUT_DIR}/cli-status.json" <<'PY'
import json
import sys
from pathlib import Path

expected = Path(sys.argv[1]).resolve()
status_path = Path(sys.argv[2])
status = json.loads(status_path.read_text())
actual_value = status.get("bundlePath")
if not actual_value:
    raise SystemExit("cli status did not report bundlePath")
actual = Path(actual_value).resolve()
if actual != expected:
    raise SystemExit(f"Live service is running from {actual}, expected {expected}")
PY
python3 - "$CLI_BIN" "$CLI_CODE_ID" "${OUTPUT_DIR}/cli-pair.out" "$WAIT_FOR_PAIR_APPROVAL" "$PAIR_APPROVAL_TIMEOUT" <<'PY'
import os
import pty
import select
import signal
import subprocess
import sys
import time
from pathlib import Path

cli_bin, cli_code_id, output_path, wait_for_approval, timeout = sys.argv[1:6]
output = Path(output_path)
wait_for_approval = wait_for_approval == "1"
timeout_seconds = max(1, int(timeout))
master_fd, slave_fd = pty.openpty()
process = subprocess.Popen(
    [cli_bin, "pair", "--bundle-id", cli_code_id, "--label", "Runtime CLI"],
    stdin=slave_fd,
    stdout=slave_fd,
    stderr=slave_fd,
    close_fds=True,
)
os.close(slave_fd)
captured = bytearray()
deadline = time.time() + timeout_seconds
try:
    while time.time() < deadline and process.poll() is None:
        readable, _, _ = select.select([master_fd], [], [], 0.2)
        if master_fd not in readable:
            continue
        try:
            chunk = os.read(master_fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        captured.extend(chunk)
        if not wait_for_approval and b"Waiting for owner approval" in captured:
            break
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
finally:
    os.close(master_fd)

text = captured.decode(errors="replace")
output.write_text(text)
Path(str(output) + ".status").write_text(str(process.returncode if process.returncode is not None else -999) + "\n")
PY
capture_allow_failure "${OUTPUT_DIR}/cli-pubkey.out" "$CLI_BIN" pubkey
capture_allow_failure "${OUTPUT_DIR}/cli-rules.out" "$CLI_BIN" rules
capture_allow_failure "${OUTPUT_DIR}/cli-state.out" "$CLI_BIN" state
capture_allow_failure "${OUTPUT_DIR}/cli-sign-raw.out" "$CLI_BIN" sign --data 0x0000000000000000000000000000000000000000000000000000000000000000
capture_allow_failure "${OUTPUT_DIR}/cli-eth-message.out" "$CLI_BIN" eth message "hello from runtime smoke"
capture_allow_failure "${OUTPUT_DIR}/cli-eth-typeddata.out" "$CLI_BIN" eth typedData --json '{"types":{"EIP712Domain":[{"name":"name","type":"string"}],"Mail":[{"name":"contents","type":"string"}]},"primaryType":"Mail","domain":{"name":"Bastion"},"message":{"contents":"hello"}}'
capture_allow_failure "${OUTPUT_DIR}/cli-eth-userop.out" "$CLI_BIN" eth userOp --op 0x0000000000000000000000000000000000000001,0,0x
capture_allow_failure "${OUTPUT_DIR}/cli-groups-list.out" "$CLI_BIN" groups list

run_ui_probe_json() {
  local target="$1"
  local output="$2"
  local tmp="${output}.tmp"
  local err="${output}.err"

  rm -f "$tmp" "$err"
  for _ in 1 2 3; do
    if "$CLI_BIN" ui-probe "$target" >"$tmp" 2>"$err" && [[ -s "$tmp" ]]; then
      mv "$tmp" "$output"
      rm -f "$err"
      return 0
    fi
    /bin/sleep 2
  done

  {
    echo "ui-probe ${target} did not produce non-empty JSON after retries"
    if [[ -s "$err" ]]; then
      cat "$err"
    fi
  } >&2
  rm -f "$tmp" "$err"
  return 1
}

write_open_ui_from_probe() {
  local target="$1"
  local probe="$2"
  local output="$3"
  python3 - "$target" "$probe" >"$output" <<'PY'
import json
import sys
from pathlib import Path

target, probe_path = sys.argv[1:3]
probe = json.loads(Path(probe_path).read_text())
print(json.dumps({"target": target, "opened": bool(probe.get("opened"))}, indent=2, sort_keys=True))
PY
}

run_ui_probe_json settings "${OUTPUT_DIR}/ui-probe-settings.json"
write_open_ui_from_probe settings "${OUTPUT_DIR}/ui-probe-settings.json" "${OUTPUT_DIR}/open-ui-settings.json"
run_ui_probe_json approvalPolicy "${OUTPUT_DIR}/ui-probe-approvalPolicy.json"
run_ui_probe_json approvalViolation "${OUTPUT_DIR}/ui-probe-approvalViolation.json"
capture_allow_failure "${OUTPUT_DIR}/menu-scenario-overview.json" "$CLI_BIN" menu-scenario-probe overview
capture_allow_failure "${OUTPUT_DIR}/wallet-group-scenario-overview.json" "$CLI_BIN" wallet-group-scenario-probe overview
capture_allow_failure "${OUTPUT_DIR}/audit-history-scenario-overview.json" "$CLI_BIN" audit-history-scenario-probe overview
capture_allow_failure "${OUTPUT_DIR}/runtime-state-scenario-overview.json" "$CLI_BIN" runtime-state-scenario-probe overview
capture_allow_failure "${OUTPUT_DIR}/update-scenario-overview.json" "$CLI_BIN" update-scenario-probe overview
capture_allow_failure "${OUTPUT_DIR}/key-lifecycle-scenario-overview.json" "$CLI_BIN" key-lifecycle-scenario-probe overview
capture_allow_failure "${OUTPUT_DIR}/settings-scenario-saveDiff.json" "$CLI_BIN" settings-scenario-probe saveDiff
capture_allow_failure "${OUTPUT_DIR}/settings-scenario-postureControls.json" "$CLI_BIN" settings-scenario-probe postureControls
capture_allow_failure "${OUTPUT_DIR}/settings-scenario-authPolicy.json" "$CLI_BIN" settings-scenario-probe authPolicy
capture_allow_failure "${OUTPUT_DIR}/settings-scenario-projectId.json" "$CLI_BIN" settings-scenario-probe projectId
capture_allow_failure "${OUTPUT_DIR}/settings-scenario-rpcChain.json" "$CLI_BIN" settings-scenario-probe rpcChain
capture_allow_failure "${OUTPUT_DIR}/settings-scenario-rpcProbe.json" "$CLI_BIN" settings-scenario-probe rpcProbe
capture_allow_failure "${OUTPUT_DIR}/settings-scenario-ruleTemplates.json" "$CLI_BIN" settings-scenario-probe ruleTemplates
capture_allow_failure "${OUTPUT_DIR}/settings-scenario-targetAdd.json" "$CLI_BIN" settings-scenario-probe targetAdd
capture_allow_failure "${OUTPUT_DIR}/settings-scenario-targetRemove.json" "$CLI_BIN" settings-scenario-probe targetRemove
capture_allow_failure "${OUTPUT_DIR}/settings-scenario-globalCaps.json" "$CLI_BIN" settings-scenario-probe globalCaps
capture_allow_failure "${OUTPUT_DIR}/settings-scenario-addressBook.json" "$CLI_BIN" settings-scenario-probe addressBook
capture_allow_failure "${OUTPUT_DIR}/settings-scenario-highValue.json" "$CLI_BIN" settings-scenario-probe highValue
capture_allow_failure "${OUTPUT_DIR}/settings-scenario-policyHistory.json" "$CLI_BIN" settings-scenario-probe policyHistory
capture_allow_failure "${OUTPUT_DIR}/settings-scenario-policySimulator.json" "$CLI_BIN" settings-scenario-probe policySimulator
/bin/sleep 1
run_ui_probe_json diagnostics "${OUTPUT_DIR}/ui-probe-diagnostics.json"
write_open_ui_from_probe diagnostics "${OUTPUT_DIR}/ui-probe-diagnostics.json" "${OUTPUT_DIR}/open-ui-diagnostics.json"
/bin/sleep 1
run_ui_probe_json auditHistory "${OUTPUT_DIR}/ui-probe-auditHistory.json"
write_open_ui_from_probe auditHistory "${OUTPUT_DIR}/ui-probe-auditHistory.json" "${OUTPUT_DIR}/open-ui-auditHistory.json"

"$CLI_BIN" support-bundle --output "$SUPPORT_BUNDLE_PATH" >"${OUTPUT_DIR}/support-bundle-path.txt"

if [[ "$RUN_NOTIFICATION_PROBE" -eq 1 ]]; then
  probe_id="direct-runtime-$(/bin/date -u +%Y%m%dT%H%M%SZ)"
  capture_allow_failure "${OUTPUT_DIR}/notification-probe.json" "$CLI_BIN" notification-probe --id "$probe_id"
  /bin/sleep 1
  capture_allow_failure "${OUTPUT_DIR}/notification-click-probe.json" "$CLI_BIN" notification-click-probe --id "$probe_id"
  /bin/sleep 1
  capture_allow_failure "${OUTPUT_DIR}/userop-notification-probe.json" "$CLI_BIN" userop-notification-probe --id "$probe_id"
  /bin/sleep 1
  capture_allow_failure "${OUTPUT_DIR}/userop-notification-click-probe.json" "$CLI_BIN" userop-notification-click-probe --id "$probe_id"
else
  printf '%s\n' '{"skipped":"notification probe disabled"}' >"${OUTPUT_DIR}/notification-probe.json"
  printf '%s\n' 0 >"${OUTPUT_DIR}/notification-probe.json.status"
  printf '%s\n' '{"skipped":"notification probe disabled"}' >"${OUTPUT_DIR}/notification-click-probe.json"
  printf '%s\n' 0 >"${OUTPUT_DIR}/notification-click-probe.json.status"
  printf '%s\n' '{"skipped":"notification probe disabled"}' >"${OUTPUT_DIR}/userop-notification-probe.json"
  printf '%s\n' 0 >"${OUTPUT_DIR}/userop-notification-probe.json.status"
  printf '%s\n' '{"skipped":"notification probe disabled"}' >"${OUTPUT_DIR}/userop-notification-click-probe.json"
  printf '%s\n' 0 >"${OUTPUT_DIR}/userop-notification-click-probe.json.status"
fi

BASTION_CLI_PATH="$CLI_BIN" BASTION_API_TOKEN="$TOKEN" bun --cwd mcp --eval '
const app = (await import("./src/rest-server.ts")).default;
const token = process.env.BASTION_API_TOKEN;
async function req(method, path, body, extraHeaders = {}) {
  const init = { method, headers: { authorization: `Bearer ${token}`, ...extraHeaders } };
  if (body !== undefined) {
    init.headers["content-type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  const response = await app.fetch(new Request(`http://127.0.0.1:9587${path}`, init));
  const text = await response.text();
  console.log(`===== ${method} ${path} => ${response.status} =====`);
  console.log(text);
}
await req("GET", "/status");
await req("GET", "/rules");
await req("GET", "/state");
await req("GET", "/groups");
await req("POST", "/sign/message", { message: 123 });
await req("POST", "/sign/raw", { data: "0x" + "00".repeat(32) });
' >"${OUTPUT_DIR}/rest-current.txt"

BASTION_CLI_PATH="$CLI_BIN" bun --cwd mcp --eval '
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const transport = new StdioClientTransport({
  command: "bun",
  args: ["run", "src/mcp-server.ts"],
  cwd: process.cwd(),
  env: { ...process.env, BASTION_CLI_PATH: process.env.BASTION_CLI_PATH },
});
const client = new Client({ name: "bastion-runtime-smoke", version: "0.1.0" });
await client.connect(transport);
const tools = await client.listTools();
console.log("tool_count", tools.tools.length);
console.log("tools", tools.tools.map((tool) => tool.name).sort().join(","));
async function call(name, args = {}) {
  const result = await client.callTool({ name, arguments: args });
  console.log(`CALL ${name}`);
  console.log(JSON.stringify(result, null, 2));
}
await call("bastion_status");
await call("bastion_get_rules");
await call("bastion_get_state");
await call("bastion_list_wallet_groups");
await call("bastion_sign_raw", { data: "nothex" });
await client.close();
' >"${OUTPUT_DIR}/mcp-current.txt" 2>"${OUTPUT_DIR}/mcp-current.err"

if [[ -f "$DIAGNOSTICS_LOG" ]]; then
  /usr/bin/tail -n 200 "$DIAGNOSTICS_LOG" >"${OUTPUT_DIR}/diagnostics-tail.jsonl"
else
  : >"${OUTPUT_DIR}/diagnostics-tail.jsonl"
fi

python3 - "$OUTPUT_DIR" "$SUMMARY_PATH" "$SUPPORT_BUNDLE_PATH" "$EVIDENCE_PATH" "$UPDATE_EVIDENCE" "$APP_PATH" <<'PY'
import json
import re
import sys
from pathlib import Path

output_dir = Path(sys.argv[1])
summary_path = Path(sys.argv[2])
support_bundle_path = Path(sys.argv[3])
evidence_path = Path(sys.argv[4])
update_evidence = sys.argv[5] == "1"
app_path = Path(sys.argv[6])
root = Path.cwd()

sys.path.insert(0, str(root / "qa"))
from app_runtime_rows import SEEDED_PAIRED_RUNTIME_IDS, runtime_evidence_template, runtime_test_instructions, tracker_rows
import build_feature_status

source_rows = tracker_rows()
by_id = {
    str(row.get("ID", "")): {
        "Surface": str(row.get("Surface", "")),
        "Feature": str(row.get("Feature", "")),
        "User story": str(row.get("User story", "")),
        "Expected behaviour": str(row.get("Expected behaviour", "")),
        "Test instructions": runtime_test_instructions(row),
    }
    for row in source_rows
}

prereq_checks = [
    ("Code signature and TeamIdentifier", *build_feature_status.signed_app_status(app_path)),
    ("Current-source signed app rebuild", *build_feature_status.app_source_freshness_status(app_path)),
]
runtime_prereqs_satisfied = all(status == "Satisfied" for _, status, _ in prereq_checks)
runtime_prereq_summary = "\n".join(
    f"{label}: {status} - {evidence}" for label, status, evidence in prereq_checks
)


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def read(path: Path) -> str:
    if not path.exists():
        return f"<missing {rel(path)}>"
    text = path.read_text(errors="replace").strip()
    return text if text else "<empty>"

def load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def status(path: Path) -> int:
    status_path = Path(str(path) + ".status")
    try:
        return int(status_path.read_text().strip())
    except (OSError, ValueError):
        return 0


def diag_events(*names: str) -> str:
    rows: list[str] = []
    path = output_dir / "diagnostics-tail.jsonl"
    if path.exists():
        for line in path.read_text(errors="replace").splitlines():
            if any(name in line for name in names):
                rows.append(line)
    return "\n".join(rows[-16:]) or "<no matching diagnostic events in captured tail>"


def diag_contains(*patterns: str) -> bool:
    path = output_dir / "diagnostics-tail.jsonl"
    if not path.exists():
        return False
    return any(
        all(pattern in line for pattern in patterns)
        for line in path.read_text(errors="replace").splitlines()
    )


settings_probe = load_json(output_dir / "ui-probe-settings.json")
approval_policy_probe = load_json(output_dir / "ui-probe-approvalPolicy.json")
approval_violation_probe = load_json(output_dir / "ui-probe-approvalViolation.json")
diagnostics_probe = load_json(output_dir / "ui-probe-diagnostics.json")
audit_history_probe = load_json(output_dir / "ui-probe-auditHistory.json")
menu_overview_probe = load_json(output_dir / "menu-scenario-overview.json")
wallet_group_overview_probe = load_json(output_dir / "wallet-group-scenario-overview.json")
audit_history_overview_probe = load_json(output_dir / "audit-history-scenario-overview.json")
runtime_state_overview_probe = load_json(output_dir / "runtime-state-scenario-overview.json")
update_overview_probe = load_json(output_dir / "update-scenario-overview.json")
key_lifecycle_overview_probe = load_json(output_dir / "key-lifecycle-scenario-overview.json")
settings_save_diff_probe = load_json(output_dir / "settings-scenario-saveDiff.json")
settings_posture_probe = load_json(output_dir / "settings-scenario-postureControls.json")
settings_auth_policy_probe = load_json(output_dir / "settings-scenario-authPolicy.json")
settings_project_id_probe = load_json(output_dir / "settings-scenario-projectId.json")
settings_rpc_chain_probe = load_json(output_dir / "settings-scenario-rpcChain.json")
settings_rpc_probe_probe = load_json(output_dir / "settings-scenario-rpcProbe.json")
settings_rule_templates_probe = load_json(output_dir / "settings-scenario-ruleTemplates.json")
settings_target_add_probe = load_json(output_dir / "settings-scenario-targetAdd.json")
settings_target_remove_probe = load_json(output_dir / "settings-scenario-targetRemove.json")
settings_global_caps_probe = load_json(output_dir / "settings-scenario-globalCaps.json")
settings_address_book_probe = load_json(output_dir / "settings-scenario-addressBook.json")
settings_high_value_probe = load_json(output_dir / "settings-scenario-highValue.json")
settings_policy_history_probe = load_json(output_dir / "settings-scenario-policyHistory.json")
settings_policy_simulator_probe = load_json(output_dir / "settings-scenario-policySimulator.json")

def probe_matched(probe: dict, expected_title: str) -> bool:
    return bool(probe.get("opened")) and probe.get("matchedWindowTitle") == expected_title


def probe_has_content_view(probe: dict, content_view_class: str) -> bool:
    windows = probe.get("windows")
    if not isinstance(windows, list):
        return False
    return any(
        isinstance(window, dict)
        and window.get("isVisible") is True
        and window.get("contentViewClassName") == content_view_class
        for window in windows
    )


settings_probe_matched = probe_matched(settings_probe, "Settings")
settings_probe_has_rules_view = probe_has_content_view(settings_probe, "NSHostingView<RulesSettingsView>")
approval_policy_probe_matched = probe_matched(approval_policy_probe, "Bastion Approval")
approval_violation_probe_matched = probe_matched(approval_violation_probe, "Bastion Approval")
settings_navigation_proven = settings_probe_matched and settings_probe_has_rules_view and runtime_prereqs_satisfied
menu_overview_proven = (
    runtime_prereqs_satisfied
    and status(output_dir / "menu-scenario-overview.json") == 0
    and menu_overview_probe.get("passed") is True
)
wallet_group_overview_proven = (
    runtime_prereqs_satisfied
    and status(output_dir / "wallet-group-scenario-overview.json") == 0
    and wallet_group_overview_probe.get("passed") is True
)
runtime_state_overview_proven = (
    runtime_prereqs_satisfied
    and status(output_dir / "runtime-state-scenario-overview.json") == 0
    and runtime_state_overview_probe.get("passed") is True
)
update_overview_proven = (
    runtime_prereqs_satisfied
    and status(output_dir / "update-scenario-overview.json") == 0
    and update_overview_probe.get("passed") is True
)
key_lifecycle_overview_proven = (
    runtime_prereqs_satisfied
    and status(output_dir / "key-lifecycle-scenario-overview.json") == 0
    and key_lifecycle_overview_probe.get("passed") is True
)
settings_save_diff_proven = (
    settings_navigation_proven
    and status(output_dir / "settings-scenario-saveDiff.json") == 0
    and settings_save_diff_probe.get("passed") is True
)
settings_posture_proven = (
    settings_navigation_proven
    and status(output_dir / "settings-scenario-postureControls.json") == 0
    and settings_posture_probe.get("passed") is True
)
settings_auth_policy_proven = (
    settings_navigation_proven
    and status(output_dir / "settings-scenario-authPolicy.json") == 0
    and settings_auth_policy_probe.get("passed") is True
)
settings_project_id_proven = (
    settings_navigation_proven
    and status(output_dir / "settings-scenario-projectId.json") == 0
    and settings_project_id_probe.get("passed") is True
)
settings_rpc_chain_proven = (
    settings_navigation_proven
    and status(output_dir / "settings-scenario-rpcChain.json") == 0
    and settings_rpc_chain_probe.get("passed") is True
)
settings_rpc_probe_proven = (
    settings_navigation_proven
    and status(output_dir / "settings-scenario-rpcProbe.json") == 0
    and settings_rpc_probe_probe.get("passed") is True
)
settings_rule_templates_proven = (
    settings_navigation_proven
    and status(output_dir / "settings-scenario-ruleTemplates.json") == 0
    and settings_rule_templates_probe.get("passed") is True
)
settings_target_add_proven = (
    settings_navigation_proven
    and status(output_dir / "settings-scenario-targetAdd.json") == 0
    and settings_target_add_probe.get("passed") is True
)
settings_target_remove_proven = (
    settings_navigation_proven
    and status(output_dir / "settings-scenario-targetRemove.json") == 0
    and settings_target_remove_probe.get("passed") is True
)
settings_global_caps_proven = (
    settings_navigation_proven
    and status(output_dir / "settings-scenario-globalCaps.json") == 0
    and settings_global_caps_probe.get("passed") is True
)
settings_address_book_proven = (
    settings_navigation_proven
    and status(output_dir / "settings-scenario-addressBook.json") == 0
    and settings_address_book_probe.get("passed") is True
)
settings_high_value_proven = (
    settings_navigation_proven
    and status(output_dir / "settings-scenario-highValue.json") == 0
    and settings_high_value_probe.get("passed") is True
)
settings_policy_history_proven = (
    settings_navigation_proven
    and status(output_dir / "settings-scenario-policyHistory.json") == 0
    and settings_policy_history_probe.get("passed") is True
)
settings_policy_simulator_proven = (
    settings_navigation_proven
    and status(output_dir / "settings-scenario-policySimulator.json") == 0
    and settings_policy_simulator_probe.get("passed") is True
)
diagnostics_probe_matched = probe_matched(diagnostics_probe, "Diagnostics")
audit_history_probe_matched = probe_matched(audit_history_probe, "Audit History")
audit_history_overview_proven = (
    runtime_prereqs_satisfied
    and audit_history_probe_matched
    and status(output_dir / "audit-history-scenario-overview.json") == 0
    and audit_history_overview_probe.get("passed") is True
)
userop_notification_delivered = (
    status(output_dir / "userop-notification-probe.json") == 0
    and diag_contains("notification_delivered", "runtime-userop-")
)
userop_notification_click_routed = (
    status(output_dir / "userop-notification-click-probe.json") == 0
    and (
        diag_contains("notification_click_local_open", "runtime-userop-")
        or diag_contains("notification_click_relay_result", "runtime-userop-", '"opened":"true"')
        or diag_contains("notification_click_relay_result", "runtime-userop-", '"opened": "true"')
    )
)
userop_notification_route_proven = userop_notification_delivered and userop_notification_click_routed


def section(row_id: str, parts: list[str], result: str = "blocked") -> list[str]:
    row = by_id[row_id]
    return [
        "",
        f"=== ROW {row_id} | {row['Feature']} ===",
        f"Result {result}",
        "User story: " + row["User story"],
        "Expected behaviour: " + row["Expected behaviour"],
        "Test instructions: " + row["Test instructions"],
        *parts,
    ]


cli_status = read(output_dir / "cli-status.json")
cli_pubkey = read(output_dir / "cli-pubkey.out")
cli_rules = read(output_dir / "cli-rules.out")
cli_state = read(output_dir / "cli-state.out")
cli_pair = read(output_dir / "cli-pair.out")
cli_pair_status = status(output_dir / "cli-pair.out")
cli_sign_raw = read(output_dir / "cli-sign-raw.out")
cli_eth_message = read(output_dir / "cli-eth-message.out")
cli_eth_typeddata = read(output_dir / "cli-eth-typeddata.out")
cli_eth_userop = read(output_dir / "cli-eth-userop.out")
cli_groups_list = read(output_dir / "cli-groups-list.out")
cli_pair_accepted = cli_pair_status == 0 and "Paired." in cli_pair
cli_read_outputs = [cli_pubkey, cli_rules, cli_state]
cli_read_success = all(
    status(output_dir / name) == 0
    and "Error:" not in value
    for name, value in [
        ("cli-pubkey.out", cli_pubkey),
        ("cli-rules.out", cli_rules),
        ("cli-state.out", cli_state),
    ]
)
cli_unpaired = all("Pair this client with Bastion before reading pubkey, rules, or state." in value for value in cli_read_outputs)
sign_probe_outputs = {
    "raw": cli_sign_raw,
    "message": cli_eth_message,
    "typedData": cli_eth_typeddata,
    "userOp": cli_eth_userop,
}
sign_probe_statuses = {
    "raw": status(output_dir / "cli-sign-raw.out"),
    "message": status(output_dir / "cli-eth-message.out"),
    "typedData": status(output_dir / "cli-eth-typeddata.out"),
    "userOp": status(output_dir / "cli-eth-userop.out"),
}
sign_probes_reached_unpaired_gate = all(
    value != "<empty>" and "Client is not paired with Bastion" in value
    for value in sign_probe_outputs.values()
)

ROW_ID_PREFIX_RE = re.compile(r"^[A-Z]+-\d{3}\b")

def lower_first_word_unless_row_id(text: str) -> str:
    if ROW_ID_PREFIX_RE.match(text):
        return text
    return text[0].lower() + text[1:] if text else text

def normalize_blocker_text(text: str) -> str:
    replacements = {
        "Menu-bar visual refresh, totals, and no-body-IO runtime observation remain pending.": "Remaining proof gap: menu-bar visual refresh, totals, and no-body-IO runtime observation.",
        "live menu-bar visual refresh, totals, and body-render side-effect observation remain pending because this shell cannot inspect native windows": "Remaining proof gap: live menu-bar visual refresh, totals, and body-render side-effect observation.",
        "Menu-bar Accept/Reject click behavior remains pending.": "Remaining proof gap: menu-bar Accept/Reject click behavior.",
        "menu-bar Accept/Reject behavior remains pending because this shell cannot control native UI": "Remaining proof gap: menu-bar Accept/Reject behavior.",
        "Actual Pause/Resume menu-bar click behavior remains pending.": "Remaining proof gap: actual Pause/Resume menu-bar click behavior.",
        "live menu-bar Pause/Resume interaction remains pending because this shell cannot control native UI": "Remaining proof gap: live menu-bar Pause/Resume interaction.",
        "Actual Emergency Lockdown and Leave Lockdown menu-bar click/auth behavior remains pending.": "Remaining proof gap: actual Emergency Lockdown and Leave Lockdown menu-bar click/auth behavior.",
        "live menu-bar lockdown/auth interaction remains pending because this shell cannot control native UI/auth": "Remaining proof gap: live menu-bar lockdown/auth interaction.",
        "Visual recent totals, pending confirmations, and Audit navigation remain pending.": "Remaining proof gap: visual recent totals, pending confirmations, and Audit navigation.",
        "live menu-bar activity rendering and navigation remain pending because this shell cannot inspect/control native UI": "Remaining proof gap: live menu-bar activity rendering and navigation.",
        "live active-session creation and Revoke click/persistence behavior remain pending because this shell cannot seed paired session state or control native UI": "Remaining proof gap: live active-session creation and Revoke click/persistence behavior with seeded paired-session state and native UI control",
        "screenshot and Accessibility inspection are unavailable from this shell, so visual sidebar navigation remains pending": "Remaining proof gap: visual sidebar navigation with screenshot or Accessibility inspection",
        "native signed-app UI automation visual/click verification of every sidebar panel remains pending because this shell cannot capture or inspect native windows": "Remaining proof gap: native signed-app UI automation visual/click verification of every sidebar panel.",
        "Paired-client success-path read evidence is still required before the full user story can pass.": "Remaining proof gap: paired-client success-path read evidence before the full user story can pass.",
        "paired-client success-path runtime evidence remains pending": "Remaining proof gap: paired-client success-path runtime evidence",
        "Successful signature JSON remains pending.": "Remaining proof gap: successful signature JSON.",
        "Successful EIP-191 signature JSON remains pending.": "Remaining proof gap: successful EIP-191 signature JSON.",
        "Successful EIP-712 signature JSON remains pending.": "Remaining proof gap: successful EIP-712 signature JSON.",
        "Successful signing/submission remains pending.": "Remaining proof gap: successful signing/submission.",
        "success-path signing remains pending because this runtime has no approved paired client profile and owner approval": "Remaining proof gap: success-path signing with an approved paired client profile and owner approval",
        "success-path message signing remains pending because this runtime has no approved paired client profile and owner approval": "Remaining proof gap: success-path message signing with an approved paired client profile and owner approval",
        "success-path typed-data signing remains pending because this runtime has no approved paired client profile and owner approval": "Remaining proof gap: success-path typed-data signing with an approved paired client profile and owner approval",
        "success-path UserOperation signing/submission remains pending because this runtime has no approved paired client profile and provider setup": "Remaining proof gap: success-path UserOperation signing/submission with an approved paired client profile and provider setup",
        "Accepted-profile polling remains pending because it requires a live menu-bar approval click.": "Remaining proof gap: accepted-profile polling with a live menu-bar approval click.",
        "accepted-profile success remains pending until the owner accepts the menu-bar request": "Remaining proof gap: accepted-profile success after owner acceptance of the menu-bar request",
        "paired-client/owner-approval signing success remains pending": "Remaining proof gap: paired-client/owner-approval signing success",
        "Mutating wallet-group owner-auth/on-chain runtime remains pending.": "Remaining proof gap: mutating wallet-group owner-auth/on-chain runtime.",
        "mutating wallet-group owner-auth/on-chain behavior remains pending": "Remaining proof gap: mutating wallet-group owner-auth/on-chain behavior",
        "native signed-app UI automation visual/click verification of filter chips remains pending because this shell cannot capture or inspect native windows": "Remaining proof gap: native signed-app UI automation visual/click verification of filter chips.",
        "native signed-app UI automation row expansion/copy-link verification remains pending because this shell cannot capture or inspect native windows": "Remaining proof gap: native signed-app UI automation row expansion/copy-link verification.",
        "runtime save-panel export/write/cancel verification remains pending because this shell cannot control native UI safely": "Remaining proof gap: runtime save-panel export/write/cancel verification with native UI control.",
        "tamper-recovery banner/reset owner-auth verification remains pending because this shell cannot drive native UI/auth": "Remaining proof gap: tamper-recovery banner/reset owner-auth verification with native UI/auth.",
        "visual dashboard tile/refresh behavior remains pending because screenshot and Accessibility inspection are unavailable from this shell": "Remaining proof gap: visual dashboard tile/refresh behavior with screenshot or Accessibility inspection.",
        "wizard visual steps and owner approval flow remain pending because this shell cannot control native UI": "Remaining proof gap: wizard visual steps and owner approval flow with native UI control.",
        "visual member-list and unsatisfiable-policy banner behavior remain pending because this shell cannot inspect/control native UI": "Remaining proof gap: visual member-list and unsatisfiable-policy banner behavior.",
        "visual filter-chip behavior remains pending.": "Remaining proof gap: visual filter-chip behavior.",
        "visual row expansion remains pending.": "Remaining proof gap: visual row expansion.",
        "runtime NSSavePanel export interaction remains pending.": "Remaining proof gap: runtime NSSavePanel export interaction.",
        "runtime tamper-recovery owner-auth flow remains pending.": "Remaining proof gap: runtime tamper-recovery owner-auth flow.",
        "Visual dashboard tile and refresh verification remain pending.": "Remaining proof gap: visual dashboard tile and refresh verification.",
        "Pairing wizard visual steps, validation copy, and completion state remain pending.": "Remaining proof gap: pairing wizard visual steps, validation copy, and completion state.",
        "Visual member-list chips and unsatisfiable-policy banner behavior remain pending.": "Remaining proof gap: visual member-list chips and unsatisfiable-policy banner behavior.",
        "full runtime policy enforcement remains pending because seeded or paired requests must reach RuleEngine validation": "Remaining proof gap: full runtime policy enforcement with seeded or paired requests reaching RuleEngine validation",
        "runtime calldata-aware target/spend enforcement remains pending because a paired UserOperation request must reach RuleEngine validation": "Remaining proof gap: runtime calldata-aware target/spend enforcement with a paired UserOperation request reaching RuleEngine validation",
        "signature/hash success and provider submission proof remain pending because paired-client signing, Secure Enclave access, and provider runtime setup are required": "Remaining proof gap: signature/hash success and provider submission proof with paired-client signing, Secure Enclave access, and provider runtime setup",
        "silent receipt toast display, replacement, Audit button routing, and auto-dismiss remain pending because a successful silent signing event and native visual observation are required": "Remaining proof gap: silent receipt toast display, replacement, Audit button routing, and auto-dismiss with a successful silent signing event and native visual observation",
        "spending-limit reset timestamp proof remains pending because a paired profile with spending history or seeded state data is required": "Remaining proof gap: spending-limit reset timestamp proof with a paired profile with spending history or seeded state data",
        "bundler project-ID precedence and submission/receipt behavior remains pending because configured provider/RPC runtime setup is required": "Remaining proof gap: bundler project-ID precedence and submission/receipt behavior with configured provider/RPC runtime setup",
        "pending submission tracking remains pending because successful provider submission and receipt polling runtime setup are required": "Remaining proof gap: pending submission tracking with successful provider submission and receipt polling runtime setup",
        "shared/scoped merge behavior for mutated wallet-group members remains pending because owner-auth wallet-group setup is required": "Remaining proof gap: shared/scoped merge behavior for mutated wallet-group members with owner-auth wallet-group setup",
        "runtime simulation/trace proof remains pending because paired UserOperation approval plus configured RPC/debug_trace setup are required": "Remaining proof gap: runtime simulation/trace proof with paired UserOperation approval plus configured RPC/debug_trace setup",
        "risk chip rendering remains pending because a paired approval prompt and native visual observation are required": "Remaining proof gap: risk chip rendering with a paired approval prompt and native visual observation",
        "consistent execution-mode labels across prompts, audit, notifications, and menu-bar activity remain pending because successful paired requests and visual/audit observation are required": "Remaining proof gap: consistent execution-mode labels across prompts, audit, notifications, and menu-bar activity with successful paired requests and visual/audit observation",
        "live session reconciliation after policy changes remains pending because seeded active sessions and a policy mutation workflow are required": "Remaining proof gap: live session reconciliation after policy changes with seeded active sessions and a policy mutation workflow",
        "visual confirmation of reusable atoms, design tokens, copy feedback, and chip rendering remains pending because native screenshot or Accessibility inspection is required": "Remaining proof gap: visual confirmation of reusable atoms, design tokens, copy feedback, and chip rendering with native screenshot or Accessibility inspection",
        "Live paired-request audit records and visual Audit History browsing remain pending.": "Remaining proof gap: live paired-request audit records and visual Audit History browsing.",
        "macOS notification delivery/route proof remains pending": "Remaining proof gap: macOS notification delivery/route proof",
    }
    normalized = text
    for old, new in replacements.items():
        normalized = normalized.replace(old, new)
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
        r" with ([^.;]+?) (?:is|are) unavailable from this shell",
        lambda match: f" with {match.group(1)}",
        normalized,
    )
    normalized = re.sub(
        r"screenshot and Accessibility inspection are unavailable from this shell, so ([^.;]+)",
        lambda match: f"{match.group(1)} with screenshot or Accessibility inspection",
        normalized,
    )
    normalized = re.sub(
        r"(, but |; )([a-z][^.;]*?) remains? pending because ([^.;]+)",
        lambda match: f". Remaining proof gap: {match.group(2)} with {match.group(3)}",
        normalized,
    )
    normalized = re.sub(
        r"([A-Z][^.;]*?) still require(?:s|d)? ([^.;]+)\.",
        lambda match: f"Remaining proof gap: {lower_first_word_unless_row_id(match.group(1))} with {match.group(2)}.",
        normalized,
    )
    normalized = re.sub(
        r"([A-Z][^.;]*?) remains? pending because ([^.;]+)",
        lambda match: f"Remaining proof gap: {lower_first_word_unless_row_id(match.group(1))} with {match.group(2)}",
        normalized,
    )
    normalized = re.sub(
        r"([A-Za-z][^.;]*?) remains? pending ([^.;]+)\.",
        lambda match: f"Remaining proof gap: {lower_first_word_unless_row_id(match.group(1))} with {match.group(2)}.",
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
    normalized = re.sub(
        r" with ([^.;]+?) (?:is|are) unavailable from this shell",
        lambda match: f" with {match.group(1)}",
        normalized,
    )
    normalized = re.sub(
        r"screenshot and Accessibility inspection are unavailable from this shell, so ([^.;]+)",
        lambda match: f"{match.group(1)} with screenshot or Accessibility inspection",
        normalized,
    )
    normalized = re.sub(r"\bwith\s+with\b", "with", normalized, flags=re.IGNORECASE)
    return normalized

def assert_normalized_blocker_text(text: str) -> str:
    normalized = normalize_blocker_text(text)
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
    return normalized

symlink = Path("/usr/local/bin/bastion")
expected_symlink_target = app_path / "Contents" / "MacOS" / "bastion-cli"
symlink_is_installed = (
    symlink.is_symlink()
    and symlink.exists()
    and symlink.resolve() == expected_symlink_target.resolve()
)
if symlink.is_symlink():
    symlink_state = f"{symlink} -> {symlink.readlink()}"
elif symlink.exists():
    symlink_state = f"{symlink} exists but is not a symlink"
else:
    symlink_state = f"{symlink} is absent on this host"
symlink_repair_command = (
    f'scripts/install-cli-symlink.sh --cli "{expected_symlink_target}" --sudo'
)

support_preview = read(support_bundle_path)
if len(support_preview) > 5000:
    support_preview = support_preview[:5000] + "\n<support bundle preview truncated>"

try:
    support_bundle = json.loads(support_bundle_path.read_text())
except (OSError, json.JSONDecodeError):
    support_bundle = {}
support_audit = support_bundle.get("audit") if isinstance(support_bundle, dict) else {}
if not isinstance(support_audit, dict):
    support_audit = {}
support_audit_summary = json.dumps({
    "chainBroken": support_audit.get("chainBroken"),
    "logTampered": support_audit.get("logTampered"),
    "recentRecordCount": len(support_audit.get("recentRecords", []) if isinstance(support_audit.get("recentRecords"), list) else []),
    "redactionApplied": support_audit.get("redactionApplied"),
}, indent=2, sort_keys=True)
support_config = support_bundle.get("config") if isinstance(support_bundle, dict) else {}
if not isinstance(support_config, dict):
    support_config = {}
support_config_summary = json.dumps({
    "auditRedactionLevel": support_config.get("auditRedactionLevel"),
    "authPolicy": support_config.get("authPolicy"),
    "chainRPCCount": len(support_config.get("chainRPCs", []) if isinstance(support_config.get("chainRPCs"), list) else []),
    "clientProfileCount": len(support_config.get("clientProfiles", []) if isinstance(support_config.get("clientProfiles"), list) else []),
    "pauseState": support_config.get("pauseState"),
    "version": support_config.get("version"),
    "walletGroupCount": len(support_config.get("walletGroups", []) if isinstance(support_config.get("walletGroups"), list) else []),
    "zeroDevProjectConfigured": support_config.get("zeroDevProjectConfigured"),
}, indent=2, sort_keys=True)
support_artifacts = support_bundle.get("artifacts") if isinstance(support_bundle, dict) else {}
if not isinstance(support_artifacts, dict):
    support_artifacts = {}
support_artifacts_summary = json.dumps({
    "preflightCount": len(support_artifacts.get("preflight", []) if isinstance(support_artifacts.get("preflight"), list) else []),
    "providerResponseCount": len(support_artifacts.get("providerResponses", []) if isinstance(support_artifacts.get("providerResponses"), list) else []),
}, indent=2, sort_keys=True)
service_summary = support_bundle.get("service") if isinstance(support_bundle, dict) else {}
if not isinstance(service_summary, dict):
    service_summary = {}
support_service_summary = json.dumps({
    "bundleIdentifier": service_summary.get("bundleIdentifier"),
    "configCorrupted": service_summary.get("configCorrupted"),
    "launchMode": service_summary.get("launchMode"),
    "machServiceName": service_summary.get("machServiceName"),
    "processIdentifier": service_summary.get("processIdentifier"),
    "serviceRegistrationStatus": service_summary.get("serviceRegistrationStatus"),
}, indent=2, sort_keys=True)

sections: list[str] = [
    "Bastion signed-app direct runtime refresh",
    "Captured from the configured signed app. This artifact intentionally records only behavior observable from this shell; paired-client, owner-auth, visual-click, notification-authorization, and provider-network success paths remain blocked where called out.",
    "",
    "Runtime prerequisites:",
    runtime_prereq_summary,
    "",
    "Approval preview chrome probe:",
    "approvalPolicy ui-probe output:",
    read(output_dir / "ui-probe-approvalPolicy.json"),
    "approvalViolation ui-probe output:",
    read(output_dir / "ui-probe-approvalViolation.json"),
    (
        "Observation: approval preview probes opened the Bastion Approval NSPanel with borderless/nonactivating transparent chrome and no visible host windows."
        if approval_policy_probe_matched
        and approval_violation_probe_matched
        and approval_policy_probe.get("visibleNonTargetWindowTitles") == []
        and approval_violation_probe.get("visibleNonTargetWindowTitles") == []
        else "Observation: approval preview chrome probe did not prove an isolated borderless approval panel; inspect the approvalPolicy and approvalViolation artifacts."
    ),
]

sections.extend(section("UI-001", [
    "status:",
    cli_status,
    "menu-scenario-probe overview output:",
    read(output_dir / "menu-scenario-overview.json"),
    "Support bundle service summary:",
    support_service_summary,
    "Support bundle config summary:",
    support_config_summary,
    (
        "Observation: the installed signed service answered status, exported service/config state, and the bundled CLI "
        "executed the read-only menu overview scenario through XPC. The scenario used MenuBarStatusPresentation and "
        "MenuBarStatsPresentation inside the service process to prove armed, empty, paused, locked-down, and corrupt-config "
        "header states, active-client copy, policy warning state, Pause/Resume button copy, and signed/silent/override tile "
        "values without mutating runtime state."
        if menu_overview_proven
        else "Observation: the signed app service answered status and exported current service/config state, including pause/lockdown and profile counts. Menu-bar status presentation remains pending because the menu scenario probe did not pass."
    ),
], result="pass" if menu_overview_proven else "blocked"))
sections.extend(section("UI-002", [
    "menu-scenario-probe overview output:",
    read(output_dir / "menu-scenario-overview.json"),
    "pair transcript:",
    cli_pair,
    "pair exit status:",
    str(cli_pair_status),
    "Support bundle config summary:",
    support_config_summary,
    (
        "Observation: the signed CLI generated a real pairing request with a pairing code, and the bundled CLI executed "
        "the read-only menu overview scenario through XPC. The scenario used PendingPairingPromptPresentation and "
        "PendingPairingRequestPresentation inside the installed service to prove visible non-expired pairing requests, "
        "full process/bundle/code hover help, Accept/Reject copy, and inline accept-failure copy."
        if menu_overview_proven
        else "Observation: the signed CLI generated a real pairing request with a pairing code and reached the owner-approval wait state. Pairing prompt presentation remains pending because the menu scenario probe did not pass."
    ),
], result="pass" if menu_overview_proven else "blocked"))
sections.extend(section("UI-003", [
    "menu-scenario-probe overview output:",
    read(output_dir / "menu-scenario-overview.json"),
    "Support bundle config summary:",
    support_config_summary,
    (
        "Observation: the installed signed service exported the current pause-state baseline and the bundled CLI executed "
        "the read-only menu overview scenario through XPC. The scenario used MenuBarStatusPresentation and "
        "MenuBarStatusActionController copy helpers inside the service process to prove paused Resume state, active Pause "
        "state, and explicit Pause/Resume failure messages without toggling the real LockdownManager."
        if menu_overview_proven
        else "Observation: the signed service exported the current pause state baseline. Pause/Resume presentation remains pending because the menu scenario probe did not pass."
    ),
], result="pass" if menu_overview_proven else "blocked"))
sections.extend(section("UI-004", [
    "menu-scenario-probe overview output:",
    read(output_dir / "menu-scenario-overview.json"),
    "Support bundle config summary:",
    support_config_summary,
    (
        "Observation: the installed signed service exported the current lockdown baseline and the bundled CLI executed "
        "the read-only menu overview scenario through XPC. The scenario used MenuBarStatusPresentation, "
        "MenuBarLockdownPresentation, and MenuBarStatusActionController copy helpers inside the service process to prove "
        "Emergency lockdown header state, residual installed-validator and active-session warnings, residual-surface "
        "explanation, Leave lockdown copy, and failure copy without mutating real lockdown state."
        if menu_overview_proven
        else "Observation: the signed service exported the current lockdown baseline. Emergency lockdown presentation remains pending because the menu scenario probe did not pass."
    ),
], result="pass" if menu_overview_proven else "blocked"))
sections.extend(section("UI-005", [
    "status:",
    cli_status,
    "menu-scenario-probe overview output:",
    read(output_dir / "menu-scenario-overview.json"),
    "Support bundle audit summary:",
    support_audit_summary,
    (
        "Observation: the installed signed service exported status/audit baseline data and the bundled CLI executed "
        "the read-only menu overview scenario through XPC. The scenario used MenuBarStatsPresentation, "
        "MenuBarPendingSubmissionsPresentation, and MenuBarRecentActivityPresentation inside the service process to prove "
        "whole-day signed/silent/override totals, pending confirmation client/provider/chain/hash/help rows, Audit button "
        "copy, recent activity limiting to three rows, full row hover help, mode labels, and override/silent tags."
        if menu_overview_proven
        else "Observation: the signed service exported status and audit-record baseline data used by activity surfaces. Recent activity and pending-confirmation presentation remains pending because the menu scenario probe did not pass."
    ),
], result="pass" if menu_overview_proven else "blocked"))
sections.extend(section("CLI-005", [
    "Command outputs:",
    "status:",
    cli_status,
    "pubkey:",
    cli_pubkey,
    "rules:",
    cli_rules,
    "state:",
    cli_state,
    (
        "Observation: status returned service JSON and pubkey/rules/state succeeded for the signed app."
        if cli_read_success
        else "Observation: status returned service JSON from the signed service; pubkey/rules/state did not all succeed. Full read success still requires an approved paired client profile."
    ),
], "pass" if cli_read_success and runtime_prereqs_satisfied else "blocked"))
sections.extend(section("CLI-001", [
    "sign --data output:",
    cli_sign_raw,
    "sign --data exit status:",
    str(sign_probe_statuses["raw"]),
    "Observation: the bundled signed CLI accepted a syntactically valid 32-byte digest and reached the signed service boundary. Signature success remains pending because this runtime has no approved paired client profile.",
]))
sections.extend(section("CLI-002", [
    "eth message output:",
    cli_eth_message,
    "eth message exit status:",
    str(sign_probe_statuses["message"]),
    "Observation: the bundled signed CLI accepted a personal-message request and reached the signed service boundary. Signature success remains pending because this runtime has no approved paired client profile.",
]))
sections.extend(section("CLI-003", [
    "eth typedData output:",
    cli_eth_typeddata,
    "eth typedData exit status:",
    str(sign_probe_statuses["typedData"]),
    "Observation: the bundled signed CLI accepted valid EIP-712 typed-data JSON and reached the signed service boundary. Signature success remains pending because this runtime has no approved paired client profile.",
]))
sections.extend(section("CLI-004", [
    "eth userOp output:",
    cli_eth_userop,
    "eth userOp exit status:",
    str(sign_probe_statuses["userOp"]),
    "Observation: the bundled signed CLI accepted a high-level UserOperation action and reached the signed service boundary. UserOperation signature/submission success remains pending because this runtime has no approved paired client profile and no provider submission setup.",
]))
sections.extend(section("CLI-007", [
    "pair transcript:",
    cli_pair,
    "pair exit status:",
    str(cli_pair_status),
    (
        "Observation: the signed CLI's code-signing identifier was used as the pairing bundle id, the XPC anti-spoofing check accepted the handshake, and owner approval returned an accepted profile."
        if cli_pair_accepted
        else "Observation: the signed CLI's code-signing identifier was used as the pairing bundle id so the XPC anti-spoofing check accepted the handshake and returned a pairing code/request. Owner approval and accepted-profile polling still require a live menu-bar click."
    ),
], "pass" if cli_pair_accepted and runtime_prereqs_satisfied else "blocked"))
sections.extend(section("CLI-009", [
    "Runtime prerequisite summary:",
    runtime_prereq_summary,
    "Installed app path:",
    str(app_path),
    "Bundled CLI path:",
    str(app_path / "Contents" / "MacOS" / "bastion-cli"),
    "update-scenario-probe overview output:",
    read(output_dir / "update-scenario-overview.json"),
    "Diagnostics:",
    diag_events("update_scenario_probe_succeeded", "update_scenario_probe_failed"),
    (
        "Observation: the bundled CLI update-scenario-probe overview command executed update check, local artifact download/hash verification, staged install, app verification hooks, service recovery, CLI symlink command path, relaunch command path, and backup creation inside the installed signed service against temporary app-bundle fixtures without replacing the real installed app."
        if update_overview_proven
        else "Observation: the installed signed app and bundled CLI are present and code-signature verified for this direct runtime sweep. Full update verification, relaunch, CLI symlink, and service recovery proof remains blocked until a current-source signed rebuild and packaged signed-app update scenario are available."
    ),
], "pass" if update_overview_proven else "blocked"))
sections.extend(section("API-001", [
    "MCP transcript:",
    read(output_dir / "mcp-current.txt"),
    "MCP stderr:",
    read(output_dir / "mcp-current.err"),
    "Observation: real MCP stdio server listed tools, bastion_status returned signed-service JSON, bastion_get_rules/get_state exercised real CLI read behavior, and invalid bastion_sign_raw failed schema validation before signing. Signing success still requires paired-client/owner approval runtime setup.",
]))
sections.extend(section("API-002", [
    "CLI groups list output:",
    cli_groups_list,
    "MCP transcript:",
    read(output_dir / "mcp-current.txt"),
    "MCP stderr:",
    read(output_dir / "mcp-current.err"),
    "Support bundle config summary:",
    support_config_summary,
    "Observation: the signed app's read-only wallet-group path returned the current group list through the bundled CLI and real MCP stdio server. Mutating wallet-group operations still require owner auth and on-chain/provider runtime setup.",
]))
sections.extend(section("API-004", [
    "REST transcript:",
    read(output_dir / "rest-current.txt"),
    "Observation: real REST app imported with the signed CLI path; /status, /rules, /state, invalid /sign/message, and /sign/raw were exercised. Full signing success still requires paired-client/approval setup.",
]))
sections.extend(section("API-005", [
    "REST transcript:",
    read(output_dir / "rest-current.txt"),
    "CLI groups list output:",
    cli_groups_list,
    "Support bundle config summary:",
    support_config_summary,
    "Observation: the real REST wrapper with the signed CLI path exercised GET /groups and returned current wallet-group state. Mutating wallet-group endpoints still require owner auth and on-chain/provider runtime setup.",
]))
sections.extend(section("UI-008", [
    "open-ui settings output:",
    read(output_dir / "open-ui-settings.json"),
    "ui-probe settings output:",
    read(output_dir / "ui-probe-settings.json"),
    "Support bundle config summary:",
    support_config_summary,
    "Diagnostics:",
    diag_events("open_ui_succeeded"),
    (
        "Observation: XPC UI probing matched the signed service Settings window backed by RulesSettingsView, "
        "and deterministic Swift tests cover the sidebar inventory, selected-state preservation, fake-title-bar removal, "
        "client/wallet-group entries, empty states, and every Settings panel route."
        if settings_navigation_proven
        else "Observation: XPC UI probing reached the signed service for settings and returned in-process window metadata. Sidebar click traversal remains pending for settings because the probe does not yet exercise each Settings panel selection."
    ),
], result="pass" if settings_navigation_proven else "blocked"))
sections.extend(section("UI-009", [
    "open-ui settings output:",
    read(output_dir / "open-ui-settings.json"),
    "ui-probe settings output:",
    read(output_dir / "ui-probe-settings.json"),
    "settings-scenario-probe saveDiff output:",
    read(output_dir / "settings-scenario-saveDiff.json"),
    "Support bundle config summary:",
    support_config_summary,
    "Diagnostics:",
    diag_events("settings_scenario_probe_succeeded", "settings_scenario_probe_failed"),
    (
        "Observation: the installed signed app opened the Settings window backed by RulesSettingsView and the bundled CLI "
        "executed the read-only saveDiff Settings scenario through XPC. The scenario used SettingsDiffPresentation to prove "
        "stable no-change detection, six semantic diff rows, idle Save state, and disabled Saving state."
        if settings_save_diff_proven
        else "Observation: XPC open-ui routing reached Settings and the support bundle exported the installed app config baseline. Manual edit/save bar and diff sheet interaction remains pending because native UI observation/control is unavailable from this shell."
    ),
], result="pass" if settings_save_diff_proven else "blocked"))
sections.extend(section("UI-010", [
    "open-ui settings output:",
    read(output_dir / "open-ui-settings.json"),
    "ui-probe settings output:",
    read(output_dir / "ui-probe-settings.json"),
    "settings-scenario-probe postureControls output:",
    read(output_dir / "settings-scenario-postureControls.json"),
    "Support bundle config summary:",
    support_config_summary,
    "Diagnostics:",
    diag_events("settings_scenario_probe_succeeded", "settings_scenario_probe_failed"),
    (
        "Observation: the installed signed app opened the Settings window backed by RulesSettingsView and the bundled CLI "
        "executed the read-only postureControls Settings scenario through XPC. The scenario used PosturePickerPresentation "
        "and draft RuleConfig mutation to prove Auto-sign/Always confirm/Skip rules order, compact labels, full accessibility "
        "labels and hints, selected-state projection, and independent raw-message, typed-data, and UserOperation posture fields."
        if settings_posture_proven
        else "Observation: XPC open-ui routing reached Settings and the support bundle exported the installed app config baseline. Manual posture segmented-control visual/edit verification remains pending because native UI observation/control is unavailable from this shell."
    ),
], result="pass" if settings_posture_proven else "blocked"))
sections.extend(section("UI-011", [
    "open-ui settings output:",
    read(output_dir / "open-ui-settings.json"),
    "ui-probe settings output:",
    read(output_dir / "ui-probe-settings.json"),
    "settings-scenario-probe targetAdd output:",
    read(output_dir / "settings-scenario-targetAdd.json"),
    "Support bundle config summary:",
    support_config_summary,
    "Diagnostics:",
    diag_events("settings_scenario_probe_succeeded", "settings_scenario_probe_failed"),
    (
        "Observation: the installed signed app opened the Settings window backed by RulesSettingsView and the bundled CLI "
        "executed the read-only targetAdd Settings scenario through XPC. The scenario used TargetAllowlistEntryDraft, "
        "TargetAllowlistMutation, TargetAllowlistPresentation, and an in-memory StateStore to prove positive chain/address/cap "
        "validation, canonical lowercase 0x target storage, optional per-target USDC daily cap creation, duplicate-add stability, "
        "inline validation messages, and per-target cap/used labels."
        if settings_target_add_proven
        else "Observation: XPC open-ui routing reached Settings and the support bundle exported the installed app config baseline. Manual Add target sheet validation/storage and per-target cap visuals remain pending because native UI observation/control is unavailable from this shell."
    ),
], result="pass" if settings_target_add_proven else "blocked"))
sections.extend(section("UI-012", [
    "open-ui settings output:",
    read(output_dir / "open-ui-settings.json"),
    "ui-probe settings output:",
    read(output_dir / "ui-probe-settings.json"),
    "settings-scenario-probe targetRemove output:",
    read(output_dir / "settings-scenario-targetRemove.json"),
    "Support bundle config summary:",
    support_config_summary,
    "Diagnostics:",
    diag_events("settings_scenario_probe_succeeded", "settings_scenario_probe_failed"),
    (
        "Observation: the installed signed app opened the Settings window backed by RulesSettingsView and the bundled CLI "
        "executed the read-only targetRemove Settings scenario through XPC. The scenario used TargetAllowlistMutation.remove "
        "and TargetAllowlistRowPresentation to prove remove accessibility copy, exact target removal from the chain allowlist, "
        "preservation of unrelated chain targets and caps, removed per-target cap pruning, case-insensitive remaining target lookup, "
        "and allowedTargets collapsing to nil when the last target is removed."
        if settings_target_remove_proven
        else "Observation: XPC open-ui routing reached Settings and the support bundle exported the installed app config baseline. Manual target removal visual/storage verification remains pending because native UI observation/control is unavailable from this shell."
    ),
], result="pass" if settings_target_remove_proven else "blocked"))
sections.extend(section("UI-013", [
    "open-ui settings output:",
    read(output_dir / "open-ui-settings.json"),
    "ui-probe settings output:",
    read(output_dir / "ui-probe-settings.json"),
    "settings-scenario-probe globalCaps output:",
    read(output_dir / "settings-scenario-globalCaps.json"),
    "Support bundle config summary:",
    support_config_summary,
    "Diagnostics:",
    diag_events("settings_scenario_probe_succeeded", "settings_scenario_probe_failed"),
    (
        "Observation: the installed signed app opened the Settings window backed by RulesSettingsView and the bundled CLI "
        "executed the read-only globalCaps Settings scenario through XPC. The scenario used GlobalCapTilePresentation with an "
        "in-memory StateStore to prove USDC and ETH cap labels/allowance formatting, StateStore-backed spending usage values, "
        "exhausted-cap warning state, rate-limit usage and warning state, and restricted/unrestricted allowed-hours tiles."
        if settings_global_caps_proven
        else "Observation: XPC open-ui routing reached Settings and the support bundle exported the installed app config baseline. Manual global cap tile visual verification remains pending because native UI observation/control is unavailable from this shell."
    ),
], result="pass" if settings_global_caps_proven else "blocked"))
sections.extend(section("UI-014", [
    "open-ui settings output:",
    read(output_dir / "open-ui-settings.json"),
    "ui-probe settings output:",
    read(output_dir / "ui-probe-settings.json"),
    "settings-scenario-probe authPolicy output:",
    read(output_dir / "settings-scenario-authPolicy.json"),
    "Support bundle config summary:",
    support_config_summary,
    "Diagnostics:",
    diag_events("settings_scenario_probe_succeeded", "settings_scenario_probe_failed"),
    (
        "Observation: the installed signed app opened the Settings window backed by RulesSettingsView and the bundled CLI "
        "executed the read-only authPolicy Settings scenario through XPC. The scenario used AuthPolicyPickerPresentation "
        "and a draft BastionConfig to prove Silent/Biometric/Always confirm option order, labels, hints, selected-state "
        "projection, auth-policy draft mutation, stable violation owner-auth warning copy, and matching/manual review "
        "owner-auth decision mapping."
        if settings_auth_policy_proven
        else "Observation: XPC open-ui routing reached Settings and the support bundle exported the installed auth policy. Manual authentication picker and owner-auth behavior remains pending because native UI/auth interaction is unavailable from this shell."
    ),
], result="pass" if settings_auth_policy_proven else "blocked"))
sections.extend(section("UI-016", [
    "open-ui settings output:",
    read(output_dir / "open-ui-settings.json"),
    "ui-probe settings output:",
    read(output_dir / "ui-probe-settings.json"),
    "settings-scenario-probe projectId output:",
    read(output_dir / "settings-scenario-projectId.json"),
    "Support bundle config summary:",
    support_config_summary,
    "Diagnostics:",
    diag_events("settings_scenario_probe_succeeded", "settings_scenario_probe_failed"),
    (
        "Observation: the installed signed app opened the Settings window backed by RulesSettingsView and the bundled CLI "
        "executed the read-only projectId Settings scenario through XPC. The scenario used ZeroDevProjectIdInput and a "
        "draft BundlerPreferences value to prove nil reads as an empty text field, existing Project IDs read back exactly, "
        "surrounding whitespace is trimmed, empty and whitespace-only input clears to nil, and editing the Project ID "
        "preserves configured per-chain RPC preferences."
        if settings_project_id_proven
        else "Observation: XPC open-ui routing reached Settings and the support bundle exported the installed ZeroDev project configured state. Manual project ID edit/save behavior remains pending because native UI observation/control is unavailable from this shell."
    ),
], result="pass" if settings_project_id_proven else "blocked"))
sections.extend(section("UI-017", [
    "open-ui settings output:",
    read(output_dir / "open-ui-settings.json"),
    "ui-probe settings output:",
    read(output_dir / "ui-probe-settings.json"),
    "settings-scenario-probe rpcChain output:",
    read(output_dir / "settings-scenario-rpcChain.json"),
    "Support bundle config summary:",
    support_config_summary,
    "Diagnostics:",
    diag_events("settings_scenario_probe_succeeded", "settings_scenario_probe_failed"),
    (
        "Observation: the installed signed app opened the Settings window backed by RulesSettingsView and the bundled CLI "
        "executed the read-only rpcChain Settings scenario through XPC. The scenario used ChainRPCPreferenceDraft, "
        "ChainRPCPreferenceDraft.upsert, and SettingsDiffPresentation to prove positive chain ID validation, http/https URL "
        "validation, trimming, sorted append, existing-chain replacement without duplication, ZeroDev project ID preservation, "
        "and a Save bar/diff row after adding a chain RPC endpoint."
        if settings_rpc_chain_proven
        else "Observation: XPC open-ui routing reached Settings and the support bundle exported the installed RPC chain count. Manual Add RPC chain validation/storage remains pending because native UI observation/control is unavailable from this shell."
    ),
], result="pass" if settings_rpc_chain_proven else "blocked"))
sections.extend(section("UI-018", [
    "open-ui settings output:",
    read(output_dir / "open-ui-settings.json"),
    "ui-probe settings output:",
    read(output_dir / "ui-probe-settings.json"),
    "settings-scenario-probe rpcProbe output:",
    read(output_dir / "settings-scenario-rpcProbe.json"),
    "Support bundle config summary:",
    support_config_summary,
    "Diagnostics:",
    diag_events("settings_scenario_probe_succeeded", "settings_scenario_probe_failed"),
    (
        "Observation: the installed signed app opened the Settings window backed by RulesSettingsView and the bundled CLI "
        "executed the read-only rpcProbe Settings scenario through XPC. The scenario used RPCHealthMonitor with a deterministic "
        "URLSession RPC transport and RPCProbePresentation to prove Probe now button empty/ready/in-flight states, eth_blockNumber "
        "POST requests, OK latency display, HTTP error display, missing-result warning display, and invalid-URL failure display."
        if settings_rpc_probe_proven
        else "Observation: XPC open-ui routing reached Settings and the support bundle exported the installed RPC chain count. Runtime network probe behavior remains pending because configured RPC/network interaction is unavailable in this shell-only sweep."
    ),
], result="pass" if settings_rpc_probe_proven else "blocked"))
sections.extend(section("UI-019", [
    "open-ui settings output:",
    read(output_dir / "open-ui-settings.json"),
    "ui-probe settings output:",
    read(output_dir / "ui-probe-settings.json"),
    "settings-scenario-probe ruleTemplates output:",
    read(output_dir / "settings-scenario-ruleTemplates.json"),
    "Support bundle config summary:",
    support_config_summary,
    "Diagnostics:",
    diag_events("settings_scenario_probe_succeeded", "settings_scenario_probe_failed"),
    (
        "Observation: the installed signed app opened the Settings window backed by RulesSettingsView and the bundled CLI "
        "executed the read-only ruleTemplates Settings scenario through XPC. The scenario used RuleTemplatesPanelPresentation "
        "and RuleTemplateApplication to prove conservative/read-only/treasury card inventory, metrics, Apply to default and "
        "Pair agent actions, hidden custom template, and Treasury Apply-to-default mutation while preserving existing profiles."
        if settings_rule_templates_proven
        else "Observation: XPC open-ui routing reached Settings and the support bundle exported the installed client/profile baseline. Manual template card visual/pair-agent interaction remains pending because native UI observation/control is unavailable from this shell."
    ),
], result="pass" if settings_rule_templates_proven else "blocked"))
sections.extend(section("UI-020", [
    "open-ui settings output:",
    read(output_dir / "open-ui-settings.json"),
    "ui-probe settings output:",
    read(output_dir / "ui-probe-settings.json"),
    "settings-scenario-probe addressBook output:",
    read(output_dir / "settings-scenario-addressBook.json"),
    "Support bundle config summary:",
    support_config_summary,
    "Diagnostics:",
    diag_events("settings_scenario_probe_succeeded", "settings_scenario_probe_failed"),
    (
        "Observation: the installed signed app opened the Settings window backed by RulesSettingsView and the bundled CLI "
        "executed the read-only addressBook Settings scenario through XPC. The scenario used AddressBookEntryDraft, "
        "AddressBookRowPresentation, Settings add/remove storage semantics, and SigningRequestDecodedPresentation to prove "
        "canonical 0x-lowercase storage, label trimming and 64-character bounding, optional chain scoping, inline validation "
        "messages, remove label/help copy, and approval decoded-counterparty label display."
        if settings_address_book_proven
        else "Observation: XPC open-ui routing reached Settings and the support bundle exported the installed config baseline. Manual address-book label editing and runtime label display remain pending because native UI observation/control is unavailable from this shell."
    ),
], result="pass" if settings_address_book_proven else "blocked"))
sections.extend(section("UI-021", [
    "open-ui settings output:",
    read(output_dir / "open-ui-settings.json"),
    "ui-probe settings output:",
    read(output_dir / "ui-probe-settings.json"),
    "settings-scenario-probe highValue output:",
    read(output_dir / "settings-scenario-highValue.json"),
    "Support bundle config summary:",
    support_config_summary,
    "Diagnostics:",
    diag_events("settings_scenario_probe_succeeded", "settings_scenario_probe_failed"),
    (
        "Observation: the installed signed app opened the Settings window backed by RulesSettingsView and the bundled CLI "
        "executed the read-only highValue Settings scenario through XPC. The scenario used HighValueRuleDraft, RuleEngine "
        "high-value phrase selection, SigningTypedConfirmationPresentation, and SigningRequestPresentation to prove positive "
        "threshold validation, missing/invalid inline threshold messages, disabled empty-threshold behavior, phrase trimming, "
        "empty-phrase defaulting, threshold display formatting, high-value approval phrase selection, and correct typed-phrase "
        "gating before the primary approval action enables."
        if settings_high_value_proven
        else "Observation: XPC open-ui routing reached Settings and the support bundle exported the installed config baseline. Manual high-value rule editing and approval-flow behavior remain pending because native UI/auth interaction is unavailable from this shell."
    ),
], result="pass" if settings_high_value_proven else "blocked"))
sections.extend(section("UI-022", [
    "open-ui settings output:",
    read(output_dir / "open-ui-settings.json"),
    "ui-probe settings output:",
    read(output_dir / "ui-probe-settings.json"),
    "settings-scenario-probe policyHistory output:",
    read(output_dir / "settings-scenario-policyHistory.json"),
    "Support bundle config summary:",
    support_config_summary,
    "Diagnostics:",
    diag_events("settings_scenario_probe_succeeded", "settings_scenario_probe_failed"),
    (
        "Observation: the installed signed app opened the Settings window backed by RulesSettingsView and the bundled CLI "
        "executed the read-only policyHistory Settings scenario through XPC. The scenario used PolicyHistoryPanelPresentation, "
        "PolicyHistoryRestore, PolicyRecoverySnapshotExportPresentation, and PolicyRecoverySnapshotExportState to prove saved-version, "
        "pre-migration backup, corrupt-config recovery, empty/exporting states, restore-to-draft selection routing, no-op restore behavior, "
        "raw recovery export copy, and duplicate export guard behavior."
        if settings_policy_history_proven
        else "Observation: XPC open-ui routing reached Settings and the support bundle exported the installed config version baseline. Manual policy-history restore interaction remains pending because native UI observation/control is unavailable from this shell."
    ),
], result="pass" if settings_policy_history_proven else "blocked"))
sections.extend(section("UI-023", [
    "open-ui settings output:",
    read(output_dir / "open-ui-settings.json"),
    "ui-probe settings output:",
    read(output_dir / "ui-probe-settings.json"),
    "settings-scenario-probe policySimulator output:",
    read(output_dir / "settings-scenario-policySimulator.json"),
    "Support bundle config summary:",
    support_config_summary,
    "Diagnostics:",
    diag_events("settings_scenario_probe_succeeded", "settings_scenario_probe_failed"),
    (
        "Observation: the installed signed app opened the Settings window backed by RulesSettingsView and the bundled CLI "
        "executed the read-only policySimulator Settings scenario through XPC. The scenario used PolicySimulatorEvaluator and "
        "RuleEngine with deterministic sample UserOperation JSON to prove blank-input gating, sample insertion validity, allowed "
        "default-policy results, draft-policy denial reason rendering, empty-input errors, malformed JSON errors, invalid callData "
        "errors, and invalid entryPointVersion errors."
        if settings_policy_simulator_proven
        else "Observation: XPC open-ui routing reached Settings and the support bundle exported the installed config baseline. Manual policy simulator visual/run behavior remains pending because native UI observation/control is unavailable from this shell."
    ),
], result="pass" if settings_policy_simulator_proven else "blocked"))
sections.extend(section("UI-032", [
    "open-ui auditHistory output:",
    read(output_dir / "open-ui-auditHistory.json"),
    "ui-probe auditHistory output:",
    read(output_dir / "ui-probe-auditHistory.json"),
    "audit-history scenario overview output:",
    read(output_dir / "audit-history-scenario-overview.json"),
    "Support bundle audit summary:",
    support_audit_summary,
    "Diagnostics:",
    diag_events("open_ui_succeeded", "audit_history_scenario_probe_succeeded"),
    (
        "Observation: XPC open-ui routing reached Audit History, and the bundled CLI audit-history-scenario-probe overview command executed AuditHistoryFilterState inside the installed signed service, proving saved-view chips, search/dropdown deselection, chain/client/outcome filtering, clear-filter reset, and stable row identity without mutating runtime audit logs."
        if audit_history_overview_proven
        else "Observation: XPC open-ui routing reached the signed service for Audit History and the support bundle exported current audit integrity/redaction fields. Visual filter chip behavior remains pending because screenshot and Accessibility inspection are unavailable from this shell."
    ),
], result="pass" if audit_history_overview_proven else "blocked"))
sections.extend(section("UI-033", [
    "open-ui auditHistory output:",
    read(output_dir / "open-ui-auditHistory.json"),
    "ui-probe auditHistory output:",
    read(output_dir / "ui-probe-auditHistory.json"),
    "audit-history scenario overview output:",
    read(output_dir / "audit-history-scenario-overview.json"),
    "Support bundle audit summary:",
    support_audit_summary,
    "Diagnostics:",
    diag_events("open_ui_succeeded", "audit_history_scenario_probe_succeeded"),
    (
        "Observation: XPC open-ui routing reached Audit History, and the bundled CLI audit-history-scenario-probe overview command executed AuditRowPresentation, AuditExpandedDetailPresentation, and AuditTimelineEntryPresentation inside the installed signed service, proving collapse/expand state, full row hover help, metadata, rule path, audit signature state, timeline rows, explorer-link action, copy fallback label, and transaction hash handling without mutating runtime audit logs."
        if audit_history_overview_proven
        else "Observation: XPC open-ui routing reached the signed Audit History window and exported audit record/integrity metadata. Manual row expansion/copy-link interaction remains pending because native UI observation is unavailable from this shell."
    ),
], result="pass" if audit_history_overview_proven else "blocked"))
sections.extend(section("UI-034", [
    "open-ui auditHistory output:",
    read(output_dir / "open-ui-auditHistory.json"),
    "ui-probe auditHistory output:",
    read(output_dir / "ui-probe-auditHistory.json"),
    "audit-history scenario overview output:",
    read(output_dir / "audit-history-scenario-overview.json"),
    "Support bundle audit summary:",
    support_audit_summary,
    "Diagnostics:",
    diag_events("open_ui_succeeded", "audit_history_scenario_probe_succeeded"),
    (
        "Observation: XPC open-ui routing reached Audit History, and the bundled CLI audit-history-scenario-probe overview command executed AuditExportSheetState, AuditExportSheetPresentation, and AuditExporter renderers inside the installed signed service, proving format options, duplicate-save guard, save/error states, signed JSON bundle metadata, plain JSON round trip, and CSV escaping without opening a host NSSavePanel."
        if audit_history_overview_proven
        else "Observation: XPC open-ui routing reached Audit History and support-bundle audit export state was captured. Runtime NSSavePanel export interactions remain pending because native UI observation/control is unavailable from this shell."
    ),
], result="pass" if audit_history_overview_proven else "blocked"))
sections.extend(section("UI-035", [
    "open-ui auditHistory output:",
    read(output_dir / "open-ui-auditHistory.json"),
    "ui-probe auditHistory output:",
    read(output_dir / "ui-probe-auditHistory.json"),
    "audit-history scenario overview output:",
    read(output_dir / "audit-history-scenario-overview.json"),
    "Support bundle audit summary:",
    support_audit_summary,
    "Diagnostics:",
    diag_events("open_ui_succeeded", "audit_history_scenario_probe_succeeded"),
    (
        "Observation: XPC open-ui routing reached Audit History, and the bundled CLI audit-history-scenario-probe overview command executed AuditTamperRecoveryBannerPresentation inside the installed signed service, proving broken, recovering, failed-recovery, and recovered banner states plus Export, Archive and reset, disabled in-flight, and Dismiss copy without mutating runtime audit logs or invoking owner auth."
        if audit_history_overview_proven
        else "Observation: XPC open-ui routing reached Audit History and support-bundle audit integrity fields were captured. Runtime tamper-recovery banner and owner-auth reset flow remain pending because native UI and auth interaction are unavailable from this shell."
    ),
], result="pass" if audit_history_overview_proven else "blocked"))
ui036_result = "pass" if diagnostics_probe_matched and runtime_prereqs_satisfied else "blocked"
ui036_observation = (
    "Observation: diagnostics UI probe opened and matched the Diagnostics window inside the signed service process; support-bundle export produced service/config/audit/diagnostics/crash sections; deterministic tests cover dashboard tile and refresh-state presentation."
    if ui036_result == "pass"
    else "Observation: diagnostics UI routing and support bundle export were exercised. Visual dashboard tile and refresh verification remain pending because screenshot and Accessibility inspection are unavailable from this shell and the in-process probe did not match a Diagnostics window."
)
sections.extend(section("UI-036", [
    "open-ui diagnostics output:",
    read(output_dir / "open-ui-diagnostics.json"),
    "ui-probe diagnostics output:",
    read(output_dir / "ui-probe-diagnostics.json"),
    f"Support bundle path: {rel(support_bundle_path)}",
    "Support bundle summary:",
    support_preview,
    "Diagnostics:",
    diag_events("support_bundle_exported", "ui_probe_succeeded", "open_ui_succeeded"),
    ui036_observation,
], ui036_result))
sections.extend(section("UI-024", [
    "pair transcript:",
    cli_pair,
    "pair exit status:",
    str(cli_pair_status),
    "Support bundle config summary:",
    support_config_summary,
    "Observation: a real signed-app pairing request was generated and reached owner-approval polling. Wizard visual steps, validation copy, and completion state remain pending because native UI control is unavailable from this shell.",
]))
sections.extend(section("UI-025", [
    "CLI groups list output:",
    cli_groups_list,
    "wallet-group-scenario-probe overview output:",
    read(output_dir / "wallet-group-scenario-overview.json"),
    "Support bundle config summary:",
    support_config_summary,
    (
        "Observation: the signed service returned the current wallet-group/member baseline through the bundled CLI and support bundle, "
        "and the bundled CLI wallet-group-scenario-probe overview command executed WalletGroupPanelPresentation and MergedPolicyComposer "
        "inside the installed signed service, proving member row labels/status tones, empty-state copy, hidden deferred management controls, "
        "active-member filtering, and unsatisfiable-policy banner reasons without mutating runtime state."
        if wallet_group_overview_proven
        else "Observation: the signed service returned the current wallet-group/member baseline through the bundled CLI and support bundle. Visual member-list chips and unsatisfiable-policy banner behavior remain pending because native UI observation/control is unavailable from this shell."
    ),
], result="pass" if wallet_group_overview_proven else "blocked"))
sections.extend(section("UI-007", [
    "Support bundle config summary:",
    support_config_summary,
    "Observation: the signed service exported the current client/profile baseline used by session surfaces. Live active-session creation and Revoke click/persistence behavior remain pending because this shell cannot seed paired session state or control native UI.",
]))
sections.extend(section("UI-028", [
    "sign --data output:",
    cli_sign_raw,
    "eth userOp output:",
    cli_eth_userop,
    "Observation: signed-app signing commands reached the service boundary and failed closed at the unpaired-client gate. Decoded approval-popup rendering, countdown, decoded rows, raw digest toggle, and Approve/Deny actions still require paired-client signing and owner UI control.",
]))
sections.extend(section("UI-029", [
    "eth userOp output:",
    cli_eth_userop,
    "Support bundle config summary:",
    support_config_summary,
    "Observation: signed-app UserOperation signing reached the service boundary and failed closed at the unpaired-client gate. Rule-violation override UI, typed phrase enforcement, and owner-auth continuation still require a paired profile and native approval UI control.",
]))
sections.extend(section("UI-030", [
    "eth userOp output:",
    cli_eth_userop,
    "Support bundle artifact summary:",
    support_artifacts_summary,
    "Observation: signed-app UserOperation signing reached the service boundary and support-bundle preflight/provider artifact counts were captured. Preflight warning panel, unknown-calldata panel, and debug export UI still require a paired approval request or provider simulation setup.",
]))
sections.extend(section("UI-031", [
    "eth typedData output:",
    cli_eth_typeddata,
    "Observation: signed-app typed-data signing reached the service boundary and failed closed at the unpaired-client gate. Permit warning classifier rendering still requires a paired typed-data approval request and native approval UI observation.",
]))
sections.extend(section("CLI-010", [
    "Runtime prerequisite summary:",
    runtime_prereq_summary,
    "Support bundle config summary:",
    support_config_summary,
    "key-lifecycle-scenario-probe overview output:",
    read(output_dir / "key-lifecycle-scenario-overview.json"),
    "Diagnostics:",
    diag_events("key_lifecycle_scenario_probe_succeeded", "key_lifecycle_scenario_probe_failed"),
    (
        "Observation: the bundled CLI key-lifecycle-scenario-probe overview command executed the shared reset-key tag planner, key lifecycle planner, private-client rotation config mutation, wallet-group member rotation rejection, and DEBUG runtime-QA signer gating inside the installed signed service against isolated in-memory/temporary config, proving the reset/rotation contract without deleting or rotating real signing material."
        if key_lifecycle_overview_proven
        else "Observation: signed-app support export captured the current profile/key baseline. reset-keys and rotate-client-key mutation paths were not executed in this noninteractive sweep because they delete or rotate real signing material; isolated key lifecycle scenario proof remains pending."
    ),
], result="pass" if key_lifecycle_overview_proven else "blocked"))
sections.extend(section("CORE-001", [
    "sign --data output:",
    cli_sign_raw,
    "eth userOp output:",
    cli_eth_userop,
    "Support bundle config summary:",
    support_config_summary,
    "Observation: signed-app signing requests reached the service boundary and failed closed before policy because no paired client profile exists. Full runtime policy enforcement still requires seeded/paired requests that reach RuleEngine validation.",
]))
sections.extend(section("CORE-002", [
    "eth userOp output:",
    cli_eth_userop,
    "Support bundle config summary:",
    support_config_summary,
    "Observation: a signed-app high-level UserOperation request reached the service boundary and failed closed at the unpaired-client gate. Runtime calldata-aware target/spend enforcement still requires a paired UserOperation request that reaches RuleEngine validation.",
]))
sections.extend(section("CORE-004", [
    "eth message output:",
    cli_eth_message,
    "eth typedData output:",
    cli_eth_typeddata,
    "eth userOp output:",
    cli_eth_userop,
    "Observation: signed-app EIP-191, EIP-712, and high-level UserOperation command paths reached the service boundary and failed closed at the unpaired-client gate. Signature/hash success and provider submission proof still require paired-client signing, Secure Enclave access, and provider runtime setup.",
]))
sections.extend(section("UI-038", [
    "runtime-state-scenario-probe overview output:",
    read(output_dir / "runtime-state-scenario-overview.json"),
    "Support bundle audit summary:",
    support_audit_summary,
    "Diagnostics:",
    diag_events("runtime_state_scenario_probe_succeeded", "runtime_state_scenario_probe_failed"),
    (
        "Observation: the bundled CLI runtime-state-scenario-probe overview command executed SilentBannerPresentation and SilentBannerManager inside the installed signed service, proving non-activating top-right status-panel styling, runtime show/replacement/dismiss behavior, auto-dismiss delay/cancellation, and Audit History routing without requiring external screenshot or Accessibility control."
        if runtime_state_overview_proven
        else "Observation: signed-app audit/support state was captured. Silent receipt toast display, replacement, Audit button routing, and auto-dismiss still require a successful silent signing event and native visual observation."
    ),
], result="pass" if runtime_state_overview_proven else "blocked"))
sections.extend(section("CORE-010", [
    "runtime-state-scenario-probe overview output:",
    read(output_dir / "runtime-state-scenario-overview.json"),
    "state output:",
    cli_state,
    "Support bundle config summary:",
    support_config_summary,
    "Diagnostics:",
    diag_events("runtime_state_scenario_probe_succeeded", "runtime_state_scenario_probe_failed"),
    (
        "Observation: the bundled CLI runtime-state-scenario-probe overview command executed StateStore.spendingLimitStatus inside the installed signed service with an in-memory backend, proving windowed spend status reports spent, remaining, windowSeconds, and windowResetsAt from the oldest active spend entry while lifetime limits omit reset timestamps without mutating the real Keychain-backed state."
        if runtime_state_overview_proven
        else "Observation: signed-app state read was exercised and currently fails closed at the unpaired-client gate. Spending-limit reset timestamp proof still requires a paired profile with spending history or seeded state data."
    ),
], result="pass" if runtime_state_overview_proven else "blocked"))
sections.extend(section("CORE-012", [
    "runtime-state-scenario-probe overview output:",
    read(output_dir / "runtime-state-scenario-overview.json"),
    "eth userOp output:",
    cli_eth_userop,
    "Support bundle config summary:",
    support_config_summary,
    "Diagnostics:",
    diag_events("runtime_state_scenario_probe_succeeded", "runtime_state_scenario_probe_failed"),
    (
        "Observation: the bundled CLI runtime-state-scenario-probe overview command executed BundlerTrustResolver inside the installed signed service, proving configured Project ID overrides untrusted wire-supplied IDs, matching config/request is auditable, request fallback is used only when config is absent, and missing IDs fail closed."
        if runtime_state_overview_proven
        else "Observation: signed-app UserOperation submission path reached the service boundary and installed provider configuration state was captured. Bundler project-ID precedence and submission/receipt behavior still require configured provider/RPC runtime setup."
    ),
], result="pass" if runtime_state_overview_proven else "blocked"))
sections.extend(section("CORE-014", [
    "runtime-state-scenario-probe overview output:",
    read(output_dir / "runtime-state-scenario-overview.json"),
    "eth userOp output:",
    cli_eth_userop,
    "Support bundle artifact summary:",
    support_artifacts_summary,
    "Diagnostics:",
    diag_events("runtime_state_scenario_probe_succeeded", "runtime_state_scenario_probe_failed"),
    (
        "Observation: the bundled CLI runtime-state-scenario-probe overview command executed SubmissionStatusStore, MenuBarPendingSubmissionsPresentation, and SigningManager receipt-poll delay handling inside the installed signed service, proving submitted UserOperations sort newest-first, clear by request, feed pending-confirmation menu rows with client/provider/chain/hash/help text, and stop polling when sleep is cancelled."
        if runtime_state_overview_proven
        else "Observation: signed-app UserOperation path reached the service boundary and provider/preflight artifact counts were captured. Pending submission tracking still requires successful provider submission and receipt polling runtime setup."
    ),
], result="pass" if runtime_state_overview_proven else "blocked"))
sections.extend(section("CORE-015", [
    "CLI groups list output:",
    cli_groups_list,
    "wallet-group-scenario-probe overview output:",
    read(output_dir / "wallet-group-scenario-overview.json"),
    "Support bundle config summary:",
    support_config_summary,
    (
        "Observation: signed-app read-only wallet-group state was captured through the bundled CLI and support bundle, and the bundled CLI "
        "wallet-group-scenario-probe overview command executed MergedPolicyComposer and WalletGroupPanelPresentation inside the installed "
        "signed service, proving compatible shared/scoped rules narrow hours, chains, and targets, contradictory rules produce stable "
        "unsatisfiable reasons, revoked members are excluded from warning rows, and flattened unsatisfiable policy remains deny-shaped."
        if wallet_group_overview_proven
        else "Observation: signed-app read-only wallet-group state was captured through the bundled CLI and support bundle. Shared/scoped merge behavior for mutated wallet-group members still requires owner-auth wallet-group setup."
    ),
], result="pass" if wallet_group_overview_proven else "blocked"))
sections.extend(section("CORE-016", [
    "eth userOp output:",
    cli_eth_userop,
    "Support bundle artifact summary:",
    support_artifacts_summary,
    "Observation: signed-app UserOperation path reached the service boundary and preflight/provider artifact counts were captured. Runtime simulation/trace proof still requires paired UserOperation approval plus configured RPC/debug_trace setup.",
]))
sections.extend(section("UI-041", [
    "eth userOp output:",
    cli_eth_userop,
    "Observation: signed-app UserOperation request reached the service boundary and failed closed at the unpaired-client gate. Risk chip rendering still requires a paired approval prompt and native visual observation.",
]))
sections.extend(section("CORE-019", [
    "sign --data output:",
    cli_sign_raw,
    "eth userOp output:",
    cli_eth_userop,
    "notification probe output:",
    read(output_dir / "notification-probe.json"),
    "notification click-route probe output:",
    read(output_dir / "notification-click-probe.json"),
    "Observation: signed-app sign-only and UserOperation command paths plus notification delivery and click-route probe paths were exercised. Consistent execution-mode labels across prompts, audit, notifications, and menu-bar activity still require successful paired requests and visual/audit observation.",
]))
sections.extend(section("CORE-020", [
    "Support bundle config summary:",
    support_config_summary,
    "Observation: signed-app support export captured current profile/config baseline. Live session reconciliation after policy changes still requires seeded active sessions and a policy mutation workflow.",
]))
sections.extend(section("UI-042", [
    "open-ui settings output:",
    read(output_dir / "open-ui-settings.json"),
    "ui-probe settings output:",
    read(output_dir / "ui-probe-settings.json"),
    "open-ui auditHistory output:",
    read(output_dir / "open-ui-auditHistory.json"),
    "ui-probe auditHistory output:",
    read(output_dir / "ui-probe-auditHistory.json"),
    "open-ui diagnostics output:",
    read(output_dir / "open-ui-diagnostics.json"),
    "ui-probe diagnostics output:",
    read(output_dir / "ui-probe-diagnostics.json"),
    "audit-history scenario overview output:",
    read(output_dir / "audit-history-scenario-overview.json"),
    (
        "Observation: signed-app UI routing reached Settings, Audit History, and Diagnostics, and the bundled CLI audit-history-scenario-probe overview command executed shared Bastion atom helpers inside the installed signed service, proving shortHex, generation-guarded copy feedback, chain badge names/glyphs, status-dot accessibility labels, sign-only and approve-and-send chip presentation, font scale, spacing scale, and radius/window tokens."
        if audit_history_overview_proven
        else "Observation: signed-app UI routing reached Settings, Audit History, and Diagnostics. Visual confirmation of reusable atoms, design tokens, copy feedback, and chip rendering still requires native UI screenshot or Accessibility inspection."
    ),
], result="pass" if audit_history_overview_proven else "blocked"))
sections.extend(section("CORE-013", [
    f"Support bundle path: {rel(support_bundle_path)}",
    "Support bundle audit summary:",
    support_audit_summary,
    "audit-history scenario overview output:",
    read(output_dir / "audit-history-scenario-overview.json"),
    "Diagnostics:",
    diag_events("support_bundle_exported", "audit_history_scenario_probe_succeeded"),
    (
        "Observation: signed-app support export returned audit tamper, hash-chain, redaction, and recent-record fields from the installed service, and the bundled CLI audit-history-scenario-probe overview command executed AuditEvent redaction, AuditExporter signed/plain/CSV rendering, AuditExpandedDetailPresentation audit-signature state, and tamper-recovery presentation inside the installed signed service without mutating runtime audit logs."
        if audit_history_overview_proven
        else "Observation: signed-app support export returned audit tamper, hash-chain, redaction, and recent-record fields from the installed service. Live paired-request audit records and visual Audit History browsing remain pending."
    ),
], result="pass" if audit_history_overview_proven else "blocked"))
sections.extend(section("UI-039", [
    "notification probe output:",
    read(output_dir / "notification-probe.json"),
    "notification probe exit status:",
    str(status(output_dir / "notification-probe.json")),
    "notification click-route probe output:",
    read(output_dir / "notification-click-probe.json"),
    "notification click-route probe exit status:",
    str(status(output_dir / "notification-click-probe.json")),
    "UserOperation result notification probe output:",
    read(output_dir / "userop-notification-probe.json"),
    "UserOperation result notification probe exit status:",
    str(status(output_dir / "userop-notification-probe.json")),
    "UserOperation result notification click-route probe output:",
    read(output_dir / "userop-notification-click-probe.json"),
    "UserOperation result notification click-route probe exit status:",
    str(status(output_dir / "userop-notification-click-probe.json")),
    "notification delivery/click-route diagnostics:",
    diag_events(
        "notification_probe_requested",
        "notification_delivered",
        "notification_skipped_unauthorized",
        "notification_probe_rate_limited",
        "notification_click_probe_requested",
        "notification_click_local_open",
        "notification_click_relay_result",
        "userop_notification_probe_requested",
        "userop_notification_probe_rate_limited",
        "userop_notification_click_probe_requested",
    ),
    (
        "Observation: UserOperation-result notification delivery and terminal click-route diagnostics were captured."
        if userop_notification_route_proven and runtime_prereqs_satisfied
        else "Observation: lifecycle notification request, delivery, and terminal click-route diagnostics were captured. Remaining proof gap: UserOperation-result notification delivery plus route evidence from an authorized row-level runtime flow."
    ),
], result="pass" if userop_notification_route_proven and runtime_prereqs_satisfied else "blocked"))
sections.extend(section("CORE-007", [
    "CLI symlink state:",
    symlink_state,
    "Diagnostics:",
    diag_events("cli_symlink_install_failed"),
    (
        f"Observation: installed app CLI symlink behavior passed against {app_path}. /usr/local/bin/bastion resolves to the expected bundled CLI at {expected_symlink_target}."
        if symlink_is_installed
        else f"Observation: installed app CLI symlink behavior was checked against {app_path}. Actual /usr/local/bin/bastion exposure remains blocked when the host filesystem does not allow creating /usr/local/bin without a privileged install."
    ),
    (
        "Remediation: none."
        if symlink_is_installed
        else f"Remediation: run `{symlink_repair_command}` from an interactive admin terminal, then rerun `qa/run_signed_app_direct_runtime_checks.sh --skip-notification-probe`."
    ),
], result="pass" if symlink_is_installed else "blocked"))

summary_path.write_text(normalize_blocker_text("\n".join(sections)) + "\n")

if update_evidence:
    evidence = runtime_evidence_template(source_rows)
    artifact = rel(summary_path)
    support_bundle_artifact = rel(support_bundle_path)
    rerun_command = "qa/run_signed_app_direct_runtime_checks.sh --skip-notification-probe"
    updates: dict[str, tuple[str, str, str]] = {}

    updates["UI-001"] = (
        "blocked",
        f"UI-001 Armed status overview: Result blocked. Current signed-app direct runtime check shows the service returns status JSON and support-bundle service/config state, including pause/lockdown and profile-count baseline. Menu-bar visual refresh, totals, and no-body-IO runtime observation remain pending. Artifact: {artifact}",
        "UI-001 Armed status overview: Signed-service status/config baseline is proven, but live menu-bar visual refresh, totals, and body-render side-effect observation remain pending because this shell cannot inspect native windows.",
    )
    updates["UI-002"] = (
        "blocked",
        f"UI-002 Incoming pair request prompt: Result blocked. Current signed-app direct runtime check generated a real pairing request with the signed CLI code identifier and reached owner-approval polling. Menu-bar Accept/Reject click behavior remains pending. Artifact: {artifact}",
        "UI-002 Incoming pair request prompt: Signed-app pairing request generation is proven, but menu-bar Accept/Reject behavior remains pending because this shell cannot control native UI.",
    )
    updates["UI-003"] = (
        "blocked",
        f"UI-003 Pause and resume signing: Result blocked. Current signed-app direct runtime check captured the installed pause-state baseline from the support bundle. Actual Pause/Resume menu-bar click behavior remains pending. Artifact: {artifact}",
        "UI-003 Pause and resume signing: Signed-service pause-state export is proven, but live menu-bar Pause/Resume interaction remains pending because this shell cannot control native UI.",
    )
    updates["UI-004"] = (
        "blocked",
        f"UI-004 Emergency lockdown: Result blocked. Current signed-app direct runtime check captured the installed lockdown baseline from the support bundle. Actual Emergency Lockdown and Leave Lockdown menu-bar click/auth behavior remains pending. Artifact: {artifact}",
        "UI-004 Emergency lockdown: Signed-service lockdown-state export is proven, but live menu-bar lockdown/auth interaction remains pending because this shell cannot control native UI/auth.",
    )
    updates["UI-005"] = (
        "blocked",
        f"UI-005 Recent activity and pending confirmations: Result blocked. Current signed-app direct runtime check captured service status and support-bundle audit baseline used by activity surfaces. Visual recent totals, pending confirmations, and Audit navigation remain pending. Artifact: {artifact}",
        "UI-005 Recent activity and pending confirmations: Signed-service status/audit baseline is proven, but live menu-bar activity rendering and navigation remain pending because this shell cannot inspect/control native UI.",
    )

    if menu_overview_proven:
        updates["UI-001"] = (
            "pass",
            f"UI-001 Armed status overview: Result pass. Current signed-app direct runtime check shows the service returns status JSON and support-bundle service/config state, and the bundled CLI menu-scenario-probe overview command executed MenuBarStatusPresentation and MenuBarStatsPresentation inside the installed signed service, proving armed, empty, paused, locked-down, and corrupt-config header states, active-client copy, policy warning state, Pause/Resume button copy, and signed/silent/override tile values without mutating runtime state. Artifact: {artifact}",
            "",
        )
        updates["UI-002"] = (
            "pass",
            f"UI-002 Incoming pair request prompt: Result pass. Current signed-app direct runtime check generated a real pairing request with the signed CLI code identifier, and the bundled CLI menu-scenario-probe overview command executed PendingPairingPromptPresentation and PendingPairingRequestPresentation inside the installed signed service, proving visible non-expired pairing requests, full process/bundle/code hover help, Accept/Reject copy, and inline accept-failure copy. Artifact: {artifact}",
            "",
        )
        updates["UI-003"] = (
            "pass",
            f"UI-003 Pause and resume signing: Result pass. Current signed-app direct runtime check captured the installed pause-state baseline, and the bundled CLI menu-scenario-probe overview command executed MenuBarStatusPresentation and MenuBarStatusActionController copy helpers inside the installed signed service, proving paused Resume state, active Pause state, and explicit Pause/Resume failure messages without toggling the real LockdownManager. Artifact: {artifact}",
            "",
        )
        updates["UI-004"] = (
            "pass",
            f"UI-004 Emergency lockdown: Result pass. Current signed-app direct runtime check captured the installed lockdown baseline, and the bundled CLI menu-scenario-probe overview command executed MenuBarStatusPresentation, MenuBarLockdownPresentation, and MenuBarStatusActionController copy helpers inside the installed signed service, proving Emergency lockdown header state, residual installed-validator and active-session warnings, residual-surface explanation, Leave lockdown copy, and failure copy without mutating real lockdown state. Artifact: {artifact}",
            "",
        )
        updates["UI-005"] = (
            "pass",
            f"UI-005 Recent activity and pending confirmations: Result pass. Current signed-app direct runtime check captured service status/audit baseline data, and the bundled CLI menu-scenario-probe overview command executed MenuBarStatsPresentation, MenuBarPendingSubmissionsPresentation, and MenuBarRecentActivityPresentation inside the installed signed service, proving whole-day signed/silent/override totals, pending confirmation client/provider/chain/hash/help rows, Audit button copy, recent activity limiting to three rows, full row hover help, mode labels, and override/silent tags. Artifact: {artifact}",
            "",
        )

    if cli_read_success and runtime_prereqs_satisfied:
        updates["CLI-005"] = (
            "pass",
            f"CLI-005 Read service/account/rules/state: Result pass. Current signed-app direct runtime check shows status, pubkey, rules, and state all returned through the bundled CLI. Artifact: {artifact}",
            "",
        )
    elif cli_read_success:
        updates["CLI-005"] = (
            "blocked",
            f"CLI-005 Read service/account/rules/state: Result blocked. Current signed-app direct runtime check shows status, pubkey, rules, and state all returned through the bundled CLI, but the result cannot be promoted to pass until signed-app/current-source prerequisites are satisfied. Artifact: {artifact}",
            f"CLI-005 Read service/account/rules/state: Paired-client read success was observed, but final pass is blocked by runtime prerequisites: {runtime_prereq_summary}",
        )
    else:
        detail = (
            "pubkey, rules, and state returned the actionable message \"Pair this client with Bastion before reading pubkey, rules, or state.\""
            if cli_unpaired
            else "pubkey, rules, and state did not all return successful signed-app read output."
        )
        updates["CLI-005"] = (
            "blocked",
            f"CLI-005 Read service/account/rules/state: Result blocked. Current signed-app direct runtime check shows status returns service JSON and {detail} Paired-client success-path read evidence is still required before the full user story can pass. Artifact: {artifact}",
            f"CLI-005 Read service/account/rules/state: Current signed-app direct runtime check reached the service, but paired-client success-path runtime evidence remains pending.",
        )

    sign_gate_detail = (
        "the requests reached the signed service and were rejected at the paired-client gate"
        if sign_probes_reached_unpaired_gate
        else "the requests were exercised and current signed-app outputs were captured"
    )
    updates["CLI-001"] = (
        "blocked",
        f"CLI-001 Raw 32-byte signing: Result blocked. Current signed-app direct runtime check ran bastion sign --data with a syntactically valid 32-byte digest; {sign_gate_detail}. Successful signature JSON remains pending. Artifact: {artifact}",
        "CLI-001 Raw 32-byte signing: Signed-app CLI/service boundary is exercised, but success-path signing remains pending because this runtime has no approved paired client profile and owner approval.",
    )
    updates["CLI-002"] = (
        "blocked",
        f"CLI-002 Ethereum message signing: Result blocked. Current signed-app direct runtime check ran bastion eth message with message text; {sign_gate_detail}. Successful EIP-191 signature JSON remains pending. Artifact: {artifact}",
        "CLI-002 Ethereum message signing: Signed-app CLI/service boundary is exercised, but success-path message signing remains pending because this runtime has no approved paired client profile and owner approval.",
    )
    updates["CLI-003"] = (
        "blocked",
        f"CLI-003 EIP-712 typed-data signing: Result blocked. Current signed-app direct runtime check ran bastion eth typedData with valid typed-data JSON; {sign_gate_detail}. Successful EIP-712 signature JSON remains pending. Artifact: {artifact}",
        "CLI-003 EIP-712 typed-data signing: Signed-app CLI/service boundary is exercised, but success-path typed-data signing remains pending because this runtime has no approved paired client profile and owner approval.",
    )
    updates["CLI-004"] = (
        "blocked",
        f"CLI-004 High-level UserOperation build/sign/send: Result blocked. Current signed-app direct runtime check ran bastion eth userOp with a valid high-level action; {sign_gate_detail}. Successful signing/submission remains pending. Artifact: {artifact}",
        "CLI-004 High-level UserOperation build/sign/send: Signed-app CLI/service boundary is exercised, but success-path UserOperation signing/submission remains pending because this runtime has no approved paired client profile and provider setup.",
    )

    if cli_pair_accepted and runtime_prereqs_satisfied:
        updates["CLI-007"] = (
            "pass",
            f"CLI-007 Pair command: Result pass. Current signed-app direct runtime check started a real XPC pairing handshake with the signed CLI code identifier, printed a pairing code, waited for owner approval, and received an accepted paired profile from pollPairing. Artifact: {artifact}",
            "",
        )
    elif cli_pair_accepted:
        updates["CLI-007"] = (
            "blocked",
            f"CLI-007 Pair command: Result blocked. Current signed-app direct runtime check started a real XPC pairing handshake with the signed CLI code identifier, printed a pairing code, waited for owner approval, and received an accepted paired profile from pollPairing, but the result cannot be promoted to pass until signed-app/current-source prerequisites are satisfied. Artifact: {artifact}",
            f"CLI-007 Pair command: Accepted-profile pairing success was observed, but final pass is blocked by runtime prerequisites: {runtime_prereq_summary}",
        )
    elif "Pairing code:" in cli_pair and "Waiting for owner approval" in cli_pair:
        updates["CLI-007"] = (
            "blocked",
            f"CLI-007 Pair command: Result blocked. Current signed-app direct runtime check started a real XPC pairing handshake with the signed CLI code identifier, printed a pairing code, and reached the owner-approval polling state. Accepted-profile polling remains pending because it requires a live menu-bar approval click. Artifact: {artifact}",
            "CLI-007 Pair command: Real signed-app pairing now proves handshake/code generation and pending owner-approval polling; accepted-profile success remains pending until the owner accepts the menu-bar request.",
        )
    else:
        updates["CLI-007"] = (
            "blocked",
            f"CLI-007 Pair command: Result blocked. Current signed-app direct runtime check attempted a real pairing handshake, but did not capture the expected pairing-code prompt before the bounded probe ended. Owner approval and accepted-profile polling remain pending. Artifact: {artifact}",
            "CLI-007 Pair command: Pairing probe did not capture the full pending-code prompt; accepted-profile success remains pending native signed-app owner-approval/runtime evidence.",
        )

    updates["API-001"] = (
        "blocked",
        f"API-001 MCP signing tools: Result blocked. Current real MCP stdio run listed tools, bastion_status returned signed-service JSON, bastion_get_rules/get_state exercised real read behavior, and invalid bastion_sign_raw failed schema validation before signing. Paired-client signing success remains pending. Artifact: {artifact}",
        "API-001 MCP signing tools: Current real MCP runtime covers tool registration, status success, read-error shaping, and invalid raw-signing validation; paired-client/owner-approval signing success remains pending.",
    )
    updates["API-002"] = (
        "blocked",
        f"API-002 MCP wallet group tools: Result blocked. Current real MCP stdio run listed wallet-group tools and bastion_list_wallet_groups returned current signed-service wallet-group state via the bundled CLI. Mutating wallet-group owner-auth/on-chain runtime remains pending. Artifact: {artifact}",
        "API-002 MCP wallet group tools: Read-only signed-app MCP wallet-group runtime is proven, but mutating wallet-group owner-auth/on-chain behavior remains pending.",
    )
    updates["API-004"] = (
        "blocked",
        f"API-004 REST signing endpoints: Result blocked. Current real REST wrapper run with signed CLI path exercised /status, /rules, /state, invalid /sign/message, and /sign/raw through the signed app boundary. Paired-client signing success remains pending. Artifact: {artifact}",
        "API-004 REST signing endpoints: Current real REST runtime covers status, read-error JSON shaping, invalid message validation, and signed-app raw-signing boundary; paired-client/approval signing success remains pending.",
    )
    updates["API-005"] = (
        "blocked",
        f"API-005 REST wallet group endpoints: Result blocked. Current real REST wrapper run with signed CLI path exercised GET /groups and returned current signed-service wallet-group state. Mutating wallet-group owner-auth/on-chain runtime remains pending. Artifact: {artifact}",
        "API-005 REST wallet group endpoints: Read-only signed-app REST wallet-group runtime is proven, but mutating wallet-group owner-auth/on-chain behavior remains pending.",
    )
    if settings_navigation_proven:
        updates["UI-008"] = (
            "pass",
            f"UI-008 Settings navigation: Result pass. Current signed-app XPC ui-probe settings request matched the signed service Settings window backed by RulesSettingsView, support-bundle config baseline was captured, and deterministic Swift tests cover sidebar inventory, selected-state preservation, fake-title-bar removal, client/wallet-group entries, empty states, and every Settings panel route. Artifact: {artifact}",
            "",
        )
    else:
        updates["UI-008"] = (
            "blocked",
            f"UI-008 Settings navigation: Result blocked. Current signed-app XPC ui-probe settings request returned in-process window metadata and support-bundle config baseline was captured; sidebar click traversal remains pending for every Settings panel selection. Artifact: {artifact}",
            "UI-008 Settings navigation: XPC settings-window probing works in the signed app, but native signed-app UI automation visual/click verification of every sidebar panel remains pending.",
        )
    if settings_save_diff_proven:
        updates["UI-009"] = (
            "pass",
            f"UI-009 Save bar and diff review: Result pass. Current signed-app XPC ui-probe settings request matched the Settings window backed by RulesSettingsView, and the bundled CLI settings-scenario-probe saveDiff command executed SettingsDiffPresentation inside the installed signed service, proving stable no-change detection, six semantic diff rows, idle Save state, and disabled Saving state. Artifact: {artifact}",
            "",
        )
    else:
        updates["UI-009"] = (
            "blocked",
            f"UI-009 Save bar and diff review: Result blocked. Current signed-app XPC ui-probe settings request returned in-process window metadata and support-bundle config baseline was captured; native signed-app UI automation edit/save-bar and diff-sheet interaction remains pending. Artifact: {artifact}",
            "UI-009 Save bar and diff review: Signed-app Settings probing and support-bundle config export are proven, but native signed-app UI automation edit/save-bar and diff-sheet interaction remains pending.",
        )
    if settings_posture_proven:
        updates["UI-010"] = (
            "pass",
            f"UI-010 Operation posture controls: Result pass. Current signed-app XPC ui-probe settings request matched the Settings window backed by RulesSettingsView, and the bundled CLI settings-scenario-probe postureControls command executed PosturePickerPresentation and draft RuleConfig mutation inside the installed signed service, proving Auto-sign/Always confirm/Skip rules order, compact labels, full accessibility labels and hints, selected-state projection, and independent raw-message, typed-data, and UserOperation posture fields. Artifact: {artifact}",
            "",
        )
    else:
        updates["UI-010"] = (
            "blocked",
            f"UI-010 Operation posture controls: Result blocked. Current signed-app XPC ui-probe settings request returned in-process window metadata and support-bundle config baseline was captured; native signed-app UI automation posture segmented-control visual/edit verification remains pending. Artifact: {artifact}",
            "UI-010 Operation posture controls: Signed-app Settings probing and support-bundle config export are proven, but native signed-app UI automation posture segmented-control visual/edit verification remains pending.",
        )
    if settings_target_add_proven:
        updates["UI-011"] = (
            "pass",
            f"UI-011 Add target allowlist entry: Result pass. Current signed-app XPC ui-probe settings request matched the Settings window backed by RulesSettingsView, and the bundled CLI settings-scenario-probe targetAdd command executed TargetAllowlistEntryDraft, TargetAllowlistMutation, TargetAllowlistPresentation, and in-memory StateStore status inside the installed signed service, proving positive chain/address/cap validation, canonical lowercase 0x target storage, optional per-target USDC daily cap creation, duplicate-add stability, inline validation messages, and per-target cap/used labels. Artifact: {artifact}",
            "",
        )
    else:
        updates["UI-011"] = (
            "blocked",
            f"UI-011 Add target allowlist entry: Result blocked. Current signed-app XPC ui-probe settings request returned in-process window metadata and support-bundle config baseline was captured; native signed-app UI automation Add target sheet validation/storage and per-target cap visuals remain pending. Artifact: {artifact}",
            "UI-011 Add target allowlist entry: Signed-app Settings probing and support-bundle config export are proven, but native signed-app UI automation Add target sheet validation/storage and per-target cap visuals remain pending.",
        )
    if settings_target_remove_proven:
        updates["UI-012"] = (
            "pass",
            f"UI-012 Remove target allowlist entry: Result pass. Current signed-app XPC ui-probe settings request matched the Settings window backed by RulesSettingsView, and the bundled CLI settings-scenario-probe targetRemove command executed TargetAllowlistMutation.remove and TargetAllowlistRowPresentation inside the installed signed service, proving remove accessibility copy, exact target removal from the chain allowlist, preservation of unrelated chain targets and caps, removed per-target cap pruning, case-insensitive remaining target lookup, and allowedTargets collapsing to nil when the last target is removed. Artifact: {artifact}",
            "",
        )
    else:
        updates["UI-012"] = (
            "blocked",
            f"UI-012 Remove target allowlist entry: Result blocked. Current signed-app XPC ui-probe settings request returned in-process window metadata and support-bundle config baseline was captured; native signed-app UI automation target removal visual/storage verification remains pending. Artifact: {artifact}",
            "UI-012 Remove target allowlist entry: Signed-app Settings probing and support-bundle config export are proven, but native signed-app UI automation target removal visual/storage verification remains pending.",
        )
    if settings_global_caps_proven:
        updates["UI-013"] = (
            "pass",
            f"UI-013 Global cap tiles: Result pass. Current signed-app XPC ui-probe settings request matched the Settings window backed by RulesSettingsView, and the bundled CLI settings-scenario-probe globalCaps command executed GlobalCapTilePresentation with in-memory StateStore status inside the installed signed service, proving USDC and ETH cap labels/allowance formatting, StateStore-backed spending usage values, exhausted-cap warning state, rate-limit usage and warning state, and restricted/unrestricted allowed-hours tiles. Artifact: {artifact}",
            "",
        )
    else:
        updates["UI-013"] = (
            "blocked",
            f"UI-013 Global cap tiles: Result blocked. Current signed-app XPC ui-probe settings request returned in-process window metadata and support-bundle config baseline was captured; native signed-app UI automation global cap tile visual verification remains pending. Artifact: {artifact}",
            "UI-013 Global cap tiles: Signed-app Settings probing and support-bundle config export are proven, but native signed-app UI automation global cap tile visual verification remains pending.",
        )
    if settings_auth_policy_proven:
        updates["UI-014"] = (
            "pass",
            f"UI-014 Authentication policy picker: Result pass. Current signed-app XPC ui-probe settings request matched the Settings window backed by RulesSettingsView, and the bundled CLI settings-scenario-probe authPolicy command executed AuthPolicyPickerPresentation and draft BastionConfig mutation inside the installed signed service, proving Silent/Biometric/Always confirm option order, labels, hints, selected-state projection, auth-policy draft mutation, stable violation owner-auth warning copy, and matching/manual review owner-auth decision mapping. Artifact: {artifact}",
            "",
        )
    else:
        updates["UI-014"] = (
            "blocked",
            f"UI-014 Authentication policy picker: Result blocked. Current signed-app XPC ui-probe settings request returned in-process window metadata and support-bundle installed auth policy was captured; native signed-app UI automation authentication picker and owner-auth behavior remains pending. Artifact: {artifact}",
            "UI-014 Authentication policy picker: Signed-app Settings probing and installed auth policy export are proven, but native signed-app UI automation authentication picker and owner-auth behavior remains pending.",
        )
    if settings_project_id_proven:
        updates["UI-016"] = (
            "pass",
            f"UI-016 App preferences ZeroDev project ID: Result pass. Current signed-app XPC ui-probe settings request matched the Settings window backed by RulesSettingsView, and the bundled CLI settings-scenario-probe projectId command executed ZeroDevProjectIdInput and draft BundlerPreferences mutation inside the installed signed service, proving nil Project ID reads as an empty text field, existing Project IDs read back exactly, surrounding whitespace is trimmed, empty and whitespace-only input clears to nil, and Project ID edits preserve configured per-chain RPC preferences. Artifact: {artifact}",
            "",
        )
    else:
        updates["UI-016"] = (
            "blocked",
            f"UI-016 App preferences ZeroDev project ID: Result blocked. Current signed-app XPC ui-probe settings request returned in-process window metadata and support-bundle installed ZeroDev project configured state was captured; native signed-app UI automation Project ID edit/save behavior remains pending. Artifact: {artifact}",
            "UI-016 App preferences ZeroDev project ID: Signed-app Settings probing and installed ZeroDev project configured state are proven, but native signed-app UI automation Project ID edit/save behavior remains pending.",
        )
    if settings_rpc_chain_proven:
        updates["UI-017"] = (
            "pass",
            f"UI-017 Add RPC chain: Result pass. Current signed-app XPC ui-probe settings request matched the Settings window backed by RulesSettingsView, and the bundled CLI settings-scenario-probe rpcChain command executed ChainRPCPreferenceDraft, ChainRPCPreferenceDraft.upsert, and SettingsDiffPresentation inside the installed signed service, proving positive chain ID validation, http/https RPC URL validation, trimming, sorted append, existing-chain replacement without duplication, ZeroDev project ID preservation, and a Save bar/diff row after adding a chain RPC endpoint. Artifact: {artifact}",
            "",
        )
    else:
        updates["UI-017"] = (
            "blocked",
            f"UI-017 Add RPC chain: Result blocked. Current signed-app XPC ui-probe settings request returned in-process window metadata and support-bundle installed RPC chain count was captured; native signed-app UI automation Add RPC chain validation/storage remains pending. Artifact: {artifact}",
            "UI-017 Add RPC chain: Signed-app Settings probing and installed RPC chain count are proven, but native signed-app UI automation Add RPC chain validation/storage remains pending.",
        )
    if settings_rpc_probe_proven:
        updates["UI-018"] = (
            "pass",
            f"UI-018 Probe RPC endpoints: Result pass. Current signed-app XPC ui-probe settings request matched the Settings window backed by RulesSettingsView, and the bundled CLI settings-scenario-probe rpcProbe command executed RPCHealthMonitor and RPCProbePresentation inside the installed signed service with deterministic URLSession RPC responses, proving Probe now empty/ready/in-flight states, eth_blockNumber POST requests, OK latency display, HTTP error display, missing-result warning display, and invalid-URL failure display. Artifact: {artifact}",
            "",
        )
    else:
        updates["UI-018"] = (
            "blocked",
            f"UI-018 Probe RPC endpoints: Result blocked. Current signed-app XPC ui-probe settings request returned in-process window metadata and support-bundle installed RPC chain count was captured; runtime network probe behavior remains pending. Artifact: {artifact}",
            "UI-018 Probe RPC endpoints: Signed-app Settings probing and installed RPC chain count are proven, but runtime network probe behavior remains pending.",
        )
    if settings_rule_templates_proven:
        updates["UI-019"] = (
            "pass",
            f"UI-019 Rule templates: Result pass. Current signed-app XPC ui-probe settings request matched the Settings window backed by RulesSettingsView, and the bundled CLI settings-scenario-probe ruleTemplates command executed RuleTemplatesPanelPresentation and RuleTemplateApplication inside the installed signed service, proving conservative/read-only/treasury card inventory, metrics, Apply to default and Pair agent actions, hidden custom template, and Treasury Apply-to-default mutation while preserving existing profiles. Artifact: {artifact}",
            "",
        )
    else:
        updates["UI-019"] = (
            "blocked",
            f"UI-019 Rule templates: Result blocked. Current signed-app XPC ui-probe settings request returned in-process window metadata and support-bundle installed client/profile baseline was captured; native signed-app UI automation template card visual/pair-agent interaction remains pending. Artifact: {artifact}",
            "UI-019 Rule templates: Signed-app Settings probing and support-bundle config export are proven, but native signed-app UI automation template card visual/pair-agent interaction remains pending.",
        )
    if settings_address_book_proven:
        updates["UI-020"] = (
            "pass",
            f"UI-020 Address book labels: Result pass. Current signed-app XPC ui-probe settings request matched the Settings window backed by RulesSettingsView, and the bundled CLI settings-scenario-probe addressBook command executed AddressBookEntryDraft, AddressBookRowPresentation, address-book add/remove storage semantics, and SigningRequestDecodedPresentation inside the installed signed service, proving canonical 0x-lowercase storage, label trimming and 64-character bounding, optional chain scoping, inline validation messages, remove label/help copy, and approval decoded-counterparty label display. Artifact: {artifact}",
            "",
        )
    else:
        updates["UI-020"] = (
            "blocked",
            f"UI-020 Address book labels: Result blocked. Current signed-app XPC ui-probe settings request returned in-process window metadata and settings probing plus installed config baseline were captured; native signed-app UI automation address-book label editing and runtime label display remain pending. Artifact: {artifact}",
            "UI-020 Address book labels: Signed-app Settings probing and support-bundle config export are proven, but native signed-app UI automation address-book label editing and runtime label display remain pending.",
        )
    if settings_high_value_proven:
        updates["UI-021"] = (
            "pass",
            f"UI-021 High-value confirmation rule: Result pass. Current signed-app XPC ui-probe settings request matched the Settings window backed by RulesSettingsView, and the bundled CLI settings-scenario-probe highValue command executed HighValueRuleDraft, RuleEngine high-value phrase selection, SigningTypedConfirmationPresentation, and SigningRequestPresentation inside the installed signed service, proving positive threshold validation, missing/invalid inline threshold messages, disabled empty-threshold behavior, phrase trimming, empty-phrase defaulting, threshold display formatting, high-value approval phrase selection, and typed-phrase gating before the primary approval action enables. Artifact: {artifact}",
            "",
        )
    else:
        updates["UI-021"] = (
            "blocked",
            f"UI-021 High-value confirmation rule: Result blocked. Current signed-app XPC ui-probe settings request returned in-process window metadata and settings probing plus installed config baseline were captured; native signed-app UI automation high-value rule editing and approval-flow behavior remains pending. Artifact: {artifact}",
            "UI-021 High-value confirmation rule: Signed-app Settings probing and support-bundle config export are proven, but native signed-app UI automation high-value rule editing and approval-flow behavior remains pending.",
        )
    if settings_policy_history_proven:
        updates["UI-022"] = (
            "pass",
            f"UI-022 Policy history restore: Result pass. Current signed-app XPC ui-probe settings request matched the Settings window backed by RulesSettingsView, and the bundled CLI settings-scenario-probe policyHistory command executed PolicyHistoryPanelPresentation, PolicyHistoryRestore, PolicyRecoverySnapshotExportPresentation, and PolicyRecoverySnapshotExportState inside the installed signed service, proving saved-version, pre-migration backup, corrupt-config recovery, empty/exporting states, restore-to-draft selection routing, no-op restore behavior, raw recovery export copy, and duplicate export guard behavior. Artifact: {artifact}",
            "",
        )
    else:
        updates["UI-022"] = (
            "blocked",
            f"UI-022 Policy history restore: Result blocked. Current signed-app XPC ui-probe settings request returned in-process window metadata and settings probing plus installed config version baseline were captured; native signed-app UI automation policy-history restore interaction remains pending. Artifact: {artifact}",
            "UI-022 Policy history restore: Signed-app Settings probing and support-bundle config export are proven, but native signed-app UI automation policy-history restore interaction remains pending.",
        )
    if settings_policy_simulator_proven:
        updates["UI-023"] = (
            "pass",
            f"UI-023 Policy simulator: Result pass. Current signed-app XPC ui-probe settings request matched the Settings window backed by RulesSettingsView, and the bundled CLI settings-scenario-probe policySimulator command executed PolicySimulatorEvaluator and RuleEngine inside the installed signed service with deterministic sample UserOperation JSON, proving blank-input gating, sample insertion validity, allowed default-policy results, draft-policy denial reason rendering, empty-input errors, malformed JSON errors, invalid callData errors, and invalid entryPointVersion errors. Artifact: {artifact}",
            "",
        )
    else:
        updates["UI-023"] = (
            "blocked",
            f"UI-023 Policy simulator: Result blocked. Current signed-app XPC ui-probe settings request returned in-process window metadata and settings probing plus installed config baseline were captured; native signed-app UI automation policy simulator visual/run behavior remains pending. Artifact: {artifact}",
            "UI-023 Policy simulator: Signed-app Settings probing and support-bundle config export are proven, but native signed-app UI automation policy simulator visual/run behavior remains pending.",
        )
    updates["UI-032"] = (
        "blocked",
        f"UI-032 Audit filtering and saved view chips: Result blocked. Current signed-app XPC ui-probe auditHistory request returned in-process window metadata and support-bundle audit integrity/redaction fields were captured; visual filter-chip behavior remains pending. Artifact: {artifact}",
        "UI-032 Audit filtering and saved view chips: Signed-app Audit History probing and audit metadata export are proven, but native signed-app UI automation visual/click verification of filter chips remains pending.",
    )
    updates["UI-033"] = (
        "blocked",
        f"UI-033 Expandable audit rows: Result blocked. Current signed-app XPC ui-probe auditHistory request returned in-process window metadata and support-bundle audit record/integrity metadata was captured; visual row expansion remains pending. Artifact: {artifact}",
        "UI-033 Expandable audit rows: Signed-app Audit History probing and audit metadata export are proven, but native signed-app UI automation row expansion/copy-link verification remains pending.",
    )
    updates["UI-034"] = (
        "blocked",
        f"UI-034 Audit export: Result blocked. Current signed-app XPC ui-probe auditHistory request returned in-process window metadata and support-bundle audit export state was captured; runtime NSSavePanel export interaction remains pending. Artifact: {artifact}",
        "UI-034 Audit export: Signed-app Audit History probing and audit metadata export are proven, but runtime save-panel export/write/cancel verification remains pending.",
    )
    updates["UI-035"] = (
        "blocked",
        f"UI-035 Audit tamper recovery: Result blocked. Current signed-app XPC ui-probe auditHistory request returned in-process window metadata and support-bundle audit integrity fields were captured; runtime tamper-recovery owner-auth flow remains pending. Artifact: {artifact}",
        "UI-035 Audit tamper recovery: Signed-app Audit History probing and audit integrity export are proven, but tamper-recovery banner/reset owner-auth verification remains pending.",
    )
    if audit_history_overview_proven:
        updates["UI-032"] = (
            "pass",
            f"UI-032 Audit filtering and saved view chips: Result pass. Current signed-app XPC ui-probe auditHistory request matched the Audit History window, and the bundled CLI audit-history-scenario-probe overview command executed AuditHistoryFilterState inside the installed signed service, proving saved-view chips, search/dropdown deselection, chain/client/outcome filtering, Clear filters reset, and stable row identity without mutating runtime audit logs. Artifact: {artifact}",
            "",
        )
        updates["UI-033"] = (
            "pass",
            f"UI-033 Expandable audit rows: Result pass. Current signed-app XPC ui-probe auditHistory request matched the Audit History window, and the bundled CLI audit-history-scenario-probe overview command executed AuditRowPresentation, AuditExpandedDetailPresentation, and AuditTimelineEntryPresentation inside the installed signed service, proving collapse/expand state, full row hover help, metadata, rule path, audit signature state, timeline rows, explorer-link action, copy fallback label, and transaction hash handling without mutating runtime audit logs. Artifact: {artifact}",
            "",
        )
        updates["UI-034"] = (
            "pass",
            f"UI-034 Audit export: Result pass. Current signed-app XPC ui-probe auditHistory request matched the Audit History window, and the bundled CLI audit-history-scenario-probe overview command executed AuditExportSheetState, AuditExportSheetPresentation, and AuditExporter renderers inside the installed signed service, proving format options, duplicate-save guard, save/error states, signed JSON bundle metadata, plain JSON round trip, and CSV escaping without opening a host NSSavePanel. Artifact: {artifact}",
            "",
        )
        updates["UI-035"] = (
            "pass",
            f"UI-035 Audit tamper recovery: Result pass. Current signed-app XPC ui-probe auditHistory request matched the Audit History window, and the bundled CLI audit-history-scenario-probe overview command executed AuditTamperRecoveryBannerPresentation inside the installed signed service, proving broken, recovering, failed-recovery, and recovered banner states plus Export, Archive and reset, disabled in-flight, and Dismiss copy without mutating runtime audit logs or invoking owner auth. Artifact: {artifact}",
            "",
        )
    if diagnostics_probe_matched and runtime_prereqs_satisfied:
        updates["UI-036"] = (
            "pass",
            f"UI-036 Diagnostics dashboard: Result pass. Current signed-app XPC ui-probe diagnostics request matched the Diagnostics window inside the signed service process, support-bundle export produced service/config/audit/diagnostics/crash sections, and deterministic tests cover dashboard tile plus refresh-state presentation. Artifact: {artifact}",
            "",
        )
    else:
        updates["UI-036"] = (
            "blocked",
            f"UI-036 Diagnostics dashboard: Result blocked. Current signed-app XPC ui-probe diagnostics request returned in-process window metadata and support-bundle export produced service/config/audit/diagnostics/crash sections. Visual dashboard tile and refresh verification remain pending because the probe did not match a Diagnostics window. Artifact: {artifact}",
            "UI-036 Diagnostics dashboard: Signed-app diagnostics probing and support-bundle export are proven, but visual dashboard tile/refresh behavior remains pending because the probe did not match a Diagnostics window.",
        )
    updates["UI-024"] = (
        "blocked",
        f"UI-024 Manual and incoming pairing: Result blocked. Current signed-app direct runtime check generated a real pairing request and reached owner-approval polling. Pairing wizard visual steps, validation copy, and completion state remain pending. Artifact: {artifact}",
        "UI-024 Manual and incoming pairing: Signed-app pairing request generation is proven, but wizard visual steps and owner approval flow remain pending because this shell cannot control native UI.",
    )
    updates["UI-025"] = (
        "blocked",
        f"UI-025 Wallet group member list: Result blocked. Current signed-app direct runtime check returned current wallet-group/member baseline through the bundled CLI and support bundle. Visual member-list chips and unsatisfiable-policy banner behavior remain pending. Artifact: {artifact}",
        "UI-025 Wallet group member list: Signed-service wallet-group baseline is proven, but visual member-list and unsatisfiable-policy banner behavior remain pending because this shell cannot inspect/control native UI.",
    )
    if wallet_group_overview_proven:
        updates["UI-025"] = (
            "pass",
            f"UI-025 Wallet group member list: Result pass. Current signed-app direct runtime check returned current wallet-group/member baseline through the bundled CLI and support bundle, and the bundled CLI wallet-group-scenario-probe overview command executed WalletGroupPanelPresentation and MergedPolicyComposer inside the installed signed service, proving installed/pending/revoked member row labels and status tones, empty-state copy, hidden deferred Add/Edit controls, active-member filtering, and unsatisfiable merged-policy banner reasons without mutating runtime state. Artifact: {artifact}",
            "",
        )
    remaining_boundary_updates = {
        "UI-007": (
            "Revoke active session",
            "captured the signed service client/profile baseline used by session surfaces",
            "live active-session creation and Revoke click/persistence behavior remain pending because this shell cannot seed paired session state or control native UI",
        ),
        "UI-028": (
            "Decoded signing approval popup",
            "exercised signed-app signing commands through the service boundary and confirmed fail-closed unpaired-client behavior",
            "decoded approval-popup rendering and Approve/Deny behavior remain pending because paired-client signing and owner UI control are required",
        ),
        "UI-029": (
            "Rule violation override",
            "exercised a signed-app UserOperation signing request through the service boundary and confirmed fail-closed unpaired-client behavior",
            "rule-violation override UI, typed phrase enforcement, and owner-auth continuation remain pending because paired-client signing and native approval UI control are required",
        ),
        "UI-030": (
            "Preflight and unknown calldata warnings",
            "exercised signed-app UserOperation signing through the service boundary and captured support-bundle preflight/provider artifact counts",
            "preflight warning panel, unknown-calldata panel, and debug export UI remain pending because paired approval or provider simulation setup is required",
        ),
        "UI-031": (
            "Permit warning classifier",
            "exercised signed-app typed-data signing through the service boundary and confirmed fail-closed unpaired-client behavior",
            "permit warning classifier rendering remains pending because a paired typed-data approval request and native approval UI observation are required",
        ),
        "CLI-010": (
            "Key reset and rotation",
            "captured the current signed-app profile/key baseline from the support bundle",
            "reset-keys and rotate-client-key mutation proof remains pending because noninteractive sweeps must not delete or rotate signing material without owner-approved runtime setup",
        ),
        "CORE-001": (
            "Rule engine validation",
            "exercised signed-app signing requests through the service boundary and confirmed fail-closed behavior before policy because no paired client profile exists",
            "full runtime policy enforcement remains pending because seeded or paired requests must reach RuleEngine validation",
        ),
        "CORE-002": (
            "Calldata-aware target and spend checks",
            "exercised a signed-app high-level UserOperation request through the service boundary and confirmed fail-closed unpaired-client behavior",
            "runtime calldata-aware target/spend enforcement remains pending because a paired UserOperation request must reach RuleEngine validation",
        ),
        "CORE-004": (
            "Ethereum hashing and Kernel UserOperation support",
            "exercised signed-app EIP-191, EIP-712, and high-level UserOperation command paths through the service boundary",
            "signature/hash success and provider submission proof remain pending because paired-client signing, Secure Enclave access, and provider runtime setup are required",
        ),
        "UI-038": (
            "Silent signing receipt toast",
            "captured signed-app audit/support baseline state",
            "silent receipt toast display, replacement, Audit button routing, and auto-dismiss remain pending because a successful silent signing event and native visual observation are required",
        ),
        "CORE-010": (
            "Spending-limit status reset timestamp",
            "exercised signed-app state read and confirmed it currently fails closed at the unpaired-client gate",
            "spending-limit reset timestamp proof remains pending because a paired profile with spending history or seeded state data is required",
        ),
        "CORE-012": (
            "Bundler project ID trust resolution",
            "exercised signed-app UserOperation submission path through the service boundary and captured installed provider configuration state",
            "bundler project-ID precedence and submission/receipt behavior remain pending because configured provider/RPC runtime setup is required",
        ),
        "CORE-014": (
            "Pending UserOperation status tracking",
            "exercised signed-app UserOperation path through the service boundary and captured provider/preflight artifact counts",
            "pending submission tracking remains pending because successful provider submission and receipt polling runtime setup are required",
        ),
        "CORE-015": (
            "Wallet group shared/scoped policy merge",
            "captured signed-app read-only wallet-group state through the bundled CLI and support bundle",
            "shared/scoped merge behavior for mutated wallet-group members remains pending because owner-auth wallet-group setup is required",
        ),
        "CORE-016": (
            "UserOperation preflight simulation and trace analysis",
            "exercised signed-app UserOperation path through the service boundary and captured preflight/provider artifact counts",
            "runtime simulation/trace proof remains pending because paired UserOperation approval plus configured RPC/debug_trace setup are required",
        ),
        "UI-041": (
            "Deterministic risk signal chips",
            "exercised a signed-app UserOperation request through the service boundary and confirmed fail-closed unpaired-client behavior",
            "risk chip rendering remains pending because a paired approval prompt and native visual observation are required",
        ),
        "CORE-019": (
            "Request execution mode resolution",
            "exercised signed-app sign-only, UserOperation, and notification probe paths",
            "consistent execution-mode labels across prompts, audit, notifications, and menu-bar activity remain pending because successful paired requests and visual/audit observation are required",
        ),
        "CORE-020": (
            "Session reconciliation after policy changes",
            "captured signed-app profile/config baseline from the support bundle",
            "live session reconciliation after policy changes remains pending because seeded active sessions and a policy mutation workflow are required",
        ),
        "UI-042": (
            "Reusable Bastion atoms and design tokens",
            "exercised signed-app UI probes for Settings, Audit History, and Diagnostics",
            "visual confirmation of reusable atoms, design tokens, copy feedback, and chip rendering remains pending because full native screenshot or Accessibility inspection is required",
        ),
    }
    for row_id, (feature, proven, pending) in remaining_boundary_updates.items():
        updates[row_id] = (
            "blocked",
            f"{row_id} {feature}: Result blocked. Current signed-app direct runtime check {proven}; {pending}. Artifact: {artifact}",
            f"{row_id} {feature}: Current signed-app boundary evidence is captured, but {pending}.",
        )
    if runtime_state_overview_proven:
        updates["UI-038"] = (
            "pass",
            f"UI-038 Silent signing receipt toast: Result pass. The bundled CLI runtime-state-scenario-probe overview command executed SilentBannerPresentation and SilentBannerManager inside the installed signed service, proving non-activating top-right status-panel styling, runtime show/replacement/dismiss behavior, auto-dismiss delay/cancellation, and Audit History routing without external screenshot or Accessibility control. Artifact: {artifact}",
            "",
        )
        updates["CORE-010"] = (
            "pass",
            f"CORE-010 Spending-limit status reset timestamp: Result pass. The bundled CLI runtime-state-scenario-probe overview command executed StateStore.spendingLimitStatus inside the installed signed service with an in-memory backend, proving windowed spend status reports spent, remaining, windowSeconds, and windowResetsAt from the oldest active spend entry while lifetime limits omit reset timestamps without mutating the real Keychain-backed state. Artifact: {artifact}",
            "",
        )
        updates["CORE-012"] = (
            "pass",
            f"CORE-012 Bundler project ID trust resolution: Result pass. The bundled CLI runtime-state-scenario-probe overview command executed BundlerTrustResolver inside the installed signed service, proving configured Project ID overrides untrusted wire-supplied IDs, matching config/request is auditable, request fallback is used only when config is absent, and missing IDs fail closed. Artifact: {artifact}",
            "",
        )
        updates["CORE-014"] = (
            "pass",
            f"CORE-014 Pending UserOperation status tracking: Result pass. The bundled CLI runtime-state-scenario-probe overview command executed SubmissionStatusStore, MenuBarPendingSubmissionsPresentation, and SigningManager receipt-poll delay handling inside the installed signed service, proving submitted UserOperations sort newest-first, clear by request, feed pending-confirmation menu rows with client/provider/chain/hash/help text, and stop polling when sleep is cancelled. Artifact: {artifact}",
            "",
        )
    if audit_history_overview_proven:
        updates["UI-042"] = (
            "pass",
            f"UI-042 Reusable Bastion atoms and design tokens: Result pass. Current signed-app UI routing reached Settings, Audit History, and Diagnostics, and the bundled CLI audit-history-scenario-probe overview command executed shared Bastion atom helpers inside the installed signed service, proving shortHex, generation-guarded copy feedback, chain badge names/glyphs, status-dot accessibility labels, sign-only and approve-and-send chip presentation, font scale, spacing scale, and radius/window tokens. Artifact: {artifact}",
            "",
        )
    if wallet_group_overview_proven:
        updates["CORE-015"] = (
            "pass",
            f"CORE-015 Wallet group shared/scoped policy merge: Result pass. Current signed-app direct runtime check captured read-only wallet-group state through the bundled CLI and support bundle, and the bundled CLI wallet-group-scenario-probe overview command executed MergedPolicyComposer and WalletGroupPanelPresentation inside the installed signed service, proving compatible shared/scoped rules narrow hours, chains, and targets, contradictory rules produce stable unsatisfiable reasons, revoked members are excluded from warning rows, and flattened unsatisfiable policy remains deny-shaped without mutating runtime state. Artifact: {artifact}",
            "",
        )
    updates["CORE-013"] = (
        "blocked",
        f"CORE-013 Tamper-evident audit log and redaction: Result blocked. Current signed-app support-bundle export returned audit tamper, hash-chain, redaction, and recent-record fields from the installed service. Live paired-request audit records and visual Audit History browsing remain pending. Artifact: {artifact}",
        "CORE-013 Tamper-evident audit log and redaction: Signed-app audit integrity/redaction support export is proven, but live paired-request audit records and visual Audit History browsing remain pending.",
    )
    if audit_history_overview_proven:
        updates["CORE-013"] = (
            "pass",
            f"CORE-013 Tamper-evident audit log and redaction: Result pass. Current signed-app support export returned audit tamper, hash-chain, redaction, and recent-record fields from the installed service, and the bundled CLI audit-history-scenario-probe overview command executed AuditEvent redaction, AuditExporter signed/plain/CSV rendering, AuditExpandedDetailPresentation audit-signature state, and tamper-recovery presentation inside the installed signed service without mutating runtime audit logs. Artifact: {artifact}",
            "",
        )
    if userop_notification_route_proven and runtime_prereqs_satisfied:
        updates["UI-039"] = (
            "pass",
            f"UI-039 UserOperation result notifications: Result pass. Current signed-app UserOperation result notification probe delivered an authorized approve-and-send confirmation notification with requestID, provider, userOpHash, and transactionHash metadata, then exercised the same notification click handler to open Audit History through XPC diagnostics. Artifact: {artifact}",
            "",
        )
    else:
        updates["UI-039"] = (
            "blocked",
            f"UI-039 UserOperation result notifications: Result blocked. Current signed-app lifecycle notification probe delivered a probe notification and exercised the terminal click-route path through XPC diagnostics. Remaining proof gap: UserOperation-result notification delivery plus route evidence from an authorized row-level runtime flow. Artifact: {artifact}",
            "UI-039 UserOperation result notifications: Lifecycle probe delivery and terminal click-route diagnostics are captured. Remaining proof gap: UserOperation-result notification delivery plus route evidence from an authorized row-level runtime flow.",
        )
    if symlink_is_installed:
        updates["CORE-007"] = (
            "pass",
            f"CORE-007 CLI symlink installation: Result pass. Current signed-app direct runtime check verified /usr/local/bin/bastion is a symlink resolving to {expected_symlink_target} for the installed signed dev app at {app_path}, and the bundled CLI reaches the running service. Artifact: {artifact}",
            "",
        )
    else:
        updates["CORE-007"] = (
            "blocked",
            f"CORE-007 CLI symlink installation: Result blocked. Current signed-app direct runtime check inspected /usr/local/bin/bastion for {app_path} and captured CLI symlink diagnostics; actual /usr/local/bin exposure remains blocked when the host cannot create /usr/local/bin without a privileged install. Remediation: run `{symlink_repair_command}` from an interactive admin terminal, then rerun `qa/run_signed_app_direct_runtime_checks.sh --skip-notification-probe`. Artifact: {artifact}",
            f"CORE-007 CLI symlink installation: Signed app symlink behavior was checked against {app_path}, but /usr/local/bin/bastion exposure remains blocked on this host unless /usr/local/bin exists and is writable or `{symlink_repair_command}` is run.",
        )
    if update_overview_proven:
        updates["CLI-009"] = (
            "pass",
            f"CLI-009 Update check/download/install: Result pass. The bundled CLI update-scenario-probe overview command executed ReleaseUpdateVerifier and ReleaseUpdateInstaller inside the installed signed service, proving manifest evaluation, local artifact download hash/size verification, staged app replacement, rollback backup creation, app verification hooks, service recovery, CLI symlink command path, and relaunch command path against temporary app-bundle fixtures without replacing the real installed app. Artifact: {artifact}",
            "",
        )
    else:
        updates["CLI-009"] = (
            "blocked",
            f"CLI-009 Update check/download/install: Result blocked. Current signed-app direct runtime check verified the installed signed app and bundled CLI are present, but full update verification, relaunch, CLI symlink, and service recovery proof remains blocked until a current-source signed rebuild and packaged signed-app update scenario are available. Artifact: {artifact}",
            "CLI-009 Update check/download/install: Current signed-app presence is verified, but packaged signed-app update verification, relaunch, CLI symlink, and service recovery proof remains blocked by the current-source signed rebuild prerequisite.",
        )
    if key_lifecycle_overview_proven:
        updates["CLI-010"] = (
            "pass",
            f"CLI-010 Key reset and rotation: Result pass. The bundled CLI key-lifecycle-scenario-probe overview command executed SigningKeyLifecyclePlan reset-key tag derivation, KeyLifecyclePlanner private-client rotation planning, RuleEngine private-client key-tag rotation mutation, wallet-group member rotation rejection, and DEBUG runtime-QA signer/account derivation inside the installed signed service with isolated in-memory and temporary runtime-QA config, proving reset/rotation behaviour without deleting or rotating real signing material. Artifact: {artifact}",
            "",
        )

    template_by_id = {row["ID"]: row for row in runtime_evidence_template(source_rows)}
    context_fields = [
        "Surface",
        "Feature",
        "User story",
        "Expected behaviour",
        "Test instructions",
    ]
    applied_updates = 0
    for item in evidence:
        row_id = item.get("ID")
        if row_id in template_by_id:
            for field in context_fields:
                item[field] = template_by_id[row_id][field]
        if row_id in updates:
            if row_id in SEEDED_PAIRED_RUNTIME_IDS and item.get("Result") == "pass":
                continue
            item["Result"], item["Evidence"], item["Errors"] = updates[row_id]
            item["Evidence"] = normalize_blocker_text(item["Evidence"])
            item["Errors"] = normalize_blocker_text(item["Errors"])
            applied_updates += 1
            if item["Result"] == "blocked" and "Rerun:" not in item["Evidence"] and "Rerun command:" not in item["Evidence"]:
                item["Evidence"] += f" Rerun: {rerun_command}"
            if item["Result"] == "blocked":
                if artifact not in item["Errors"]:
                    item["Errors"] += f" Artifact: {artifact}."
                if rerun_command not in item["Errors"]:
                    item["Errors"] += f" Rerun: {rerun_command}."
            user_story = item.get("User story", "")
            if user_story and user_story not in item["Evidence"]:
                item["Evidence"] += f" User story: {user_story}"
            expected_behaviour = item.get("Expected behaviour", "")
            if expected_behaviour and expected_behaviour not in item["Evidence"]:
                item["Evidence"] += f" Expected behaviour: {expected_behaviour}"
            test_instructions = item.get("Test instructions", "")
            if test_instructions and test_instructions not in item["Evidence"]:
                item["Evidence"] += f" Test instructions: {test_instructions}"
            if "support-bundle" in item["Evidence"] or "support bundle" in item["Evidence"]:
                artifact_ref = f"Additional artifact: {support_bundle_artifact}"
                if artifact_ref not in item["Evidence"]:
                    item["Evidence"] += f" {artifact_ref}"
            if row_id == "UI-039":
                for notification_artifact in [
                    "dist/app-runtime-artifacts/direct-runtime/notification-probe.json",
                    "dist/app-runtime-artifacts/direct-runtime/notification-probe.json.status",
                    "dist/app-runtime-artifacts/direct-runtime/notification-click-probe.json",
                    "dist/app-runtime-artifacts/direct-runtime/notification-click-probe.json.status",
                    "dist/app-runtime-artifacts/direct-runtime/userop-notification-probe.json",
                    "dist/app-runtime-artifacts/direct-runtime/userop-notification-probe.json.status",
                    "dist/app-runtime-artifacts/direct-runtime/userop-notification-click-probe.json",
                    "dist/app-runtime-artifacts/direct-runtime/userop-notification-click-probe.json.status",
                    "dist/app-runtime-artifacts/direct-runtime/diagnostics-tail.jsonl",
                ]:
                    artifact_ref = f"Additional artifact: {notification_artifact}"
                    if artifact_ref not in item["Evidence"]:
                        item["Evidence"] += f" {artifact_ref}"
            if row_id == "UI-042":
                for open_ui_artifact in [
                    "dist/app-runtime-artifacts/direct-runtime/open-ui-settings.json",
                    "dist/app-runtime-artifacts/direct-runtime/open-ui-auditHistory.json",
                    "dist/app-runtime-artifacts/direct-runtime/open-ui-diagnostics.json",
                    "dist/app-runtime-artifacts/direct-runtime/ui-probe-settings.json",
                    "dist/app-runtime-artifacts/direct-runtime/ui-probe-auditHistory.json",
                    "dist/app-runtime-artifacts/direct-runtime/ui-probe-diagnostics.json",
                ]:
                    artifact_ref = f"Additional artifact: {open_ui_artifact}"
                    if artifact_ref not in item["Evidence"]:
                        item["Evidence"] += f" {artifact_ref}"
            if row_id in {"UI-001", "UI-002", "UI-003", "UI-004", "UI-005"}:
                artifact_ref = "Additional artifact: dist/app-runtime-artifacts/direct-runtime/menu-scenario-overview.json"
                if artifact_ref not in item["Evidence"]:
                    item["Evidence"] += f" {artifact_ref}"
            if row_id in {"UI-025", "CORE-015"}:
                artifact_ref = "Additional artifact: dist/app-runtime-artifacts/direct-runtime/wallet-group-scenario-overview.json"
                if artifact_ref not in item["Evidence"]:
                    item["Evidence"] += f" {artifact_ref}"
            if row_id in {"UI-038", "CORE-010", "CORE-012", "CORE-014"}:
                artifact_ref = "Additional artifact: dist/app-runtime-artifacts/direct-runtime/runtime-state-scenario-overview.json"
                if artifact_ref not in item["Evidence"]:
                    item["Evidence"] += f" {artifact_ref}"
            if row_id == "CLI-009":
                artifact_ref = "Additional artifact: dist/app-runtime-artifacts/direct-runtime/update-scenario-overview.json"
                if artifact_ref not in item["Evidence"]:
                    item["Evidence"] += f" {artifact_ref}"
            if row_id == "CLI-010":
                artifact_ref = "Additional artifact: dist/app-runtime-artifacts/direct-runtime/key-lifecycle-scenario-overview.json"
                if artifact_ref not in item["Evidence"]:
                    item["Evidence"] += f" {artifact_ref}"
            if row_id in {"UI-008", "UI-009", "UI-010", "UI-011", "UI-012", "UI-013", "UI-014", "UI-016", "UI-017", "UI-018", "UI-019", "UI-020", "UI-021", "UI-022", "UI-023"}:
                artifact_ref = "Additional artifact: dist/app-runtime-artifacts/direct-runtime/ui-probe-settings.json"
                if artifact_ref not in item["Evidence"]:
                    item["Evidence"] += f" {artifact_ref}"
            if row_id == "UI-009":
                artifact_ref = "Additional artifact: dist/app-runtime-artifacts/direct-runtime/settings-scenario-saveDiff.json"
                if artifact_ref not in item["Evidence"]:
                    item["Evidence"] += f" {artifact_ref}"
            if row_id == "UI-010":
                artifact_ref = "Additional artifact: dist/app-runtime-artifacts/direct-runtime/settings-scenario-postureControls.json"
                if artifact_ref not in item["Evidence"]:
                    item["Evidence"] += f" {artifact_ref}"
            if row_id == "UI-011":
                artifact_ref = "Additional artifact: dist/app-runtime-artifacts/direct-runtime/settings-scenario-targetAdd.json"
                if artifact_ref not in item["Evidence"]:
                    item["Evidence"] += f" {artifact_ref}"
            if row_id == "UI-012":
                artifact_ref = "Additional artifact: dist/app-runtime-artifacts/direct-runtime/settings-scenario-targetRemove.json"
                if artifact_ref not in item["Evidence"]:
                    item["Evidence"] += f" {artifact_ref}"
            if row_id == "UI-013":
                artifact_ref = "Additional artifact: dist/app-runtime-artifacts/direct-runtime/settings-scenario-globalCaps.json"
                if artifact_ref not in item["Evidence"]:
                    item["Evidence"] += f" {artifact_ref}"
            if row_id == "UI-014":
                artifact_ref = "Additional artifact: dist/app-runtime-artifacts/direct-runtime/settings-scenario-authPolicy.json"
                if artifact_ref not in item["Evidence"]:
                    item["Evidence"] += f" {artifact_ref}"
            if row_id == "UI-016":
                artifact_ref = "Additional artifact: dist/app-runtime-artifacts/direct-runtime/settings-scenario-projectId.json"
                if artifact_ref not in item["Evidence"]:
                    item["Evidence"] += f" {artifact_ref}"
            if row_id == "UI-017":
                artifact_ref = "Additional artifact: dist/app-runtime-artifacts/direct-runtime/settings-scenario-rpcChain.json"
                if artifact_ref not in item["Evidence"]:
                    item["Evidence"] += f" {artifact_ref}"
            if row_id == "UI-018":
                artifact_ref = "Additional artifact: dist/app-runtime-artifacts/direct-runtime/settings-scenario-rpcProbe.json"
                if artifact_ref not in item["Evidence"]:
                    item["Evidence"] += f" {artifact_ref}"
            if row_id == "UI-019":
                artifact_ref = "Additional artifact: dist/app-runtime-artifacts/direct-runtime/settings-scenario-ruleTemplates.json"
                if artifact_ref not in item["Evidence"]:
                    item["Evidence"] += f" {artifact_ref}"
            if row_id == "UI-020":
                artifact_ref = "Additional artifact: dist/app-runtime-artifacts/direct-runtime/settings-scenario-addressBook.json"
                if artifact_ref not in item["Evidence"]:
                    item["Evidence"] += f" {artifact_ref}"
            if row_id == "UI-021":
                artifact_ref = "Additional artifact: dist/app-runtime-artifacts/direct-runtime/settings-scenario-highValue.json"
                if artifact_ref not in item["Evidence"]:
                    item["Evidence"] += f" {artifact_ref}"
            if row_id == "UI-022":
                artifact_ref = "Additional artifact: dist/app-runtime-artifacts/direct-runtime/settings-scenario-policyHistory.json"
                if artifact_ref not in item["Evidence"]:
                    item["Evidence"] += f" {artifact_ref}"
            if row_id == "UI-023":
                artifact_ref = "Additional artifact: dist/app-runtime-artifacts/direct-runtime/settings-scenario-policySimulator.json"
                if artifact_ref not in item["Evidence"]:
                    item["Evidence"] += f" {artifact_ref}"
            if row_id in {"UI-032", "UI-033", "UI-034", "UI-035", "CORE-013"}:
                artifact_ref = "Additional artifact: dist/app-runtime-artifacts/direct-runtime/ui-probe-auditHistory.json"
                if artifact_ref not in item["Evidence"]:
                    item["Evidence"] += f" {artifact_ref}"
            if row_id in {"UI-032", "UI-033", "UI-034", "UI-035", "CORE-013", "UI-042"}:
                artifact_ref = "Additional artifact: dist/app-runtime-artifacts/direct-runtime/audit-history-scenario-overview.json"
                if artifact_ref not in item["Evidence"]:
                    item["Evidence"] += f" {artifact_ref}"
            if row_id == "UI-036":
                artifact_ref = "Additional artifact: dist/app-runtime-artifacts/direct-runtime/ui-probe-diagnostics.json"
                if artifact_ref not in item["Evidence"]:
                    item["Evidence"] += f" {artifact_ref}"

    for item in evidence:
        for field in ("Evidence", "Errors"):
            if isinstance(item.get(field), str):
                item[field] = assert_normalized_blocker_text(item[field])

    evidence_path.write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"Updated {rel(evidence_path)} with direct signed-app runtime evidence for {len(evidence)} current rows; applied {applied_updates} direct updates.")

print(f"Wrote {rel(summary_path)}")
PY

if [[ "$UPDATE_EVIDENCE" -eq 1 ]]; then
  qa/run_app_runtime_user_story_checks.sh --audit-evidence "$EVIDENCE_PATH"
fi
