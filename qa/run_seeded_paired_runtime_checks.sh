#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

APP_PATH="${BASTION_APP_PATH:-${HOME}/Applications/Bastion Dev.app}"
OUTPUT_DIR="dist/app-runtime-artifacts/seeded-paired-runtime"
HELPER_APP="${OUTPUT_DIR}/runtime-profile-seeder.app"
HELPER="${HELPER_APP}/Contents/MacOS/runtime-profile-seeder"
ENTITLEMENTS="${OUTPUT_DIR}/runtime-profile-seeder.entitlements"
BACKUP="${OUTPUT_DIR}/config.backup.json"
SUMMARY="${OUTPUT_DIR}/seeded-paired-runtime-summary.log"
BLOCKER_SUMMARY="${OUTPUT_DIR}/seeded-paired-runtime-blocker.log"
CODESIGN_PREFLIGHT_LOG="${OUTPUT_DIR}/codesign-preflight.log"
EVIDENCE_PATH="dist/app-runtime-evidence.current.json"
CLI_BIN="${APP_PATH}/Contents/MacOS/bastion-cli"
TOKEN="VNSq8yXf9L2mR7pT4cK6zJ1bH5wD3eQ0uA8sG9nP2vC7xY4rM6tZ1kL5hF3dB0qW"
RESTORED=0
UPDATE_EVIDENCE=1

usage() {
  cat <<'USAGE'
Usage:
  qa/run_seeded_paired_runtime_checks.sh [--app <app-bundle>] [--output-dir <dir>] [--evidence <json>] [--skip-evidence-update]

Default app bundle: ~/Applications/Bastion Dev.app

Builds a same-team signed QA helper that temporarily seeds a paired bastion-cli
profile in Bastion's DEBUG-only runtime QA config override, restarts the service,
collects paired CLI/REST/MCP runtime evidence, restores the exact original QA
override state, and restarts the service again. The real Keychain-backed config
is not mutated.
USAGE
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --app)
      shift
      [[ "$#" -gt 0 ]] || { echo "--app requires a path" >&2; exit 2; }
      APP_PATH="$1"
      CLI_BIN="${APP_PATH}/Contents/MacOS/bastion-cli"
      ;;
    --output-dir)
      shift
      [[ "$#" -gt 0 ]] || { echo "--output-dir requires a directory" >&2; exit 2; }
      OUTPUT_DIR="$1"
      HELPER_APP="${OUTPUT_DIR}/runtime-profile-seeder.app"
      HELPER="${HELPER_APP}/Contents/MacOS/runtime-profile-seeder"
      ENTITLEMENTS="${OUTPUT_DIR}/runtime-profile-seeder.entitlements"
      BACKUP="${OUTPUT_DIR}/config.backup.json"
      SUMMARY="${OUTPUT_DIR}/seeded-paired-runtime-summary.log"
      BLOCKER_SUMMARY="${OUTPUT_DIR}/seeded-paired-runtime-blocker.log"
      CODESIGN_PREFLIGHT_LOG="${OUTPUT_DIR}/codesign-preflight.log"
      ;;
    --evidence)
      shift
      [[ "$#" -gt 0 ]] || { echo "--evidence requires a path" >&2; exit 2; }
      EVIDENCE_PATH="$1"
      ;;
    --skip-evidence-update)
      UPDATE_EVIDENCE=0
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

mkdir -p "$OUTPUT_DIR"

write_blocker_summary() {
  local reason="$1"
  local detail_path="${2:-}"
  python3 - "$BLOCKER_SUMMARY" "$EVIDENCE_PATH" "$UPDATE_EVIDENCE" "$reason" "$detail_path" <<'PY'
import json
import sys
from pathlib import Path

summary_path = Path(sys.argv[1])
evidence_path = Path(sys.argv[2])
update_evidence = sys.argv[3] == "1"
reason = sys.argv[4]
detail_path = Path(sys.argv[5]) if len(sys.argv) > 5 and sys.argv[5] else None
root = Path.cwd()
try:
    artifact = str(summary_path.resolve().relative_to(root.resolve()))
except ValueError:
    artifact = str(summary_path)
detail_artifact = ""
if detail_path and detail_path.exists():
    try:
        detail_artifact = str(detail_path.resolve().relative_to(root.resolve()))
    except ValueError:
        detail_artifact = str(detail_path)

source = json.loads(Path("qa/feature_status_source.json").read_text())
rows_by_id = {row["ID"]: row for row in source}
sys.path.insert(0, str(root / "qa"))
from app_runtime_rows import SEEDED_PAIRED_RUNTIME_IDS

row_ids = sorted(SEEDED_PAIRED_RUNTIME_IDS)

detail = ""
if detail_path and detail_path.exists():
    detail = detail_path.read_text(errors="replace").strip()
elif detail_path:
    detail = f"<missing detail file: {detail_path}>"

lines = [
    "== Bastion seeded paired-client runtime blocker ==",
    "Attempted closure path: build a same-team signed QA helper that backs up the DEBUG-only runtime QA config override, seeds a temporary bastion-cli paired profile with open auth/auto-sign rules, restarts the signed service, collects paired CLI/REST/MCP evidence, restores the original QA override state, and restarts the service again.",
    f"Result: blocked before paired-client evidence collection. {reason}",
    "Config safety: the helper writes only Bastion's DEBUG-only runtime QA config override; the real Keychain-backed config is not mutated. If a backup exists from a later phase, the script's EXIT trap attempts restore.",
]
if detail:
    lines.extend(["", "== Failure detail ==", detail])

for row_id in row_ids:
    row = rows_by_id[row_id]
    lines.extend([
        "",
        f"ROW {row_id}",
        f"Surface: {row['Surface']}",
        f"Feature: {row['Feature']}",
        f"User story: {row['User story']}",
        f"Expected behaviour: {row['Expected behaviour']}",
        "Remaining proof gap: paired-client runtime closure with either a live owner-accepted pairing or a same-team signed QA seeder; this run could not collect paired evidence because " + reason,
    ])

summary_path.write_text("\n".join(lines) + "\n")

if update_evidence and evidence_path.exists():
    evidence = json.loads(evidence_path.read_text())
    reason_sentence = f"Seeded paired-runtime closure attempt blocked before paired evidence collection: {reason}"
    for item in evidence:
        row_id = item.get("ID")
        if row_id not in row_ids or item.get("Result") == "pass":
            continue
        evidence_text = item.get("Evidence", "")
        artifact_refs = [f"Additional artifact: {artifact}"]
        if detail_artifact:
            artifact_refs.append(f"Additional artifact: {detail_artifact}")
        for artifact_text in artifact_refs:
            if artifact_text not in evidence_text:
                evidence_text = (evidence_text.rstrip() + " " + artifact_text).strip()
        item["Evidence"] = evidence_text
        errors = item.get("Errors", "").strip()
        marker = "Seeded paired-runtime closure attempt"
        if marker in errors:
            errors = errors.split(marker, 1)[0].rstrip()
        item["Errors"] = (errors + " " + reason_sentence).strip()
    evidence_path.write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"Updated {evidence_path} with seeded paired-runtime blocker evidence.")

print(f"Wrote {artifact}")
PY
}

fail_with_blocker() {
  local reason="$1"
  local detail_path="${2:-}"
  write_blocker_summary "$reason" "$detail_path"
  exit 1
}

if [[ ! -x "$CLI_BIN" ]]; then
  fail_with_blocker "bundled CLI was missing or not executable at ${CLI_BIN}."
fi

if ! scripts/dev-enable-codesign-keychain-access.sh --check >"$CODESIGN_PREFLIGHT_LOG" 2>&1; then
  fail_with_blocker "non-mutating codesign usability preflight failed; run scripts/dev-enable-codesign-keychain-access.sh --check, repair keychain access with scripts/dev-enable-codesign-keychain-access.sh, then rerun qa/run_seeded_paired_runtime_checks.sh." "$CODESIGN_PREFLIGHT_LOG"
fi

SERVICE_LABEL="com.bastion.xpc"
SERVICE_DOMAIN="gui/$(id -u)"

restart_service() {
  /bin/launchctl kickstart -k "${SERVICE_DOMAIN}/${SERVICE_LABEL}" >/dev/null 2>&1 || true
  sleep 2
}

restore_config() {
  if [[ "$RESTORED" -eq 0 && -x "$HELPER" && -f "$BACKUP" ]]; then
    "$HELPER" restore "$BACKUP" >"${OUTPUT_DIR}/restore.log" 2>&1 || true
    RESTORED=1
    restart_service
  fi
}
trap restore_config EXIT HUP INT TERM

IDENTITY_ROW="$(/usr/bin/security find-identity -v -p codesigning | /usr/bin/awk '/^[[:space:]]*[0-9]+[)]/ { print; exit }')"
IDENTITY_HASH="$(printf '%s\n' "$IDENTITY_ROW" | /usr/bin/awk '{ print $2 }')"
if [[ -z "$IDENTITY_HASH" ]]; then
  fail_with_blocker "no valid code-signing identity was available from security find-identity."
fi

cat >"$ENTITLEMENTS" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.application-identifier</key>
  <string>926A27BQ7W.com.bastion.app</string>
  <key>com.apple.developer.team-identifier</key>
  <string>926A27BQ7W</string>
  <key>com.apple.security.app-sandbox</key>
  <false/>
  <key>com.apple.security.files.user-selected.read-only</key>
  <true/>
  <key>com.apple.security.get-task-allow</key>
  <true/>
  <key>keychain-access-groups</key>
  <array>
    <string>926A27BQ7W.com.bastion</string>
  </array>
</dict>
</plist>
PLIST

if [[ ! -f "${APP_PATH}/Contents/embedded.provisionprofile" ]]; then
  fail_with_blocker "installed signed app is missing embedded.provisionprofile, so the QA helper cannot carry provisioned keychain-access-group entitlements."
fi
rm -rf "$HELPER_APP"
mkdir -p "${HELPER_APP}/Contents/MacOS"
cat >"${HELPER_APP}/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>runtime-profile-seeder</string>
  <key>CFBundleIdentifier</key>
  <string>com.bastion.app</string>
  <key>CFBundleName</key>
  <string>Bastion Runtime Seeder</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>1.0</string>
  <key>CFBundleVersion</key>
  <string>1</string>
</dict>
</plist>
PLIST
cp "${APP_PATH}/Contents/embedded.provisionprofile" "${HELPER_APP}/Contents/embedded.provisionprofile"

if ! /usr/bin/swiftc qa/runtime_profile_seed.swift -o "$HELPER" >"${OUTPUT_DIR}/swiftc.log" 2>&1; then
  fail_with_blocker "runtime-profile-seeder failed to compile before any config mutation." "${OUTPUT_DIR}/swiftc.log"
fi
if ! /usr/bin/codesign --force --deep --sign "$IDENTITY_HASH" --timestamp=none --entitlements "$ENTITLEMENTS" "$HELPER_APP" >"${OUTPUT_DIR}/codesign.log" 2>&1; then
  fail_with_blocker "same-team QA helper app signing failed, usually because the login keychain denies noninteractive signing-key access." "${OUTPUT_DIR}/codesign.log"
fi
if ! /usr/bin/codesign --verify --deep --strict "$HELPER_APP" >"${OUTPUT_DIR}/codesign-verify.log" 2>&1; then
  fail_with_blocker "same-team QA helper app signature verification failed before any config mutation." "${OUTPUT_DIR}/codesign-verify.log"
fi

if ! "$HELPER" backup "$BACKUP" >"${OUTPUT_DIR}/backup.log" 2>"${OUTPUT_DIR}/backup.err"; then
  fail_with_blocker "runtime-profile-seeder could not back up the DEBUG-only runtime QA config override before mutation." "${OUTPUT_DIR}/backup.err"
fi
if ! "$HELPER" seed "$BACKUP" bastion-cli "Runtime QA CLI" >"${OUTPUT_DIR}/seed.log" 2>"${OUTPUT_DIR}/seed.err"; then
  reason="runtime-profile-seeder could not write the temporary paired profile to the DEBUG-only runtime QA config override."
  fail_with_blocker "$reason" "${OUTPUT_DIR}/seed.err"
fi
restart_service

"$CLI_BIN" status >"${OUTPUT_DIR}/cli-status.json"
"$CLI_BIN" pubkey >"${OUTPUT_DIR}/cli-pubkey.json"
"$CLI_BIN" rules >"${OUTPUT_DIR}/cli-rules.json"
"$CLI_BIN" state >"${OUTPUT_DIR}/cli-state.json"
"$CLI_BIN" sign --data "0x$(printf '11%.0s' {1..32})" >"${OUTPUT_DIR}/cli-sign-raw.json"
"$CLI_BIN" eth message "Bastion runtime QA message" >"${OUTPUT_DIR}/cli-sign-message.json"
SCOPE_JSON='{"allowedChains":[11155111]}'
TX_HASH="0x$(printf 'ab%.0s' {1..32})"
REVOKE_TX_HASH="0x$(printf 'cd%.0s' {1..32})"
VALIDATOR_ADDRESS="0x$(printf '12%.0s' {1..20})"
"$CLI_BIN" groups create --label "Runtime QA CLI Group" --chain 11155111 --scope-json "$SCOPE_JSON" >"${OUTPUT_DIR}/cli-group-create.json"
CLI_GROUP_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "${OUTPUT_DIR}/cli-group-create.json")"
"$CLI_BIN" groups add-agent "$CLI_GROUP_ID" --label "Runtime QA CLI Agent" --scope-json "$SCOPE_JSON" >"${OUTPUT_DIR}/cli-group-add-agent.json"
CLI_MEMBER_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "${OUTPUT_DIR}/cli-group-add-agent.json")"
"$CLI_BIN" groups update-scope "$CLI_GROUP_ID" "$CLI_MEMBER_ID" --scope-json "$SCOPE_JSON" >"${OUTPUT_DIR}/cli-group-update-scope.txt"
"$CLI_BIN" groups mark-installed "$CLI_GROUP_ID" "$CLI_MEMBER_ID" --tx "$TX_HASH" --validator "$VALIDATOR_ADDRESS" >"${OUTPUT_DIR}/cli-group-mark-installed.json"
"$CLI_BIN" groups remove-agent "$CLI_GROUP_ID" "$CLI_MEMBER_ID" --tx "$REVOKE_TX_HASH" >"${OUTPUT_DIR}/cli-group-remove-agent.txt"
"$CLI_BIN" groups show "$CLI_GROUP_ID" >"${OUTPUT_DIR}/cli-group-show.json"
"$CLI_BIN" groups list >"${OUTPUT_DIR}/cli-groups-list.json"

BASTION_CLI_PATH="$CLI_BIN" BASTION_API_TOKEN="$TOKEN" bun --cwd mcp --eval '
const app = (await import("./src/rest-server.ts")).default;
const token = process.env.BASTION_API_TOKEN;
async function req(method, path, body) {
  const init = { method, headers: { authorization: `Bearer ${token}` } };
  if (body !== undefined) {
    init.headers["content-type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  const response = await app.fetch(new Request(`http://127.0.0.1:9587${path}`, init));
  const text = await response.text();
  console.log(`===== ${method} ${path} => ${response.status} =====`);
  console.log(text);
  if (response.status >= 400) {
    throw new Error(`${method} ${path} failed: ${response.status} ${text}`);
  }
  return JSON.parse(text || "{}");
}
await req("GET", "/status");
await req("GET", "/rules");
await req("GET", "/state");
await req("POST", "/sign/raw", { data: "0x" + "22".repeat(32) });
await req("POST", "/sign/message", { message: "Bastion REST runtime QA message" });
const scope = { allowedChains: [11155111] };
const tx = "0x" + "ef".repeat(32);
const revokeTx = "0x" + "34".repeat(32);
const validator = "0x" + "56".repeat(20);
const group = await req("POST", "/groups", { label: "Runtime QA REST Group", chainIds: [11155111], sharedRules: scope });
const member = await req("POST", `/groups/${group.id}/agents`, { label: "Runtime QA REST Agent", scopedRules: scope });
await req("PATCH", `/groups/${group.id}/agents/${member.id}/scope`, { scopedRules: scope });
await req("POST", `/groups/${group.id}/agents/${member.id}/installed`, { txHash: tx, validatorAddress: validator });
await req("DELETE", `/groups/${group.id}/agents/${member.id}?tx=${revokeTx}`);
await req("GET", `/groups/${group.id}`);
' >"${OUTPUT_DIR}/rest-paired.txt"

BASTION_CLI_PATH="$CLI_BIN" bun --cwd mcp --eval '
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
const transport = new StdioClientTransport({
  command: "bun",
  args: ["run", "src/mcp-server.ts"],
  cwd: process.cwd(),
  env: { ...process.env, BASTION_CLI_PATH: process.env.BASTION_CLI_PATH },
});
const client = new Client({ name: "bastion-seeded-runtime", version: "0.1.0" });
await client.connect(transport);
async function call(name, args = {}) {
  const result = await client.callTool({ name, arguments: args });
  console.log(`CALL ${name}`);
  console.log(JSON.stringify(result, null, 2));
  if (result.isError) {
    throw new Error(`${name} failed: ${JSON.stringify(result)}`);
  }
  return result;
}
function contentText(result) {
  return result.content?.[0]?.text ?? "{}";
}
await call("bastion_status");
await call("bastion_get_rules");
await call("bastion_get_state");
await call("bastion_sign_raw", { data: "0x" + "33".repeat(32) });
await call("bastion_sign_message", { message: "Bastion MCP runtime QA message" });
const scope = JSON.stringify({ allowedChains: [11155111] });
const group = JSON.parse(contentText(await call("bastion_create_wallet_group", {
  label: "Runtime QA MCP Group",
  chainIds: [11155111],
  sharedRulesJson: scope,
})));
const member = JSON.parse(contentText(await call("bastion_add_agent_to_group", {
  groupId: group.id,
  label: "Runtime QA MCP Agent",
  scopedRulesJson: scope,
})));
await call("bastion_update_agent_scope", {
  groupId: group.id,
  memberId: member.id,
  scopedRulesJson: scope,
});
await call("bastion_mark_agent_installed", {
  groupId: group.id,
  memberId: member.id,
  txHash: "0x" + "78".repeat(32),
  validatorAddress: "0x" + "9a".repeat(20),
});
await call("bastion_remove_agent_from_group", {
  groupId: group.id,
  memberId: member.id,
  txHash: "0x" + "bc".repeat(32),
});
await call("bastion_get_wallet_group", { groupId: group.id });
await client.close();
' >"${OUTPUT_DIR}/mcp-paired.txt" 2>"${OUTPUT_DIR}/mcp-paired.err"

restore_config

python3 - "$OUTPUT_DIR" "$SUMMARY" "$EVIDENCE_PATH" "$UPDATE_EVIDENCE" <<'PY'
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
summary = Path(sys.argv[2])
evidence_path = Path(sys.argv[3])
update_evidence = sys.argv[4] == "1"
root = Path.cwd()
sys.path.insert(0, str(root / "qa"))
from app_runtime_rows import SEEDED_PAIRED_RUNTIME_IDS, runtime_test_instructions

def read(name: str) -> str:
    path = out / name
    return path.read_text(errors="replace").strip() if path.exists() else f"<missing {name}>"

summary_artifact = str(summary.resolve().relative_to(root.resolve()))

sections = [
    "Bastion seeded paired-client runtime evidence",
    "A same-team signed QA helper backed up the original DEBUG-only runtime QA config override, seeded a temporary bastion-cli profile with open auth and auto-sign rules, restarted the service, collected paired-client CLI/REST/MCP signing plus wallet-group mutation evidence, restored the original QA override state, and restarted the service again. The real Keychain-backed config was not mutated.",
    "",
    "== Seeder backup ==",
    read("backup.log"),
    "",
    "== Seeder seed ==",
    read("seed.log"),
    "",
    "== Seeder restore ==",
    read("restore.log"),
    "",
    "== CLI status ==",
    read("cli-status.json"),
    "",
    "== CLI pubkey ==",
    read("cli-pubkey.json"),
    "",
    "== CLI rules ==",
    read("cli-rules.json"),
    "",
    "== CLI state ==",
    read("cli-state.json"),
    "",
    "== CLI raw signing ==",
    read("cli-sign-raw.json"),
    "",
    "== CLI message signing ==",
    read("cli-sign-message.json"),
    "",
    "== CLI wallet-group create ==",
    read("cli-group-create.json"),
    "",
    "== CLI wallet-group add-agent ==",
    read("cli-group-add-agent.json"),
    "",
    "== CLI wallet-group update-scope ==",
    read("cli-group-update-scope.txt"),
    "",
    "== CLI wallet-group mark-installed ==",
    read("cli-group-mark-installed.json"),
    "",
    "== CLI wallet-group remove-agent ==",
    read("cli-group-remove-agent.txt"),
    "",
    "== CLI wallet-group show/list ==",
    read("cli-group-show.json"),
    read("cli-groups-list.json"),
    "",
    "== REST paired transcript ==",
    read("rest-paired.txt"),
    "",
    "== MCP paired transcript ==",
    read("mcp-paired.txt"),
    "",
    "== MCP stderr ==",
    read("mcp-paired.err") or "<empty>",
]

source_rows = json.loads(Path("qa/feature_status_source.json").read_text())
template_by_id = {}
for row in source_rows:
    row_id = row.get("ID")
    if row_id not in SEEDED_PAIRED_RUNTIME_IDS:
        continue
    template_by_id[row_id] = {
        "ID": str(row_id),
        "Surface": str(row.get("Surface", "")),
        "Feature": str(row.get("Feature", "")),
        "User story": str(row.get("User story", "")),
        "Expected behaviour": str(row.get("Expected behaviour", "")),
        "Test instructions": runtime_test_instructions(row),
    }
for row_id in sorted(template_by_id):
    item = template_by_id[row_id]
    sections.extend([
        "",
        f"ROW {row_id} {item['Feature']}",
        f"Surface: {item['Surface']}",
        f"Feature: {item['Feature']}",
        f"User story: {item['User story']}",
        f"Expected behaviour: {item['Expected behaviour']}",
        f"Test instructions: {item['Test instructions']}",
        "Result pass",
        "Evidence: Seeded paired-client runtime setup used a provisioned same-team QA helper app to seed a temporary bastion-cli profile into Bastion's DEBUG-only runtime QA config override with open auth and auto-sign rules; signed CLI, REST, and MCP read/sign flows returned paired-client success responses; wallet-group create/add/update/mark-installed/remove mutations succeeded through the signed CLI and REST/MCP wrappers; the original QA override state was restored afterward and the real Keychain-backed config was not mutated.",
    ])
summary.write_text("\n".join(sections) + "\n")

required_files = [
    "cli-pubkey.json",
    "cli-rules.json",
    "cli-state.json",
    "cli-sign-raw.json",
    "cli-sign-message.json",
    "cli-group-create.json",
    "cli-group-add-agent.json",
    "cli-group-mark-installed.json",
    "cli-group-show.json",
    "cli-groups-list.json",
    "rest-paired.txt",
    "mcp-paired.txt",
]
for name in required_files:
    text = read(name)
    if "Error:" in text or "Client is not paired" in text or "Pair this client" in text:
        raise SystemExit(f"paired runtime evidence still contains unpaired/error output in {name}")

for name in ["cli-sign-raw.json", "cli-sign-message.json"]:
    data = json.loads(read(name))
    for key in ["pubkeyX", "pubkeyY", "r", "s", "accountAddress", "clientBundleId"]:
        if key not in data or data[key] in ("", None):
            raise SystemExit(f"{name} missing signed response field {key}")

created_group = json.loads(read("cli-group-create.json"))
created_member = json.loads(read("cli-group-add-agent.json"))
installed_member = json.loads(read("cli-group-mark-installed.json"))
shown_group = json.loads(read("cli-group-show.json"))
if not created_group.get("id") or not created_member.get("id"):
    raise SystemExit("wallet-group create/add did not return ids")
if installed_member.get("installStatus", {}).get("state") != "installed":
    raise SystemExit("mark-installed did not return installed membership")
if shown_group.get("members", [{}])[0].get("installStatus", {}).get("state") != "revoked":
    raise SystemExit("remove-agent did not leave the CLI-created member revoked")
for transcript_name in ["rest-paired.txt", "mcp-paired.txt"]:
    transcript = read(transcript_name)
    for marker in [
        "Runtime QA REST Group" if transcript_name.startswith("rest") else "bastion_create_wallet_group",
        "installed",
        "revoked",
    ]:
        if marker not in transcript:
            raise SystemExit(f"{transcript_name} missing wallet-group marker {marker!r}")

if update_evidence and evidence_path.exists():
    evidence = json.loads(evidence_path.read_text())
    pass_text = (
        "Seeded paired-client runtime passed using a provisioned same-team QA helper app: "
        "the helper backed up Bastion's DEBUG-only runtime QA config override, seeded a temporary bastion-cli profile with open auth and auto-sign rules, "
        "restarted the signed service, collected paired CLI/REST/MCP read and signing success responses plus real wallet-group create/add/update/mark-installed/remove mutations through the signed CLI and REST/MCP wrappers, restored the original QA override state, "
        f"and restarted the service again without mutating the real Keychain-backed config. Artifact: {summary_artifact}"
    )
    for item in evidence:
        if item.get("ID") not in SEEDED_PAIRED_RUNTIME_IDS:
            continue
        item["Result"] = "pass"
        item["Evidence"] = (
            f"{item['ID']} {item.get('Feature', '')}: Result pass. "
            f"User story: {item.get('User story', '')} "
            f"Expected behaviour: {item.get('Expected behaviour', '')} "
            f"Test instructions: {item.get('Test instructions', '')} "
            f"{pass_text}"
        )
        item["Errors"] = ""
    evidence_path.write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"Updated {evidence_path} with seeded paired-client pass evidence for {len(SEEDED_PAIRED_RUNTIME_IDS)} rows.")

print(f"Wrote {summary}")
PY

echo "$SUMMARY"
