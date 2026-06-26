#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bastion-mcp-smoke.XXXXXX")"
BIN="$TMP_DIR/bastion-mcp"
REST_LOG="$TMP_DIR/rest.log"
REST_BODY="$TMP_DIR/rest-body.json"
REST_PID=""

cleanup() {
  if [[ -n "$REST_PID" ]] && kill -0 "$REST_PID" >/dev/null 2>&1; then
    kill "$REST_PID" >/dev/null 2>&1 || true
    wait "$REST_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "==> Building Swift bastion-mcp sidecar"
xcrun swiftc bastion-mcp/main.swift -sdk "$(xcrun --sdk macosx --show-sdk-path)" -target "$(uname -m)-apple-macos13.0" -o "$BIN"

echo "==> Checking MCP tools and local validation"
MCP_OUTPUT="$(
  printf '%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
    '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
    '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"bastion_sign_raw","arguments":{"data":"0x12","agentProfileId":"00000000-0000-0000-0000-000000000000"}}}' \
    '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"bastion_get_account","arguments":{}}}' \
  | "$BIN" 2>/dev/null
)"

python3 - "$MCP_OUTPUT" <<'PY'
import json
import sys

messages = [json.loads(line) for line in sys.argv[1].splitlines() if line.strip()]
by_id = {message["id"]: message for message in messages}
tools = by_id[2]["result"]["tools"]
names = {tool["name"] for tool in tools}
expected = {
    "bastion_pair_agent",
    "bastion_poll_pairing",
    "bastion_status",
    "bastion_get_account",
    "bastion_get_rules",
    "bastion_get_state",
    "bastion_sign_message",
    "bastion_sign_typed_data",
    "bastion_sign_raw",
    "bastion_send_user_op",
    "bastion_sign_user_op_json",
    "bastion_create_wallet_group",
    "bastion_list_wallet_groups",
    "bastion_get_wallet_group",
    "bastion_add_agent_to_group",
    "bastion_remove_agent_from_group",
    "bastion_update_agent_scope",
    "bastion_mark_agent_installed",
    "bastion_install_agent_on_chain",
    "bastion_uninstall_agent_on_chain",
}
missing = sorted(expected - names)
if missing:
    raise SystemExit(f"missing MCP tools: {missing}")

for tool_name in ("bastion_install_agent_on_chain", "bastion_uninstall_agent_on_chain"):
    tool = next(tool for tool in tools if tool["name"] == tool_name)
    wait_schema = tool["inputSchema"]["properties"]["waitForReceiptSeconds"]
    if wait_schema.get("minimum") != 0 or wait_schema.get("maximum") != 120:
        raise SystemExit(f"{tool_name} waitForReceiptSeconds schema mismatch: {wait_schema}")

raw_error = by_id[3]["result"]
if not raw_error.get("isError") or "data must be 32 bytes of hex" not in raw_error["content"][0]["text"]:
    raise SystemExit(f"invalid raw-data validation response: {raw_error}")

profile_error = by_id[4]["result"]
if not profile_error.get("isError") or "agentProfileId is required" not in profile_error["content"][0]["text"]:
    raise SystemExit(f"missing-profile validation response mismatch: {profile_error}")
PY

echo "==> Checking REST token entropy rejection"
if BASTION_API_TOKEN="abcdefghijklmnopqrstuvwxyz0123456789" "$BIN" rest >"$TMP_DIR/low-entropy.out" 2>&1; then
  echo "Expected low-entropy REST token to be rejected." >&2
  exit 1
fi
grep -F "BASTION_API_TOKEN must be set to a high-entropy value" "$TMP_DIR/low-entropy.out" >/dev/null

TOKEN="$(openssl rand -hex 32)"
PORT="$((18000 + RANDOM % 20000))"
echo "==> Checking REST auth, origin rejection, and body limit on 127.0.0.1:${PORT}"
BASTION_API_TOKEN="$TOKEN" BASTION_API_PORT="$PORT" "$BIN" rest >"$REST_LOG" 2>&1 &
REST_PID="$!"

for _ in {1..50}; do
  if /usr/bin/curl -fsS -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:${PORT}/health" >"$REST_BODY" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
grep -F '"status":"ok"' "$REST_BODY" >/dev/null

HTTP_CODE="$(/usr/bin/curl -sS -o "$REST_BODY" -w "%{http_code}" "http://127.0.0.1:${PORT}/health")"
[[ "$HTTP_CODE" == "401" ]]

HTTP_CODE="$(/usr/bin/curl -sS -o "$REST_BODY" -w "%{http_code}" -H "Authorization: Bearer $TOKEN" -H "Origin: https://example.invalid" "http://127.0.0.1:${PORT}/health")"
[[ "$HTTP_CODE" == "403" ]]
grep -F "Cross-origin requests are not allowed" "$REST_BODY" >/dev/null

HTTP_CODE="$(python3 - <<'PY' | /usr/bin/curl -sS -o "$REST_BODY" -w "%{http_code}" -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" --data-binary @- "http://127.0.0.1:${PORT}/groups"
import sys
sys.stdout.write("a" * (1024 * 1024 + 1))
PY
)"
[[ "$HTTP_CODE" == "413" ]]

echo "==> bastion-mcp smoke passed"
