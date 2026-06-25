#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CLI_SMOKE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bastion-cli-smoke.XXXXXX")"
trap 'rm -rf "$CLI_SMOKE_DIR"' EXIT

swiftc \
  bastion-cli/main.swift \
  bastion/Utilities/ReleaseUpdate.swift \
  bastion/Utilities/ReleaseUpdateInstaller.swift \
  -o "$CLI_SMOKE_DIR/bastion-cli"

expect_cli_error() {
  local name="$1"
  local expected="$2"
  shift 2
  if "$CLI_SMOKE_DIR/bastion-cli" "$@" >"$CLI_SMOKE_DIR/${name}.out" 2>"$CLI_SMOKE_DIR/${name}.err"; then
    echo "Expected native CLI smoke '$name' to fail" >&2
    exit 1
  fi
  grep -F -- "$expected" "$CLI_SMOKE_DIR/${name}.err" >/dev/null
}

expect_cli_xpc_error() {
  local name="$1"
  shift
  if "$CLI_SMOKE_DIR/bastion-cli" "$@" >"$CLI_SMOKE_DIR/${name}.out" 2>"$CLI_SMOKE_DIR/${name}.err"; then
    echo "Expected native CLI smoke '$name' to fail without running Bastion service" >&2
    exit 1
  fi
  grep -E "XPC connection|Failed to get XPC proxy|No response data|Request timed out|timed out|Bastion app is not running" "$CLI_SMOKE_DIR/${name}.err" >/dev/null
  grep -E "signed Bastion app and service|Bastion app is not running" "$CLI_SMOKE_DIR/${name}.err" >/dev/null
}

expect_cli_error sign-short "--data must be exactly 32 bytes" sign --data 1234
expect_cli_xpc_error sign-prefixed-32 sign --data 0x0000000000000000000000000000000000000000000000000000000000000000
if grep -F -- "--data must be exactly 32 bytes" "$CLI_SMOKE_DIR/sign-prefixed-32.err" >/dev/null; then
  echo "Prefixed 32-byte raw signing input was rejected by argument validation" >&2
  exit 1
fi

expect_cli_error eth-message-missing "Usage: bastion eth message <text>" eth message
expect_cli_error typed-data-json-missing "--json requires a value" eth typedData --json
expect_cli_error typed-data-json-file-missing "--json-file requires a path" eth typedData --json-file
expect_cli_error userop-bad-value "Invalid --op value (expected uint256 decimal or 0x hex): nope" eth userOp --op 0x1111111111111111111111111111111111111111,nope,0x
expect_cli_error userop-chain-id-bad "--chain-id must be an integer" eth userOp --chain-id nope --op 0x1111111111111111111111111111111111111111,0,0x
expect_cli_error userop-mixed-input "Use either --op/--ops or --json/--json-file, not both" eth userOp --op 0x1111111111111111111111111111111111111111,0,0x --json '{}'
expect_cli_xpc_error status-no-service status
expect_cli_error open-ui-target "Unknown UI target: wrong. Use settings, auditHistory, or diagnostics." open-ui wrong
expect_cli_xpc_error pair-default-no-service pair
expect_cli_error pair-unknown "Unknown pair argument: --bad" pair --bad
expect_cli_error pair-label-missing "--label requires a value" pair --label
expect_cli_error pair-label-empty "--label cannot be empty" pair --label ""
expect_cli_error pair-label-blank "--label cannot be empty" pair --label "   "
expect_cli_error rotate-client-key-missing "Usage: bastion rotate-client-key <profileId>" rotate-client-key
expect_cli_xpc_error reset-keys-no-service reset-keys
expect_cli_error groups-create-label-empty "--label cannot be empty" groups create --label "   "
expect_cli_error groups-create-chain-bad "--chain must be an integer" groups create --label Team --chain nope
expect_cli_error groups-create-chain-missing "--chain requires a value" groups create --label Team --chain
expect_cli_xpc_error groups-list-no-service groups list
expect_cli_error groups-show-missing "Usage: bastion groups show <groupId>" groups show
expect_cli_error groups-show-empty "groupId cannot be empty" groups show ""
expect_cli_error groups-add-agent-empty-group "groupId cannot be empty" groups add-agent "" --label Agent
expect_cli_error groups-add-agent-label-empty "--label cannot be empty" groups add-agent group-1 --label "   "
expect_cli_error groups-add-agent-profile-empty "--profile-id cannot be empty" groups add-agent group-1 --profile-id "   "
expect_cli_error groups-remove-agent-empty-group "groupId cannot be empty" groups remove-agent "" member-1
expect_cli_error groups-remove-agent-empty-member "memberId cannot be empty" groups remove-agent group-1 ""
expect_cli_error groups-remove-agent-tx-empty "--tx cannot be empty" groups remove-agent group-1 member-1 --tx "   "
expect_cli_error groups-update-scope-empty-group "groupId cannot be empty" groups update-scope "" member-1 --scope-json '{}'
expect_cli_error groups-update-scope-empty-member "memberId cannot be empty" groups update-scope group-1 "" --scope-json '{}'
expect_cli_error groups-install-empty-group "groupId cannot be empty" groups install-agent "" member-1 --chain 1
expect_cli_error groups-install-empty-member "memberId cannot be empty" groups install-agent group-1 "" --chain 1
expect_cli_error groups-install-project-empty "--project-id cannot be empty" groups install-agent group-1 member-1 --chain 1 --project-id "   "
expect_cli_error groups-install-wait-bad "--wait-seconds must be an integer" groups install-agent group-1 member-1 --chain 1 --wait-seconds nope
expect_cli_error groups-install-wait-range "--wait-seconds must be between 0 and 120" groups install-agent group-1 member-1 --chain 1 --wait-seconds 121
expect_cli_error groups-uninstall-empty-group "groupId cannot be empty" groups uninstall-agent "" member-1 --chain 1
expect_cli_error groups-uninstall-empty-member "memberId cannot be empty" groups uninstall-agent group-1 "" --chain 1
expect_cli_error groups-uninstall-project-empty "--project-id cannot be empty" groups uninstall-agent group-1 member-1 --chain 1 --project-id "   "
expect_cli_error groups-mark-installed-empty-group "groupId cannot be empty" groups mark-installed "" member-1 --tx 0x111
expect_cli_error groups-mark-installed-empty-member "memberId cannot be empty" groups mark-installed group-1 "" --tx 0x111
expect_cli_error groups-mark-installed-tx-empty "--tx cannot be empty" groups mark-installed group-1 member-1 --tx "   "
expect_cli_error groups-mark-installed-validator-empty "--validator cannot be empty" groups mark-installed group-1 member-1 --tx 0x111 --validator "   "
