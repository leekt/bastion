#!/usr/bin/env bash
# Regression PoC for audit 2026-06-taek — bridge-side fixes:
#   AC-01 / RE-01  one bridge may only act for profiles in its BASTION_AGENT_PROFILE_ID allow-set
#   RP-01          X-Bastion-Agent-Profile header is normalized identically to the MCP path
#   DO-01          unbounded pre-header buffer is capped (413 instead of OOM)
#
# These exercise the bridge authorization layer, which rejects BEFORE any XPC
# call — so the Bastion app/XPC service does NOT need to be running. A request
# that PASSES authorization then fails at XPC (502 / "Request timed out"),
# which is the positive signal that auth was cleared.
#
# Usage: ./bridge-attribution-regression.sh /path/to/bastion-mcp
#   (or it will `swiftc` the in-repo source if no binary is given)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BIN="${1:-}"
if [[ -z "$BIN" ]]; then
  BIN="$(mktemp -t bastion-mcp-poc)"
  swiftc -O "$REPO_ROOT/bastion-mcp/main.swift" -o "$BIN"
fi

TOKEN="Zx9Qm2Vf7Lp4Rt8Wb1Yn6Kc3Hd5Jg0Aue-Sloweq7r2"   # >=32 chars, >=128 est. bits
ALLOWED="11111111-1111-1111-1111-111111111111"
VICTIM="22222222-2222-2222-2222-222222222222"
PORT="${BASTION_API_PORT:-19599}"

BASTION_API_TOKEN="$TOKEN" BASTION_AGENT_PROFILE_ID="$ALLOWED" BASTION_API_PORT="$PORT" "$BIN" rest >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
sleep 1

code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }
fail=0
expect() { # desc expected actual
  if [[ "$2" == "$3" ]]; then echo "  PASS  $1 ($3)"; else echo "  FAIL  $1 (expected $2, got $3)"; fail=1; fi
}

echo "AC-01 / RE-01 / RP-01:"
expect "no bearer token -> 401" 401 "$(code http://127.0.0.1:$PORT/account)"
expect "victim profile rejected (AC-01)" 400 "$(code -H "Authorization: Bearer $TOKEN" -H "X-Bastion-Agent-Profile: $VICTIM" http://127.0.0.1:$PORT/account)"
expect "overlong profile rejected (RP-01)" 400 "$(code -H "Authorization: Bearer $TOKEN" -H "X-Bastion-Agent-Profile: $(printf 'a%.0s' {1..200})" http://127.0.0.1:$PORT/account)"
expect "authorized profile clears auth -> 502 XPC down" 502 "$(code -H "Authorization: Bearer $TOKEN" -H "X-Bastion-Agent-Profile: $ALLOWED" http://127.0.0.1:$PORT/account)"

echo "DO-01:"
# Stream a >64KB header section with no terminator; the bridge must reply 413
# rather than buffering to OOM. Guard the pipeline from pipefail/SIGPIPE.
set +e +o pipefail
capresp="$({ printf 'GET /account HTTP/1.1\r\n'; printf 'X-Pad: '; printf 'A%.0s' {1..70000}; printf '\r\n'; sleep 1; } | nc 127.0.0.1 "$PORT" 2>/dev/null)"
set -e -o pipefail
capcode="$(printf '%s' "$capresp" | sed -n '1s/.*\([0-9]\{3\}\).*/\1/p')"
expect ">64KB header capped (413)" 413 "$capcode"

exit $fail
