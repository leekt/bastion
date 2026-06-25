#!/bin/sh

set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
EVIDENCE_DIR="${BASTION_LIFECYCLE_EVIDENCE_DIR:-${ROOT_DIR}/dist/lifecycle}"
REQUIRED_PHASES="fresh-install reinstall post-reboot post-login notification-click"
failures=0

usage() {
  cat <<'USAGE'
Usage:
  scripts/audit-service-lifecycle-evidence.sh [--evidence-dir <dir>] [--phase <name>]...

Default phases:
  fresh-install reinstall post-reboot post-login notification-click

The audit passes only when each required phase has a lifecycle verifier log with:
  - "==> Live lifecycle verification complete"
  - no "FAIL:" lines
  - a Phase line matching the required phase
  - the same App, Domain, and TeamIdentifier across all required phases
  - notification delivery and click-route evidence when the phase is notification-click
USAGE
}

custom_phases=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --evidence-dir)
      shift
      [ "$#" -gt 0 ] || { usage >&2; exit 2; }
      EVIDENCE_DIR="$1"
      ;;
    --phase)
      shift
      [ "$#" -gt 0 ] || { usage >&2; exit 2; }
      custom_phases="${custom_phases} $1"
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

if [ -n "$custom_phases" ]; then
  REQUIRED_PHASES="$custom_phases"
fi

note() {
  printf '%s\n' "$*"
}

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  failures=$((failures + 1))
}

latest_phase_log() {
  phase="$1"
  safe_phase="$(printf '%s' "$phase" | /usr/bin/tr -c 'A-Za-z0-9_.-' '_')"
  find "$EVIDENCE_DIR" -maxdepth 1 -type f -name "*-${safe_phase}.log" -print 2>/dev/null \
    | /usr/bin/sort \
    | /usr/bin/tail -1
}

note "==> Bastion lifecycle evidence audit"
note "Evidence directory: ${EVIDENCE_DIR}"
note "Required phases: ${REQUIRED_PHASES}"

if [ ! -d "$EVIDENCE_DIR" ]; then
  fail "Evidence directory not found: ${EVIDENCE_DIR}"
else
  expected_app=""
  expected_domain=""
  expected_team_id=""
  for phase in $REQUIRED_PHASES; do
    log_path="$(latest_phase_log "$phase")"
    if [ -z "$log_path" ]; then
      fail "Missing lifecycle evidence log for phase ${phase}"
      continue
    fi

    note "==> ${phase}: ${log_path}"
    if ! /usr/bin/grep -F '==> Live lifecycle verification complete' "$log_path" >/dev/null; then
      fail "Phase ${phase} did not complete successfully"
    fi
    if /usr/bin/grep -F 'FAIL:' "$log_path" >/dev/null; then
      fail "Phase ${phase} contains failure lines"
    fi

    recorded_phase="$(/usr/bin/sed -n 's/^Phase: //p' "$log_path" | /usr/bin/head -1)"
    app_path="$(/usr/bin/sed -n 's/^App: //p' "$log_path" | /usr/bin/head -1)"
    domain="$(/usr/bin/sed -n 's/^Domain: //p' "$log_path" | /usr/bin/head -1)"
    team_id="$(/usr/bin/sed -n 's/^TeamIdentifier: //p' "$log_path" | /usr/bin/head -1)"

    if [ -z "$recorded_phase" ]; then
      fail "Phase ${phase} does not record its phase label"
    elif [ "$recorded_phase" != "$phase" ]; then
      fail "Phase ${phase} log records Phase: ${recorded_phase}"
    fi

    if [ -z "$app_path" ]; then
      fail "Phase ${phase} does not record the app path"
    elif [ -z "$expected_app" ]; then
      expected_app="$app_path"
    elif [ "$app_path" != "$expected_app" ]; then
      fail "Phase ${phase} app path ${app_path} does not match ${expected_app}"
    fi

    if [ -z "$domain" ]; then
      fail "Phase ${phase} does not record the LaunchAgent domain"
    elif [ -z "$expected_domain" ]; then
      expected_domain="$domain"
    elif [ "$domain" != "$expected_domain" ]; then
      fail "Phase ${phase} LaunchAgent domain ${domain} does not match ${expected_domain}"
    fi

    if [ -z "$team_id" ] || [ "$team_id" = "<none>" ]; then
      fail "Phase ${phase} does not record a signed TeamIdentifier"
    elif [ -z "$expected_team_id" ]; then
      expected_team_id="$team_id"
    elif [ "$team_id" != "$expected_team_id" ]; then
      fail "Phase ${phase} TeamIdentifier ${team_id} does not match ${expected_team_id}"
    fi

    if [ "$phase" = "notification-click" ]; then
      if ! /usr/bin/grep -F 'Matched delivery diagnostic:' "$log_path" >/dev/null; then
        fail "Phase notification-click does not contain matched notification delivery diagnostics"
      fi
      if ! /usr/bin/grep -F 'Matched click route diagnostic:' "$log_path" >/dev/null; then
        fail "Phase notification-click does not contain matched notification click-route diagnostics"
      fi
    fi
  done
fi

if [ "$failures" -gt 0 ]; then
  note "==> Lifecycle evidence audit failed with ${failures} failure(s)"
  exit 1
fi

note "==> Lifecycle evidence audit complete"
