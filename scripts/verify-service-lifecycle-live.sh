#!/bin/sh

set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
APP_PATH="${BASTION_APP_PATH:-${HOME}/Applications/Bastion Dev.app}"
PHASE="${BASTION_LIFECYCLE_PHASE:-current}"
EVIDENCE_DIR="${BASTION_LIFECYCLE_EVIDENCE_DIR:-${ROOT_DIR}/dist/lifecycle}"
LABEL="${BASTION_LAUNCH_AGENT_LABEL:-com.bastion.xpc}"
DOMAIN="gui/$(id -u)/${LABEL}"
APP_BIN=""
CLI_BIN=""
STATUS_PROCESS_IDENTIFIER=""
REGISTER_SERVICE=0
RUN_RELAY_OPEN=1
REQUIRE_NOTIFICATION_CLICK=0
NOTIFICATION_TIMEOUT=60
EXPECTED_TEAM_ID="${BASTION_EXPECTED_TEAM_ID:-}"
DIAGNOSTIC_LOG_PATH="${HOME}/Library/Application Support/Bastion/diagnostics.jsonl"
failures=0

usage() {
  cat <<'USAGE'
Usage:
  scripts/verify-service-lifecycle-live.sh [--app <app-bundle>] [--phase <name>] [--register] [--skip-relay-open] [--require-notification-click]

Environment:
  BASTION_APP_PATH                    Default app path, if --app is not provided. Defaults to ~/Applications/Bastion Dev.app.
  BASTION_LIFECYCLE_PHASE             Evidence label, e.g. fresh-install, reinstall, post-reboot, post-login.
  BASTION_LIFECYCLE_EVIDENCE_DIR      Directory for the captured log.
  BASTION_EXPECTED_TEAM_ID            Optional signing team identifier to require.

Options:
  --notification-timeout <seconds>     Retained for compatibility; native banner activation is manual evidence, not required by this shell gate.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --app)
      shift
      [ "$#" -gt 0 ] || { usage >&2; exit 2; }
      APP_PATH="$1"
      ;;
    --phase)
      shift
      [ "$#" -gt 0 ] || { usage >&2; exit 2; }
      PHASE="$1"
      ;;
    --register)
      REGISTER_SERVICE=1
      ;;
    --skip-relay-open)
      RUN_RELAY_OPEN=0
      ;;
    --require-notification-click)
      REQUIRE_NOTIFICATION_CLICK=1
      ;;
    --notification-timeout)
      shift
      [ "$#" -gt 0 ] || { usage >&2; exit 2; }
      NOTIFICATION_TIMEOUT="$1"
      case "$NOTIFICATION_TIMEOUT" in
        ''|*[!0-9]*)
          echo "--notification-timeout must be a positive integer" >&2
          exit 2
          ;;
      esac
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

safe_phase="$(printf '%s' "$PHASE" | /usr/bin/tr -c 'A-Za-z0-9_.-' '_')"
timestamp="$(/bin/date -u '+%Y%m%dT%H%M%SZ')"
/bin/mkdir -p "$EVIDENCE_DIR"
LOG_PATH="${EVIDENCE_DIR}/${timestamp}-${safe_phase}.log"

note() {
  printf '%s\n' "$*" | /usr/bin/tee -a "$LOG_PATH"
}

warn() {
  printf 'WARN: %s\n' "$*" | /usr/bin/tee -a "$LOG_PATH" >&2
}

notification_permission_help() {
  note "Notification delivery authorization is required for automated notification live-runtime closure."
  note "Enable notifications for Bastion in System Settings > Notifications, then rerun:"
  note "  qa/run_live_runtime_checks.sh --run-phase notification-click --require-notification-click"
  note "If Bastion is not listed yet, launch the app once from ${APP_PATH} and trigger a signing or lifecycle notification probe first."
}

fail() {
  printf 'FAIL: %s\n' "$*" | /usr/bin/tee -a "$LOG_PATH" >&2
  failures=$((failures + 1))
}

run_capture() {
  label="$1"
  shift
  tmp="$(/usr/bin/mktemp)"
  note "==> ${label}"
  if "$@" >"$tmp" 2>&1; then
    status=0
  else
    status=$?
  fi
  /bin/cat "$tmp" | /usr/bin/tee -a "$LOG_PATH"
  /bin/rm -f "$tmp"
  return "$status"
}

json_value() {
  key="$1"
  file="$2"
  /usr/bin/plutil -extract "$key" raw -o - "$file" 2>/dev/null || true
}

process_count_for() {
  executable="$1"
  basename="$(/usr/bin/basename "$executable")"
  bundle_relative="Contents/MacOS/${basename}"
  /bin/ps -axo pid=,command= \
    | /usr/bin/awk -v absolute="$executable" -v relative="$bundle_relative" '
        {
          command = $0
          sub(/^[[:space:]]*[0-9]+[[:space:]]+/, "", command)
          if (command == absolute || command == relative ||
              substr(command, 1, length(absolute) + 1) == absolute " " ||
              substr(command, 1, length(relative) + 1) == relative " ") {
            count += 1
          }
        }
        END { print count + 0 }
      '
}

process_command_for_pid() {
  pid="$1"
  [ -n "$pid" ] || return 1
  /bin/ps -p "$pid" -o command= 2>/dev/null || true
}

check_duplicate_processes() {
  if [ -n "$STATUS_PROCESS_IDENTIFIER" ]; then
    command="$(process_command_for_pid "$STATUS_PROCESS_IDENTIFIER")"
    if [ -z "$command" ]; then
      fail "CLI status reported processIdentifier ${STATUS_PROCESS_IDENTIFIER}, but that process is no longer running"
    else
      note "Bastion service process ${STATUS_PROCESS_IDENTIFIER}: ${command}"
    fi
  fi

  count="$(process_count_for "$APP_BIN")"
  note "Bastion service process count for ${APP_BIN}: ${count}"
  if [ "$count" -gt 1 ]; then
    fail "More than one Bastion process is running from ${APP_BIN}"
    /bin/ps -axo pid=,command= \
      | /usr/bin/awk -v absolute="$APP_BIN" -v relative="Contents/MacOS/$(/usr/bin/basename "$APP_BIN")" '
          {
            line = $0
            command = $0
            sub(/^[[:space:]]*[0-9]+[[:space:]]+/, "", command)
            if (command == absolute || command == relative ||
                substr(command, 1, length(absolute) + 1) == absolute " " ||
                substr(command, 1, length(relative) + 1) == relative " ") {
              print line
            }
          }
        ' \
      | /usr/bin/tee -a "$LOG_PATH" \
      || true
  fi
}

wait_for_relay_exit() {
  timeout="${BASTION_RELAY_EXIT_TIMEOUT:-15}"
  case "$timeout" in
    ''|*[!0-9]*)
      timeout=15
      ;;
  esac

  end_time=$(( $(/bin/date +%s) + timeout ))
  while [ "$(/bin/date +%s)" -le "$end_time" ]; do
    count="$(process_count_for "$APP_BIN")"
    if [ "$count" -le 1 ]; then
      return 0
    fi
    note "Waiting for LaunchServices relay handoff to exit; process count is ${count}"
    /bin/sleep 1
  done

  return 1
}

probe_line_matching() {
  probe_id="$1"
  event_regex="$2"
  [ -f "$DIAGNOSTIC_LOG_PATH" ] || return 1
  matches="$(/usr/bin/grep -F "\"bastionProbeID\":\"${probe_id}\"" "$DIAGNOSTIC_LOG_PATH" \
    | /usr/bin/grep -E "$event_regex" \
    || true)"
  [ -n "$matches" ] || return 1
  printf '%s\n' "$matches" | /usr/bin/tail -1
}

wait_for_probe_line() {
  probe_id="$1"
  event_regex="$2"
  timeout="$3"
  end_time=$(( $(/bin/date +%s) + timeout ))

  while [ "$(/bin/date +%s)" -le "$end_time" ]; do
    if line="$(probe_line_matching "$probe_id" "$event_regex")"; then
      printf '%s\n' "$line"
      return 0
    fi
    /bin/sleep 1
  done

  return 1
}

note "==> Bastion live service lifecycle verification"
note "Phase: ${PHASE}"
note "App: ${APP_PATH}"
note "Domain: ${DOMAIN}"
note "Evidence: ${LOG_PATH}"

case "$APP_PATH" in
  *DerivedData*)
    fail "App path is under DerivedData. Install to a stable app path before live lifecycle verification."
    ;;
esac

if [ ! -d "$APP_PATH" ]; then
  fail "App bundle not found at ${APP_PATH}"
  note "Current developer directory: $(/usr/bin/xcode-select -p 2>/dev/null || printf '<unknown>')"
  if ! /usr/bin/xcodebuild -version >/dev/null 2>&1; then
    warn "xcodebuild is not available from the active developer directory; install/select Xcode before running ./scripts/dev-rebuild-signed.sh."
  fi
  note "Install a signed stable build, then rerun:"
  note "  ./scripts/dev-rebuild-signed.sh"
  note "  scripts/verify-service-lifecycle-live.sh --phase fresh-install --register"
  exit 1
fi

APP_BIN="${APP_PATH}/Contents/MacOS/bastion"
CLI_BIN="${APP_PATH}/Contents/MacOS/bastion-cli"

[ -x "$APP_BIN" ] || fail "Main app executable missing at ${APP_BIN}"
[ -x "$CLI_BIN" ] || fail "Bundled CLI missing at ${CLI_BIN}"

if [ "$failures" -eq 0 ]; then
  run_capture "codesign verify app" /usr/bin/codesign --verify --deep --strict --verbose=2 "$APP_PATH" || fail "App codesign verification failed"
  team_id="$(/usr/bin/codesign -dv "$APP_PATH" 2>&1 | /usr/bin/awk -F= '/^TeamIdentifier=/{ print $2 }')"
  note "TeamIdentifier: ${team_id:-<none>}"
  if [ -n "$EXPECTED_TEAM_ID" ] && [ "$team_id" != "$EXPECTED_TEAM_ID" ]; then
    fail "TeamIdentifier ${team_id:-<none>} does not match BASTION_EXPECTED_TEAM_ID=${EXPECTED_TEAM_ID}"
  elif [ -z "$team_id" ]; then
    fail "Signed stable install must have a TeamIdentifier; ad hoc signatures are not enough for this live gate."
  fi
fi

if [ "$REGISTER_SERVICE" -eq 1 ] && [ "$failures" -eq 0 ]; then
  run_capture "register SMAppService" "$APP_BIN" --register-service || fail "Service registration failed"
  run_capture "kickstart SMAppService" /bin/launchctl kickstart -k "$DOMAIN" || warn "launchctl kickstart failed; continuing to status check"
  /bin/sleep 1
fi

if [ "$failures" -eq 0 ]; then
  run_capture "embedded service diagnostic" "${ROOT_DIR}/scripts/diagnose-service-lifecycle.sh" "$APP_PATH" || fail "Embedded service diagnostic failed"
fi

if [ "$failures" -eq 0 ]; then
  status_file="$(/usr/bin/mktemp)"
  note "==> CLI status"
  status_ok=0
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if "$CLI_BIN" status >"$status_file" 2>>"$LOG_PATH"; then
      status_ok=1
      break
    fi
    /bin/sleep 1
  done
  /bin/cat "$status_file" | /usr/bin/tee -a "$LOG_PATH"
  if [ "$status_ok" -ne 1 ]; then
    fail "CLI status did not reach the XPC service"
  else
    executable_path="$(json_value executablePath "$status_file")"
    bundle_path="$(json_value bundlePath "$status_file")"
    launch_mode="$(json_value launchMode "$status_file")"
    mach_service="$(json_value machServiceName "$status_file")"
    STATUS_PROCESS_IDENTIFIER="$(json_value processIdentifier "$status_file")"
    resolved_executable_path="$executable_path"
    case "$resolved_executable_path" in
      /*) ;;
      Contents/*) resolved_executable_path="${APP_PATH}/${resolved_executable_path}" ;;
    esac
    if [ "$resolved_executable_path" != "$APP_BIN" ]; then
      fail "XPC responded from ${executable_path:-<unknown>} instead of ${APP_BIN}"
    fi
    if [ "$bundle_path" != "$APP_PATH" ]; then
      fail "XPC bundlePath is ${bundle_path:-<unknown>} instead of ${APP_PATH}"
    fi
    if [ "$launch_mode" != "service" ]; then
      fail "XPC launchMode is ${launch_mode:-<unknown>} instead of service"
    fi
    if [ "$mach_service" != "$LABEL" ]; then
      fail "XPC machServiceName is ${mach_service:-<unknown>} instead of ${LABEL}"
    fi
  fi
  /bin/rm -f "$status_file"
fi

if [ "$failures" -eq 0 ]; then
  check_duplicate_processes
fi

if [ "$failures" -eq 0 ]; then
  run_capture "XPC UI open auditHistory" "$CLI_BIN" open-ui auditHistory || fail "XPC open-ui auditHistory failed"
fi

if [ "$REQUIRE_NOTIFICATION_CLICK" -eq 1 ] && [ "$failures" -eq 0 ]; then
  short_phase="$(printf '%s' "$safe_phase" | /usr/bin/cut -c 1-32)"
  probe_id="${short_phase}-${timestamp}-$$"
  note "==> Notification delivery probe"
  note "Probe ID: ${probe_id}"
  run_capture "deliver notification probe" "$CLI_BIN" notification-probe --id "$probe_id" || fail "Notification probe request failed"

  if [ "$failures" -eq 0 ]; then
    if delivered_line="$(wait_for_probe_line "$probe_id" '"event":"notification_delivered"' 10)"; then
      note "Matched delivery diagnostic: ${delivered_line}"
    elif skipped_line="$(probe_line_matching "$probe_id" '"event":"notification_skipped_unauthorized"')"; then
      fail "Notification probe was skipped because notification authorization is unavailable: ${skipped_line}"
      notification_permission_help
    else
      fail "Notification probe delivery was not recorded in ${DIAGNOSTIC_LOG_PATH}"
      notification_permission_help
    fi
  fi

  if [ "$failures" -eq 0 ]; then
    run_capture "trigger notification click route probe" "$CLI_BIN" notification-click-probe --id "$probe_id" || fail "Notification click route probe failed"
  fi

  if [ "$failures" -eq 0 ]; then
    if click_line="$(wait_for_probe_line "$probe_id" '"event":"notification_click_local_open"|"event":"notification_click_relay_result"' 10)"; then
      note "Matched click route diagnostic: ${click_line}"
    else
      fail "Notification click route was not recorded for probe ${probe_id}"
    fi
  fi

  if [ "$failures" -eq 0 ]; then
    note "Notification delivery and click-route behavior are proven through XPC diagnostics. Native Notification Center banner activation is optional manual OS-interaction evidence and is not required by this shell gate."
  fi
fi

if [ "$RUN_RELAY_OPEN" -eq 1 ] && [ "$failures" -eq 0 ]; then
  run_capture "LaunchServices relay open" /usr/bin/open -n "$APP_PATH" || fail "LaunchServices relay open failed"
  if ! wait_for_relay_exit; then
    fail "LaunchServices relay process did not exit after handoff timeout"
  fi
  check_duplicate_processes
fi

if [ "$failures" -gt 0 ]; then
  note "==> Live lifecycle verification failed with ${failures} failure(s)"
  note "Evidence: ${LOG_PATH}"
  exit 1
fi

note "==> Live lifecycle verification complete"
note "Evidence: ${LOG_PATH}"
