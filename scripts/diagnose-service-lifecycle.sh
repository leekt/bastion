#!/bin/sh

set -eu

APP_PATH="${1:-${BASTION_APP_PATH:-${HOME}/Applications/Bastion Dev.app}}"
LABEL="${BASTION_LAUNCH_AGENT_LABEL:-com.bastion.xpc}"
DOMAIN="gui/$(id -u)/${LABEL}"
PLIST_PATH="${APP_PATH}/Contents/Library/LaunchAgents/${LABEL}.plist"
LEGACY_PLIST="${HOME}/Library/LaunchAgents/${LABEL}.plist"
APP_BIN="${APP_PATH}/Contents/MacOS/bastion"
CLI_BIN="${APP_PATH}/Contents/MacOS/bastion-cli"
HELPER_BIN="${APP_PATH}/Contents/Helpers/bastion-helper.app/Contents/MacOS/bastion-helper"
failures=0

note() {
  printf '%s\n' "$*"
}

warn() {
  printf 'WARN: %s\n' "$*" >&2
}

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  failures=$((failures + 1))
}

plist_value() {
  /usr/libexec/PlistBuddy -c "Print :$2" "$1" 2>/dev/null || true
}

check_executable() {
  label="$1"
  path="$2"
  if [ -x "$path" ]; then
    note "OK: ${label}: ${path}"
  else
    fail "${label} is not executable at ${path}"
  fi
}

note "==> Bastion service lifecycle diagnostic"
note "App: ${APP_PATH}"
note "Domain: ${DOMAIN}"

if [ ! -d "$APP_PATH" ]; then
  fail "App bundle not found. Build/install first or pass an app path."
else
  check_executable "main app executable" "$APP_BIN"
  if [ -e "$HELPER_BIN" ]; then
    check_executable "embedded helper executable" "$HELPER_BIN"
  else
    warn "Embedded helper executable not found at ${HELPER_BIN}"
  fi
fi

note "==> Embedded SMAppService plist"
if [ ! -f "$PLIST_PATH" ]; then
  fail "Embedded LaunchAgent plist missing at ${PLIST_PATH}"
else
  label="$(plist_value "$PLIST_PATH" Label)"
  bundle_program="$(plist_value "$PLIST_PATH" BundleProgram)"
  mach_enabled="$(plist_value "$PLIST_PATH" "MachServices:${LABEL}")"
  keepalive_successful_exit="$(plist_value "$PLIST_PATH" "KeepAlive:SuccessfulExit")"

  [ "$label" = "$LABEL" ] || fail "LaunchAgent Label is ${label:-<missing>} (expected ${LABEL})"
  [ -n "$bundle_program" ] || fail "LaunchAgent BundleProgram is missing"
  [ "$mach_enabled" = "true" ] || fail "MachServices.${LABEL} is not true"
  [ "$keepalive_successful_exit" = "false" ] || fail "KeepAlive.SuccessfulExit must be false so user Quit does not relaunch Bastion"

  if [ -n "$bundle_program" ]; then
    case "$bundle_program" in
      /*)
        fail "BundleProgram must be app-bundle relative, got absolute path ${bundle_program}"
        ;;
      *)
        check_executable "BundleProgram target" "${APP_PATH}/${bundle_program}"
        ;;
    esac

    if printf '%s' "$bundle_program" | /usr/bin/grep -q '^Contents/Helpers/'; then
      note "INFO: BundleProgram points at embedded helper path."
      note "INFO: launchd.plist says BundleProgram is only supported for plists installed using SMAppService."
      note "INFO: If launchctl reports EX_CONFIG with this path, verify the job came from SMAppService, not a legacy plist."
    fi
  fi
fi

note "==> Legacy LaunchAgent conflict check"
if [ -f "$LEGACY_PLIST" ]; then
  warn "Legacy LaunchAgent plist exists at ${LEGACY_PLIST}"
  legacy_bundle_program="$(plist_value "$LEGACY_PLIST" BundleProgram)"
  legacy_program="$(plist_value "$LEGACY_PLIST" Program)"
  if [ -n "$legacy_bundle_program" ]; then
    fail "Legacy plist contains BundleProgram=${legacy_bundle_program}. BundleProgram is only supported for SMAppService-installed plists and can produce invalid Program/ProgramArguments / EX_CONFIG."
  elif [ -n "$legacy_program" ]; then
    note "INFO: Legacy plist Program=${legacy_program}"
  else
    warn "Legacy plist has no Program or BundleProgram value."
  fi
else
  note "OK: no legacy plist at ${LEGACY_PLIST}"
fi

note "==> launchctl state"
if /bin/launchctl print "$DOMAIN" >/tmp/bastion-launchctl-state.$$ 2>/tmp/bastion-launchctl-error.$$; then
  /usr/bin/awk '
    /state =/ || /last exit code =/ || /program =/ || /path =/ || /origin =/ || /spawn type =/ || /runs =/ {
      gsub(/^[ \t]+/, "")
      print
    }
  ' /tmp/bastion-launchctl-state.$$
else
  warn "launchctl print ${DOMAIN} failed:"
  /bin/cat /tmp/bastion-launchctl-error.$$ >&2 || true
fi
/bin/rm -f /tmp/bastion-launchctl-state.$$ /tmp/bastion-launchctl-error.$$

note "==> CLI/XPC status"
if [ -x "$CLI_BIN" ]; then
  if "$CLI_BIN" status; then
    note "OK: CLI reached XPC service"
  else
    warn "CLI status failed; service may not be running or may require registration."
  fi
else
  warn "Bundled CLI missing at ${CLI_BIN}"
fi

if [ "$failures" -gt 0 ]; then
  note "==> Diagnostic complete with ${failures} failure(s)"
  exit 1
fi

note "==> Diagnostic complete"
