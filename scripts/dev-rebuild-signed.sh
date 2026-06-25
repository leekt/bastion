#!/bin/sh

set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
PROJECT_PATH="${ROOT_DIR}/bastion.xcodeproj"
SCHEME="bastion"
LOCAL_ENV_FILE="${ROOT_DIR}/.bastion-dev-local.env"
DERIVED_DATA_PATH="${HOME}/Library/Developer/Xcode/DerivedData/bastion-dev-signed"
BUILD_APP_PATH="${DERIVED_DATA_PATH}/Build/Products/Debug/bastion.app"
APP_XCENT_PATH="${DERIVED_DATA_PATH}/Build/Intermediates.noindex/bastion.build/Debug/bastion.build/bastion.app.xcent"
INSTALL_APP_PATH="${HOME}/Applications/Bastion Dev.app"
APP_PATH="${INSTALL_APP_PATH}"
APP_BIN="${INSTALL_APP_PATH}/Contents/MacOS/bastion"
CLI_BIN="${INSTALL_APP_PATH}/Contents/MacOS/bastion-cli"
HELPER_BIN="${INSTALL_APP_PATH}/Contents/Helpers/bastion-helper.app/Contents/MacOS/bastion-helper"
LAUNCH_AGENT_LABEL="com.bastion.xpc"
LAUNCH_AGENT_PLIST="${HOME}/Library/LaunchAgents/${LAUNCH_AGENT_LABEL}.plist"
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Versions/Current/Frameworks/LaunchServices.framework/Versions/Current/Support/lsregister"
LOGIN_KEYCHAIN="${HOME}/Library/Keychains/login.keychain-db"

if [ -f "${LOCAL_ENV_FILE}" ]; then
  # shellcheck disable=SC1090
  . "${LOCAL_ENV_FILE}"
fi

APP_BUNDLE_ID="${BASTION_APP_BUNDLE_ID:-com.bastion.app}"
HELPER_BUNDLE_ID="${BASTION_HELPER_BUNDLE_ID:-com.bastion.helper}"

resolve_private_key_label() {
  cert_key_hash="$(/usr/bin/security find-certificate -c "${IDENTITY_NAME}" -Z "${LOGIN_KEYCHAIN}" 2>/dev/null | /usr/bin/awk '
    /"skid"<blob>=0x/ {
      line = $0
      sub(/^.*"skid"<blob>=0x/, "", line)
      sub(/[[:space:]].*$/, "", line)
      print line
      exit
    }
  ')"
  if [ -z "${cert_key_hash}" ]; then
    return 0
  fi

  /usr/bin/security dump-keychain "${LOGIN_KEYCHAIN}" 2>/dev/null | /usr/bin/awk -v key_hash="${cert_key_hash}" '
    BEGIN {
      target = toupper(key_hash)
      in_private_key = 0
      label = ""
    }
    /^class:/ {
      in_private_key = ($2 == "0x00000010")
      label = ""
      next
    }
    in_private_key && /0x00000001 <blob>=/ {
      line = $0
      sub(/^.*<blob>="/, "", line)
      sub(/"$/, "", line)
      label = line
      next
    }
    in_private_key && /0x00000006 <blob>=0x/ {
      line = $0
      sub(/^.*<blob>=0x/, "", line)
      sub(/[[:space:]].*$/, "", line)
      if (toupper(line) == target && label != "") {
        print label
        exit
      }
    }
  '
}

print_codesign_keychain_help() {
  cat >&2 <<EOF
Code-signing identity ${IDENTITY_HASH} exists but cannot sign from this shell.
Identity: ${IDENTITY_NAME}
This usually means the private key is locked, its access-control list does not
allow /usr/bin/codesign, or the private key is missing the apple-tool/apple/
codesign partition list required by noninteractive signing.

To repair the local keychain access, unlock the login keychain and grant Apple signing tools access to the private key:
  scripts/dev-enable-codesign-keychain-access.sh

Manual equivalent:
  security unlock-keychain "${LOGIN_KEYCHAIN}"
  security set-keychain-settings "${LOGIN_KEYCHAIN}"
  security set-key-partition-list -S apple-tool:,apple:,codesign: -s -t private -k <login-keychain-password> "${LOGIN_KEYCHAIN}"

Run each manual command on one shell command line. Do not add a -l identity-name
filter; Apple certificate names and private-key labels can differ after Xcode
rotates or replaces development certificates.

Alternatively, open Keychain Access, expand the certificate named "${IDENTITY_NAME}",
EOF
  if [ -n "${IDENTITY_PRIVATE_KEY_LABEL:-}" ]; then
    cat >&2 <<EOF
then select the nested private key labeled "${IDENTITY_PRIVATE_KEY_LABEL}",
EOF
  else
    cat >&2 <<EOF
then open the nested private key,
EOF
  fi
  cat >&2 <<EOF
choose Access Control, and allow /usr/bin/codesign access. If Keychain Access
already says all applications may access that private key, run the helper anyway;
the remaining blocker is usually the private key partition list, not the visible
Access Control checkbox.
Then rerun:
  scripts/dev-rebuild-signed.sh
EOF
}

echo "==> Checking code-signing identity usability"
IDENTITY_ROW="$(/usr/bin/security find-identity -v -p codesigning | /usr/bin/awk '/^[[:space:]]*[0-9]+[)]/ { print; exit }')"
IDENTITY_HASH="$(printf '%s\n' "${IDENTITY_ROW}" | /usr/bin/awk '{ print $2 }')"
IDENTITY_NAME="$(printf '%s\n' "${IDENTITY_ROW}" | /usr/bin/sed -E 's/^[[:space:]]*[0-9]+\)[[:space:]]+[A-Fa-f0-9]+[[:space:]]+"(.*)"$/\1/')"
if [ -z "${IDENTITY_HASH}" ]; then
  echo "No valid code-signing identity found. Install or import an Apple Development identity before rebuilding the signed app." >&2
  exit 1
fi
IDENTITY_PRIVATE_KEY_LABEL="$(resolve_private_key_label || true)"
PROBE_DIR="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/bastion-codesign-probe.XXXXXX")"
trap '/bin/rm -rf "${PROBE_DIR}"' EXIT HUP INT TERM
PROBE_BIN="${PROBE_DIR}/probe"
printf '#!/bin/sh\nexit 0\n' > "${PROBE_BIN}"
/bin/chmod +x "${PROBE_BIN}"
if ! /usr/bin/codesign --force --sign "${IDENTITY_HASH}" --timestamp=none "${PROBE_BIN}" >/dev/null 2>"${PROBE_DIR}/codesign.log"; then
  print_codesign_keychain_help
  /bin/cat "${PROBE_DIR}/codesign.log" >&2
  exit 1
fi

echo "==> Building signed Bastion app"
# -allowProvisioningUpdates lets xcodebuild fetch or create the local Mac App
# Development profiles that the project's automatic-signing config expects.
# Machines with existing private development profiles can set BASTION_APP_BUNDLE_ID
# and BASTION_HELPER_BUNDLE_ID in the environment or .bastion-dev-local.env.
xcodebuild \
  -project "${PROJECT_PATH}" \
  -scheme "${SCHEME}" \
  -derivedDataPath "${DERIVED_DATA_PATH}" \
  -allowProvisioningUpdates \
  BASTION_APP_BUNDLE_ID="${APP_BUNDLE_ID}" \
  BASTION_HELPER_BUNDLE_ID="${HELPER_BUNDLE_ID}" \
  INFOPLIST_KEY_CFBundleName="Bastion Dev" \
  INFOPLIST_KEY_CFBundleDisplayName="Bastion Dev" \
  ENABLE_USER_SCRIPT_SANDBOXING=NO \
  ENABLE_DEBUG_DYLIB=NO \
  ENABLE_PREVIEWS=NO \
  build

if [ ! -x "${APP_BIN}" ]; then
  if [ ! -x "${BUILD_APP_PATH}/Contents/MacOS/bastion" ]; then
    echo "Signed app binary not found at ${BUILD_APP_PATH}" >&2
    exit 1
  fi
fi

echo "==> Unregistering stale Bastion app bundles"
find "${HOME}/Library/Developer/Xcode/DerivedData" -path "*/Build/Products/Debug/bastion.app" -type d | while read -r candidate; do
  if [ "${candidate}" != "${BUILD_APP_PATH}" ]; then
    "${LSREGISTER}" -u "${candidate}" >/dev/null 2>&1 || true
  fi
done

echo "==> Removing legacy LaunchAgent bootstrap"
/bin/launchctl bootout "gui/$(id -u)/${LAUNCH_AGENT_LABEL}" >/dev/null 2>&1 || true
/bin/rm -f "${LAUNCH_AGENT_PLIST}"

echo "==> Stopping stale Bastion processes"
/usr/bin/pkill -f '/(Bastion Dev|bastion).app/Contents/MacOS/bastion($| )' >/dev/null 2>&1 || true
/usr/bin/pkill -f '/bastion-helper.app/Contents/MacOS/bastion-helper($| )' >/dev/null 2>&1 || true

echo "==> Installing signed Bastion app to stable path"
/bin/mkdir -p "${HOME}/Applications"
/bin/rm -rf "${INSTALL_APP_PATH}"
/usr/bin/ditto "${BUILD_APP_PATH}" "${INSTALL_APP_PATH}"
if [ -d "${DERIVED_DATA_PATH}/Build/Products/Debug/bastion-helper.app" ]; then
  /bin/rm -rf "${INSTALL_APP_PATH}/Contents/Helpers/bastion-helper.app"
  /bin/mkdir -p "${INSTALL_APP_PATH}/Contents/Helpers"
  /usr/bin/ditto "${DERIVED_DATA_PATH}/Build/Products/Debug/bastion-helper.app" "${INSTALL_APP_PATH}/Contents/Helpers/bastion-helper.app"
fi
for runtime_binary in "${APP_BIN}" "${CLI_BIN}" "${HELPER_BIN}"; do
  if [ -e "${runtime_binary}" ]; then
    /usr/bin/touch "${runtime_binary}"
  fi
done

echo "==> Branding installed development app bundle"
APP_INFO_PLIST="${INSTALL_APP_PATH}/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleName Bastion Dev" "${APP_INFO_PLIST}" >/dev/null 2>&1 \
  || /usr/libexec/PlistBuddy -c "Add :CFBundleName string Bastion Dev" "${APP_INFO_PLIST}" >/dev/null
/usr/libexec/PlistBuddy -c "Set :CFBundleDisplayName Bastion Dev" "${APP_INFO_PLIST}" >/dev/null 2>&1 \
  || /usr/libexec/PlistBuddy -c "Add :CFBundleDisplayName string Bastion Dev" "${APP_INFO_PLIST}" >/dev/null
if [ -f "${APP_XCENT_PATH}" ]; then
  /usr/bin/codesign --force --sign "${IDENTITY_HASH}" --timestamp=none --options runtime --entitlements "${APP_XCENT_PATH}" "${INSTALL_APP_PATH}" >/dev/null
else
  /usr/bin/codesign --force --sign "${IDENTITY_HASH}" --timestamp=none --options runtime "${INSTALL_APP_PATH}" >/dev/null
fi
/usr/bin/codesign --verify --deep --strict --verbose=2 "${INSTALL_APP_PATH}" >/dev/null

echo "==> Registering signed Bastion app bundle"
"${LSREGISTER}" -f -R -trusted "${APP_PATH}" >/dev/null 2>&1 || true

echo "==> Registering SMAppService agent"
"${APP_BIN}" --register-service
/bin/launchctl kickstart -k "gui/$(id -u)/${LAUNCH_AGENT_LABEL}" >/dev/null 2>&1 || true
/bin/sleep 1

echo "==> Installing CLI symlink"
if ! "${ROOT_DIR}/scripts/install-cli-symlink.sh" --cli "${CLI_BIN}" --sudo-if-interactive; then
  echo "WARN: CLI symlink was not installed. For an interactive privileged install, run:"
  echo "      \"${ROOT_DIR}/scripts/install-cli-symlink.sh\" --cli \"${CLI_BIN}\" --sudo"
fi

if [ -x "${CLI_BIN}" ]; then
  echo "==> CLI status"
  STATUS_OK=0
  STATUS_OUTPUT="${PROBE_DIR}/cli-status.json"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if "${CLI_BIN}" status >"${STATUS_OUTPUT}"; then
      /bin/cat "${STATUS_OUTPUT}"
      STATUS_OK=1
      break
    fi
    /bin/sleep 1
  done
  if [ "${STATUS_OK}" -ne 1 ]; then
    echo "Bastion service did not become reachable over XPC." >&2
    exit 1
  fi
  python3 - "${INSTALL_APP_PATH}" "${STATUS_OUTPUT}" <<'PY'
import json
import sys
from pathlib import Path

expected = Path(sys.argv[1]).resolve()
status_path = Path(sys.argv[2])
status = json.loads(status_path.read_text())
actual_value = status.get("bundlePath")
if not actual_value:
    raise SystemExit("CLI status did not report bundlePath")
actual = Path(actual_value).resolve()
if actual != expected:
    raise SystemExit(f"Live service is running from {actual}, expected {expected}")
PY
fi

echo "==> Active Bastion processes"
/bin/ps aux | /usr/bin/grep -E '/(Bastion Dev|bastion)\\.app/Contents/MacOS/bastion|/bastion-helper\\.app/Contents/MacOS/bastion-helper' | /usr/bin/grep -v grep || true

echo "==> Done"
echo "App: ${APP_PATH}"
echo "CLI: ${CLI_BIN}"
echo "Helper: ${HELPER_BIN}"
