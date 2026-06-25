#!/bin/sh

set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
OUTPUT_ROOT="${BASTION_RELEASE_OUTPUT_DIR:-${ROOT_DIR}/dist/release}"
APP_PATH="${1:-${OUTPUT_ROOT}/Bastion.app}"
EXPECTED_TEAM_ID="${BASTION_EXPECTED_TEAM_ID:-926A27BQ7W}"
EXPECTED_BUNDLE_ID="${BASTION_EXPECTED_BUNDLE_ID:-com.bastion.app}"
EXPECTED_HELPER_BUNDLE_ID="${BASTION_EXPECTED_HELPER_BUNDLE_ID:-com.bastion.helper}"
EXPECTED_MACH_SERVICE="${BASTION_EXPECTED_MACH_SERVICE:-com.bastion.xpc}"
PLIST_BUDDY="/usr/libexec/PlistBuddy"

fail() {
  echo "$*" >&2
  exit 1
}

plist_value() {
  "${PLIST_BUDDY}" -c "Print $2" "$1" 2>/dev/null || true
}

verify_signature() {
  path="$1"
  /usr/bin/codesign --verify --deep --strict --verbose=2 "${path}" >/dev/null
  team_id="$(/usr/bin/codesign -dv "${path}" 2>&1 | /usr/bin/awk -F= '/^TeamIdentifier=/{print $2}')"
  if [ "${team_id}" != "${EXPECTED_TEAM_ID}" ]; then
    fail "Unexpected TeamIdentifier for ${path}: ${team_id:-<none>} (expected ${EXPECTED_TEAM_ID})"
  fi
}

verify_app_assessment() {
  app_path="$1"
  /usr/sbin/spctl --assess --type execute --verbose "${app_path}" >/dev/null
  /usr/bin/xcrun stapler validate "${app_path}" >/dev/null
}

if [ ! -d "${APP_PATH}" ]; then
  fail "App bundle not found at ${APP_PATH}"
fi

INFO_PLIST="${APP_PATH}/Contents/Info.plist"
APP_BIN="${APP_PATH}/Contents/MacOS/bastion"
CLI_BIN="${APP_PATH}/Contents/MacOS/bastion-cli"
SERVICE_PLIST="${APP_PATH}/Contents/Library/LaunchAgents/com.bastion.xpc.plist"
HELPER_APP="${APP_PATH}/Contents/Helpers/bastion-helper.app"

echo "==> Verifying app bundle identity"
if [ ! -f "${INFO_PLIST}" ]; then
  fail "Info.plist missing at ${INFO_PLIST}"
fi
if [ ! -x "${APP_BIN}" ]; then
  fail "Main executable missing or not executable at ${APP_BIN}"
fi
VERSION="$(/usr/bin/defaults read "${APP_PATH}/Contents/Info" CFBundleShortVersionString)"
BUILD_NUMBER="$(/usr/bin/defaults read "${APP_PATH}/Contents/Info" CFBundleVersion)"
BUNDLE_ID="$(/usr/bin/defaults read "${APP_PATH}/Contents/Info" CFBundleIdentifier)"
if [ "${BUNDLE_ID}" != "${EXPECTED_BUNDLE_ID}" ]; then
  fail "Unexpected bundle identifier: ${BUNDLE_ID} (expected ${EXPECTED_BUNDLE_ID})"
fi

echo "==> Verifying app signature and notarization"
verify_signature "${APP_PATH}"
verify_app_assessment "${APP_PATH}"

echo "==> Verifying bundled CLI"
if [ ! -x "${CLI_BIN}" ]; then
  fail "Bundled CLI missing or not executable at ${CLI_BIN}"
fi
verify_signature "${CLI_BIN}"

echo "==> Verifying service launch plist"
if [ ! -f "${SERVICE_PLIST}" ]; then
  fail "Service LaunchAgent plist missing at ${SERVICE_PLIST}"
fi
LABEL="$(plist_value "${SERVICE_PLIST}" ":Label")"
BUNDLE_PROGRAM="$(plist_value "${SERVICE_PLIST}" ":BundleProgram")"
MACH_ENABLED="$(plist_value "${SERVICE_PLIST}" ":MachServices:${EXPECTED_MACH_SERVICE}")"
KEEPALIVE_SUCCESSFUL_EXIT="$(plist_value "${SERVICE_PLIST}" ":KeepAlive:SuccessfulExit")"
MAIN_ASSOCIATED="$(plist_value "${SERVICE_PLIST}" ":AssociatedBundleIdentifiers:0")"
HELPER_ASSOCIATED="$(plist_value "${SERVICE_PLIST}" ":AssociatedBundleIdentifiers:1")"
if [ "${LABEL}" != "${EXPECTED_MACH_SERVICE}" ]; then
  fail "LaunchAgent label mismatch: ${LABEL:-<missing>}"
fi
if [ "${BUNDLE_PROGRAM}" != "Contents/MacOS/bastion" ]; then
  fail "LaunchAgent BundleProgram mismatch: ${BUNDLE_PROGRAM:-<missing>}"
fi
if [ "${MACH_ENABLED}" != "true" ]; then
  fail "LaunchAgent MachServices:${EXPECTED_MACH_SERVICE} is not true"
fi
if [ "${KEEPALIVE_SUCCESSFUL_EXIT}" != "false" ]; then
  fail "LaunchAgent KeepAlive:SuccessfulExit must be false so user Quit does not relaunch Bastion"
fi
if [ "${MAIN_ASSOCIATED}" != "${EXPECTED_BUNDLE_ID}" ]; then
  fail "LaunchAgent associated main bundle mismatch: ${MAIN_ASSOCIATED:-<missing>}"
fi
if [ "${HELPER_ASSOCIATED}" != "${EXPECTED_HELPER_BUNDLE_ID}" ]; then
  fail "LaunchAgent associated helper bundle mismatch: ${HELPER_ASSOCIATED:-<missing>}"
fi

if [ -d "${HELPER_APP}" ]; then
  echo "==> Verifying bundled helper"
  HELPER_ID="$(/usr/bin/defaults read "${HELPER_APP}/Contents/Info" CFBundleIdentifier)"
  if [ "${HELPER_ID}" != "${EXPECTED_HELPER_BUNDLE_ID}" ]; then
    fail "Unexpected helper bundle identifier: ${HELPER_ID} (expected ${EXPECTED_HELPER_BUNDLE_ID})"
  fi
  verify_signature "${HELPER_APP}"
fi

ZIP_PATH="${OUTPUT_ROOT}/Bastion-${VERSION}-${BUILD_NUMBER}-macOS.zip"
DMG_PATH="${OUTPUT_ROOT}/Bastion-${VERSION}-${BUILD_NUMBER}-macOS.dmg"
MANIFEST_PATH="${OUTPUT_ROOT}/latest.json"

echo "==> Verifying release zip"
if [ ! -f "${ZIP_PATH}" ]; then
  fail "Release zip missing at ${ZIP_PATH}"
fi
ZIP_SHA256="$(/usr/bin/shasum -a 256 "${ZIP_PATH}" | /usr/bin/awk '{print $1}')"
ZIP_SIZE="$(/usr/bin/stat -f%z "${ZIP_PATH}")"

echo "==> Verifying DMG"
if [ ! -f "${DMG_PATH}" ]; then
  fail "Release DMG missing at ${DMG_PATH}"
fi
/usr/bin/hdiutil verify "${DMG_PATH}" >/dev/null

echo "==> Verifying update manifest"
if [ ! -f "${MANIFEST_PATH}" ]; then
  fail "Release manifest missing at ${MANIFEST_PATH}"
fi
MANIFEST_BUNDLE_ID="$(/usr/bin/plutil -extract bundleIdentifier raw -expect string -o - "${MANIFEST_PATH}")"
MANIFEST_VERSION="$(/usr/bin/plutil -extract version raw -expect string -o - "${MANIFEST_PATH}")"
MANIFEST_BUILD="$(/usr/bin/plutil -extract build raw -expect string -o - "${MANIFEST_PATH}")"
MANIFEST_URL="$(/usr/bin/plutil -extract downloadURL raw -expect string -o - "${MANIFEST_PATH}")"
MANIFEST_SHA256="$(/usr/bin/plutil -extract sha256 raw -expect string -o - "${MANIFEST_PATH}")"
MANIFEST_SIZE="$(/usr/bin/plutil -extract sizeBytes raw -expect integer -o - "${MANIFEST_PATH}")"
MANIFEST_NOTARIZED="$(/usr/bin/plutil -extract notarized raw -expect bool -o - "${MANIFEST_PATH}")"
MANIFEST_STAPLED="$(/usr/bin/plutil -extract stapled raw -expect bool -o - "${MANIFEST_PATH}")"
if [ "${MANIFEST_BUNDLE_ID}" != "${BUNDLE_ID}" ] || [ "${MANIFEST_VERSION}" != "${VERSION}" ] || [ "${MANIFEST_BUILD}" != "${BUILD_NUMBER}" ]; then
  fail "Manifest identity does not match ${APP_PATH}"
fi
if [ -z "${MANIFEST_URL}" ]; then
  fail "Manifest downloadURL is empty"
fi
if [ "${MANIFEST_SHA256}" != "${ZIP_SHA256}" ]; then
  fail "Manifest sha256 does not match release zip"
fi
if [ "${MANIFEST_SIZE}" != "${ZIP_SIZE}" ]; then
  fail "Manifest sizeBytes does not match release zip"
fi
if [ "${MANIFEST_NOTARIZED}" != "true" ] || [ "${MANIFEST_STAPLED}" != "true" ]; then
  fail "Manifest is not marked notarized/stapled"
fi

echo "==> Release verification complete"
echo "App: ${APP_PATH}"
echo "Zip: ${ZIP_PATH}"
echo "DMG: ${DMG_PATH}"
echo "Manifest: ${MANIFEST_PATH}"
