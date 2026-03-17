#!/bin/sh

set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
OUTPUT_ROOT="${BASTION_RELEASE_OUTPUT_DIR:-${ROOT_DIR}/dist/release}"
APP_PATH="${1:-${OUTPUT_ROOT}/Bastion.app}"

if [ ! -d "${APP_PATH}" ]; then
  echo "App bundle not found at ${APP_PATH}" >&2
  exit 1
fi

if [ -z "${BASTION_RELEASE_DOWNLOAD_URL:-}" ]; then
  echo "Set BASTION_RELEASE_DOWNLOAD_URL before generating a release manifest." >&2
  exit 1
fi

VERSION="$(/usr/bin/defaults read "${APP_PATH}/Contents/Info" CFBundleShortVersionString)"
BUILD_NUMBER="$(/usr/bin/defaults read "${APP_PATH}/Contents/Info" CFBundleVersion)"
BUNDLE_ID="$(/usr/bin/defaults read "${APP_PATH}/Contents/Info" CFBundleIdentifier)"
ZIP_PATH="${OUTPUT_ROOT}/Bastion-${VERSION}-${BUILD_NUMBER}-macOS.zip"
MANIFEST_PATH="${OUTPUT_ROOT}/latest.json"
NOTARY_STATUS_PATH="${OUTPUT_ROOT}/Bastion-${VERSION}-${BUILD_NUMBER}-notary-status.json"

if [ ! -f "${ZIP_PATH}" ]; then
  echo "Release zip not found at ${ZIP_PATH}. Run ./scripts/release-build.sh first." >&2
  exit 1
fi

SHA256="$(/usr/bin/shasum -a 256 "${ZIP_PATH}" | /usr/bin/awk '{print $1}')"
SIZE_BYTES="$(/usr/bin/stat -f%z "${ZIP_PATH}")"
MINIMUM_OS_VERSION="$(/usr/bin/defaults read "${APP_PATH}/Contents/Info" LSMinimumSystemVersion 2>/dev/null || echo "11.0")"
PUBLISHED_AT="$(/bin/date -u +"%Y-%m-%dT%H:%M:%SZ")"
RELEASE_NOTES_URL="${BASTION_RELEASE_NOTES_URL:-}"
NOTARIZED=false
STAPLED=false

if [ -f "${NOTARY_STATUS_PATH}" ]; then
  NOTARIZED="$(/usr/bin/plutil -extract notarized raw -expect bool -o - "${NOTARY_STATUS_PATH}" 2>/dev/null || echo false)"
  STAPLED="$(/usr/bin/plutil -extract stapled raw -expect bool -o - "${NOTARY_STATUS_PATH}" 2>/dev/null || echo false)"
fi

cat > "${MANIFEST_PATH}" <<EOF
{
  "app": "Bastion",
  "bundleIdentifier": "${BUNDLE_ID}",
  "version": "${VERSION}",
  "build": "${BUILD_NUMBER}",
  "platform": "macOS",
  "minimumOSVersion": "${MINIMUM_OS_VERSION}",
  "publishedAt": "${PUBLISHED_AT}",
  "downloadURL": "${BASTION_RELEASE_DOWNLOAD_URL}",
  "releaseNotesURL": "${RELEASE_NOTES_URL}",
  "sha256": "${SHA256}",
  "sizeBytes": ${SIZE_BYTES},
  "notarized": ${NOTARIZED},
  "stapled": ${STAPLED}
}
EOF

echo "==> Release manifest written"
echo "Manifest: ${MANIFEST_PATH}"
echo "Download URL: ${BASTION_RELEASE_DOWNLOAD_URL}"
