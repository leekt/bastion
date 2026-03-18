#!/bin/sh

set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
PROJECT_PATH="${ROOT_DIR}/bastion.xcodeproj"
SCHEME="bastion"
CONFIGURATION="Release"
DERIVED_DATA_PATH="${BASTION_RELEASE_DERIVED_DATA_PATH:-${HOME}/Library/Developer/Xcode/DerivedData/bastion-release}"
OUTPUT_ROOT="${BASTION_RELEASE_OUTPUT_DIR:-${ROOT_DIR}/dist/release}"
BUILD_APP_PATH="${DERIVED_DATA_PATH}/Build/Products/${CONFIGURATION}/bastion.app"
STAGING_APP_PATH="${OUTPUT_ROOT}/Bastion.app"

echo "==> Building signed Bastion release app"
xcodebuild \
  -project "${PROJECT_PATH}" \
  -scheme "${SCHEME}" \
  -configuration "${CONFIGURATION}" \
  -derivedDataPath "${DERIVED_DATA_PATH}" \
  ENABLE_USER_SCRIPT_SANDBOXING=NO \
  ENABLE_DEBUG_DYLIB=NO \
  ENABLE_PREVIEWS=NO \
  build

if [ ! -d "${BUILD_APP_PATH}" ]; then
  echo "Release app not found at ${BUILD_APP_PATH}" >&2
  exit 1
fi

echo "==> Staging release bundle"
/bin/mkdir -p "${OUTPUT_ROOT}"
/bin/rm -rf "${STAGING_APP_PATH}"
/usr/bin/ditto "${BUILD_APP_PATH}" "${STAGING_APP_PATH}"

echo "==> Verifying code signature"
/usr/bin/codesign --verify --deep --strict "${STAGING_APP_PATH}"

VERSION="$(/usr/bin/defaults read "${STAGING_APP_PATH}/Contents/Info" CFBundleShortVersionString)"
BUILD_NUMBER="$(/usr/bin/defaults read "${STAGING_APP_PATH}/Contents/Info" CFBundleVersion)"
ZIP_PATH="${OUTPUT_ROOT}/Bastion-${VERSION}-${BUILD_NUMBER}-macOS.zip"

echo "==> Creating distributable zip"
/bin/rm -f "${ZIP_PATH}"
/usr/bin/ditto -c -k --sequesterRsrc --keepParent "${STAGING_APP_PATH}" "${ZIP_PATH}"

SHA256="$(/usr/bin/shasum -a 256 "${ZIP_PATH}" | /usr/bin/awk '{print $1}')"
SIZE_BYTES="$(/usr/bin/stat -f%z "${ZIP_PATH}")"

echo "==> Release artifact ready"
echo "App: ${STAGING_APP_PATH}"
echo "Zip: ${ZIP_PATH}"
echo "Version: ${VERSION}"
echo "Build: ${BUILD_NUMBER}"
echo "SHA256: ${SHA256}"
echo "Size: ${SIZE_BYTES}"
