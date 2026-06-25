#!/bin/sh

set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
OUTPUT_ROOT="${BASTION_RELEASE_OUTPUT_DIR:-${ROOT_DIR}/dist/release}"
APP_PATH="${OUTPUT_ROOT}/Bastion.app"

RELEASE_TAG="${BASTION_RELEASE_TAG:-${GITHUB_REF_NAME:-}}"
DOWNLOAD_BASE_URL="${BASTION_RELEASE_DOWNLOAD_BASE_URL:-}"

if [ -z "${BASTION_NOTARY_PROFILE:-}" ]; then
  echo "Set BASTION_NOTARY_PROFILE before running the CI release pipeline." >&2
  exit 1
fi

echo "==> Running signed release pipeline"
"${ROOT_DIR}/scripts/release-build.sh"
"${ROOT_DIR}/scripts/release-notarize.sh" "${APP_PATH}"
"${ROOT_DIR}/scripts/release-create-dmg.sh" "${APP_PATH}"

VERSION="$(/usr/bin/defaults read "${APP_PATH}/Contents/Info" CFBundleShortVersionString)"
BUILD_NUMBER="$(/usr/bin/defaults read "${APP_PATH}/Contents/Info" CFBundleVersion)"
ZIP_NAME="Bastion-${VERSION}-${BUILD_NUMBER}-macOS.zip"

if [ -z "${BASTION_RELEASE_DOWNLOAD_URL:-}" ]; then
  if [ -n "${DOWNLOAD_BASE_URL}" ]; then
    BASTION_RELEASE_DOWNLOAD_URL="${DOWNLOAD_BASE_URL%/}/${ZIP_NAME}"
  elif [ -n "${GITHUB_REPOSITORY:-}" ] && [ -n "${RELEASE_TAG}" ]; then
    BASTION_RELEASE_DOWNLOAD_URL="https://github.com/${GITHUB_REPOSITORY}/releases/download/${RELEASE_TAG}/${ZIP_NAME}"
  else
    echo "Set BASTION_RELEASE_DOWNLOAD_URL, or set BASTION_RELEASE_DOWNLOAD_BASE_URL, or run in GitHub Actions on a tag." >&2
    exit 1
  fi
  export BASTION_RELEASE_DOWNLOAD_URL
fi

if [ -z "${BASTION_RELEASE_NOTES_URL:-}" ] && [ -n "${GITHUB_REPOSITORY:-}" ] && [ -n "${RELEASE_TAG}" ]; then
  BASTION_RELEASE_NOTES_URL="https://github.com/${GITHUB_REPOSITORY}/releases/tag/${RELEASE_TAG}"
  export BASTION_RELEASE_NOTES_URL
fi

"${ROOT_DIR}/scripts/release-generate-manifest.sh" "${APP_PATH}"
"${ROOT_DIR}/scripts/release-verify.sh" "${APP_PATH}"

echo "==> CI release pipeline complete"
echo "Output: ${OUTPUT_ROOT}"
