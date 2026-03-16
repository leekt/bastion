#!/bin/sh

set -eu

SOURCE_FILE="${SRCROOT}/bastion-cli/main.swift"
OUTPUT_DIR="${TARGET_BUILD_DIR}/${CONTENTS_FOLDER_PATH}/MacOS"
OUTPUT_FILE="${OUTPUT_DIR}/bastion-cli"
TEMP_DIR="${TARGET_TEMP_DIR}/bastion-cli"
SDK_PATH="$(xcrun --sdk macosx --show-sdk-path)"
SWIFTC="$(xcrun --find swiftc)"

SWIFT_OPT="-Onone"
if [ "${CONFIGURATION}" = "Release" ]; then
    SWIFT_OPT="-O"
fi

mkdir -p "${OUTPUT_DIR}" "${TEMP_DIR}"

set --
for ARCH in ${ARCHS}; do
    ARCH_OUTPUT="${TEMP_DIR}/bastion-cli-${ARCH}"
    TARGET_TRIPLE="${ARCH}-apple-macos${MACOSX_DEPLOYMENT_TARGET}"

    "${SWIFTC}" \
        "${SOURCE_FILE}" \
        -sdk "${SDK_PATH}" \
        -target "${TARGET_TRIPLE}" \
        "${SWIFT_OPT}" \
        -o "${ARCH_OUTPUT}"

    set -- "$@" "${ARCH_OUTPUT}"
done

if [ "$#" -eq 1 ]; then
    /bin/cp "$1" "${OUTPUT_FILE}"
else
    /usr/bin/lipo -create "$@" -output "${OUTPUT_FILE}"
fi

/bin/chmod 755 "${OUTPUT_FILE}"

if [ "${CODE_SIGNING_ALLOWED:-NO}" = "YES" ] && [ -n "${EXPANDED_CODE_SIGN_IDENTITY:-}" ]; then
    /usr/bin/codesign --force --sign "${EXPANDED_CODE_SIGN_IDENTITY}" --timestamp=none "${OUTPUT_FILE}"
fi
