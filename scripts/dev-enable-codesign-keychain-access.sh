#!/bin/sh

set -eu

usage() {
  cat <<'USAGE'
Usage:
  scripts/dev-enable-codesign-keychain-access.sh [--check] [login-keychain-db]

Unlocks the login keychain and grants Apple's signing tools noninteractive
access to private signing keys so local signed rebuilds can run from this shell.

Options:
  --check    Print the selected identity, matched private-key label, and
             throwaway codesign probe result without changing the keychain.

Run this from an interactive terminal. Enter the Mac login/keychain password,
not the Apple ID password. Rerun it after importing or replacing signing keys.
USAGE
}

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

print_codesign_probe_failure() {
  if [ "${CHECK_ONLY:-0}" -eq 1 ]; then
    cat >&2 <<EOF
The non-mutating codesign usability probe failed; keychain access was not changed.
/usr/bin/codesign still cannot use the private key for "${IDENTITY_NAME}" from this shell.

EOF
  else
    cat >&2 <<EOF
Code-signing keychain access was updated, but /usr/bin/codesign still cannot
use the private key for "${IDENTITY_NAME}" from this shell.

EOF
  fi
  cat >&2 <<EOF
Open Keychain Access, find and expand the certificate named:
  ${IDENTITY_NAME}

EOF
  if [ -n "${IDENTITY_PRIVATE_KEY_LABEL:-}" ]; then
    cat >&2 <<EOF
Detected nested private-key label matched to that certificate:
  ${IDENTITY_PRIVATE_KEY_LABEL}

EOF
  fi
  cat >&2 <<EOF
Then open the private key nested under that certificate, choose Access Control,
and allow /usr/bin/codesign to use the key. The private key can have an older
or different label than the certificate, so target the nested private key instead
of filtering by the certificate name.

If Keychain Access already says all applications may access that private key,
the remaining blocker is usually the private key partition list. Run the
interactive repair helper and enter the Mac login/keychain password so it can
apply:
  security set-key-partition-list -S apple-tool:,apple:,codesign: -s -t private -k <login-keychain-password> "${LOGIN_KEYCHAIN}"

After the helper succeeds, rerun:
  scripts/dev-rebuild-signed.sh
EOF
}

case "${1:-}" in
  -h|--help)
    usage
    exit 0
    ;;
esac

CHECK_ONLY=0
KEYCHAIN_ARG=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --check)
      CHECK_ONLY=1
      ;;
    -*)
      usage >&2
      exit 2
      ;;
    *)
      if [ -n "${KEYCHAIN_ARG}" ]; then
        usage >&2
        exit 2
      fi
      KEYCHAIN_ARG="$1"
      ;;
  esac
  shift
done

LOGIN_KEYCHAIN="${KEYCHAIN_ARG:-${HOME}/Library/Keychains/login.keychain-db}"
PARTITION_LIST="apple-tool:,apple:,codesign:"

IDENTITY_ROW="$(/usr/bin/security find-identity -v -p codesigning | /usr/bin/awk '/^[[:space:]]*[0-9]+[)]/ { print; exit }')"
IDENTITY_HASH="$(printf '%s\n' "${IDENTITY_ROW}" | /usr/bin/awk '{ print $2 }')"
IDENTITY_NAME="$(printf '%s\n' "${IDENTITY_ROW}" | /usr/bin/sed -E 's/^[[:space:]]*[0-9]+\)[[:space:]]+[A-Fa-f0-9]+[[:space:]]+"(.*)"$/\1/')"

if [ -z "${IDENTITY_HASH}" ]; then
  echo "No valid code-signing identity found. Create or import an Apple Development identity before enabling codesign access." >&2
  exit 1
fi

if [ ! -f "${LOGIN_KEYCHAIN}" ]; then
  echo "Login keychain not found at ${LOGIN_KEYCHAIN}" >&2
  exit 1
fi
IDENTITY_PRIVATE_KEY_LABEL="$(resolve_private_key_label || true)"

if [ "${CHECK_ONLY}" -eq 1 ]; then
  echo "Code-signing identity hash: ${IDENTITY_HASH}"
  echo "Code-signing identity name: ${IDENTITY_NAME}"
  echo "Login keychain: ${LOGIN_KEYCHAIN}"
  if [ -n "${IDENTITY_PRIVATE_KEY_LABEL}" ]; then
    echo "Matched private signing key: ${IDENTITY_PRIVATE_KEY_LABEL}"
  else
    echo "Matched private signing key: <not resolved>"
  fi
  echo "==> Verifying codesign can use ${IDENTITY_NAME} without changing keychain access"
  PROBE_DIR="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/bastion-codesign-probe.XXXXXX")"
  trap '/bin/rm -rf "${PROBE_DIR}"' EXIT HUP INT TERM
  PROBE_BIN="${PROBE_DIR}/probe"
  printf '#!/bin/sh\nexit 0\n' > "${PROBE_BIN}"
  /bin/chmod +x "${PROBE_BIN}"
  if ! /usr/bin/codesign --force --sign "${IDENTITY_HASH}" --timestamp=none "${PROBE_BIN}" 2>"${PROBE_DIR}/codesign.log"; then
    /bin/cat "${PROBE_DIR}/codesign.log" >&2
    print_codesign_probe_failure
    exit 1
  fi
  if ! /usr/bin/codesign --verify --strict "${PROBE_BIN}" 2>"${PROBE_DIR}/codesign-verify.log"; then
    /bin/cat "${PROBE_DIR}/codesign-verify.log" >&2
    print_codesign_probe_failure
    exit 1
  fi
  echo "Codesign usability probe passed for ${IDENTITY_NAME}."
  exit 0
fi

if [ ! -t 0 ]; then
  echo "This script needs an interactive terminal so it can read the keychain password without echoing it." >&2
  echo "Run: scripts/dev-enable-codesign-keychain-access.sh ${LOGIN_KEYCHAIN}" >&2
  exit 1
fi

restore_tty() {
  if [ -n "${STTY_STATE:-}" ]; then
    /bin/stty "${STTY_STATE}" 2>/dev/null || true
  fi
}

STTY_STATE="$(/bin/stty -g 2>/dev/null || true)"
trap 'restore_tty' EXIT HUP INT TERM

printf 'Keychain password for %s: ' "${LOGIN_KEYCHAIN}" >&2
if [ -n "${STTY_STATE}" ]; then
  /bin/stty -echo 2>/dev/null || true
fi
IFS= read -r KC_PASS
restore_tty
printf '\n' >&2

echo "==> Unlocking login keychain"
/usr/bin/security unlock-keychain -p "${KC_PASS}" "${LOGIN_KEYCHAIN}"

echo "==> Disabling keychain auto-lock timeout for this keychain"
/usr/bin/security set-keychain-settings "${LOGIN_KEYCHAIN}"

echo "==> Granting Apple signing and codesign tools access to private signing keys"
/usr/bin/security set-key-partition-list -S "${PARTITION_LIST}" -s -t private -k "${KC_PASS}" "${LOGIN_KEYCHAIN}"

unset KC_PASS

if [ -n "${IDENTITY_PRIVATE_KEY_LABEL}" ]; then
  echo "==> Matched private signing key: ${IDENTITY_PRIVATE_KEY_LABEL}"
fi
echo "==> Verifying codesign can use ${IDENTITY_NAME}"
PROBE_DIR="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/bastion-codesign-probe.XXXXXX")"
trap 'restore_tty; /bin/rm -rf "${PROBE_DIR}"' EXIT HUP INT TERM
PROBE_BIN="${PROBE_DIR}/probe"
printf '#!/bin/sh\nexit 0\n' > "${PROBE_BIN}"
/bin/chmod +x "${PROBE_BIN}"
if ! /usr/bin/codesign --force --sign "${IDENTITY_HASH}" --timestamp=none "${PROBE_BIN}"; then
  print_codesign_probe_failure
  exit 1
fi
if ! /usr/bin/codesign --verify --strict "${PROBE_BIN}"; then
  print_codesign_probe_failure
  exit 1
fi

echo "Code-signing keychain access is enabled for ${IDENTITY_NAME}."
echo "Next: ./scripts/dev-rebuild-signed.sh"
