#!/usr/bin/env sh
set -eu

APP_PATH="${BASTION_APP_PATH:-${HOME}/Applications/Bastion Dev.app}"
CLI_BIN=""
LINK_PATH="/usr/local/bin/bastion"
USE_SUDO=0
NO_SUDO=0
SUDO_IF_INTERACTIVE=0
SCRIPT_DISPLAY="$0"

usage() {
  cat <<'USAGE'
Usage:
  scripts/install-cli-symlink.sh [--app <Bastion.app>] [--cli <path>] [--link <path>] [--sudo|--no-sudo|--sudo-if-interactive]

Installs the bundled Bastion CLI symlink atomically.

Defaults:
  --app   ~/Applications/Bastion Dev.app
  --cli   <app>/Contents/MacOS/bastion-cli
  --link  /usr/local/bin/bastion

Use --no-sudo from non-interactive checks to report filesystem blockers without
prompting. Use --sudo from an interactive terminal to create /usr/local/bin when
it is owned by root.
Use --sudo-if-interactive from install scripts to request sudo only when sudo is
already cached or stdin is an interactive terminal.
USAGE
}

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

note() {
  printf '%s\n' "$*"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --app)
      shift
      [ "$#" -gt 0 ] || fail "--app requires a value"
      APP_PATH="$1"
      ;;
    --cli)
      shift
      [ "$#" -gt 0 ] || fail "--cli requires a value"
      CLI_BIN="$1"
      ;;
    --link)
      shift
      [ "$#" -gt 0 ] || fail "--link requires a value"
      LINK_PATH="$1"
      ;;
    --sudo)
      USE_SUDO=1
      ;;
    --no-sudo)
      NO_SUDO=1
      ;;
    --sudo-if-interactive)
      SUDO_IF_INTERACTIVE=1
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

SUDO_MODE_COUNT=0
[ "$USE_SUDO" = "1" ] && SUDO_MODE_COUNT=$((SUDO_MODE_COUNT + 1))
[ "$NO_SUDO" = "1" ] && SUDO_MODE_COUNT=$((SUDO_MODE_COUNT + 1))
[ "$SUDO_IF_INTERACTIVE" = "1" ] && SUDO_MODE_COUNT=$((SUDO_MODE_COUNT + 1))
[ "$SUDO_MODE_COUNT" -le 1 ] || fail "Use only one of --sudo, --no-sudo, or --sudo-if-interactive"

if [ -z "$CLI_BIN" ]; then
  CLI_BIN="${APP_PATH}/Contents/MacOS/bastion-cli"
fi

[ -x "$CLI_BIN" ] || fail "Bundled CLI is missing or not executable: ${CLI_BIN}"

PARENT_DIR="$(dirname "$LINK_PATH")"
EXISTING_TARGET="$(readlink "$LINK_PATH" 2>/dev/null || true)"
if [ "$EXISTING_TARGET" = "$CLI_BIN" ]; then
  note "CLI symlink already installed: ${LINK_PATH} -> ${CLI_BIN}"
  exit 0
fi

install_without_sudo() {
  TMP_LINK="${LINK_PATH}.tmp.$$"
  rm -f "$TMP_LINK" 2>/dev/null || true
  mkdir -p "$PARENT_DIR" || return 1
  ln -s "$CLI_BIN" "$TMP_LINK" || return 1
  if mv -f "$TMP_LINK" "$LINK_PATH"; then
    return 0
  fi
  rm -f "$TMP_LINK" 2>/dev/null || true
  return 1
}

if install_without_sudo; then
  note "Installed CLI symlink: ${LINK_PATH} -> ${CLI_BIN}"
  exit 0
fi

if [ "$NO_SUDO" = "1" ]; then
  fail "Could not install ${LINK_PATH} without sudo. Run: ${SCRIPT_DISPLAY} --cli \"${CLI_BIN}\" --sudo"
fi

if [ "$SUDO_IF_INTERACTIVE" = "1" ]; then
  if sudo -n true >/dev/null 2>&1 || [ -t 0 ]; then
    USE_SUDO=1
  else
    fail "Could not install ${LINK_PATH} without sudo and no interactive sudo is available. Run: ${SCRIPT_DISPLAY} --cli \"${CLI_BIN}\" --sudo"
  fi
fi

if [ "$USE_SUDO" != "1" ]; then
  fail "Could not install ${LINK_PATH}. Re-run with --sudo from an interactive admin terminal."
fi

if ! sudo -n true >/dev/null 2>&1 && [ ! -t 0 ]; then
  fail "sudo needs a password, but this is not an interactive terminal. Run this command manually from Terminal: ${SCRIPT_DISPLAY} --cli \"${CLI_BIN}\" --sudo"
fi

TMP_PRIVILEGED_LINK="/tmp/bastion-cli-link.$$"
rm -f "$TMP_PRIVILEGED_LINK" 2>/dev/null || true
ln -s "$CLI_BIN" "$TMP_PRIVILEGED_LINK" || fail "Could not create temporary symlink: ${TMP_PRIVILEGED_LINK}"
sudo /bin/mkdir -p "$PARENT_DIR"
sudo /bin/mv -f "$TMP_PRIVILEGED_LINK" "$LINK_PATH"

FINAL_TARGET="$(readlink "$LINK_PATH" 2>/dev/null || true)"
[ "$FINAL_TARGET" = "$CLI_BIN" ] || fail "Installed symlink points to ${FINAL_TARGET:-<missing>} instead of ${CLI_BIN}"

note "Installed CLI symlink: ${LINK_PATH} -> ${CLI_BIN}"
