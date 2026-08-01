#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly REPOSITORY_URL="https://github.com/Homard-Simpson/coinbase-amoled-terminal.git"
readonly REPOSITORY_BRANCH="main"
readonly DEFAULT_FIRMWARE_VERSION=""
readonly LAUNCHD_LABEL="com.homardsimpson.coinbase-amoled-bridge"
readonly SYSTEMD_UNIT="coinbase-amoled-bridge.service"

SAMPLE=0
UNINSTALL=0
PURGE=0
ALLOW_TEST_ARTIFACTS=0
NO_OPEN=0
NON_INTERACTIVE=0
FIRMWARE_VERSION="$DEFAULT_FIRMWARE_VERSION"
MANIFEST_URL=""
BOARD=""
SERIAL_PORT=""
BRIDGE_URL=""
CLONE_TEMP=""

usage() {
  cat <<'EOF'
Coinbase AMOLED Terminal per-user installer

Usage:
  install.sh --version v1.2.3
                         Install bridge, verify release, flash, and open setup
  install.sh --manifest-url URL --allow-unverified-test-artifacts
                         Explicit review/testing path; not a production release
  install.sh --sample    Install an offline sample bridge without flashing
  install.sh --uninstall [--purge]

Optional flashing arguments:
  --board v1|v2          Required only when trusted firmware cannot identify it
  --port /dev/...        Use this USB serial port instead of exact-one detection
  --bridge-url URL       Override the detected private-LAN device-feed URL
  --no-open              Compatibility flag; captive portal now owns fallback
  --non-interactive      Fail rather than prompting when board identity is unclear
EOF
}

die() {
  printf 'Setup stopped: %s\n' "$1" >&2
  exit 1
}

need_value() {
  [[ $# -ge 2 && -n "$2" ]] || die "$1 needs a value"
}

cleanup_clone() {
  if [[ -n "$CLONE_TEMP" && -d "$CLONE_TEMP" ]]; then
    rm -rf -- "$CLONE_TEMP"
  fi
}
trap cleanup_clone EXIT

git_exact() {
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    git -c core.hooksPath=/dev/null -c core.fsmonitor=false \
    -c protocol.file.allow=never "$@"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sample) SAMPLE=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; shift ;;
    --allow-unverified-test-artifacts) ALLOW_TEST_ARTIFACTS=1; shift ;;
    --no-open) NO_OPEN=1; shift ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    --version)
      need_value "$@"; FIRMWARE_VERSION="$2"; shift 2 ;;
    --manifest-url)
      need_value "$@"; MANIFEST_URL="$2"; shift 2 ;;
    --board)
      need_value "$@"; BOARD="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"; shift 2 ;;
    --port)
      need_value "$@"; SERIAL_PORT="$2"; shift 2 ;;
    --bridge-url)
      need_value "$@"; BRIDGE_URL="$2"; shift 2 ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die "unknown option: $1"
      ;;
  esac
done

[[ "$BOARD" == "" || "$BOARD" == "v1" || "$BOARD" == "v2" ]] || \
  die "--board must be v1 or v2"
if [[ "$PURGE" == "1" && "$UNINSTALL" != "1" ]]; then
  die "--purge is valid only with --uninstall"
fi
if [[ "$SAMPLE" == "1" && "$UNINSTALL" == "1" ]]; then
  die "--sample and --uninstall cannot be combined"
fi
if [[ -n "$FIRMWARE_VERSION" && -n "$MANIFEST_URL" ]]; then
  die "use either --version or --manifest-url, not both"
fi
if [[ "$ALLOW_TEST_ARTIFACTS" == "1" && -z "$MANIFEST_URL" ]]; then
  die "test-artifact mode requires an explicit --manifest-url"
fi
if [[ "$SAMPLE" == "1" && ( -n "$FIRMWARE_VERSION" || -n "$MANIFEST_URL" || -n "$BOARD" || -n "$SERIAL_PORT" ) ]]; then
  die "sample mode does not flash firmware"
fi
if [[ "$SAMPLE" != "1" && "$UNINSTALL" != "1" && -z "$FIRMWARE_VERSION" && -z "$MANIFEST_URL" ]]; then
  die "production firmware assets are not published yet; this draft cannot run the public one-liner"
fi
if [[ "${EUID:-$(id -u)}" == "0" ]]; then
  die "run this installer as your normal user, never with sudo"
fi
if [[ -z "${HOME:-}" || "$HOME" != /* || "$HOME" == "/" ]]; then
  die "HOME must be a safe absolute user directory"
fi
case "$HOME$FIRMWARE_VERSION$MANIFEST_URL$BOARD$SERIAL_PORT$BRIDGE_URL" in
  *$'\n'*|*$'\r'*|*$'\t'*) die "an installer argument contains a control character" ;;
esac

case "$(uname -s)" in
  Darwin)
    PLATFORM="macos"
    INSTALL_ROOT="$HOME/Library/Application Support/coinbase-amoled-terminal"
    STATE_DIR="$HOME/Library/Application Support/coinbase-amoled-bridge"
    SERVICE_FILE="$HOME/Library/LaunchAgents/$LAUNCHD_LABEL.plist"
    ;;
  Linux)
    PLATFORM="linux"
    DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
    CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
    [[ "$DATA_HOME" == /* ]] || die "XDG_DATA_HOME must be an absolute path"
    [[ "$CONFIG_HOME" == /* ]] || die "XDG_CONFIG_HOME must be an absolute path"
    case "$DATA_HOME$CONFIG_HOME" in
      *$'\n'*|*$'\r'*|*$'\t'*) die "XDG paths contain a control character" ;;
    esac
    INSTALL_ROOT="$DATA_HOME/coinbase-amoled-terminal"
    STATE_DIR="$CONFIG_HOME/coinbase-amoled-bridge"
    SERVICE_FILE="$CONFIG_HOME/systemd/user/$SYSTEMD_UNIT"
    ;;
  *) die "supported systems are macOS and mainstream Linux" ;;
esac

SOURCE_DIR="$INSTALL_ROOT/source"
VENV_DIR="$INSTALL_ROOT/venv"
APP_BIN="$INSTALL_ROOT/bin/coinbase-amoled-bridge"
USER_BIN="$HOME/.local/bin/coinbase-amoled-bridge"

case "$STATE_DIR/" in
  "$INSTALL_ROOT/"*) die "application and private-state directories must not overlap" ;;
esac
case "$INSTALL_ROOT/" in
  "$STATE_DIR/"*) die "application and private-state directories must not overlap" ;;
esac

uninstall_app() {
  if [[ "$PLATFORM" == "macos" ]]; then
    if command -v launchctl >/dev/null 2>&1; then
      launchctl bootout "gui/$(id -u)" "$SERVICE_FILE" >/dev/null 2>&1 || true
    fi
  elif command -v systemctl >/dev/null 2>&1; then
    systemctl --user disable --now "$SYSTEMD_UNIT" >/dev/null 2>&1 || true
  fi
  rm -f -- "$SERVICE_FILE"
  if [[ -L "$USER_BIN" && "$(readlink "$USER_BIN" 2>/dev/null || true)" == "$APP_BIN" ]]; then
    rm -f -- "$USER_BIN"
  fi
  rm -rf -- "$INSTALL_ROOT"
  if [[ "$PLATFORM" == "linux" ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl --user daemon-reload >/dev/null 2>&1 || true
  fi
  printf 'Removed the app and per-user service.\n'
  if [[ "$PURGE" == "1" ]]; then
    rm -rf -- "$STATE_DIR"
    printf 'Removed local credentials, configuration, and device tokens.\n'
  else
    printf 'Kept private configuration and credentials at:\n  %s\n' "$STATE_DIR"
    printf 'Add --purge only when you also want to remove those private files.\n'
  fi
}

if [[ "$UNINSTALL" == "1" ]]; then
  uninstall_app
  exit 0
fi

command -v git >/dev/null 2>&1 || die "Git is missing. Install Git, then run the same line again."
PYTHON_BIN=""
for candidate in python3 python3.14 python3.13 python3.12 python3.11; do
  if command -v "$candidate" >/dev/null 2>&1 && \
    "$candidate" -c 'import sys; raise SystemExit(sys.version_info < (3, 11))' >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v "$candidate")"
    break
  fi
done
[[ -n "$PYTHON_BIN" ]] || die "Python 3.11 or newer is missing. Install Python, then run the same line again."

mkdir -p -- "$INSTALL_ROOT"
chmod 700 "$INSTALL_ROOT" 2>/dev/null || true
if [[ ! -e "$SOURCE_DIR" ]]; then
  CLONE_TEMP="$INSTALL_ROOT/.source-clone-$$"
  if ! git_exact clone --branch "$REPOSITORY_BRANCH" --single-branch "$REPOSITORY_URL" "$CLONE_TEMP"; then
    die "I couldn't download the app. Check your internet connection, then try again."
  fi
  mv -- "$CLONE_TEMP" "$SOURCE_DIR"
  CLONE_TEMP=""
elif [[ ! -d "$SOURCE_DIR/.git" ]]; then
  die "install source exists but is not the expected Git checkout: $SOURCE_DIR"
else
  origin_url="$(git_exact -C "$SOURCE_DIR" config --get remote.origin.url || true)"
  [[ "$origin_url" == "$REPOSITORY_URL" ]] || die "existing source is not the approved repository"
  branch="$(git_exact -C "$SOURCE_DIR" symbolic-ref --quiet --short HEAD || true)"
  [[ "$branch" == "$REPOSITORY_BRANCH" ]] || die "existing source is not on the approved main branch"
  [[ -z "$(git_exact -C "$SOURCE_DIR" status --porcelain --untracked-files=normal)" ]] || \
    die "existing source has local changes; preserve or remove them before updating"
  git_exact -C "$SOURCE_DIR" fetch --prune origin "$REPOSITORY_BRANCH" || \
    die "I couldn't update the app. Check your internet connection, then try again."
  local_revision="$(git_exact -C "$SOURCE_DIR" rev-parse HEAD)"
  remote_revision="$(git_exact -C "$SOURCE_DIR" rev-parse "origin/$REPOSITORY_BRANCH")"
  if [[ "$local_revision" != "$remote_revision" ]]; then
    git_exact -C "$SOURCE_DIR" merge-base --is-ancestor "$local_revision" "$remote_revision" || \
      die "installed source diverged from main; refusing to overwrite it"
    git_exact -C "$SOURCE_DIR" merge --ff-only "origin/$REPOSITORY_BRANCH"
  fi
fi

"$PYTHON_BIN" -m venv "$VENV_DIR" || \
  die "Python could not create its private environment. Install venv support, then try again."
pip_arguments=(
  --index-url https://pypi.org/simple
  --disable-pip-version-check
  --no-input
  --upgrade
  "$SOURCE_DIR/bridge"
)
if [[ "$SAMPLE" != "1" ]]; then
  pip_arguments+=("esptool>=4.8,<5")
fi
"$VENV_DIR/bin/python" -m pip --isolated install "${pip_arguments[@]}" || \
  die "I couldn't install the bridge and isolated flashing tools."

mkdir -p -- "$INSTALL_ROOT/bin" "$HOME/.local/bin" "$(dirname "$SERVICE_FILE")"
ln -sfn -- "$VENV_DIR/bin/coinbase-amoled-bridge" "$APP_BIN"
if [[ ! -e "$USER_BIN" && ! -L "$USER_BIN" ]]; then
  ln -s -- "$APP_BIN" "$USER_BIN"
elif [[ ! -L "$USER_BIN" || "$(readlink "$USER_BIN" 2>/dev/null || true)" != "$APP_BIN" ]]; then
  printf 'warning: left existing command untouched: %s\n' "$USER_BIN" >&2
fi

render_arguments=(
  --output "$SERVICE_FILE"
  --executable "$VENV_DIR/bin/coinbase-amoled-bridge"
  --data-dir "$STATE_DIR"
)
[[ "$SAMPLE" == "1" ]] && render_arguments+=(--sample)
if [[ "$PLATFORM" == "macos" ]]; then
  "$VENV_DIR/bin/python" "$SOURCE_DIR/installer/render_service.py" \
    --platform launchd \
    --template "$SOURCE_DIR/installer/com.homardsimpson.coinbase-amoled-bridge.plist.in" \
    "${render_arguments[@]}"
else
  "$VENV_DIR/bin/python" "$SOURCE_DIR/installer/render_service.py" \
    --platform systemd \
    --template "$SOURCE_DIR/installer/coinbase-amoled-bridge.service.in" \
    "${render_arguments[@]}"
fi

if [[ "$SAMPLE" == "1" ]]; then
  "$APP_BIN" --data-dir "$STATE_DIR" quickstart --sample || \
    die "sample bridge setup did not finish"
  printf 'Sample bridge installed. No Coinbase account was contacted.\n'
  exit 0
fi

onboard_arguments=(--data-dir "$STATE_DIR")
if [[ -n "$FIRMWARE_VERSION" ]]; then
  onboard_arguments+=(--version "$FIRMWARE_VERSION")
else
  onboard_arguments+=(--manifest-url "$MANIFEST_URL")
fi
[[ -n "$BOARD" ]] && onboard_arguments+=(--board "$BOARD")
[[ -n "$SERIAL_PORT" ]] && onboard_arguments+=(--port "$SERIAL_PORT")
[[ -n "$BRIDGE_URL" ]] && onboard_arguments+=(--bridge-url "$BRIDGE_URL")
[[ "$ALLOW_TEST_ARTIFACTS" == "1" ]] && onboard_arguments+=(--allow-unverified-test-artifacts)
[[ "$NO_OPEN" == "1" ]] && onboard_arguments+=(--no-open)
[[ "$NON_INTERACTIVE" == "1" ]] && onboard_arguments+=(--non-interactive)

"$VENV_DIR/bin/python" "$SOURCE_DIR/installer/onboard_device.py" "${onboard_arguments[@]}" || \
  die "setup stopped safely; rerun the same command to create a new one-time session"
