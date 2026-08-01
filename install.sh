#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly REPOSITORY_URL="https://github.com/Homard-Simpson/coinbase-amoled-terminal.git"
readonly REPOSITORY_BRANCH="main"
readonly LAUNCHD_LABEL="com.homardsimpson.coinbase-amoled-bridge"
readonly SYSTEMD_UNIT="coinbase-amoled-bridge.service"

SAMPLE=0
UNINSTALL=0
PURGE=0
CLONE_TEMP=""

usage() {
  cat <<'EOF'
Coinbase AMOLED Terminal per-user installer

Usage:
  install.sh             Install/update and open the secure key prompt
  install.sh --sample    Install/update with offline sample data
  install.sh --uninstall Remove the app and user service; keep credentials
  install.sh --uninstall --purge
                         Also remove local credentials and device tokens
EOF
}

die() {
  printf 'install error: %s\n' "$1" >&2
  exit 1
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

for argument in "$@"; do
  case "$argument" in
    --sample) SAMPLE=1 ;;
    --uninstall) UNINSTALL=1 ;;
    --purge) PURGE=1 ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die "unknown option: $argument"
      ;;
  esac
done

if [[ "$PURGE" == "1" && "$UNINSTALL" != "1" ]]; then
  die "--purge is valid only with --uninstall"
fi
if [[ "$SAMPLE" == "1" && "$UNINSTALL" == "1" ]]; then
  die "--sample and --uninstall cannot be combined"
fi
if [[ "${EUID:-$(id -u)}" == "0" ]]; then
  die "run this installer as your normal user, never with sudo"
fi
if [[ -z "${HOME:-}" || "$HOME" != /* || "$HOME" == "/" ]]; then
  die "HOME must be a safe absolute user directory"
fi
case "$HOME" in
  *$'\n'*|*$'\r'*|*$'\t'*) die "HOME contains a control character" ;;
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
  *)
    die "supported systems are macOS and mainstream Linux"
    ;;
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
  if [[ -L "$USER_BIN" ]]; then
    linked_target="$(readlink "$USER_BIN" 2>/dev/null || true)"
    if [[ "$linked_target" == "$APP_BIN" ]]; then
      rm -f -- "$USER_BIN"
    fi
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
    printf 'To remove them too, rerun the installer with --uninstall --purge.\n'
  fi
}

if [[ "$UNINSTALL" == "1" ]]; then
  uninstall_app
  exit 0
fi

command -v git >/dev/null 2>&1 || die \
  "Git is required. Install Git with your operating system's supported package manager."

PYTHON_BIN=""
for candidate in python3 python3.14 python3.13 python3.12 python3.11; do
  if command -v "$candidate" >/dev/null 2>&1 && \
    "$candidate" -c 'import sys; raise SystemExit(sys.version_info < (3, 11))' \
      >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v "$candidate")"
    break
  fi
done
if [[ -z "$PYTHON_BIN" ]]; then
  die "Python 3.11 or newer is required. Install Python with venv support, then rerun."
fi

mkdir -p -- "$INSTALL_ROOT"
chmod 700 "$INSTALL_ROOT" 2>/dev/null || true

if [[ ! -e "$SOURCE_DIR" ]]; then
  CLONE_TEMP="$INSTALL_ROOT/.source-clone-$$"
  if ! git_exact clone --branch "$REPOSITORY_BRANCH" --single-branch \
    "$REPOSITORY_URL" "$CLONE_TEMP"; then
    die "GitHub download failed; check the HTTP/network error above and retry"
  fi
  mv -- "$CLONE_TEMP" "$SOURCE_DIR"
  CLONE_TEMP=""
elif [[ ! -d "$SOURCE_DIR/.git" ]]; then
  die "install source exists but is not the expected Git checkout: $SOURCE_DIR"
else
  origin_url="$(git_exact -C "$SOURCE_DIR" config --get remote.origin.url || true)"
  [[ "$origin_url" == "$REPOSITORY_URL" ]] || \
    die "existing install source is not the exact approved GitHub repository"
  branch="$(git_exact -C "$SOURCE_DIR" symbolic-ref --quiet --short HEAD || true)"
  [[ "$branch" == "$REPOSITORY_BRANCH" ]] || \
    die "existing install source is not on the approved main branch"
  [[ -z "$(git_exact -C "$SOURCE_DIR" status --porcelain --untracked-files=normal)" ]] || \
    die "existing install source has local changes; preserve or remove them before updating"
  if ! git_exact -C "$SOURCE_DIR" fetch --prune origin "$REPOSITORY_BRANCH"; then
    die "GitHub update failed; check the HTTP/network error above and retry"
  fi
  local_revision="$(git_exact -C "$SOURCE_DIR" rev-parse HEAD)"
  remote_revision="$(git_exact -C "$SOURCE_DIR" rev-parse "origin/$REPOSITORY_BRANCH")"
  if [[ "$local_revision" != "$remote_revision" ]]; then
    if ! git_exact -C "$SOURCE_DIR" merge-base --is-ancestor \
      "$local_revision" "$remote_revision"; then
      die "installed source diverged from the approved main branch; refusing to overwrite it"
    fi
    git_exact -C "$SOURCE_DIR" merge --ff-only "origin/$REPOSITORY_BRANCH"
  fi
fi

if ! "$PYTHON_BIN" -m venv "$VENV_DIR"; then
  die "Python venv creation failed; install your distribution's Python venv package and retry"
fi
if ! "$VENV_DIR/bin/python" -m pip --isolated install \
  --index-url https://pypi.org/simple --disable-pip-version-check --no-input --upgrade \
  "$SOURCE_DIR/bridge"; then
  die "bridge package installation failed; review the pip/network error above and retry"
fi

mkdir -p -- "$INSTALL_ROOT/bin" "$HOME/.local/bin" "$(dirname "$SERVICE_FILE")"
ln -sfn -- "$VENV_DIR/bin/coinbase-amoled-bridge" "$APP_BIN"
if [[ ! -e "$USER_BIN" && ! -L "$USER_BIN" ]]; then
  ln -s -- "$APP_BIN" "$USER_BIN"
elif [[ -L "$USER_BIN" && "$(readlink "$USER_BIN" 2>/dev/null || true)" == "$APP_BIN" ]]; then
  :
else
  printf 'warning: left existing command untouched: %s\n' "$USER_BIN" >&2
fi

render_arguments=(
  --output "$SERVICE_FILE"
  --executable "$VENV_DIR/bin/coinbase-amoled-bridge"
  --data-dir "$STATE_DIR"
)
if [[ "$SAMPLE" == "1" ]]; then
  render_arguments+=(--sample)
fi
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

printf '\nInstalled the read-only bridge from %s (%s).\n' \
  "$REPOSITORY_URL" "$REPOSITORY_BRANCH"
printf 'No Docker or administrator access was used.\n\n'

quickstart_arguments=(--data-dir "$STATE_DIR" quickstart)
if [[ "$SAMPLE" == "1" ]]; then
  quickstart_arguments+=(--sample)
fi
if ! "$APP_BIN" "${quickstart_arguments[@]}"; then
  printf '\nQuickstart did not complete. Nothing was sent through this installer.\n' >&2
  printf 'Rerun it in a terminal with:\n  %q --data-dir %q quickstart' \
    "$APP_BIN" "$STATE_DIR" >&2
  if [[ "$SAMPLE" == "1" ]]; then
    printf ' --sample' >&2
  fi
  printf '\n' >&2
  exit 1
fi
