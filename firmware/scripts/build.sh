#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VARIANT="${1:-}"
case "$VARIANT" in
  v1|v2) ;;
  *) echo "Usage: $0 v1|v2" >&2; exit 2 ;;
esac

# shellcheck source=lib-idf.sh
source "$ROOT/scripts/lib-idf.sh"
load_idf_552

BUILD_DIR="$ROOT/build/$VARIANT"
SDKCONFIG_FILE="$BUILD_DIR/sdkconfig"
DEFAULTS="$ROOT/sdkconfig.defaults;$ROOT/sdkconfig.$VARIANT.defaults"
RELEASE_VERSION="${FIRMWARE_RELEASE_VERSION:-1.0.0}"
RELEASE_VERSION="${RELEASE_VERSION#v}"
[[ "$RELEASE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.-]+)?$ ]] || {
  echo "FIRMWARE_RELEASE_VERSION must be a semantic version" >&2
  exit 2
}
PROJECT_VERSION="$RELEASE_VERSION-$VARIANT"
if (( ${#PROJECT_VERSION} >= 32 )); then
  echo "firmware version is too long for the ESP application descriptor" >&2
  exit 2
fi
mkdir -p "$BUILD_DIR"

echo "Building $VARIANT with ESP-IDF 5.5.2 -> $BUILD_DIR"
if [[ ! -f "$SDKCONFIG_FILE" ]]; then
  idf.py -C "$ROOT" -B "$BUILD_DIR" \
    -D "SDKCONFIG=$SDKCONFIG_FILE" \
    -D "SDKCONFIG_DEFAULTS=$DEFAULTS" \
    -D "PROJECT_VER=$PROJECT_VERSION" \
    set-target esp32s3
fi
idf.py -C "$ROOT" -B "$BUILD_DIR" \
  -D "SDKCONFIG=$SDKCONFIG_FILE" \
  -D "SDKCONFIG_DEFAULTS=$DEFAULTS" \
  -D "PROJECT_VER=$PROJECT_VERSION" \
  build

echo "Built: $BUILD_DIR/coinbase_amoled_terminal.bin ($PROJECT_VERSION)"
