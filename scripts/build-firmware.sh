#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/build-firmware.sh <v1|v2> [--ci-placeholder]

Builds the ESP-IDF firmware for the selected Waveshare board revision into
firmware/build/<variant>/.

The firmware uses runtime onboarding: Wi-Fi, the bridge feed URL, the device ID,
and the per-device bearer token are entered on the device through its captive
portal and stored in NVS. No URL, token, or personal identifier is compiled in,
so building requires no secrets.

--ci-placeholder is accepted for CI parity and behaves like a normal build; the
resulting image still requires on-device onboarding before it can reach a bridge.
EOF
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage >&2
  exit 2
fi

VARIANT="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
case "$VARIANT" in
  v1 | v2) ;;
  *)
    echo "board variant must be v1 or v2" >&2
    exit 2
    ;;
esac

if [[ $# -eq 2 && "$2" != "--ci-placeholder" ]]; then
  usage >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIRMWARE_ROOT="$ROOT/firmware"
BUILD_SCRIPT="$FIRMWARE_ROOT/scripts/build.sh"

if [[ ! -f "$BUILD_SCRIPT" ]]; then
  echo "firmware build entrypoint is missing: firmware/scripts/build.sh" >&2
  exit 1
fi

if [[ -z "${IDF_EXPORT:-}" && -n "${IDF_PATH:-}" && -f "$IDF_PATH/export.sh" ]]; then
  export IDF_EXPORT="$IDF_PATH/export.sh"
fi

bash "$BUILD_SCRIPT" "$VARIANT"
echo "Firmware build passed for $VARIANT."
