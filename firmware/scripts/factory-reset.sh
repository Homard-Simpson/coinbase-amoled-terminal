#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${1:-}"
CONFIRM="${2:-}"
if [[ -z "$PORT" || "$CONFIRM" != "--confirm=RESET" ]]; then
  echo "Usage: $0 /dev/cu.usbmodemXXXX --confirm=RESET" >&2
  echo "This erases NVS plus one-time onboarding metadata; firmware and OTA remain." >&2
  exit 2
fi

# shellcheck source=lib-idf.sh
source "$ROOT/scripts/lib-idf.sh"
load_idf_552
python -m esptool --chip esp32s3 -p "$PORT" \
  --before default_reset --after no_reset erase_region 0x9000 0x6000
python -m esptool --chip esp32s3 -p "$PORT" \
  --before default_reset --after hard_reset erase_region 0xE20000 0x2000
echo "Configuration erased. Reboot into first-boot onboarding."
