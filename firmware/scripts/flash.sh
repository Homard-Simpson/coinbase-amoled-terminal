#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VARIANT="${1:-}"
PORT="${2:-${ESPPORT:-}}"
case "$VARIANT" in
  v1|v2) ;;
  *) echo "Usage: $0 v1|v2 /dev/cu.usbmodemXXXX" >&2; exit 2 ;;
esac
if [[ -z "$PORT" ]]; then
  echo "Usage: $0 v1|v2 /dev/cu.usbmodemXXXX" >&2
  exit 2
fi

BUILD_DIR="$ROOT/build/$VARIANT"
for file in \
  "$BUILD_DIR/bootloader/bootloader.bin" \
  "$BUILD_DIR/partition_table/partition-table.bin" \
  "$BUILD_DIR/ota_data_initial.bin" \
  "$BUILD_DIR/coinbase_amoled_terminal.bin"; do
  [[ -s "$file" ]] || { echo "Missing $VARIANT artifact: $file; run scripts/build-$VARIANT.sh first." >&2; exit 1; }
done

# shellcheck source=lib-idf.sh
source "$ROOT/scripts/lib-idf.sh"
load_idf_552

echo "Flashing $VARIANT to $PORT (NVS at 0x9000 is preserved)"
python -m esptool --chip esp32s3 -p "$PORT" -b 460800 \
  --before default_reset --after hard_reset write_flash \
  --flash_mode dio --flash_size 16MB --flash_freq 80m \
  0x0 "$BUILD_DIR/bootloader/bootloader.bin" \
  0x8000 "$BUILD_DIR/partition_table/partition-table.bin" \
  0x10000 "$BUILD_DIR/ota_data_initial.bin" \
  0x20000 "$BUILD_DIR/coinbase_amoled_terminal.bin"
