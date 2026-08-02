#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/tests/.build"
trap 'rm -rf "$OUT"' EXIT
mkdir -p "$OUT"

"${CXX:-c++}" -std=c++17 -Wall -Wextra -Werror \
  -I"$ROOT/main" \
  "$ROOT/main/config_validation.cc" \
  "$ROOT/tests/config_validation_test.cc" \
  -o "$OUT/config_validation_test"
"$OUT/config_validation_test"

for test in bollinger_bands control_policy key_levels ui_helpers; do
  "${CXX:-c++}" -std=c++17 -Wall -Wextra -Werror \
    -I"$ROOT/main" \
    "$ROOT/tests/test_${test}.cc" \
    -o "$OUT/test_${test}"
  "$OUT/test_${test}"
done
python3 "$ROOT/tests/test_contract.py"
