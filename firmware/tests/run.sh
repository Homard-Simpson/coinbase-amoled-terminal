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
python3 "$ROOT/tests/test_contract.py"
