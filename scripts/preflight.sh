#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-python3}"
STRICT="${PREFLIGHT_STRICT_TOOLS:-0}"

if [[ "$STRICT" != "0" && "$STRICT" != "1" ]]; then
  echo "PREFLIGHT_STRICT_TOOLS must be 0 or 1" >&2
  exit 2
fi

note() {
  printf '\n==> %s\n' "$1"
}

optional_missing() {
  local tool="$1"
  if [[ "$STRICT" == "1" ]]; then
    echo "required preflight tool is missing: $tool" >&2
    exit 1
  fi
  echo "warning: skipping unavailable optional tool: $tool" >&2
}

command -v "$PYTHON" >/dev/null 2>&1 || {
  echo "Python is required: $PYTHON" >&2
  exit 1
}

note "Public secret and privacy scan"
"$PYTHON" scripts/scan_public_safety.py .

note "Shell syntax"
bash -n install.sh
while IFS= read -r -d '' script; do
  bash -n "$script"
done < <(find scripts installer -type f -name '*.sh' -print0)

note "Python bytecode compilation"
"$PYTHON" -m compileall -q installer scripts tests bridge

if "$PYTHON" -m ruff --version >/dev/null 2>&1; then
  note "Ruff lint"
  "$PYTHON" -m ruff check bridge installer scripts tests
  note "Ruff format check"
  "$PYTHON" -m ruff format --check bridge installer scripts tests
else
  optional_missing "ruff (install requirements-dev.txt)"
fi

if "$PYTHON" -m pytest --version >/dev/null 2>&1; then
  note "Python tests (repository)"
  "$PYTHON" -m pytest -q
  if [[ -f bridge/pyproject.toml ]]; then
    note "Python tests (bridge)"
    "$PYTHON" -m pytest -q bridge
  fi
else
  note "Python tests (standard-library fallback)"
  "$PYTHON" -m unittest discover -s tests -p 'test_*.py'
  if [[ -d bridge/tests ]]; then
    ( cd bridge && PYTHONPATH=src "$PYTHON" -m unittest discover -s tests -t . -p 'test_*.py' )
  fi
  optional_missing "pytest (standard-library tests passed)"
fi

if command -v shellcheck >/dev/null 2>&1; then
  note "ShellCheck"
  find scripts installer -type f -name '*.sh' -print0 | xargs -0 shellcheck
  shellcheck install.sh
else
  optional_missing "shellcheck"
fi

if command -v markdownlint-cli2 >/dev/null 2>&1; then
  note "Markdown lint"
  markdownlint-cli2
else
  optional_missing "markdownlint-cli2"
fi

if command -v actionlint >/dev/null 2>&1; then
  note "GitHub Actions lint"
  actionlint .github/workflows/*.yml
else
  optional_missing "actionlint"
fi

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  note "Docker Compose model"
  docker compose --env-file .env.example config --quiet
else
  optional_missing "docker compose"
fi

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  note "Git whitespace"
  git diff --check -- .
fi

if [[ "${PREFLIGHT_FIRMWARE:-0}" == "1" ]]; then
  note "ESP-IDF V1 placeholder build"
  ./scripts/build-firmware.sh v1 --ci-placeholder
  note "ESP-IDF V2 placeholder build"
  ./scripts/build-firmware.sh v2 --ci-placeholder
fi

printf '\nPreflight passed.\n'
