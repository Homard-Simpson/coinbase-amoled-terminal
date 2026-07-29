#!/usr/bin/env bash
# shellcheck shell=bash

load_idf_552() {
  local export_script="${IDF_EXPORT:-${HOME}/.espressif/v5.5.2/esp-idf/export.sh}"
  if ! command -v idf.py >/dev/null 2>&1; then
    if [[ ! -r "$export_script" ]]; then
      echo "ESP-IDF 5.5.2 not found. Set IDF_EXPORT to its export.sh path." >&2
      return 1
    fi
    if [[ -z "${IDF_PYTHON_ENV_PATH:-}" && -x "${HOME}/.espressif/python_env/idf5.5_py3.14_env/bin/python" ]]; then
      export IDF_PYTHON_ENV_PATH="${HOME}/.espressif/python_env/idf5.5_py3.14_env"
    fi
    # ESP-IDF's supported environment initializer.
    # shellcheck disable=SC1090
    source "$export_script" >/dev/null
  fi

  local version
  version="$(idf.py --version 2>&1)"
  if [[ "$version" != *"v5.5.2"* && "$version" != *"5.5.2"* ]]; then
    echo "ESP-IDF 5.5.2 is required; found: $version" >&2
    return 1
  fi
}
