#!/usr/bin/env bash
set -euo pipefail
PORT="${1:-${ESPPORT:-}}"
exec "$(cd "$(dirname "$0")" && pwd)/flash.sh" v1 "$PORT"
