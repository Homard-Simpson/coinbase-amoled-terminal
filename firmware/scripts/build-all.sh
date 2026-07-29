#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
"$HERE/build.sh" v1
"$HERE/build.sh" v2
