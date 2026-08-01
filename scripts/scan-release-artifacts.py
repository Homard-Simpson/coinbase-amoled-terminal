#!/usr/bin/env python3
"""Fail closed on high-confidence secrets in staged firmware binaries."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "installer" / "firmware_installer.py"
SPEC = importlib.util.spec_from_file_location("_artifact_secret_validator", VALIDATOR_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("firmware validator could not be loaded")
VALIDATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VALIDATOR
SPEC.loader.exec_module(VALIDATOR)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args()
    scanned = 0
    for path in args.paths:
        if not path.is_file() or path.suffix != ".bin":
            parser.error(f"not a firmware binary: {path}")
        size = path.stat().st_size
        if not 0 < size <= VALIDATOR.MAX_ARTIFACT_BYTES:
            parser.error(f"firmware binary has an invalid size: {path}")
        try:
            VALIDATOR.scan_release_artifact_for_secrets(path.read_bytes())
        except VALIDATOR.FirmwareInstallError as exc:
            print(f"{path}: {exc}", file=sys.stderr)
            return 1
        scanned += 1
    print(f"binary artifact secret scan passed: {scanned} file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
