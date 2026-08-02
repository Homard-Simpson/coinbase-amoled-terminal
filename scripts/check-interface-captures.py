#!/usr/bin/env python3
"""Fail when committed interface PNGs do not match the production capture harness."""

from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAPTURE = ROOT / "tools" / "framebuffer_capture" / "capture.py"
DATA = ROOT / "docs" / "images" / "capture-market-data.json"
IMAGES = (
    "prices-page.png",
    "positions-privacy-page.png",
    "btc-chart-bb20-levels.png",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="amoled-capture-check-") as temp_name:
        output = Path(temp_name)
        subprocess.run(
            [
                sys.executable,
                str(CAPTURE),
                "--data",
                str(DATA),
                "--output-dir",
                str(output),
            ],
            check=True,
        )
        mismatches: list[str] = []
        for name in IMAGES:
            expected = ROOT / "docs" / "images" / name
            actual = output / name
            if not expected.is_file():
                mismatches.append(f"missing committed image: {expected.relative_to(ROOT)}")
            elif expected.read_bytes() != actual.read_bytes():
                mismatches.append(
                    f"stale interface image: {expected.relative_to(ROOT)} "
                    f"committed={digest(expected)} generated={digest(actual)}"
                )
        if mismatches:
            print("\n".join(mismatches), file=sys.stderr)
            print(
                "Regenerate with: python3 tools/framebuffer_capture/capture.py "
                "--data docs/images/capture-market-data.json --output-dir docs/images",
                file=sys.stderr,
            )
            return 1
    print("interface capture reproduction passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
