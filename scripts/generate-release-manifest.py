#!/usr/bin/env python3
"""Stage V1/V2 firmware artifacts and emit their strict release manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path

OFFSETS = {
    "bootloader": 0x0,
    "partition_table": 0x8000,
    "ota_data": 0x10000,
    "application": 0x20000,
}
INPUTS = {
    "bootloader": Path("bootloader/bootloader.bin"),
    "partition_table": Path("partition_table/partition-table.bin"),
    "ota_data": Path("ota_data_initial.bin"),
    "application": Path("coinbase_amoled_terminal.bin"),
}
VERSION_RE = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[.-][A-Za-z0-9.-]+)?")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def generate(build_root: Path, output: Path, version: str) -> Path:
    output.mkdir(mode=0o755, parents=True, exist_ok=True)
    variants: dict[str, object] = {}
    for board in ("v1", "v2"):
        artifacts: list[dict[str, object]] = []
        app_size = 0
        app_digest = ""
        for role, relative_input in INPUTS.items():
            source = build_root / board / relative_input
            if not source.is_file() or source.stat().st_size <= 0:
                raise FileNotFoundError(source)
            destination = output / f"coinbase-amoled-{board}-{role}.bin"
            shutil.copyfile(source, destination)
            size = destination.stat().st_size
            digest = _sha256(destination)
            artifacts.append(
                {
                    "role": role,
                    "path": destination.name,
                    "offset": OFFSETS[role],
                    "size": size,
                    "sha256": digest,
                }
            )
            if role == "application":
                app_size = size
                app_digest = digest
        variants[board] = {
            "board_revision": board,
            "firmware_version": f"{version.removeprefix('v')}-{board}",
            # A build passing CI is not a hardware attestation. Release managers
            # may set these only after the V1 and V2 physical checklist passes.
            "ready_for_production": False,
            "controls_verified": False,
            "hardware_attested": False,
            "artifacts": artifacts,
            "detection": [
                {"offset": 0x20000, "size": app_size, "sha256": app_digest},
                {"offset": 0x720000, "size": app_size, "sha256": app_digest},
            ],
            "onboarding_partition": {"offset": 0xE20000, "size": 0x2000},
        }
    manifest = {
        "schema_version": 1,
        "release_version": version,
        "esp_idf_version": "5.5.2",
        "variants": variants,
    }
    destination = output / "firmware-manifest.json"
    destination.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    if not VERSION_RE.fullmatch(args.version):
        parser.error("--version must be a v-prefixed semantic version")
    generate(args.build_root, args.output, args.version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
