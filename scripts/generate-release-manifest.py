#!/usr/bin/env python3
"""Stage validated V1/V2 firmware and emit immutable release metadata."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "installer" / "firmware_installer.py"
_VALIDATOR_SPEC = importlib.util.spec_from_file_location(
    "_release_firmware_validator", VALIDATOR_PATH
)
if _VALIDATOR_SPEC is None or _VALIDATOR_SPEC.loader is None:
    raise RuntimeError("firmware validator could not be loaded")
VALIDATOR = importlib.util.module_from_spec(_VALIDATOR_SPEC)
sys.modules[_VALIDATOR_SPEC.name] = VALIDATOR
_VALIDATOR_SPEC.loader.exec_module(VALIDATOR)

OFFSETS = dict(VALIDATOR.EXPECTED_OFFSETS)
INPUTS = {
    "bootloader": Path("bootloader/bootloader.bin"),
    "partition_table": Path("partition_table/partition-table.bin"),
    "ota_data": Path("ota_data_initial.bin"),
    "application": Path("coinbase_amoled_terminal.bin"),
}
VERSION_RE = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
SOURCE_REPOSITORY = "https://github.com/Homard-Simpson/coinbase-amoled-terminal"
BUILD_WORKFLOW = ".github/workflows/release-firmware.yml"
TRUST_BLOCKER = (
    "This test bundle is unsigned and lacks verified physical-control and V1/V2 hardware "
    "attestations; it must not be published as a production release."
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_new(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _json_bytes(value: Any, *, compact: bool = False) -> bytes:
    if compact:
        rendered = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    else:
        rendered = json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True)
    return (rendered + "\n").encode("ascii")


def _subject(path: Path, *, relative_to: Path) -> dict[str, object]:
    return {
        "name": path.relative_to(relative_to).as_posix(),
        "size": path.stat().st_size,
        "digest": {"sha256": _sha256(path)},
    }


def generate(
    build_root: Path,
    output: Path,
    version: str,
    *,
    source_commit: str,
    source_tree_clean: bool,
    source_repository: str = SOURCE_REPOSITORY,
) -> Path:
    if not VERSION_RE.fullmatch(version):
        raise ValueError("version must be a v-prefixed semantic version")
    if any(len(f"{version.removeprefix('v')}-{board}") >= 32 for board in ("v1", "v2")):
        raise ValueError("version is too long for the ESP application descriptor")
    if not COMMIT_RE.fullmatch(source_commit):
        raise ValueError("source commit must be an exact 40-character Git object ID")
    if not source_tree_clean:
        raise ValueError("release metadata requires a verified clean source tree")
    if source_repository != SOURCE_REPOSITORY:
        raise ValueError("release source repository is not approved")

    output.mkdir(mode=0o755, parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise FileExistsError("release output directory must be empty")
    variants: dict[str, object] = {}
    binary_paths: list[Path] = []
    filename_version = version.replace("+", "_")
    for board in ("v1", "v2"):
        artifacts: list[dict[str, object]] = []
        firmware_version = f"{version.removeprefix('v')}-{board}"
        for role, relative_input in INPUTS.items():
            source = build_root / board / relative_input
            if not source.is_file() or source.stat().st_size <= 0:
                raise FileNotFoundError(source)
            payload = source.read_bytes()
            VALIDATOR.validate_release_artifact_payload(
                role,
                payload,
                firmware_version=firmware_version,
            )
            destination = output / f"coinbase-amoled-{filename_version}-{board}-{role}.bin"
            _write_new(destination, payload)
            binary_paths.append(destination)
            artifacts.append(
                {
                    "role": role,
                    "path": destination.name,
                    "offset": OFFSETS[role],
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
        variants[board] = {
            "board_revision": board,
            "firmware_version": firmware_version,
            "artifacts": artifacts,
            "onboarding_partition": {
                "offset": VALIDATOR.ONBOARDING_OFFSET,
                "size": VALIDATOR.ONBOARDING_SIZE,
            },
        }

    manifest: dict[str, object] = {
        "schema_version": VALIDATOR.MANIFEST_SCHEMA_VERSION,
        "release_version": version,
        "build": {
            "esp_idf_version": VALIDATOR.ESP_IDF_VERSION,
            "container_image": VALIDATOR.ESP_IDF_CONTAINER_IMAGE,
            "container_digest": VALIDATOR.ESP_IDF_CONTAINER_DIGEST,
        },
        "release_evidence": {
            "production_ready": False,
            "controls_verified": False,
            "client_signature_verified": False,
            "hardware_attested": {"v1": False, "v2": False},
            "trust_blocker": TRUST_BLOCKER,
        },
        "source": {
            "repository": source_repository,
            "commit": source_commit,
        },
        "variants": variants,
    }
    manifest["manifest_id"] = VALIDATOR.compute_manifest_id(manifest)
    manifest_path = output / "firmware-manifest.json"
    _write_new(manifest_path, _json_bytes(manifest))

    binary_subjects = [_subject(path, relative_to=output) for path in sorted(binary_paths)]
    provenance = {
        "schema_version": VALIDATOR.PROVENANCE_SCHEMA_VERSION,
        "release_version": version,
        "manifest_id": manifest["manifest_id"],
        "source": {
            "repository": source_repository,
            "commit": source_commit,
            "tree_clean": True,
        },
        "builder": {
            "workflow": BUILD_WORKFLOW,
            "esp_idf_version": VALIDATOR.ESP_IDF_VERSION,
            "container_image": VALIDATOR.ESP_IDF_CONTAINER_IMAGE,
            "container_digest": VALIDATOR.ESP_IDF_CONTAINER_DIGEST,
        },
        "subjects": binary_subjects,
        "signed": False,
        "production_ready": False,
        "trust_blocker": TRUST_BLOCKER,
    }
    provenance_path = output / "firmware-provenance.json"
    _write_new(provenance_path, _json_bytes(provenance))

    attestation_subject_paths = [*binary_paths, manifest_path, provenance_path]
    attestation = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": subject["name"],
                "digest": subject["digest"],
            }
            for subject in (
                _subject(path, relative_to=output) for path in sorted(attestation_subject_paths)
            )
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": f"{source_repository}/{BUILD_WORKFLOW}@v1",
                "externalParameters": {
                    "release_version": version,
                    "board_variants": ["v1", "v2"],
                },
                "internalParameters": {
                    "esp_idf_version": VALIDATOR.ESP_IDF_VERSION,
                    "container_digest": VALIDATOR.ESP_IDF_CONTAINER_DIGEST,
                },
                "resolvedDependencies": [
                    {
                        "uri": f"git+{source_repository}@{source_commit}",
                        "digest": {"gitCommit": source_commit},
                    },
                    {
                        "uri": (
                            f"pkg:docker/espressif/idf@v{VALIDATOR.ESP_IDF_VERSION}"
                            f"?digest={VALIDATOR.ESP_IDF_CONTAINER_DIGEST}"
                        ),
                        "digest": {
                            "sha256": VALIDATOR.ESP_IDF_CONTAINER_DIGEST.removeprefix("sha256:")
                        },
                    },
                ],
            },
            "runDetails": {
                "builder": {
                    "id": f"{source_repository}/{BUILD_WORKFLOW}@{source_commit}",
                },
                "metadata": {
                    "invocationId": f"{source_commit}:{version}",
                },
            },
        },
    }
    attestation_path = output / "firmware-attestation.intoto.jsonl"
    _write_new(attestation_path, _json_bytes(attestation, compact=True))

    checksum_paths = [*binary_paths, manifest_path, provenance_path, attestation_path]
    checksums = "".join(
        f"{_sha256(path)}  {path.relative_to(output).as_posix()}\n"
        for path in sorted(checksum_paths)
    ).encode("ascii")
    _write_new(output / "SHA256SUMS", checksums)
    return manifest_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree-clean", action="store_true")
    args = parser.parse_args()
    if not VERSION_RE.fullmatch(args.version):
        parser.error("--version must be a v-prefixed semantic version")
    if not COMMIT_RE.fullmatch(args.source_commit):
        parser.error("--source-commit must be a full lowercase Git object ID")
    if not args.source_tree_clean:
        parser.error("--source-tree-clean is required after a clean-tree check")
    generate(
        args.build_root,
        args.output,
        args.version,
        source_commit=args.source_commit,
        source_tree_clean=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
