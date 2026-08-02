#!/usr/bin/env python3
"""Sign an already-reviewed release manifest with the fixed production Ed25519 key."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "installer" / "firmware_installer.py"
_VALIDATOR_SPEC = importlib.util.spec_from_file_location(
    "_signing_firmware_validator", VALIDATOR_PATH
)
if _VALIDATOR_SPEC is None or _VALIDATOR_SPEC.loader is None:
    raise RuntimeError("firmware validator could not be loaded")
VALIDATOR = importlib.util.module_from_spec(_VALIDATOR_SPEC)
sys.modules[_VALIDATOR_SPEC.name] = VALIDATOR
_VALIDATOR_SPEC.loader.exec_module(VALIDATOR)

PRODUCTION_KEY_PATH = (
    Path.home()
    / "Library"
    / "Application Support"
    / "CoinbaseAMOLED"
    / "release-signing-key-v1.pem"
)
SIGNED_TRUST_BLOCKER = (
    "The manifest signature is verified, but physical-control and V1/V2 hardware attestations "
    "are not all complete; this release must remain non-production."
)


def _json_bytes(value: Any, *, compact: bool = False) -> bytes:
    if compact:
        rendered = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    else:
        rendered = json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True)
    return (rendered + "\n").encode("ascii")


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _replace_file(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.signing-{os.getpid()}")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    os.replace(temporary, path)


def _load_signing_key(
    key_path: Path,
    *,
    expected_public_key: bytes,
) -> Ed25519PrivateKey:
    try:
        metadata = key_path.lstat()
    except OSError as exc:
        raise ValueError("release signing key is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.getuid()
    ):
        raise ValueError("release signing key permissions are unsafe")
    try:
        with key_path.open("rb") as handle:
            private_key = serialization.load_pem_private_key(handle.read(), password=None)
    except (OSError, TypeError, ValueError) as exc:
        raise ValueError("release signing key could not be loaded") from exc
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("release signing key type is invalid")
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if public_key != expected_public_key:
        raise ValueError("release signing key does not match the fixed trust root")
    return private_key


def _updated_manifest(raw: dict[str, Any]) -> dict[str, Any]:
    evidence = raw["release_evidence"]
    if evidence["client_signature_verified"] is not False:
        raise ValueError("manifest is not an unsigned release candidate")
    evidence["client_signature_verified"] = True
    production_ready = evidence["controls_verified"] and all(evidence["hardware_attested"].values())
    evidence["production_ready"] = production_ready
    evidence["trust_blocker"] = "" if production_ready else SIGNED_TRUST_BLOCKER
    raw["manifest_id"] = VALIDATOR.compute_manifest_id(raw)
    return raw


def _update_bundle_metadata(
    bundle: Path,
    *,
    manifest: dict[str, Any],
    manifest_payload: bytes,
    envelope_payload: bytes,
) -> dict[Path, bytes]:
    provenance_path = bundle / "firmware-provenance.json"
    attestation_path = bundle / "firmware-attestation.intoto.jsonl"
    if not provenance_path.is_file() or not attestation_path.is_file():
        return {}
    provenance = json.loads(provenance_path.read_text(encoding="ascii"))
    if (
        provenance.get("signed") is not False
        or provenance.get("source", {}).get("commit") != manifest["source"]["commit"]
    ):
        raise ValueError("release provenance is inconsistent with the manifest")
    evidence = manifest["release_evidence"]
    provenance["manifest_id"] = manifest["manifest_id"]
    provenance["signed"] = True
    provenance["production_ready"] = evidence["production_ready"]
    provenance["trust_blocker"] = evidence["trust_blocker"]
    provenance_payload = _json_bytes(provenance)

    attestation = json.loads(attestation_path.read_text(encoding="ascii"))
    if attestation.get("_type") != "https://in-toto.io/Statement/v1":
        raise ValueError("release attestation is invalid")
    subjects: list[dict[str, object]] = []
    for path in sorted(bundle.glob("*.bin")):
        subjects.append({"name": path.name, "digest": {"sha256": _sha256_file(path)}})
    subjects.extend(
        (
            {
                "name": "firmware-manifest.json",
                "digest": {"sha256": _sha256_bytes(manifest_payload)},
            },
            {
                "name": "firmware-manifest.json.sig",
                "digest": {"sha256": _sha256_bytes(envelope_payload)},
            },
            {
                "name": "firmware-provenance.json",
                "digest": {"sha256": _sha256_bytes(provenance_payload)},
            },
        )
    )
    attestation["subject"] = sorted(subjects, key=lambda item: str(item["name"]))
    return {
        provenance_path: provenance_payload,
        attestation_path: _json_bytes(attestation, compact=True),
    }


def sign_release_manifest(
    manifest_path: Path,
    *,
    key_path: Path = PRODUCTION_KEY_PATH,
    expected_public_key: bytes | None = None,
    key_id: str = VALIDATOR.RELEASE_KEY_ID,
) -> Path:
    manifest_path = manifest_path.resolve()
    if manifest_path.name != "firmware-manifest.json" or not manifest_path.is_file():
        raise ValueError("expected a firmware-manifest.json release candidate")
    signature_path = manifest_path.with_name(manifest_path.name + ".sig")
    if signature_path.exists():
        raise FileExistsError("manifest signature already exists")
    public_key = expected_public_key or VALIDATOR._production_public_key()
    if expected_public_key is None and key_id != VALIDATOR.RELEASE_KEY_ID:
        raise ValueError("production signing key id is fixed")

    unsigned = VALIDATOR.load_manifest(manifest_path.as_uri(), allow_test_url=True)
    if unsigned.signature_verified or unsigned.evidence.client_signature_verified:
        raise ValueError("manifest is not an unsigned release candidate")
    with tempfile.TemporaryDirectory(prefix="cbat-signing-validation-") as temporary:
        validation_root = Path(temporary)
        for board in ("v1", "v2"):
            VALIDATOR.download_variant(
                unsigned,
                board,
                validation_root / board,
                allow_test_url=True,
            )
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    signed_manifest = _updated_manifest(raw)
    manifest_payload = _json_bytes(signed_manifest)
    private_key = _load_signing_key(key_path, expected_public_key=public_key)
    signature = private_key.sign(manifest_payload)
    envelope = {
        "schema_version": VALIDATOR.SIGNATURE_SCHEMA_VERSION,
        "algorithm": VALIDATOR.SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "manifest_sha256": _sha256_bytes(manifest_payload),
        "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
    }
    envelope_payload = _json_bytes(envelope)
    metadata_updates = _update_bundle_metadata(
        manifest_path.parent,
        manifest=signed_manifest,
        manifest_payload=manifest_payload,
        envelope_payload=envelope_payload,
    )

    _replace_file(manifest_path, manifest_payload)
    _replace_file(signature_path, envelope_payload)
    for path, payload in metadata_updates.items():
        _replace_file(path, payload)
    checksum_paths = [*manifest_path.parent.glob("*.bin"), manifest_path, signature_path]
    checksum_paths.extend(path for path in metadata_updates if path.is_file())
    checksum_paths = sorted(set(checksum_paths))
    checksums = "".join(f"{_sha256_file(path)}  {path.name}\n" for path in checksum_paths).encode(
        "ascii"
    )
    _replace_file(manifest_path.parent / "SHA256SUMS", checksums)
    return signature_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    sign_release_manifest(args.manifest)
    print("Signed release manifest with the fixed production release key.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
