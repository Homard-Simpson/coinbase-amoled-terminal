#!/usr/bin/env python3
"""Checksum-verified firmware selection, flashing, and USB setup provisioning."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

MANIFEST_SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 256 * 1024
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
ESP_IMAGE_MAGIC = 0xE9
ESP_APP_DESC_OFFSET = 32
ESP_APP_DESC_MAGIC = 0xABCD5432
ESP_APP_VERSION_OFFSET = ESP_APP_DESC_OFFSET + 16
ESP_APP_PROJECT_OFFSET = ESP_APP_VERSION_OFFSET + 32
ESP_APP_IDF_OFFSET = ESP_APP_PROJECT_OFFSET + 64
ESP_APP_FIELD_BYTES = 32
ONBOARDING_OFFSET = 0xE20000
ONBOARDING_SIZE = 0x2000
ONBOARDING_MAGIC = b"CBATST01"
BOARD_HELP_URL = "https://www.waveshare.com/wiki/ESP32-S3-Touch-AMOLED-1.8#Version_Options"
OFFICIAL_RELEASE_PREFIX = (
    "https://github.com/Homard-Simpson/coinbase-amoled-terminal/releases/download/"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")
EXPECTED_OFFSETS = {
    "bootloader": 0x0,
    "partition_table": 0x8000,
    "ota_data": 0x10000,
    "application": 0x20000,
}
EXPECTED_REGION_ENDS = {
    "bootloader": 0x8000,
    "partition_table": 0x9000,
    "ota_data": 0x20000,
    "application": 0x720000,
}
FORBIDDEN_ESP_MARKERS = (
    b"privateKey",
    b"apiKey",
    b"apiSecret",
    b"PRIVATE KEY-----",
    b"coinbase_api",
)


class FirmwareInstallError(Exception):
    """A sanitized firmware installation failure."""


@dataclass(frozen=True, slots=True)
class Artifact:
    role: str
    path: str
    offset: int
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class DetectionFingerprint:
    offset: int
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class VariantManifest:
    board_revision: str
    firmware_version: str
    ready_for_production: bool
    controls_verified: bool
    hardware_attested: bool
    artifacts: tuple[Artifact, ...]
    detection: tuple[DetectionFingerprint, ...]
    onboarding_offset: int
    onboarding_size: int


@dataclass(frozen=True, slots=True)
class FirmwareManifest:
    release_version: str
    esp_idf_version: str
    variants: dict[str, VariantManifest]
    source_url: str


@dataclass(frozen=True, slots=True)
class SetupMetadata:
    session_id: str
    setup_token: str
    csrf_token: str
    endpoint_url: str
    local_page_url: str
    bridge_url: str
    expires_at: int


@dataclass(frozen=True, slots=True)
class DownloadedArtifact:
    artifact: Artifact
    path: Path


def official_manifest_url(version: str) -> str:
    if not VERSION_RE.fullmatch(version):
        raise FirmwareInstallError("firmware version must look like v1.2.3")
    return (
        OFFICIAL_RELEASE_PREFIX + urllib.parse.quote(version, safe="") + "/firmware-manifest.json"
    )


def _read_url(url: str, *, maximum: int, allow_test_url: bool) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise FirmwareInstallError("firmware URLs cannot contain credentials or query data")
    if parsed.scheme == "file":
        if not allow_test_url or parsed.netloc not in ("", "localhost"):
            raise FirmwareInstallError("local firmware URLs require explicit test mode")
        path = Path(urllib.request.url2pathname(parsed.path))
        try:
            if not path.is_file() or not 0 < path.stat().st_size <= maximum:
                raise FirmwareInstallError("firmware file has an invalid size")
            return path.read_bytes()
        except OSError as exc:
            raise FirmwareInstallError("firmware file could not be read") from exc
    if parsed.scheme != "https":
        raise FirmwareInstallError("firmware URLs must use HTTPS")
    if not allow_test_url and not url.startswith(OFFICIAL_RELEASE_PREFIX):
        raise FirmwareInstallError("firmware manifest is not an official release URL")
    request = urllib.request.Request(  # noqa: S310 - validated HTTPS URL
        url,
        headers={
            "Accept": "application/json, application/octet-stream",
            "Cache-Control": "no-cache",
            "User-Agent": "coinbase-amoled-installer/1",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=30.0) as response:  # noqa: S310
            final = urllib.parse.urlsplit(response.geturl())
            if final.scheme != "https" or not final.hostname:
                raise FirmwareInstallError("firmware download left HTTPS")
            payload = response.read(maximum + 1)
    except FirmwareInstallError:
        raise
    except (OSError, TimeoutError, urllib.error.URLError) as exc:
        raise FirmwareInstallError("firmware download failed") from exc
    if not payload or len(payload) > maximum:
        raise FirmwareInstallError("firmware download has an invalid size")
    return payload


def load_manifest(url: str, *, allow_test_url: bool = False) -> FirmwareManifest:
    payload = _read_url(url, maximum=MAX_MANIFEST_BYTES, allow_test_url=allow_test_url)
    try:
        raw = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FirmwareInstallError("firmware manifest is invalid") from exc
    if not isinstance(raw, dict) or set(raw) != {
        "schema_version",
        "release_version",
        "esp_idf_version",
        "variants",
    }:
        raise FirmwareInstallError("firmware manifest fields are invalid")
    if raw["schema_version"] != MANIFEST_SCHEMA_VERSION:
        raise FirmwareInstallError("firmware manifest schema is unsupported")
    release_version = raw["release_version"]
    if not isinstance(release_version, str) or not VERSION_RE.fullmatch(release_version):
        raise FirmwareInstallError("firmware release version is invalid")
    if raw["esp_idf_version"] != "5.5.2":
        raise FirmwareInstallError("firmware was not built with ESP-IDF 5.5.2")
    variants_raw = raw["variants"]
    if not isinstance(variants_raw, dict) or set(variants_raw) != {"v1", "v2"}:
        raise FirmwareInstallError("firmware manifest must contain V1 and V2")
    variants = {board: _parse_variant(board, value) for board, value in variants_raw.items()}
    return FirmwareManifest(
        release_version=release_version,
        esp_idf_version="5.5.2",
        variants=variants,
        source_url=url,
    )


def _parse_variant(board: str, raw: Any) -> VariantManifest:
    required = {
        "board_revision",
        "firmware_version",
        "ready_for_production",
        "controls_verified",
        "hardware_attested",
        "artifacts",
        "detection",
        "onboarding_partition",
    }
    if not isinstance(raw, dict) or set(raw) != required:
        raise FirmwareInstallError("firmware variant fields are invalid")
    if raw["board_revision"] != board:
        raise FirmwareInstallError("firmware board label is inconsistent")
    firmware_version = raw["firmware_version"]
    if (
        not isinstance(firmware_version, str)
        or len(firmware_version) > 64
        or not firmware_version.endswith("-" + board)
    ):
        raise FirmwareInstallError("firmware image version is invalid")
    if not all(
        isinstance(raw[name], bool)
        for name in (
            "ready_for_production",
            "controls_verified",
            "hardware_attested",
        )
    ):
        raise FirmwareInstallError("firmware readiness flags are invalid")

    artifacts_raw = raw["artifacts"]
    if not isinstance(artifacts_raw, list) or len(artifacts_raw) != 4:
        raise FirmwareInstallError("firmware artifact list is invalid")
    artifacts = tuple(_parse_artifact(item) for item in artifacts_raw)
    roles = {artifact.role for artifact in artifacts}
    if roles != set(EXPECTED_OFFSETS):
        raise FirmwareInstallError("firmware artifact roles are incomplete")
    for artifact in artifacts:
        if artifact.offset != EXPECTED_OFFSETS[artifact.role]:
            raise FirmwareInstallError("firmware flash offset is unsafe")

    detection_raw = raw["detection"]
    if not isinstance(detection_raw, list) or not 1 <= len(detection_raw) <= 4:
        raise FirmwareInstallError("firmware detection fingerprints are invalid")
    detection = tuple(_parse_detection(item) for item in detection_raw)
    onboarding = raw["onboarding_partition"]
    if not isinstance(onboarding, dict) or set(onboarding) != {"offset", "size"}:
        raise FirmwareInstallError("onboarding partition is invalid")
    if onboarding["offset"] != ONBOARDING_OFFSET or onboarding["size"] != ONBOARDING_SIZE:
        raise FirmwareInstallError("onboarding partition layout is unsafe")
    return VariantManifest(
        board_revision=board,
        firmware_version=firmware_version,
        ready_for_production=raw["ready_for_production"],
        controls_verified=raw["controls_verified"],
        hardware_attested=raw["hardware_attested"],
        artifacts=artifacts,
        detection=detection,
        onboarding_offset=ONBOARDING_OFFSET,
        onboarding_size=ONBOARDING_SIZE,
    )


def _parse_artifact(raw: Any) -> Artifact:
    if not isinstance(raw, dict) or set(raw) != {"role", "path", "offset", "size", "sha256"}:
        raise FirmwareInstallError("firmware artifact fields are invalid")
    role, path, offset, size, digest = (
        raw["role"],
        raw["path"],
        raw["offset"],
        raw["size"],
        raw["sha256"],
    )
    if role not in EXPECTED_OFFSETS:
        raise FirmwareInstallError("firmware artifact role is invalid")
    if (
        not isinstance(path, str)
        or len(path) > 180
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*\.bin", path)
    ):
        raise FirmwareInstallError("firmware artifact path is invalid")
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts:
        raise FirmwareInstallError("firmware artifact path is unsafe")
    if not isinstance(offset, int) or isinstance(offset, bool):
        raise FirmwareInstallError("firmware artifact offset is invalid")
    if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= MAX_ARTIFACT_BYTES:
        raise FirmwareInstallError("firmware artifact size is invalid")
    if offset != EXPECTED_OFFSETS[role] or offset + size > EXPECTED_REGION_ENDS[role]:
        raise FirmwareInstallError("firmware artifact exceeds its approved flash region")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise FirmwareInstallError("firmware artifact checksum is invalid")
    return Artifact(role=role, path=path, offset=offset, size=size, sha256=digest)


def _parse_detection(raw: Any) -> DetectionFingerprint:
    if not isinstance(raw, dict) or set(raw) != {"offset", "size", "sha256"}:
        raise FirmwareInstallError("firmware detection fingerprint is invalid")
    offset, size, digest = raw["offset"], raw["size"], raw["sha256"]
    if offset not in (0x20000, 0x720000):
        raise FirmwareInstallError("firmware detection offset is invalid")
    if not isinstance(size, int) or isinstance(size, bool) or not 1_024 <= size <= 0x700000:
        raise FirmwareInstallError("firmware detection size is invalid")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise FirmwareInstallError("firmware detection checksum is invalid")
    return DetectionFingerprint(offset=offset, size=size, sha256=digest)


def require_release_readiness(
    manifest: FirmwareManifest,
    *,
    board: str,
    allow_unverified_test_artifacts: bool,
) -> None:
    variant = manifest.variants[board]
    if variant.ready_for_production and variant.controls_verified and variant.hardware_attested:
        return
    if allow_unverified_test_artifacts:
        return
    raise FirmwareInstallError("firmware release is not hardware-attested or production-ready")


FlashReader = Callable[[int, int], bytes]


def detect_trusted_board(
    manifest: FirmwareManifest,
    reader: FlashReader,
) -> str | None:
    """Detect only an exact release image fingerprint; never probe hardware."""

    matches: set[str] = set()
    cache: dict[tuple[int, int], bytes] = {}
    for board, variant in manifest.variants.items():
        for fingerprint in variant.detection:
            key = (fingerprint.offset, fingerprint.size)
            if key not in cache:
                payload = reader(*key)
                if len(payload) != fingerprint.size:
                    raise FirmwareInstallError("USB firmware read was incomplete")
                cache[key] = payload
            actual = hashlib.sha256(cache[key]).hexdigest()
            if actual == fingerprint.sha256:
                matches.add(board)
    if len(matches) > 1:
        raise FirmwareInstallError("existing firmware identifies conflicting boards")
    return next(iter(matches), None)


def select_board(
    manifest: FirmwareManifest,
    reader: FlashReader,
    *,
    requested: str | None = None,
    interactive: bool = True,
    input_fn: Callable[[str], str] = input,
) -> str:
    if requested not in (None, "v1", "v2"):
        raise FirmwareInstallError("board must be v1 or v2")
    detected = detect_trusted_board(manifest, reader)
    if detected:
        if requested and requested != detected:
            raise FirmwareInstallError("requested board conflicts with verified installed firmware")
        return detected
    if requested:
        return requested
    if not interactive:
        raise FirmwareInstallError("board revision is ambiguous; explicit choice required")
    prompt = (
        "The connected board cannot be identified safely.\n"
        f"Check the board or package: {BOARD_HELP_URL}\n"
        "Enter 1 for V1 (SH8601 / FT-family) or 2 for V2 (CO5300 / CST-family): "
    )
    answer = input_fn(prompt).strip().lower()
    if answer in {"1", "v1"}:
        return "v1"
    if answer in {"2", "v2"}:
        return "v2"
    raise FirmwareInstallError("board revision remains ambiguous; nothing was flashed")


def resolve_artifact_url(manifest_url: str, relative_path: str) -> str:
    pure = PurePosixPath(relative_path)
    if pure.is_absolute() or ".." in pure.parts:
        raise FirmwareInstallError("firmware artifact path is unsafe")
    return urllib.parse.urljoin(manifest_url, relative_path)


def download_variant(
    manifest: FirmwareManifest,
    board: str,
    destination: Path,
    *,
    allow_test_url: bool,
) -> tuple[DownloadedArtifact, ...]:
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    downloaded: list[DownloadedArtifact] = []
    variant = manifest.variants[board]
    for artifact in variant.artifacts:
        url = resolve_artifact_url(manifest.source_url, artifact.path)
        payload = _read_url(url, maximum=MAX_ARTIFACT_BYTES, allow_test_url=allow_test_url)
        if len(payload) != artifact.size or hashlib.sha256(payload).hexdigest() != artifact.sha256:
            raise FirmwareInstallError("firmware artifact checksum or size mismatch")
        if artifact.role == "application":
            _validate_application_image(payload, variant)
        output = destination / (artifact.role + ".bin")
        descriptor = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        downloaded.append(DownloadedArtifact(artifact=artifact, path=output))
    return tuple(downloaded)


def _app_field(payload: bytes, offset: int) -> str:
    field = payload[offset : offset + ESP_APP_FIELD_BYTES]
    if len(field) != ESP_APP_FIELD_BYTES or b"\0" not in field:
        raise FirmwareInstallError("firmware application metadata is invalid")
    try:
        return field.split(b"\0", 1)[0].decode("ascii")
    except UnicodeDecodeError as exc:
        raise FirmwareInstallError("firmware application metadata is invalid") from exc


def _validate_application_image(payload: bytes, variant: VariantManifest) -> None:
    if (
        len(payload) < ESP_APP_IDF_OFFSET + ESP_APP_FIELD_BYTES
        or payload[0] != ESP_IMAGE_MAGIC
        or struct.unpack_from("<I", payload, ESP_APP_DESC_OFFSET)[0] != ESP_APP_DESC_MAGIC
    ):
        raise FirmwareInstallError("firmware application image is invalid")
    if (
        _app_field(payload, ESP_APP_VERSION_OFFSET) != variant.firmware_version
        or _app_field(payload, ESP_APP_PROJECT_OFFSET) != "coinbase_amoled_terminal"
        or _app_field(payload, ESP_APP_IDF_OFFSET) != "v5.5.2"
    ):
        raise FirmwareInstallError("firmware application metadata does not match manifest")


def build_setup_partition(metadata: SetupMetadata) -> bytes:
    payload_value = {
        "schema_version": 1,
        "session_id": metadata.session_id,
        "setup_token": metadata.setup_token,
        "csrf_token": metadata.csrf_token,
        "endpoint_url": metadata.endpoint_url,
        "local_page_url": metadata.local_page_url,
        "bridge_url": metadata.bridge_url,
        "expires_at": metadata.expires_at,
    }
    for name in ("session_id", "setup_token", "csrf_token"):
        value = payload_value[name]
        if (
            not isinstance(value, str)
            or not 20 <= len(value) <= 128
            or not re.fullmatch(r"[A-Za-z0-9_-]+", value)
        ):
            raise FirmwareInstallError("setup session metadata is invalid")
        try:
            value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise FirmwareInstallError("setup session metadata is invalid") from exc
    try:
        endpoint = urllib.parse.urlsplit(metadata.endpoint_url)
        local_page = urllib.parse.urlsplit(metadata.local_page_url)
        endpoint_port = endpoint.port
        local_page_port = local_page.port
    except ValueError as exc:
        raise FirmwareInstallError("localhost setup URL is invalid") from exc
    for parsed in (endpoint, local_page):
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or not (endpoint_port if parsed is endpoint else local_page_port)
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise FirmwareInstallError("localhost setup URL is invalid")
    if (
        endpoint.path != "/v1/onboarding"
        or local_page.path != f"/setup/{metadata.session_id}"
        or (endpoint.hostname, endpoint_port) != (local_page.hostname, local_page_port)
    ):
        raise FirmwareInstallError("localhost setup URL is invalid")
    try:
        bridge = urllib.parse.urlsplit(metadata.bridge_url)
        _bridge_port = bridge.port
    except ValueError as exc:
        raise FirmwareInstallError("bridge provisioning URL is invalid") from exc
    if (
        bridge.scheme not in {"http", "https"}
        or not bridge.hostname
        or bridge.username
        or bridge.password
        or bridge.query
        or bridge.fragment
        or bridge.path != "/v1/device-feed"
        or len(metadata.bridge_url) > 255
    ):
        raise FirmwareInstallError("bridge provisioning URL is invalid")
    if not isinstance(metadata.expires_at, int) or metadata.expires_at <= 0:
        raise FirmwareInstallError("setup session expiry is invalid")

    payload = json.dumps(
        payload_value, separators=(",", ":"), sort_keys=True, ensure_ascii=True
    ).encode("ascii")
    if any(marker.lower() in payload.lower() for marker in FORBIDDEN_ESP_MARKERS):
        raise FirmwareInstallError("unsafe credential material reached ESP metadata")
    header = ONBOARDING_MAGIC + struct.pack("<II", 1, len(payload))
    image = header + hashlib.sha256(payload).digest() + payload
    if len(image) > ONBOARDING_SIZE:
        raise FirmwareInstallError("setup session metadata is too large")
    return image + (b"\xff" * (ONBOARDING_SIZE - len(image)))


def parse_setup_partition(image: bytes) -> dict[str, Any]:
    """Host-side verifier used by release and regression tests."""

    if len(image) != ONBOARDING_SIZE or not image.startswith(ONBOARDING_MAGIC):
        raise FirmwareInstallError("setup partition image is invalid")
    version, length = struct.unpack("<II", image[8:16])
    if version != 1 or not 1 <= length <= ONBOARDING_SIZE - 48:
        raise FirmwareInstallError("setup partition image is invalid")
    digest = image[16:48]
    payload = image[48 : 48 + length]
    if hashlib.sha256(payload).digest() != digest:
        raise FirmwareInstallError("setup partition checksum failed")
    try:
        value = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FirmwareInstallError("setup partition payload is invalid") from exc
    if not isinstance(value, dict):
        raise FirmwareInstallError("setup partition payload is invalid")
    return value


def validate_serial_port(value: str) -> str:
    if (
        not value
        or not os.path.isabs(value)
        or len(value) > 256
        or any(ord(character) < 0x20 for character in value)
    ):
        raise FirmwareInstallError("USB serial port is invalid")
    return value


def detect_serial_port() -> str:
    try:
        from serial.tools import list_ports
    except ImportError as exc:
        raise FirmwareInstallError("esptool serial support is not installed") from exc
    candidates: list[str] = []
    for port in list_ports.comports():
        device = str(getattr(port, "device", ""))
        vid = getattr(port, "vid", None)
        if vid == 0x303A or "usbmodem" in device or "ttyACM" in device:
            candidates.append(device)
    candidates = sorted(set(filter(None, candidates)))
    if len(candidates) != 1:
        raise FirmwareInstallError("connect exactly one ESP32-S3 display by USB, or pass --port")
    return validate_serial_port(candidates[0])


class EsptoolRunner:
    """Run esptool without shell expansion or identifier-bearing console logs."""

    def __init__(self, *, python: str, port: str) -> None:
        self.python = str(Path(python).resolve())
        self.port = validate_serial_port(port)

    def _run(self, arguments: list[str]) -> None:
        command = [
            self.python,
            "-m",
            "esptool",
            "--chip",
            "esp32s3",
            "--port",
            self.port,
            "--baud",
            "460800",
            *arguments,
        ]
        try:
            completed = subprocess.run(
                command,
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=180,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise FirmwareInstallError("USB firmware operation failed") from exc
        if completed.returncode != 0:
            # esptool output can contain a globally unique hardware address. Do
            # not print or retain it in installer logs.
            raise FirmwareInstallError("USB firmware operation failed")

    def read_flash(self, offset: int, size: int) -> bytes:
        if offset < 0 or not 1 <= size <= 0x700000:
            raise FirmwareInstallError("unsafe firmware read range")
        with tempfile.TemporaryDirectory(prefix="cbat-read-") as temporary:
            output = Path(temporary) / "existing.bin"
            self._run(
                [
                    "--before",
                    "default_reset",
                    "--after",
                    "no_reset",
                    "read_flash",
                    hex(offset),
                    hex(size),
                    str(output),
                ]
            )
            try:
                payload = output.read_bytes()
            except OSError as exc:
                raise FirmwareInstallError("USB firmware read failed") from exc
        return payload

    def flash(
        self,
        artifacts: tuple[DownloadedArtifact, ...],
        setup_partition: Path,
    ) -> None:
        if setup_partition.stat().st_size != ONBOARDING_SIZE:
            raise FirmwareInstallError("setup partition file is invalid")
        pairs: list[str] = []
        for downloaded in sorted(artifacts, key=lambda item: item.artifact.offset):
            artifact = downloaded.artifact
            if (
                artifact.role not in EXPECTED_OFFSETS
                or artifact.offset != EXPECTED_OFFSETS[artifact.role]
                or artifact.offset + artifact.size > EXPECTED_REGION_ENDS[artifact.role]
                or not downloaded.path.is_file()
                or downloaded.path.stat().st_size != artifact.size
            ):
                raise FirmwareInstallError("refusing an unsafe firmware flash region")
            pairs.extend((hex(downloaded.artifact.offset), str(downloaded.path)))
        pairs.extend((hex(ONBOARDING_OFFSET), str(setup_partition)))
        self._run(
            [
                "--before",
                "default_reset",
                "--after",
                "hard_reset",
                "write_flash",
                "--flash_mode",
                "dio",
                "--flash_size",
                "16MB",
                "--flash_freq",
                "80m",
                *pairs,
            ]
        )


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-url", required=True)
    parser.add_argument("--port")
    parser.add_argument("--board", choices=("v1", "v2"))
    parser.add_argument("--allow-unverified-test-artifacts", action="store_true")
    args = parser.parse_args()
    manifest = load_manifest(
        args.manifest_url,
        allow_test_url=args.allow_unverified_test_artifacts,
    )
    runner = EsptoolRunner(python=sys.executable, port=args.port or detect_serial_port())
    board = select_board(manifest, runner.read_flash, requested=args.board)
    require_release_readiness(
        manifest,
        board=board,
        allow_unverified_test_artifacts=args.allow_unverified_test_artifacts,
    )
    print(f"Verified board selection: {board.upper()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
