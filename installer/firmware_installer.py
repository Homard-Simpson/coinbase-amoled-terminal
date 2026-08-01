#!/usr/bin/env python3
"""Checksum-pinned firmware selection, validation, flashing, and status checks."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

MANIFEST_SCHEMA_VERSION = 2
PROVENANCE_SCHEMA_VERSION = 1
ESP_IDF_VERSION = "5.5.2"
ESP_IDF_CONTAINER_IMAGE = "espressif/idf:v5.5.2"
ESP_IDF_CONTAINER_DIGEST = "sha256:05cbfc42ed2e987b8026722c15bf1d8523d3e4fd1b4ac04d2e4056f5e0918b99"
CLIENT_SIGNATURE_VERIFICATION_AVAILABLE = False
MAX_MANIFEST_BYTES = 256 * 1024
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
DOWNLOAD_CHUNK_BYTES = 64 * 1024
DOWNLOAD_SOCKET_TIMEOUT_SECONDS = 10.0
DOWNLOAD_TOTAL_TIMEOUT_SECONDS = 45.0
MAX_REDIRECTS = 5
ESP_IMAGE_MAGIC = 0xE9
ESP_IMAGE_HEADER_BYTES = 24
ESP_IMAGE_CHIP_ESP32S3 = 9
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
TRUSTED_RELEASE_REDIRECT_HOSTS = frozenset(
    {
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
    }
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
EXPECTED_PARTITIONS = {
    "nvs": (1, 0x02, 0x9000, 0x6000),
    "phy_init": (1, 0x01, 0xF000, 0x1000),
    "otadata": (1, 0x00, 0x10000, 0x2000),
    "ota_0": (0, 0x10, 0x20000, 0x700000),
    "ota_1": (0, 0x11, 0x720000, 0x700000),
    "onboarding": (1, 0x40, ONBOARDING_OFFSET, ONBOARDING_SIZE),
}
FORBIDDEN_ESP_MARKERS = (
    b"privateKey",
    b"apiKey",
    b"apiSecret",
    b"PRIVATE KEY-----",
    b"coinbase_api",
)
_PRIVATE_KEY_BLOCK_RE = re.compile(
    rb"-----BEGIN (?:EC |RSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\r\n]+"
    rb"[A-Za-z0-9+/=\r\n]{64,}-----END (?:EC |RSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
)
_TOKEN_PATTERNS = (
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
)
_SECRET_ASSIGNMENT_RE = re.compile(
    rb"(?i)(?:api[_-]?(?:key|secret)|access[_-]?token|private[_-]?key)"
    rb"\s*[:=]\s*[\"']?([A-Za-z0-9_./+\-=]{20,})"
)
_PRIVATE_HOST_RE = re.compile(
    rb"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.[a-z0-9-]+\.ts\.net\b",
    re.I,
)
_IPV4_BYTES_RE = re.compile(rb"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


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
class VariantManifest:
    board_revision: str
    firmware_version: str
    artifacts: tuple[Artifact, ...]
    onboarding_offset: int
    onboarding_size: int


@dataclass(frozen=True, slots=True)
class ReleaseEvidence:
    production_ready: bool
    controls_verified: bool
    client_signature_verified: bool
    hardware_attested: dict[str, bool]
    trust_blocker: str


@dataclass(frozen=True, slots=True)
class FirmwareManifest:
    release_version: str
    manifest_id: str
    manifest_sha256: str
    esp_idf_version: str
    esp_idf_container_image: str
    esp_idf_container_digest: str
    evidence: ReleaseEvidence
    variants: dict[str, VariantManifest]
    source_url: str
    test_mode: bool


@dataclass(frozen=True, slots=True)
class SetupMetadata:
    session_id: str
    setup_token: str
    completion_token: str
    csrf_token: str
    endpoint_url: str
    local_page_url: str
    bridge_url: str
    expires_at: int


@dataclass(frozen=True, slots=True)
class DownloadedArtifact:
    artifact: Artifact
    path: Path
    board_revision: str
    firmware_version: str


def official_manifest_url(version: str) -> str:
    if not VERSION_RE.fullmatch(version):
        raise FirmwareInstallError("firmware version must look like v1.2.3")
    return (
        OFFICIAL_RELEASE_PREFIX + urllib.parse.quote(version, safe="") + "/firmware-manifest.json"
    )


def compute_manifest_id(raw: dict[str, Any]) -> str:
    """Return the canonical identity of a manifest, excluding its identity field."""

    identity_payload = dict(raw)
    identity_payload.pop("manifest_id", None)
    canonical = json.dumps(
        identity_payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def _validate_https_url(
    url: str,
    *,
    allowed_hosts: frozenset[str],
    allow_query: bool,
) -> urllib.parse.SplitResult:
    parsed = urllib.parse.urlsplit(url)
    hostname = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "https"
        or hostname not in allowed_hosts
        or parsed.username
        or parsed.password
        or parsed.fragment
        or (parsed.query and not allow_query)
    ):
        raise FirmwareInstallError("firmware download used an untrusted URL")
    return parsed


class _TrustedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: frozenset[str]) -> None:
        super().__init__()
        self.allowed_hosts = allowed_hosts

    def redirect_request(  # type: ignore[no-untyped-def]
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl,
    ):
        target = urllib.parse.urljoin(req.full_url, newurl)
        _validate_https_url(target, allowed_hosts=self.allowed_hosts, allow_query=True)
        redirect_count = int(getattr(req, "_cbat_redirect_count", 0)) + 1
        if redirect_count > MAX_REDIRECTS:
            raise FirmwareInstallError("firmware download used too many redirects")
        redirected = super().redirect_request(req, fp, code, msg, headers, target)
        if redirected is None:
            raise FirmwareInstallError("firmware redirect was refused")
        setattr(redirected, "_cbat_redirect_count", redirect_count)
        return redirected


def _read_url(
    url: str,
    *,
    maximum: int,
    allow_test_url: bool,
    release_version: str | None = None,
    opener: Any | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> bytes:
    if not 1 <= maximum <= MAX_ARTIFACT_BYTES:
        raise FirmwareInstallError("firmware download limit is invalid")
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

    initial_host = (parsed.hostname or "").lower()
    if allow_test_url:
        if not initial_host:
            raise FirmwareInstallError("firmware URL has no host")
        allowed_hosts = frozenset({initial_host})
    else:
        if (
            release_version is None
            or url != official_manifest_url(release_version)
            and not url.startswith(
                official_manifest_url(release_version).removesuffix("firmware-manifest.json")
            )
        ):
            raise FirmwareInstallError("firmware URL is not bound to the requested release")
        allowed_hosts = TRUSTED_RELEASE_REDIRECT_HOSTS
    _validate_https_url(url, allowed_hosts=allowed_hosts, allow_query=False)

    redirect_handler = _TrustedRedirectHandler(allowed_hosts)
    network_opener = opener or urllib.request.build_opener(redirect_handler)
    request = urllib.request.Request(  # noqa: S310 - URL and redirect hosts are validated
        url,
        headers={
            "Accept": "application/json, application/octet-stream",
            "Cache-Control": "no-cache",
            "User-Agent": "coinbase-amoled-installer/2",
        },
        method="GET",
    )
    started = clock()
    try:
        with network_opener.open(  # noqa: S310 - opener is constrained above
            request,
            timeout=DOWNLOAD_SOCKET_TIMEOUT_SECONDS,
        ) as response:
            _validate_https_url(
                response.geturl(),
                allowed_hosts=allowed_hosts,
                allow_query=True,
            )
            content_length = response.headers.get("Content-Length")
            declared_length: int | None = None
            if content_length is not None:
                try:
                    declared_length = int(content_length)
                except ValueError as exc:
                    raise FirmwareInstallError("firmware download length is invalid") from exc
                if not 0 < declared_length <= maximum:
                    raise FirmwareInstallError("firmware download has an invalid size")
            chunks: list[bytes] = []
            received = 0
            while True:
                if clock() - started > DOWNLOAD_TOTAL_TIMEOUT_SECONDS:
                    raise FirmwareInstallError("firmware download exceeded its time limit")
                chunk = response.read(min(DOWNLOAD_CHUNK_BYTES, maximum + 1 - received))
                if not chunk:
                    break
                chunks.append(chunk)
                received += len(chunk)
                if received > maximum:
                    raise FirmwareInstallError("firmware download has an invalid size")
            payload = b"".join(chunks)
            if declared_length is not None and received != declared_length:
                raise FirmwareInstallError("firmware download length did not match its body")
    except FirmwareInstallError:
        raise
    except (OSError, TimeoutError, ValueError, urllib.error.URLError) as exc:
        raise FirmwareInstallError("firmware download failed") from exc
    if not payload:
        raise FirmwareInstallError("firmware download has an invalid size")
    return payload


def load_manifest(
    url: str,
    *,
    expected_release_version: str | None = None,
    expected_manifest_sha256: str | None = None,
    allow_test_url: bool = False,
) -> FirmwareManifest:
    if not allow_test_url:
        if expected_release_version is None or not VERSION_RE.fullmatch(expected_release_version):
            raise FirmwareInstallError("an exact firmware release version is required")
        if expected_manifest_sha256 is None or not SHA256_RE.fullmatch(expected_manifest_sha256):
            raise FirmwareInstallError("an authenticated manifest SHA-256 is required")
        if url != official_manifest_url(expected_release_version):
            raise FirmwareInstallError("firmware manifest URL is not the exact requested release")
    elif expected_manifest_sha256 is not None and not SHA256_RE.fullmatch(expected_manifest_sha256):
        raise FirmwareInstallError("firmware manifest SHA-256 is invalid")

    payload = _read_url(
        url,
        maximum=MAX_MANIFEST_BYTES,
        allow_test_url=allow_test_url,
        release_version=expected_release_version,
    )
    payload_digest = hashlib.sha256(payload).hexdigest()
    if expected_manifest_sha256 is not None and payload_digest != expected_manifest_sha256:
        raise FirmwareInstallError("firmware manifest identity did not match")
    try:
        raw = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FirmwareInstallError("firmware manifest is invalid") from exc
    expected_fields = {
        "schema_version",
        "release_version",
        "manifest_id",
        "build",
        "release_evidence",
        "variants",
    }
    if not isinstance(raw, dict) or set(raw) != expected_fields:
        raise FirmwareInstallError("firmware manifest fields are invalid")
    if raw["schema_version"] != MANIFEST_SCHEMA_VERSION:
        raise FirmwareInstallError("firmware manifest schema is unsupported")
    release_version = raw["release_version"]
    if not isinstance(release_version, str) or not VERSION_RE.fullmatch(release_version):
        raise FirmwareInstallError("firmware release version is invalid")
    if expected_release_version is not None and release_version != expected_release_version:
        raise FirmwareInstallError("firmware manifest release version did not match")
    manifest_id = raw["manifest_id"]
    if (
        not isinstance(manifest_id, str)
        or not SHA256_RE.fullmatch(manifest_id)
        or manifest_id != compute_manifest_id(raw)
    ):
        raise FirmwareInstallError("firmware manifest canonical identity is invalid")

    build = _parse_build_identity(raw["build"])
    evidence = _parse_release_evidence(raw["release_evidence"])
    variants_raw = raw["variants"]
    if not isinstance(variants_raw, dict) or set(variants_raw) != {"v1", "v2"}:
        raise FirmwareInstallError("firmware manifest must contain V1 and V2")
    variants = {
        board: _parse_variant(board, value, release_version=release_version)
        for board, value in variants_raw.items()
    }
    artifact_paths = [
        artifact.path for variant in variants.values() for artifact in variant.artifacts
    ]
    if len(artifact_paths) != len(set(artifact_paths)):
        raise FirmwareInstallError("firmware artifact paths must be variant-specific")
    return FirmwareManifest(
        release_version=release_version,
        manifest_id=manifest_id,
        manifest_sha256=payload_digest,
        esp_idf_version=build[0],
        esp_idf_container_image=build[1],
        esp_idf_container_digest=build[2],
        evidence=evidence,
        variants=variants,
        source_url=url,
        test_mode=allow_test_url,
    )


def _parse_build_identity(raw: Any) -> tuple[str, str, str]:
    if not isinstance(raw, dict) or set(raw) != {
        "esp_idf_version",
        "container_image",
        "container_digest",
    }:
        raise FirmwareInstallError("firmware build identity is invalid")
    expected = (ESP_IDF_VERSION, ESP_IDF_CONTAINER_IMAGE, ESP_IDF_CONTAINER_DIGEST)
    actual = (raw["esp_idf_version"], raw["container_image"], raw["container_digest"])
    if actual != expected:
        raise FirmwareInstallError("firmware build environment is not the pinned ESP-IDF image")
    return expected


def _parse_release_evidence(raw: Any) -> ReleaseEvidence:
    required = {
        "production_ready",
        "controls_verified",
        "client_signature_verified",
        "hardware_attested",
        "trust_blocker",
    }
    if not isinstance(raw, dict) or set(raw) != required:
        raise FirmwareInstallError("firmware release evidence is invalid")
    if not all(
        isinstance(raw[name], bool)
        for name in ("production_ready", "controls_verified", "client_signature_verified")
    ):
        raise FirmwareInstallError("firmware release evidence flags are invalid")
    attested = raw["hardware_attested"]
    if (
        not isinstance(attested, dict)
        or set(attested) != {"v1", "v2"}
        or not all(isinstance(value, bool) for value in attested.values())
    ):
        raise FirmwareInstallError("firmware hardware evidence is invalid")
    blocker = raw["trust_blocker"]
    if not isinstance(blocker, str) or len(blocker) > 500:
        raise FirmwareInstallError("firmware trust blocker is invalid")
    all_evidence = (
        raw["controls_verified"] and raw["client_signature_verified"] and all(attested.values())
    )
    if raw["production_ready"] != all_evidence:
        raise FirmwareInstallError("firmware production readiness is inconsistent")
    if raw["production_ready"] and blocker:
        raise FirmwareInstallError("production firmware cannot declare a trust blocker")
    if not raw["production_ready"] and not blocker:
        raise FirmwareInstallError("non-production firmware must state its trust blocker")
    return ReleaseEvidence(
        production_ready=raw["production_ready"],
        controls_verified=raw["controls_verified"],
        client_signature_verified=raw["client_signature_verified"],
        hardware_attested=dict(attested),
        trust_blocker=blocker,
    )


def _parse_variant(board: str, raw: Any, *, release_version: str) -> VariantManifest:
    required = {
        "board_revision",
        "firmware_version",
        "artifacts",
        "onboarding_partition",
    }
    if not isinstance(raw, dict) or set(raw) != required:
        raise FirmwareInstallError("firmware variant fields are invalid")
    if raw["board_revision"] != board:
        raise FirmwareInstallError("firmware board label is inconsistent")
    firmware_version = raw["firmware_version"]
    expected_firmware_version = f"{release_version.removeprefix('v')}-{board}"
    if (
        firmware_version != expected_firmware_version
        or len(firmware_version) >= ESP_APP_FIELD_BYTES
    ):
        raise FirmwareInstallError("firmware image version is not release-bound")

    artifacts_raw = raw["artifacts"]
    if not isinstance(artifacts_raw, list) or len(artifacts_raw) != 4:
        raise FirmwareInstallError("firmware artifact list is invalid")
    artifacts = tuple(_parse_artifact(item) for item in artifacts_raw)
    if {artifact.role for artifact in artifacts} != set(EXPECTED_OFFSETS):
        raise FirmwareInstallError("firmware artifact roles are incomplete")

    onboarding = raw["onboarding_partition"]
    if not isinstance(onboarding, dict) or set(onboarding) != {"offset", "size"}:
        raise FirmwareInstallError("onboarding partition is invalid")
    if onboarding["offset"] != ONBOARDING_OFFSET or onboarding["size"] != ONBOARDING_SIZE:
        raise FirmwareInstallError("onboarding partition layout is unsafe")
    _validate_flash_layout(
        artifacts, onboarding_offset=ONBOARDING_OFFSET, onboarding_size=ONBOARDING_SIZE
    )
    return VariantManifest(
        board_revision=board,
        firmware_version=firmware_version,
        artifacts=artifacts,
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
    if role == "partition_table" and size != 0xC00:
        raise FirmwareInstallError("firmware partition table size is invalid")
    if role == "ota_data" and size != 0x2000:
        raise FirmwareInstallError("firmware OTA data size is invalid")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise FirmwareInstallError("firmware artifact checksum is invalid")
    return Artifact(role=role, path=path, offset=offset, size=size, sha256=digest)


def _validate_flash_layout(
    artifacts: tuple[Artifact, ...],
    *,
    onboarding_offset: int,
    onboarding_size: int,
) -> None:
    intervals = [
        (artifact.offset, artifact.offset + artifact.size, artifact.role) for artifact in artifacts
    ]
    intervals.append((onboarding_offset, onboarding_offset + onboarding_size, "onboarding"))
    protected = ((0x9000, 0xF000, "nvs"), (0xF000, 0x10000, "phy_init"))
    for start, end, role in intervals:
        if start < 0 or end <= start or end > 0x1000000:
            raise FirmwareInstallError("firmware flash layout is invalid")
        for protected_start, protected_end, protected_role in protected:
            if role != protected_role and max(start, protected_start) < min(end, protected_end):
                raise FirmwareInstallError("firmware flash layout overlaps protected data")
    for index, (start, end, _role) in enumerate(sorted(intervals)):
        for other_start, other_end, _other_role in sorted(intervals)[index + 1 :]:
            if other_start >= end:
                break
            if max(start, other_start) < min(end, other_end):
                raise FirmwareInstallError("firmware flash regions overlap")


def require_release_readiness(
    manifest: FirmwareManifest,
    *,
    board: str,
    allow_unverified_test_artifacts: bool,
) -> None:
    if board not in manifest.variants:
        raise FirmwareInstallError("board must be v1 or v2")
    if allow_unverified_test_artifacts:
        return
    evidence = manifest.evidence
    if not CLIENT_SIGNATURE_VERIFICATION_AVAILABLE:
        raise FirmwareInstallError(
            "production flashing is blocked because trusted client-side signature verification "
            "is not implemented"
        )
    if (
        evidence.production_ready
        and evidence.controls_verified
        and evidence.client_signature_verified
        and evidence.hardware_attested[board]
    ):
        return
    raise FirmwareInstallError("firmware release is not fully attested or production-ready")


FlashReader = Callable[[int, int], bytes]


def select_board(
    manifest: FirmwareManifest,
    reader: FlashReader | None = None,
    *,
    requested: str | None = None,
    interactive: bool = True,
    input_fn: Callable[[str], str] = input,
) -> str:
    """Select a physical board without inferring it from an application image."""

    del reader  # App-image identity is deliberately never physical-board authority.
    if set(manifest.variants) != {"v1", "v2"}:
        raise FirmwareInstallError("firmware manifest does not provide both board revisions")
    if requested not in (None, "v1", "v2"):
        raise FirmwareInstallError("board must be v1 or v2")
    if requested:
        return requested
    if not interactive:
        raise FirmwareInstallError("board revision is ambiguous; explicit --board is required")
    prompt = (
        "The physical board revision cannot be identified safely from installed firmware.\n"
        f"Check the board or package: {BOARD_HELP_URL}\n"
        "Enter 1 for V1 (SH8601 / FT-family) or 2 for V2 (CO5300 / CST-family): "
    )
    answer = input_fn(prompt).strip().lower()
    if answer in {"1", "v1"}:
        return "v1"
    if answer in {"2", "v2"}:
        return "v2"
    raise FirmwareInstallError("board revision remains ambiguous; nothing was flashed")


def resolve_artifact_url(manifest: FirmwareManifest, relative_path: str) -> str:
    pure = PurePosixPath(relative_path)
    if pure.is_absolute() or ".." in pure.parts:
        raise FirmwareInstallError("firmware artifact path is unsafe")
    resolved = urllib.parse.urljoin(manifest.source_url, relative_path)
    if not manifest.test_mode:
        release_base = official_manifest_url(manifest.release_version).removesuffix(
            "firmware-manifest.json"
        )
        if not resolved.startswith(release_base):
            raise FirmwareInstallError("firmware artifact escaped its exact release")
    return resolved


def download_variant(
    manifest: FirmwareManifest,
    board: str,
    destination: Path,
    *,
    allow_test_url: bool,
) -> tuple[DownloadedArtifact, ...]:
    if allow_test_url != manifest.test_mode:
        raise FirmwareInstallError("firmware download trust mode changed after manifest validation")
    if board not in manifest.variants:
        raise FirmwareInstallError("board must be v1 or v2")
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    downloaded: list[DownloadedArtifact] = []
    variant = manifest.variants[board]
    for artifact in variant.artifacts:
        url = resolve_artifact_url(manifest, artifact.path)
        payload = _read_url(
            url,
            maximum=artifact.size,
            allow_test_url=allow_test_url,
            release_version=manifest.release_version,
        )
        if len(payload) != artifact.size or hashlib.sha256(payload).hexdigest() != artifact.sha256:
            raise FirmwareInstallError("firmware artifact checksum or size mismatch")
        validate_release_artifact_payload(
            artifact.role,
            payload,
            firmware_version=variant.firmware_version,
        )
        output = destination / (artifact.role + ".bin")
        descriptor = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        downloaded.append(
            DownloadedArtifact(
                artifact=artifact,
                path=output,
                board_revision=board,
                firmware_version=variant.firmware_version,
            )
        )
    return tuple(downloaded)


def scan_release_artifact_for_secrets(payload: bytes) -> None:
    """Reject high-confidence credentials or private infrastructure in release binaries."""

    if _PRIVATE_KEY_BLOCK_RE.search(payload) or any(
        pattern.search(payload) for pattern in _TOKEN_PATTERNS
    ):
        raise FirmwareInstallError("release artifact failed binary credential scanning")
    assignment = _SECRET_ASSIGNMENT_RE.search(payload)
    if assignment:
        value = assignment.group(1).lower()
        placeholders = (b"placeholder", b"example", b"replace", b"redacted")
        if not any(marker in value for marker in placeholders) and len(set(value)) > 3:
            raise FirmwareInstallError("release artifact failed binary credential scanning")
    if _PRIVATE_HOST_RE.search(payload):
        raise FirmwareInstallError("release artifact contains private infrastructure")
    for match in _IPV4_BYTES_RE.finditer(payload):
        try:
            value = match.group(0).decode("ascii")
            address = ipaddress.ip_address(value)
        except (UnicodeDecodeError, ValueError):
            continue
        if address.is_private and value not in {"127.0.0.1", "192.168.4.1"}:
            raise FirmwareInstallError("release artifact contains private infrastructure")


def validate_release_artifact_payload(
    role: str,
    payload: bytes,
    *,
    firmware_version: str,
) -> None:
    scan_release_artifact_for_secrets(payload)
    if role == "bootloader":
        _validate_esp_image(payload, image_name="bootloader")
    elif role == "partition_table":
        _validate_partition_table(payload)
    elif role == "ota_data":
        _validate_ota_data(payload)
    elif role == "application":
        _validate_application_image(payload, firmware_version=firmware_version)
    else:
        raise FirmwareInstallError("firmware artifact role is invalid")


def _validate_esp_image(payload: bytes, *, image_name: str) -> None:
    if len(payload) < ESP_IMAGE_HEADER_BYTES + 8 + 1 + 32 or payload[0] != ESP_IMAGE_MAGIC:
        raise FirmwareInstallError(f"firmware {image_name} ESP image is invalid")
    segment_count = payload[1]
    chip_id = struct.unpack_from("<H", payload, 12)[0]
    if (
        not 1 <= segment_count <= 16
        or payload[2] != 0x02
        or payload[3] != 0x4F
        or chip_id != ESP_IMAGE_CHIP_ESP32S3
        or payload[23] != 1
    ):
        raise FirmwareInstallError(f"firmware {image_name} ESP image header is invalid")
    cursor = ESP_IMAGE_HEADER_BYTES
    checksum = 0xEF
    for _index in range(segment_count):
        if cursor + 8 > len(payload):
            raise FirmwareInstallError(f"firmware {image_name} ESP segment is invalid")
        load_address, data_length = struct.unpack_from("<II", payload, cursor)
        cursor += 8
        segment_end = cursor + data_length
        approved_address = (
            0x3C000000 <= load_address < 0x44000000 or 0x50000000 <= load_address < 0x50010000
        )
        if (
            not approved_address
            or data_length == 0
            or segment_end > len(payload)
            or load_address + data_length > 0x1_0000_0000
        ):
            raise FirmwareInstallError(f"firmware {image_name} ESP segment is unsafe")
        for value in payload[cursor:segment_end]:
            checksum ^= value
        cursor = segment_end
    hashed_end = (cursor + 1 + 15) & ~15
    if hashed_end + 32 != len(payload):
        raise FirmwareInstallError(f"firmware {image_name} ESP image length is invalid")
    if any(payload[cursor : hashed_end - 1]) or payload[hashed_end - 1] != checksum:
        raise FirmwareInstallError(f"firmware {image_name} ESP checksum is invalid")
    if payload[hashed_end:] != hashlib.sha256(payload[:hashed_end]).digest():
        raise FirmwareInstallError(f"firmware {image_name} ESP SHA-256 is invalid")


def _app_field(payload: bytes, offset: int) -> str:
    field = payload[offset : offset + ESP_APP_FIELD_BYTES]
    if len(field) != ESP_APP_FIELD_BYTES or b"\0" not in field:
        raise FirmwareInstallError("firmware application metadata is invalid")
    try:
        return field.split(b"\0", 1)[0].decode("ascii")
    except UnicodeDecodeError as exc:
        raise FirmwareInstallError("firmware application metadata is invalid") from exc


def _validate_application_image(payload: bytes, *, firmware_version: str) -> None:
    _validate_esp_image(payload, image_name="application")
    if (
        len(payload) < ESP_APP_IDF_OFFSET + ESP_APP_FIELD_BYTES
        or struct.unpack_from("<I", payload, ESP_APP_DESC_OFFSET)[0] != ESP_APP_DESC_MAGIC
    ):
        raise FirmwareInstallError("firmware application descriptor is invalid")
    if (
        _app_field(payload, ESP_APP_VERSION_OFFSET) != firmware_version
        or _app_field(payload, ESP_APP_PROJECT_OFFSET) != "coinbase_amoled_terminal"
        or _app_field(payload, ESP_APP_IDF_OFFSET) != f"v{ESP_IDF_VERSION}"
    ):
        raise FirmwareInstallError("firmware application metadata does not match manifest")


def _validate_partition_table(payload: bytes) -> None:
    if len(payload) != 0xC00:
        raise FirmwareInstallError("firmware partition table length is invalid")
    entries: dict[str, tuple[int, int, int, int]] = {}
    md5_seen = False
    terminator_seen = False
    for offset in range(0, len(payload), 32):
        block = payload[offset : offset + 32]
        magic = struct.unpack_from("<H", block)[0]
        if magic == 0x50AA and not md5_seen:
            _magic, entry_type, subtype, partition_offset, size, label_raw, flags = struct.unpack(
                "<HBBII16sI", block
            )
            try:
                label = label_raw.split(b"\0", 1)[0].decode("ascii")
            except UnicodeDecodeError as exc:
                raise FirmwareInstallError("firmware partition label is invalid") from exc
            if not label or flags != 0 or label in entries:
                raise FirmwareInstallError("firmware partition entry is invalid")
            entries[label] = (entry_type, subtype, partition_offset, size)
        elif magic == 0xEBEB and not md5_seen:
            if block[2:16] != b"\xff" * 14:
                raise FirmwareInstallError("firmware partition digest marker is invalid")
            expected = hashlib.md5(payload[:offset], usedforsecurity=False).digest()
            if block[16:] != expected:
                raise FirmwareInstallError("firmware partition table digest is invalid")
            md5_seen = True
        elif block == b"\xff" * 32 and md5_seen:
            if any(value != 0xFF for value in payload[offset:]):
                raise FirmwareInstallError("firmware partition table trailing data is invalid")
            terminator_seen = True
            break
        else:
            raise FirmwareInstallError("firmware partition table structure is invalid")
    if not md5_seen or not terminator_seen or entries != EXPECTED_PARTITIONS:
        raise FirmwareInstallError("firmware partition layout does not match the approved map")
    intervals = sorted(
        (partition_offset, partition_offset + size, label)
        for label, (_entry_type, _subtype, partition_offset, size) in entries.items()
    )
    for (_start, end, _label), (next_start, _next_end, _next_label) in zip(
        intervals, intervals[1:]
    ):
        if end > next_start:
            raise FirmwareInstallError("firmware partition table contains overlap")


def _validate_ota_data(payload: bytes) -> None:
    if len(payload) != 0x2000 or payload != b"\xff" * 0x2000:
        raise FirmwareInstallError("firmware initial OTA data is not blank and safe")


def build_setup_partition(metadata: SetupMetadata) -> bytes:
    payload_value = {
        "schema_version": 1,
        "session_id": metadata.session_id,
        "setup_token": metadata.setup_token,
        "completion_token": metadata.completion_token,
        "csrf_token": metadata.csrf_token,
        "endpoint_url": metadata.endpoint_url,
        "local_page_url": metadata.local_page_url,
        "bridge_url": metadata.bridge_url,
        "expires_at": metadata.expires_at,
    }
    for name in ("session_id", "setup_token", "completion_token", "csrf_token"):
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
    """Host-side semantic verifier for the dedicated onboarding partition."""

    if len(image) != ONBOARDING_SIZE or not image.startswith(ONBOARDING_MAGIC):
        raise FirmwareInstallError("setup partition image is invalid")
    version, length = struct.unpack("<II", image[8:16])
    if version != 1 or not 1 <= length <= ONBOARDING_SIZE - 48:
        raise FirmwareInstallError("setup partition image is invalid")
    digest = image[16:48]
    payload = image[48 : 48 + length]
    if hashlib.sha256(payload).digest() != digest:
        raise FirmwareInstallError("setup partition checksum failed")
    if image[48 + length :] != b"\xff" * (ONBOARDING_SIZE - 48 - length):
        raise FirmwareInstallError("setup partition has unexpected trailing data")
    try:
        value = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FirmwareInstallError("setup partition payload is invalid") from exc
    expected_fields = {
        "schema_version",
        "session_id",
        "setup_token",
        "completion_token",
        "csrf_token",
        "endpoint_url",
        "local_page_url",
        "bridge_url",
        "expires_at",
    }
    if not isinstance(value, dict) or set(value) != expected_fields or value["schema_version"] != 1:
        raise FirmwareInstallError("setup partition payload is invalid")
    try:
        metadata = SetupMetadata(
            session_id=value["session_id"],
            setup_token=value["setup_token"],
            completion_token=value["completion_token"],
            csrf_token=value["csrf_token"],
            endpoint_url=value["endpoint_url"],
            local_page_url=value["local_page_url"],
            bridge_url=value["bridge_url"],
            expires_at=value["expires_at"],
        )
        rebuilt = build_setup_partition(metadata)
    except (FirmwareInstallError, TypeError, ValueError) as exc:
        raise FirmwareInstallError("setup partition payload is invalid") from exc
    if rebuilt != image:
        raise FirmwareInstallError("setup partition semantic validation failed")
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
    """Run esptool through the exact isolated interpreter without shell expansion."""

    def __init__(self, *, python: str, port: str) -> None:
        # abspath intentionally does not resolve a venv's python symlink. Resolving
        # it would discard pyvenv.cfg discovery and execute from the base environment.
        self.python = os.path.abspath(os.path.expanduser(python))
        if not os.path.isfile(self.python) or not os.access(self.python, os.X_OK):
            raise FirmwareInstallError("isolated flashing interpreter is unavailable")
        self.port = validate_serial_port(port)

    def _run(self, arguments: list[str]) -> None:
        command = [
            self.python,
            "-I",
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
        if offset < 0 or not 1 <= size <= 0x700000 or offset + size > 0x1000000:
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
        if len(payload) != size:
            raise FirmwareInstallError("USB firmware read was incomplete")
        return payload

    def flash(
        self,
        artifacts: tuple[DownloadedArtifact, ...],
        setup_partition: Path,
    ) -> None:
        try:
            setup_payload = setup_partition.read_bytes()
        except OSError as exc:
            raise FirmwareInstallError("setup partition file is invalid") from exc
        parse_setup_partition(setup_payload)
        pairs: list[str] = []
        seen_roles: set[str] = set()
        board_revisions = {downloaded.board_revision for downloaded in artifacts}
        firmware_versions = {downloaded.firmware_version for downloaded in artifacts}
        if len(board_revisions) != 1 or len(firmware_versions) != 1:
            raise FirmwareInstallError("refusing a mixed-board firmware bundle")
        for downloaded in sorted(artifacts, key=lambda item: item.artifact.offset):
            artifact = downloaded.artifact
            try:
                payload = downloaded.path.read_bytes()
            except OSError as exc:
                raise FirmwareInstallError("firmware artifact could not be re-verified") from exc
            if (
                artifact.role in seen_roles
                or artifact.role not in EXPECTED_OFFSETS
                or artifact.offset != EXPECTED_OFFSETS[artifact.role]
                or artifact.offset + artifact.size > EXPECTED_REGION_ENDS[artifact.role]
                or len(payload) != artifact.size
                or hashlib.sha256(payload).hexdigest() != artifact.sha256
            ):
                raise FirmwareInstallError("refusing an unsafe or changed firmware artifact")
            validate_release_artifact_payload(
                artifact.role,
                payload,
                firmware_version=downloaded.firmware_version,
            )
            seen_roles.add(artifact.role)
            pairs.extend((hex(artifact.offset), str(downloaded.path)))
        if seen_roles != set(EXPECTED_OFFSETS):
            raise FirmwareInstallError("refusing an incomplete firmware bundle")
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


def inspect_flash_status(reader: FlashReader) -> dict[str, Any]:
    """Read-only recovery status; never infers the physical board revision."""

    slots: dict[str, dict[str, str]] = {}
    for name, offset in (("ota_0", 0x20000), ("ota_1", 0x720000)):
        payload = reader(offset, ESP_APP_IDF_OFFSET + ESP_APP_FIELD_BYTES)
        if payload == b"\xff" * len(payload):
            slots[name] = {"state": "blank"}
            continue
        try:
            if (
                payload[0] != ESP_IMAGE_MAGIC
                or struct.unpack_from("<I", payload, ESP_APP_DESC_OFFSET)[0] != ESP_APP_DESC_MAGIC
            ):
                raise FirmwareInstallError("unrecognized")
            project = _app_field(payload, ESP_APP_PROJECT_OFFSET)
            version = _app_field(payload, ESP_APP_VERSION_OFFSET)
            idf_version = _app_field(payload, ESP_APP_IDF_OFFSET)
            if project != "coinbase_amoled_terminal":
                raise FirmwareInstallError("unrecognized")
        except (FirmwareInstallError, IndexError, struct.error):
            slots[name] = {"state": "unrecognized"}
        else:
            slots[name] = {
                "state": "recognized",
                "project": project,
                "version": version,
                "esp_idf": idf_version,
            }
    onboarding = reader(ONBOARDING_OFFSET, ONBOARDING_SIZE)
    if onboarding == b"\xff" * ONBOARDING_SIZE:
        onboarding_state = "blank"
    else:
        try:
            parse_setup_partition(onboarding)
        except FirmwareInstallError:
            onboarding_state = "invalid-or-interrupted"
        else:
            onboarding_state = "valid"
    return {
        "physical_board_revision": "unverified",
        "app_slots": slots,
        "onboarding_partition": onboarding_state,
        "operation": "read-only",
    }


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--status", action="store_true", help="read safe interrupted-flash status")
    parser.add_argument("--manifest-url")
    parser.add_argument("--release-version")
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--port")
    parser.add_argument("--board", choices=("v1", "v2"))
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--allow-unverified-test-artifacts", action="store_true")
    args = parser.parse_args()
    runner = EsptoolRunner(python=sys.executable, port=args.port or detect_serial_port())
    if args.status:
        print(json.dumps(inspect_flash_status(runner.read_flash), indent=2, sort_keys=True))
        return 0
    if not args.manifest_url:
        parser.error("--manifest-url is required unless --status is used")
    manifest = load_manifest(
        args.manifest_url,
        expected_release_version=args.release_version,
        expected_manifest_sha256=args.manifest_sha256,
        allow_test_url=args.allow_unverified_test_artifacts,
    )
    board = select_board(
        manifest,
        requested=args.board,
        interactive=not args.non_interactive,
    )
    require_release_readiness(
        manifest,
        board=board,
        allow_unverified_test_artifacts=args.allow_unverified_test_artifacts,
    )
    print(f"Verified explicit board selection: {board.upper()}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(_main())
    except FirmwareInstallError as exc:
        print(f"install error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
