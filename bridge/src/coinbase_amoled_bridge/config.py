"""Versioned, atomic configuration storage.

Raw Coinbase credentials and bearer tokens are deliberately forbidden in this
file. Credentials live in environment/file secrets; device bearer tokens are
stored only as SHA-256 digests.
"""

from __future__ import annotations

import copy
import json
import os
import re
import secrets
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .errors import ConfigError
from .symbols import DEFAULT_SYMBOLS, normalize_symbols
from .util import ensure_private_directory, iso_z, safe_text

try:  # POSIX in production (Linux/macOS); a guarded fallback helps test imports.
    import fcntl
except ImportError:  # pragma: no cover - Windows is not a supported deployment.
    fcntl = None  # type: ignore[assignment]


CURRENT_SCHEMA_VERSION = 1
MAX_CONFIG_BYTES = 1_048_576
DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{11,63}$")
INSTANCE_ID_RE = re.compile(r"^bridge_[A-Za-z0-9_-]{20,72}$")


DEFAULT_SETTINGS: dict[str, Any] = {
    "symbols": list(DEFAULT_SYMBOLS),
    "quote_currency": "USD",
    "refresh_seconds": 15,
    "stale_after_seconds": 90,
    "max_stale_seconds": 600,
    "upstream_timeout_seconds": 8,
    "include_cfm_positions": True,
    "include_intx_positions": True,
    "ip_rate_per_minute": 120,
    "device_rate_per_minute": 60,
    "rate_burst": 20,
    "max_concurrent_requests": 16,
}


FORBIDDEN_CONFIG_KEYS = {
    "api_key",
    "api_key_name",
    "api_secret",
    "bearer_token",
    "device_token",
    "key_name",
    "key_secret",
    "private_key",
    "raw_token",
    "secret",
    "token",
}


def default_config() -> dict[str, Any]:
    return {
        "schema_version": CURRENT_SCHEMA_VERSION,
        "instance_id": "bridge_" + secrets.token_urlsafe(18),
        "created_at": iso_z(),
        "settings": copy.deepcopy(DEFAULT_SETTINGS),
        "devices": {},
    }


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _bounded_int(
    settings: dict[str, Any], name: str, minimum: int, maximum: int
) -> None:
    value = settings.get(name)
    if not _is_int(value) or not minimum <= value <= maximum:
        raise ConfigError(
            f"settings.{name} must be an integer in [{minimum}, {maximum}]"
        )


def _reject_embedded_secrets(value: Any, *, path: str = "config") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if normalized in FORBIDDEN_CONFIG_KEYS:
                raise ConfigError(f"raw credential field is forbidden at {path}.{key}")
            _reject_embedded_secrets(child, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_embedded_secrets(child, path=f"{path}[{index}]")
    elif isinstance(value, str) and "PRIVATE KEY-----" in value.upper():
        raise ConfigError(f"private key material is forbidden at {path}")


def validate_config(config: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(config, dict):
        raise ConfigError("config root must be an object")
    _reject_embedded_secrets(config)

    allowed_root = {
        "schema_version",
        "instance_id",
        "created_at",
        "settings",
        "devices",
    }
    unknown_root = set(config) - allowed_root
    if unknown_root:
        raise ConfigError(f"unknown config fields: {', '.join(sorted(unknown_root))}")

    version = config.get("schema_version")
    if version != CURRENT_SCHEMA_VERSION:
        raise ConfigError(
            f"unsupported schema_version {version!r}; expected {CURRENT_SCHEMA_VERSION}"
        )

    instance_id = config.get("instance_id")
    if not isinstance(instance_id, str) or not INSTANCE_ID_RE.fullmatch(instance_id):
        raise ConfigError("instance_id is invalid")
    try:
        safe_text(instance_id, max_length=80, allow_empty=False)
        safe_text(config.get("created_at", ""), max_length=40, allow_empty=False)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc

    settings = config.get("settings")
    if not isinstance(settings, dict):
        raise ConfigError("settings must be an object")
    if set(settings) != set(DEFAULT_SETTINGS):
        missing = set(DEFAULT_SETTINGS) - set(settings)
        unknown = set(settings) - set(DEFAULT_SETTINGS)
        details: list[str] = []
        if missing:
            details.append("missing=" + ",".join(sorted(missing)))
        if unknown:
            details.append("unknown=" + ",".join(sorted(unknown)))
        raise ConfigError("invalid settings fields (" + "; ".join(details) + ")")

    quote = settings.get("quote_currency")
    if quote != "USD":
        raise ConfigError("settings.quote_currency currently supports only USD")
    symbols = settings.get("symbols")
    if not isinstance(symbols, list) or not all(
        isinstance(item, str) for item in symbols
    ):
        raise ConfigError("settings.symbols must be a list of strings")
    try:
        normalized = normalize_symbols(symbols, quote_currency=quote)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
    settings["symbols"] = [item.symbol for item in normalized]

    _bounded_int(settings, "refresh_seconds", 2, 300)
    _bounded_int(settings, "stale_after_seconds", 10, 3600)
    _bounded_int(settings, "max_stale_seconds", 30, 86_400)
    if settings["max_stale_seconds"] < settings["stale_after_seconds"]:
        raise ConfigError("max_stale_seconds must be >= stale_after_seconds")
    _bounded_int(settings, "upstream_timeout_seconds", 2, 30)
    _bounded_int(settings, "ip_rate_per_minute", 1, 10_000)
    _bounded_int(settings, "device_rate_per_minute", 1, 10_000)
    _bounded_int(settings, "rate_burst", 1, 1_000)
    _bounded_int(settings, "max_concurrent_requests", 1, 256)
    for name in ("include_cfm_positions", "include_intx_positions"):
        if not isinstance(settings.get(name), bool):
            raise ConfigError(f"settings.{name} must be a boolean")

    devices = config.get("devices")
    if not isinstance(devices, dict):
        raise ConfigError("devices must be an object")
    if len(devices) > 1_000:
        raise ConfigError("device allowlist exceeds 1000 entries")
    for device_id, record in devices.items():
        if not isinstance(device_id, str) or not DEVICE_ID_RE.fullmatch(device_id):
            raise ConfigError("device IDs must be 12-64 ASCII letters/digits/_/-")
        if not isinstance(record, dict):
            raise ConfigError(f"device {device_id!r} must be an object")
        allowed_record = {
            "token_sha256",
            "enabled",
            "created_at",
            "updated_at",
            "label",
        }
        if set(record) != allowed_record:
            raise ConfigError(f"device {device_id!r} has invalid fields")
        digest = record.get("token_sha256")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(ch not in "0123456789abcdef" for ch in digest)
        ):
            raise ConfigError(f"device {device_id!r} has invalid token digest")
        if not isinstance(record.get("enabled"), bool):
            raise ConfigError(f"device {device_id!r} enabled must be boolean")
        try:
            safe_text(record.get("created_at", ""), max_length=40, allow_empty=False)
            safe_text(record.get("updated_at", ""), max_length=40, allow_empty=False)
            safe_text(record.get("label", ""), max_length=80)
        except ValueError as exc:
            raise ConfigError(f"device {device_id!r}: {exc}") from exc
    return config


class ConfigStore:
    """Atomic config reader/writer with schema migration and process locking."""

    def __init__(self, data_dir: str | os.PathLike[str]) -> None:
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.path = self.data_dir / "config.json"
        self.lock_path = self.data_dir / ".config.lock"

    @contextmanager
    def _lock(self, *, exclusive: bool) -> Iterator[None]:
        ensure_private_directory(self.data_dir)
        fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            if fcntl is not None:
                operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
                fcntl.flock(fd, operation)
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def exists(self) -> bool:
        return self.path.is_file()

    def initialize(self) -> dict[str, Any]:
        with self._lock(exclusive=True):
            if self.path.exists():
                return copy.deepcopy(self._load_and_migrate_unlocked())
            config = validate_config(default_config())
            self._write_unlocked(config)
            return copy.deepcopy(config)

    def load(self) -> dict[str, Any]:
        # Migration requires an exclusive lock; config reads are infrequent and
        # this keeps the transition atomic across processes.
        with self._lock(exclusive=True):
            return copy.deepcopy(self._load_and_migrate_unlocked())

    def update(self, mutator: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        with self._lock(exclusive=True):
            config = self._load_and_migrate_unlocked()
            candidate = copy.deepcopy(config)
            mutator(candidate)
            validate_config(candidate)
            self._write_unlocked(candidate)
            return copy.deepcopy(candidate)

    def replace(self, config: dict[str, Any]) -> dict[str, Any]:
        with self._lock(exclusive=True):
            candidate = validate_config(copy.deepcopy(config))
            self._write_unlocked(candidate)
            return copy.deepcopy(candidate)

    def mtime_ns(self) -> int:
        try:
            return self.path.stat().st_mtime_ns
        except FileNotFoundError:
            return 0

    def _read_unlocked(self) -> tuple[dict[str, Any], bytes]:
        if not self.path.exists():
            raise ConfigError(
                "configuration not initialized; run setup with data directory "
                f"{self.data_dir}"
            )
        try:
            raw_bytes = self.path.read_bytes()
        except OSError as exc:
            raise ConfigError("unable to read configuration") from exc
        if len(raw_bytes) > MAX_CONFIG_BYTES:
            raise ConfigError("configuration file is too large")
        try:
            parsed = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ConfigError("configuration is not valid UTF-8 JSON") from exc
        if not isinstance(parsed, dict):
            raise ConfigError("config root must be an object")
        return parsed, raw_bytes

    def _load_and_migrate_unlocked(self) -> dict[str, Any]:
        parsed, original_bytes = self._read_unlocked()
        version = parsed.get("schema_version", 0)
        if not _is_int(version) or version < 0:
            raise ConfigError("schema_version is invalid")
        if version > CURRENT_SCHEMA_VERSION:
            raise ConfigError(
                f"config schema {version} is newer than this bridge supports"
            )
        if version == CURRENT_SCHEMA_VERSION:
            return validate_config(parsed)

        # Never duplicate raw secrets into a migration backup.
        _reject_embedded_secrets(parsed)
        migrated = self._migrate(copy.deepcopy(parsed), version)
        validate_config(migrated)
        self._write_backup_unlocked(original_bytes, version)
        self._write_unlocked(migrated)
        return migrated

    def _migrate(self, config: dict[str, Any], version: int) -> dict[str, Any]:
        while version < CURRENT_SCHEMA_VERSION:
            if version == 0:
                config["schema_version"] = 1
                config.setdefault("instance_id", "bridge_" + secrets.token_urlsafe(18))
                config.setdefault("created_at", iso_z())
                incoming_settings = config.get("settings", {})
                if not isinstance(incoming_settings, dict):
                    raise ConfigError("legacy settings must be an object")
                merged_settings = copy.deepcopy(DEFAULT_SETTINGS)
                merged_settings.update(incoming_settings)
                config["settings"] = merged_settings
                config.setdefault("devices", {})
                version = 1
                continue
            raise ConfigError(f"no migration path from schema {version}")
        return config

    def _write_backup_unlocked(self, payload: bytes, source_version: int) -> None:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        base = self.data_dir / f"config.json.bak-v{source_version}-{stamp}"
        path = base
        counter = 1
        while path.exists():
            path = Path(str(base) + f"-{counter}")
            counter += 1
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)

    def _write_unlocked(self, config: dict[str, Any]) -> None:
        ensure_private_directory(self.data_dir)
        payload = (
            json.dumps(config, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
        ).encode("utf-8")
        if len(payload) > MAX_CONFIG_BYTES:
            raise ConfigError("configuration file is too large")
        fd, temporary_name = tempfile.mkstemp(
            dir=self.data_dir, prefix=".config-", suffix=".tmp"
        )
        temporary_path = Path(temporary_name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=True) as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, self.path)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
            try:
                directory_fd = os.open(self.data_dir, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                pass
        except BaseException:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise
