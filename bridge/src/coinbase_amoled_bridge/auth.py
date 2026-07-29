"""Coinbase JWT signing and per-device bearer authentication."""

from __future__ import annotations

import base64
import copy
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from .config import ConfigStore
from .errors import ConfigError, CredentialError, ReadOnlyViolation
from .util import ensure_private_directory, iso_z, safe_text

KEY_NAME_ENV = "COINBASE_API_KEY_NAME"
PRIVATE_KEY_ENV = "COINBASE_API_PRIVATE_KEY"
KEY_NAME_FILE_ENV = "COINBASE_API_KEY_NAME_FILE"
PRIVATE_KEY_FILE_ENV = "COINBASE_API_PRIVATE_KEY_FILE"
MAX_KEY_NAME_BYTES = 2_048
MAX_PRIVATE_KEY_BYTES = 65_536
DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{11,63}$")
DEVICE_TOKEN_RE = re.compile(r"^cbat_[A-Za-z0-9_-]{43}$")
DUMMY_TOKEN_DIGEST = hashlib.sha256(b"bridge-auth-dummy-value").hexdigest()


@dataclass(frozen=True, slots=True)
class Credentials:
    key_name: str
    private_key_pem: bytes
    source: str

    @classmethod
    def load(
        cls,
        data_dir: str | os.PathLike[str],
        *,
        environ: Mapping[str, str] | None = None,
    ) -> Credentials:
        env = dict(os.environ if environ is None else environ)
        data_path = Path(data_dir).expanduser().resolve()
        local_key_name = data_path / "secrets" / "coinbase_api_key_name"
        local_private_key = data_path / "secrets" / "coinbase_api_private_key"
        docker_key_name = Path("/run/secrets/coinbase_api_key_name")
        docker_private_key = Path("/run/secrets/coinbase_api_private_key")

        direct_present = bool(env.get(KEY_NAME_ENV) or env.get(PRIVATE_KEY_ENV))
        file_present = bool(env.get(KEY_NAME_FILE_ENV) or env.get(PRIVATE_KEY_FILE_ENV))
        if direct_present:
            if not env.get(KEY_NAME_ENV) or not env.get(PRIVATE_KEY_ENV):
                raise CredentialError(
                    "both direct credential environment variables are required"
                )
            key_name_bytes = env[KEY_NAME_ENV].encode("utf-8")
            private_key_bytes = (
                env[PRIVATE_KEY_ENV].replace("\\n", "\n").encode("utf-8")
            )
            source = "environment"
        elif file_present:
            if not env.get(KEY_NAME_FILE_ENV) or not env.get(PRIVATE_KEY_FILE_ENV):
                raise CredentialError(
                    "both credential file environment variables are required"
                )
            key_name_bytes = _read_secret_file(
                Path(env[KEY_NAME_FILE_ENV]).expanduser(), MAX_KEY_NAME_BYTES
            )
            private_key_bytes = _read_secret_file(
                Path(env[PRIVATE_KEY_FILE_ENV]).expanduser(), MAX_PRIVATE_KEY_BYTES
            )
            source = "file_environment"
        elif docker_key_name.is_file() and docker_private_key.is_file():
            key_name_bytes = _read_secret_file(docker_key_name, MAX_KEY_NAME_BYTES)
            private_key_bytes = _read_secret_file(
                docker_private_key, MAX_PRIVATE_KEY_BYTES
            )
            source = "docker_secrets"
        elif local_key_name.is_file() and local_private_key.is_file():
            key_name_bytes = _read_secret_file(local_key_name, MAX_KEY_NAME_BYTES)
            private_key_bytes = _read_secret_file(
                local_private_key, MAX_PRIVATE_KEY_BYTES
            )
            source = "local_setup"
        else:
            raise CredentialError(
                "Coinbase credentials are missing; use environment, file secrets, "
                "or setup"
            )

        try:
            key_name = key_name_bytes.decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            raise CredentialError("API key name must be UTF-8") from exc
        if not key_name or len(key_name.encode("utf-8")) > MAX_KEY_NAME_BYTES:
            raise CredentialError("API key name is empty or too long")
        if any(ord(ch) < 0x20 or ch.isspace() for ch in key_name):
            raise CredentialError(
                "API key name contains whitespace or control characters"
            )

        private_key_bytes = private_key_bytes.strip() + b"\n"
        # Parse immediately so bad material fails before the server can bind.
        JWTSigner._load_private_key(private_key_bytes)
        return cls(key_name=key_name, private_key_pem=private_key_bytes, source=source)


def _read_secret_file(path: Path, maximum_bytes: int) -> bytes:
    try:
        if not path.is_file():
            raise CredentialError("credential secret path is not a regular file")
        size = path.stat().st_size
        if size <= 0 or size > maximum_bytes:
            raise CredentialError("credential secret file has an invalid size")
        payload = path.read_bytes()
    except CredentialError:
        raise
    except OSError as exc:
        raise CredentialError("unable to read credential secret file") from exc
    if b"\x00" in payload:
        raise CredentialError("credential secret file contains NUL bytes")
    return payload


def _b64url(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


class JWTSigner:
    """Minimal ES256 JWT implementation for Coinbase App REST requests."""

    def __init__(self, credentials: Credentials) -> None:
        self._key_name = credentials.key_name
        self._private_key = self._load_private_key(credentials.private_key_pem)

    @staticmethod
    def _load_private_key(payload: bytes) -> ec.EllipticCurvePrivateKey:
        try:
            key = serialization.load_pem_private_key(payload, password=None)
        except (TypeError, ValueError) as exc:
            raise CredentialError(
                "private key is not a valid unencrypted PEM key"
            ) from exc
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise CredentialError("Coinbase App requires an ECDSA private key")
        if not isinstance(key.curve, ec.SECP256R1):
            raise CredentialError("Coinbase App requires an ES256/P-256 private key")
        return key

    def sign(self, method: str, request_path: str, *, now: int | None = None) -> str:
        if method != "GET":
            raise ReadOnlyViolation("only GET Coinbase requests can be signed")
        if (
            not request_path.startswith("/api/v3/brokerage/")
            or "?" in request_path
            or "#" in request_path
            or len(request_path) > 512
        ):
            raise ReadOnlyViolation(
                "request path is outside the Advanced Trade allowlist"
            )
        try:
            request_path.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ReadOnlyViolation("request path must be ASCII") from exc

        issued_at = int(time.time() if now is None else now)
        header = {
            "alg": "ES256",
            "kid": self._key_name,
            "nonce": secrets.token_hex(16),
            "typ": "JWT",
        }
        payload = {
            "exp": issued_at + 120,
            "iss": "cdp",
            "nbf": issued_at,
            "sub": self._key_name,
            "uri": f"GET api.coinbase.com{request_path}",
        }
        encoded_header = _b64url(
            json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        encoded_payload = _b64url(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
        der_signature = self._private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r_value, s_value = decode_dss_signature(der_signature)
        jose_signature = r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big")
        return f"{encoded_header}.{encoded_payload}.{_b64url(jose_signature)}"


def generate_device_id() -> str:
    return "dev_" + secrets.token_urlsafe(18)


def validate_device_id(device_id: str) -> str:
    candidate = str(device_id).strip()
    if not DEVICE_ID_RE.fullmatch(candidate):
        raise ConfigError(
            "device ID must be an opaque 12-64 character value using letters, "
            "digits, _ or -"
        )
    return candidate


def generate_device_token() -> str:
    return "cbat_" + secrets.token_urlsafe(32)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("ascii", "strict")).hexdigest()


def write_secret_atomic(path: Path, payload: bytes, *, replace: bool = False) -> None:
    ensure_private_directory(path.parent)
    if path.exists() and not replace:
        raise CredentialError("secret destination already exists")
    fd, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=".secret-", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if path.exists() and not replace:
            raise CredentialError("secret destination already exists")
        os.replace(temporary, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


@dataclass(frozen=True, slots=True)
class DeviceProvision:
    device_id: str
    token_path: Path


class DeviceManager:
    """Manage the explicit device allowlist without returning raw tokens."""

    def __init__(self, store: ConfigStore) -> None:
        self.store = store

    def _default_token_path(self, device_id: str) -> Path:
        return self.store.data_dir / "secrets" / "devices" / f"{device_id}.token"

    def _validate_token_destination(self, destination: Path) -> None:
        protected = {
            self.store.path.resolve(strict=False),
            self.store.lock_path.resolve(strict=False),
            (self.store.data_dir / "secrets" / "coinbase_api_key_name").resolve(
                strict=False
            ),
            (self.store.data_dir / "secrets" / "coinbase_api_private_key").resolve(
                strict=False
            ),
        }
        if destination.resolve(strict=False) in protected:
            raise CredentialError(
                "device token destination collides with protected state"
            )
        if destination.exists() and not destination.is_file():
            raise CredentialError("device token destination is not a regular file")

    def add(
        self,
        *,
        device_id: str | None = None,
        label: str = "",
        token_path: str | os.PathLike[str] | None = None,
    ) -> DeviceProvision:
        candidate = validate_device_id(device_id or generate_device_id())
        try:
            clean_label = safe_text(label, max_length=80)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
        destination = (
            Path(token_path).expanduser().resolve()
            if token_path is not None
            else self._default_token_path(candidate)
        )
        self._validate_token_destination(destination)
        token = generate_device_token()
        digest = token_digest(token)
        if destination.exists():
            raise CredentialError("device token destination already exists")

        timestamp = iso_z()

        def mutate(config: dict[str, Any]) -> None:
            devices = config["devices"]
            if candidate in devices:
                raise ConfigError("device ID is already allowlisted")
            devices[candidate] = {
                "token_sha256": digest,
                "enabled": True,
                "created_at": timestamp,
                "updated_at": timestamp,
                "label": clean_label,
            }

        # The token is written first; on config failure it is removed. The raw
        # token is never returned or printed by this API.
        write_secret_atomic(destination, (token + "\n").encode("ascii"))
        try:
            self.store.update(mutate)
        except BaseException:
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        finally:
            token = ""  # Minimize lifetime; Python does not promise zeroization.
        return DeviceProvision(device_id=candidate, token_path=destination)

    def rotate(
        self,
        device_id: str,
        *,
        token_path: str | os.PathLike[str] | None = None,
        replace_token_file: bool = False,
    ) -> DeviceProvision:
        candidate = validate_device_id(device_id)
        destination = (
            Path(token_path).expanduser().resolve()
            if token_path is not None
            else self._default_token_path(candidate)
        )
        self._validate_token_destination(destination)
        default_destination = self._default_token_path(candidate)
        if (
            token_path is not None
            and destination.exists()
            and destination != default_destination
            and not replace_token_file
        ):
            raise CredentialError(
                "custom token destination exists; explicitly allow replacement"
            )
        config = self.store.load()
        old_record = copy.deepcopy(config["devices"].get(candidate))
        if old_record is None:
            raise ConfigError("device ID is not allowlisted")
        token = generate_device_token()
        digest = token_digest(token)
        timestamp = iso_z()
        if destination.is_file() and destination.stat().st_size > 512:
            raise CredentialError("existing device token file is unexpectedly large")
        backup_payload = destination.read_bytes() if destination.is_file() else None

        def mutate(updated: dict[str, Any]) -> None:
            record = updated["devices"].get(candidate)
            if record is None:
                raise ConfigError("device ID is not allowlisted")
            record["token_sha256"] = digest
            record["updated_at"] = timestamp

        self.store.update(mutate)
        try:
            write_secret_atomic(
                destination, (token + "\n").encode("ascii"), replace=True
            )
        except BaseException:
            # Restore the old digest and, if possible, the prior token file.
            def rollback(updated: dict[str, Any]) -> None:
                if candidate in updated["devices"]:
                    updated["devices"][candidate] = old_record

            self.store.update(rollback)
            if backup_payload is not None:
                write_secret_atomic(destination, backup_payload, replace=True)
            raise
        finally:
            token = ""
        return DeviceProvision(device_id=candidate, token_path=destination)

    def set_enabled(self, device_id: str, enabled: bool) -> None:
        candidate = validate_device_id(device_id)

        def mutate(config: dict[str, Any]) -> None:
            record = config["devices"].get(candidate)
            if record is None:
                raise ConfigError("device ID is not allowlisted")
            record["enabled"] = bool(enabled)
            record["updated_at"] = iso_z()

        self.store.update(mutate)

    def list_public(self) -> list[dict[str, Any]]:
        config = self.store.load()
        return [
            {
                "device_id": device_id,
                "enabled": record["enabled"],
                "created_at": record["created_at"],
                "updated_at": record["updated_at"],
                "label": record["label"],
            }
            for device_id, record in sorted(config["devices"].items())
        ]


class DeviceRegistry:
    """Hot-reloading, constant-time verifier for device requests."""

    def __init__(self, store: ConfigStore, *, reload_interval: float = 1.0) -> None:
        self.store = store
        self.reload_interval = max(0.0, reload_interval)
        self._lock = threading.RLock()
        self._next_check = 0.0
        self._mtime_ns = -1
        self._devices: dict[str, dict[str, Any]] = {}
        self._reload(force=True)

    def _reload(self, *, force: bool = False) -> None:
        now = time.monotonic()
        with self._lock:
            if not force and now < self._next_check:
                return
            self._next_check = now + self.reload_interval
            mtime_ns = self.store.mtime_ns()
            if not force and mtime_ns == self._mtime_ns:
                return
            config = self.store.load()
            self._devices = copy.deepcopy(config["devices"])
            self._mtime_ns = self.store.mtime_ns()

    def authenticate(self, device_id: str | None, token: str | None) -> bool:
        self._reload()
        candidate_id = device_id or ""
        candidate_token = token or ""
        valid_shape = bool(
            DEVICE_ID_RE.fullmatch(candidate_id)
            and DEVICE_TOKEN_RE.fullmatch(candidate_token)
        )
        with self._lock:
            record = self._devices.get(candidate_id)
            expected = (
                record.get("token_sha256", DUMMY_TOKEN_DIGEST)
                if record is not None
                else DUMMY_TOKEN_DIGEST
            )
            enabled = bool(record and record.get("enabled"))
        try:
            actual = token_digest(candidate_token)
        except (UnicodeEncodeError, ValueError):
            actual = DUMMY_TOKEN_DIGEST
        matches = hmac.compare_digest(actual, expected)
        return bool(valid_shape and enabled and matches)


def save_local_credentials(
    data_dir: str | os.PathLike[str],
    *,
    key_name: str,
    private_key_pem: bytes,
    replace: bool = False,
) -> tuple[Path, Path]:
    """Validate and store local setup credentials as private files."""

    key_name = key_name.strip()
    if (
        not key_name
        or len(key_name.encode("utf-8")) > MAX_KEY_NAME_BYTES
        or any(ord(ch) < 0x20 or ch.isspace() for ch in key_name)
    ):
        raise CredentialError("API key name is invalid")
    normalized_private_key = private_key_pem.strip() + b"\n"
    JWTSigner._load_private_key(normalized_private_key)
    secrets_dir = Path(data_dir).expanduser().resolve() / "secrets"
    key_name_path = secrets_dir / "coinbase_api_key_name"
    private_key_path = secrets_dir / "coinbase_api_private_key"
    old_key_name = (
        _read_secret_file(key_name_path, MAX_KEY_NAME_BYTES)
        if key_name_path.is_file()
        else None
    )
    write_secret_atomic(
        key_name_path, (key_name + "\n").encode("utf-8"), replace=replace
    )
    try:
        write_secret_atomic(private_key_path, normalized_private_key, replace=replace)
    except BaseException:
        try:
            if old_key_name is None:
                key_name_path.unlink(missing_ok=True)
            else:
                write_secret_atomic(key_name_path, old_key_name, replace=True)
        except (OSError, CredentialError) as rollback_error:
            raise CredentialError(
                "credential update failed and the prior key name could not be restored"
            ) from rollback_error
        raise
    return key_name_path, private_key_path


def prompt_key_name() -> str:
    """Read a key name without terminal echo; no credential is printed."""

    return getpass.getpass("Coinbase CDP API key name (hidden): ").strip()
