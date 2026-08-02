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
import struct
import tempfile
import threading
import time
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from .config import ConfigStore
from .errors import ConfigError, CredentialError, ReadOnlyViolation
from .util import ensure_private_directory, iso_z, safe_text

try:  # POSIX in production (Linux/macOS); guarded for import-time portability.
    import fcntl
except ImportError:  # pragma: no cover - Windows is not a supported deployment.
    fcntl = None  # type: ignore[assignment]

KEY_NAME_ENV = "COINBASE_API_KEY_NAME"
PRIVATE_KEY_ENV = "COINBASE_API_PRIVATE_KEY"
KEY_NAME_FILE_ENV = "COINBASE_API_KEY_NAME_FILE"
PRIVATE_KEY_FILE_ENV = "COINBASE_API_PRIVATE_KEY_FILE"
MAX_KEY_NAME_BYTES = 2_048
MAX_PRIVATE_KEY_BYTES = 65_536
MAX_CREDENTIAL_BUNDLE_BYTES = MAX_KEY_NAME_BYTES + MAX_PRIVATE_KEY_BYTES + 64
CREDENTIAL_BUNDLE_MAGIC = b"CBATCRD1"
CREDENTIAL_BUNDLE_FILE = "coinbase_credentials"
ACTIVE_CREDENTIAL_SLOT_FILE = "coinbase_credentials.active"
CREDENTIAL_SLOT_DIRECTORY = "credential-slots"
CREDENTIAL_SLOT_RE = re.compile(r"^onboarding_[A-Za-z0-9_-]{20,80}\.bundle$")
DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{11,63}$")
DEVICE_TOKEN_RE = re.compile(r"^cbat_[A-Za-z0-9_-]{43}$")
DUMMY_TOKEN_DIGEST = hashlib.sha256(b"bridge-auth-dummy-value").hexdigest()


@dataclass(frozen=True, slots=True)
class Credentials:
    key_name: str
    private_key_pem: bytes
    source: str

    @classmethod
    def from_values(
        cls, *, key_name: str, private_key_pem: bytes, source: str
    ) -> Credentials:
        clean_name = key_name.strip()
        if (
            not clean_name
            or len(clean_name.encode("utf-8")) > MAX_KEY_NAME_BYTES
            or any(ord(ch) < 0x20 or ch.isspace() for ch in clean_name)
        ):
            raise CredentialError("API key name is invalid")
        normalized_private_key = private_key_pem.strip() + b"\n"
        JWTSigner._load_private_key(normalized_private_key)
        return cls(
            key_name=clean_name,
            private_key_pem=normalized_private_key,
            source=source,
        )

    @classmethod
    def load_local(cls, data_dir: str | os.PathLike[str]) -> Credentials:
        data_path = Path(data_dir).expanduser().resolve()
        with local_credential_lock(data_path, exclusive=False):
            return _load_local_credentials_unlocked(data_path)

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
        local_bundle = data_path / "secrets" / CREDENTIAL_BUNDLE_FILE
        local_active = data_path / "secrets" / ACTIVE_CREDENTIAL_SLOT_FILE
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
        elif local_active.exists() or local_bundle.is_file():
            with local_credential_lock(data_path, exclusive=False):
                return _load_local_credentials_unlocked(data_path)
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
            key_name = key_name_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CredentialError("API key name must be UTF-8") from exc
        # Parse immediately so bad material fails before the server can bind.
        return cls.from_values(
            key_name=key_name,
            private_key_pem=private_key_bytes,
            source=source,
        )


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


def _encode_credential_bundle(credentials: Credentials) -> bytes:
    """Encode both credential values into one atomically replaceable file."""

    name = credentials.key_name.encode("utf-8")
    private_key = credentials.private_key_pem
    return (
        CREDENTIAL_BUNDLE_MAGIC
        + struct.pack(">II", len(name), len(private_key))
        + name
        + private_key
    )


def _read_credential_bundle(path: Path) -> Credentials:
    try:
        if (
            not path.is_file()
            or not 1 <= path.stat().st_size <= MAX_CREDENTIAL_BUNDLE_BYTES
        ):
            raise CredentialError("local credential bundle is invalid")
        payload = path.read_bytes()
    except CredentialError:
        raise
    except OSError as exc:
        raise CredentialError("local credential bundle is invalid") from exc
    header_size = len(CREDENTIAL_BUNDLE_MAGIC) + 8
    if len(payload) < header_size or not payload.startswith(CREDENTIAL_BUNDLE_MAGIC):
        raise CredentialError("local credential bundle is invalid")
    name_length, key_length = struct.unpack(
        ">II", payload[len(CREDENTIAL_BUNDLE_MAGIC) : header_size]
    )
    if (
        name_length < 1
        or name_length > MAX_KEY_NAME_BYTES
        or key_length < 1
        or key_length > MAX_PRIVATE_KEY_BYTES
        or header_size + name_length + key_length != len(payload)
    ):
        raise CredentialError("local credential bundle is invalid")
    try:
        key_name = payload[header_size : header_size + name_length].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CredentialError("local credential bundle is invalid") from exc
    private_key = payload[header_size + name_length :]
    return Credentials.from_values(
        key_name=key_name,
        private_key_pem=private_key,
        source="local_setup",
    )


def _fsync_directory(path: Path) -> None:
    try:
        directory_fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        # Some filesystems do not permit directory fsync. File fsync plus atomic
        # rename is still the strongest portable fallback available here.
        pass


@contextmanager
def local_credential_lock(
    data_dir: str | os.PathLike[str], *, exclusive: bool
) -> Iterator[None]:
    """Serialize local credential pointer and file mutations across processes."""

    data_path = Path(data_dir).expanduser().resolve()
    ensure_private_directory(data_path)
    descriptor = os.open(data_path / ".credentials.lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        if fcntl is not None:
            operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            fcntl.flock(descriptor, operation)
        yield
    finally:
        if fcntl is not None:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _active_credential_slot_unlocked(data_path: Path) -> str | None:
    pointer = data_path / "secrets" / ACTIVE_CREDENTIAL_SLOT_FILE
    if not pointer.exists():
        return None
    try:
        payload = _read_secret_file(pointer, 160)
        value = payload.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise CredentialError("local credential selector is invalid") from exc
    if not CREDENTIAL_SLOT_RE.fullmatch(value):
        raise CredentialError("local credential selector is invalid")
    slot = data_path / "secrets" / CREDENTIAL_SLOT_DIRECTORY / value
    if not slot.is_file():
        raise CredentialError("selected local credential bundle is missing")
    return value


def active_local_credential_slot(data_dir: str | os.PathLike[str]) -> str | None:
    data_path = Path(data_dir).expanduser().resolve()
    with local_credential_lock(data_path, exclusive=False):
        return _active_credential_slot_unlocked(data_path)


def _load_local_credentials_unlocked(data_path: Path) -> Credentials:
    active = _active_credential_slot_unlocked(data_path)
    if active is not None:
        return _read_credential_bundle(
            data_path / "secrets" / CREDENTIAL_SLOT_DIRECTORY / active
        )
    bundle_path = data_path / "secrets" / CREDENTIAL_BUNDLE_FILE
    if bundle_path.is_file():
        return _read_credential_bundle(bundle_path)
    key_name_bytes = _read_secret_file(
        data_path / "secrets" / "coinbase_api_key_name", MAX_KEY_NAME_BYTES
    )
    private_key_bytes = _read_secret_file(
        data_path / "secrets" / "coinbase_api_private_key",
        MAX_PRIVATE_KEY_BYTES,
    )
    try:
        key_name = key_name_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CredentialError("API key name must be UTF-8") from exc
    return Credentials.from_values(
        key_name=key_name,
        private_key_pem=private_key_bytes,
        source="local_setup",
    )


def stage_local_credential_slot(
    data_dir: str | os.PathLike[str],
    *,
    credentials: Credentials,
    slot_name: str,
) -> Path:
    """Write an inactive, owner-only credential version for onboarding."""

    if not CREDENTIAL_SLOT_RE.fullmatch(slot_name):
        raise CredentialError("local credential slot name is invalid")
    validated = Credentials.from_values(
        key_name=credentials.key_name,
        private_key_pem=credentials.private_key_pem,
        source="local_setup",
    )
    data_path = Path(data_dir).expanduser().resolve()
    destination = data_path / "secrets" / CREDENTIAL_SLOT_DIRECTORY / slot_name
    with local_credential_lock(data_path, exclusive=True):
        write_secret_atomic(destination, _encode_credential_bundle(validated))
    return destination


def load_local_credential_slot(
    data_dir: str | os.PathLike[str], slot_name: str
) -> Credentials:
    if not CREDENTIAL_SLOT_RE.fullmatch(slot_name):
        raise CredentialError("local credential slot name is invalid")
    data_path = Path(data_dir).expanduser().resolve()
    with local_credential_lock(data_path, exclusive=False):
        return _read_credential_bundle(
            data_path / "secrets" / CREDENTIAL_SLOT_DIRECTORY / slot_name
        )


def compare_and_swap_local_credential_slot(
    data_dir: str | os.PathLike[str],
    *,
    expected: str | None,
    replacement: str | None,
) -> bool:
    """Atomically change only the active local credential selector."""

    for value in (expected, replacement):
        if value is not None and not CREDENTIAL_SLOT_RE.fullmatch(value):
            raise CredentialError("local credential slot name is invalid")
    data_path = Path(data_dir).expanduser().resolve()
    pointer = data_path / "secrets" / ACTIVE_CREDENTIAL_SLOT_FILE
    with local_credential_lock(data_path, exclusive=True):
        current = _active_credential_slot_unlocked(data_path)
        if current != expected:
            return False
        if replacement is None:
            pointer.unlink(missing_ok=True)
            if pointer.parent.exists():
                _fsync_directory(pointer.parent)
        else:
            slot = data_path / "secrets" / CREDENTIAL_SLOT_DIRECTORY / replacement
            if not slot.is_file():
                raise CredentialError("replacement local credential bundle is missing")
            write_secret_atomic(
                pointer,
                (replacement + "\n").encode("ascii"),
                replace=pointer.exists(),
            )
        return True


def remove_local_credential_slot(
    data_dir: str | os.PathLike[str], slot_name: str
) -> None:
    """Remove an inactive staged slot without disturbing any active version."""

    if not CREDENTIAL_SLOT_RE.fullmatch(slot_name):
        raise CredentialError("local credential slot name is invalid")
    data_path = Path(data_dir).expanduser().resolve()
    slot = data_path / "secrets" / CREDENTIAL_SLOT_DIRECTORY / slot_name
    with local_credential_lock(data_path, exclusive=True):
        if _active_credential_slot_unlocked(data_path) == slot_name:
            raise CredentialError("cannot remove the active local credential bundle")
        slot.unlink(missing_ok=True)
        if slot.parent.exists():
            _fsync_directory(slot.parent)
        try:
            slot.parent.rmdir()
        except OSError:
            pass


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
    """Generate the lowercase UUIDv4 identity required by device firmware."""

    return str(uuid.uuid4())


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
        _fsync_directory(path.parent)
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
        token: str | None = None,
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
        issued_token = generate_device_token() if token is None else token
        if not DEVICE_TOKEN_RE.fullmatch(issued_token):
            raise CredentialError("device token is invalid")
        digest = token_digest(issued_token)
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
        write_secret_atomic(destination, (issued_token + "\n").encode("ascii"))
        try:
            self.store.update(mutate)
        except BaseException:
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        finally:
            issued_token = ""  # Python does not promise zeroization.
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

    validated = Credentials.from_values(
        key_name=key_name,
        private_key_pem=private_key_pem,
        source="local_setup",
    )
    key_name = validated.key_name
    normalized_private_key = validated.private_key_pem
    secrets_dir = Path(data_dir).expanduser().resolve() / "secrets"
    key_name_path = secrets_dir / "coinbase_api_key_name"
    private_key_path = secrets_dir / "coinbase_api_private_key"
    data_path = Path(data_dir).expanduser().resolve()
    with local_credential_lock(data_path, exclusive=True):
        old_key_name = (
            _read_secret_file(key_name_path, MAX_KEY_NAME_BYTES)
            if key_name_path.is_file()
            else None
        )
        write_secret_atomic(
            key_name_path, (key_name + "\n").encode("utf-8"), replace=replace
        )
        try:
            write_secret_atomic(
                private_key_path, normalized_private_key, replace=replace
            )
            active_pointer = secrets_dir / ACTIVE_CREDENTIAL_SLOT_FILE
            active_pointer.unlink(missing_ok=True)
            _fsync_directory(secrets_dir)
        except BaseException:
            try:
                if old_key_name is None:
                    key_name_path.unlink(missing_ok=True)
                else:
                    write_secret_atomic(key_name_path, old_key_name, replace=True)
            except (OSError, CredentialError) as rollback_error:
                raise CredentialError(
                    "credential update failed and the prior key name could not "
                    "be restored"
                ) from rollback_error
            raise
    return key_name_path, private_key_path


def save_local_credentials_atomic(
    data_dir: str | os.PathLike[str],
    *,
    credentials: Credentials,
    replace: bool = False,
) -> Path:
    """Store key name and PEM in one atomic, owner-only credential bundle.

    The web onboarding path uses this format so another process can never observe
    a new key name paired with an old PEM (or the reverse). Legacy two-file local
    credentials remain readable for existing installations.
    """

    validated = Credentials.from_values(
        key_name=credentials.key_name,
        private_key_pem=credentials.private_key_pem,
        source="local_setup",
    )
    destination = (
        Path(data_dir).expanduser().resolve() / "secrets" / CREDENTIAL_BUNDLE_FILE
    )
    data_path = Path(data_dir).expanduser().resolve()
    with local_credential_lock(data_path, exclusive=True):
        write_secret_atomic(
            destination,
            _encode_credential_bundle(validated),
            replace=replace,
        )
        active_pointer = destination.parent / ACTIVE_CREDENTIAL_SLOT_FILE
        active_pointer.unlink(missing_ok=True)
        _fsync_directory(destination.parent)
    return destination


def prompt_key_name() -> str:
    """Read a key name without terminal echo; no credential is printed."""

    return getpass.getpass("Coinbase CDP API key name (hidden): ").strip()
