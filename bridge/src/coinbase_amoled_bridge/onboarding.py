# ruff: noqa: E501
"""Two-phase onboarding for the USB-provisioned display.

The credential endpoint binds only to loopback.  It performs bounded local parsing
and durably stages an inactive credential bundle, but deliberately does not contact
Coinbase or enable a device.  A second, token-authenticated LAN endpoint is used by
the ESP after it joins home Wi-Fi.  Only that claim can trigger the read-only
permission check and atomic activation.  Request bodies and authorization values
are never logged.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import http.client
import io
import json
import os
import re
import secrets
import socket
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from .auth import (
    CREDENTIAL_SLOT_RE,
    DEVICE_ID_RE,
    DEVICE_TOKEN_RE,
    Credentials,
    DeviceManager,
    JWTSigner,
    active_local_credential_slot,
    compare_and_swap_local_credential_slot,
    generate_device_id,
    generate_device_token,
    load_local_credential_slot,
    remove_local_credential_slot,
    stage_local_credential_slot,
    token_digest,
    write_secret_atomic,
)
from .coinbase import CoinbaseClient
from .config import ConfigStore
from .errors import (
    CoinbaseAPIError,
    CredentialError,
    ProvisioningError,
    SetupSessionError,
)
from .quickstart import MAX_CDP_JSON_BYTES, parse_cdp_key_json
from .ratelimit import ClientHasher, TokenBucketLimiter
from .user_service import (
    ServiceStartResult,
    restore_user_service,
    rollback_user_service,
    start_user_service,
)
from .util import ensure_private_directory, iso_z

try:  # POSIX in production (Linux/macOS).
    import fcntl
except ImportError:  # pragma: no cover - Windows is unsupported.
    fcntl = None  # type: ignore[assignment]

LOOPBACK_HOST = "127.0.0.1"
PORTAL_ORIGIN = "http://192.168.4.1"
ONBOARDING_PATH = "/v1/onboarding"
PENDING_CLAIM_PATH = "/v1/onboarding/claim"
PENDING_STATUS_PATH = "/v1/onboarding/status"
# Reserved legacy targets. They intentionally have no handlers: browser ACKs
# must never activate a transaction now that the ESP owns the claim.
PROVISIONING_PATH = "/v1/onboarding/provisioning"
FINISH_PATH = "/v1/onboarding/finish"
MAX_HEADER_BYTES = 16_384
MAX_REQUEST_TARGET = 512
MAX_REQUEST_LINE = 768
MAX_HEADER_COUNT = 64
MAX_CONCURRENT_CONNECTIONS = 4
ONBOARDING_JOURNAL_VERSION = 2
MAX_JOURNAL_BYTES = 16_384
DEFAULT_PENDING_TTL_SECONDS = 1_800
MAX_PENDING_TTL_SECONDS = 3_600
PENDING_RETRY_MAX_SECONDS = 15.0
PENDING_REJECTION_GRACE_SECONDS = 15.0
TRANSACTION_ID_RE = re.compile(r"^txn_[A-Za-z0-9_-]{20,72}$")
GENERIC_ERROR = {"ok": False, "error": "Setup could not be completed."}
RETRYABLE_PERMISSION_CODES = frozenset(
    {"upstream_unreachable", "upstream_rate_limited", "upstream_server_error"}
)


@dataclass(frozen=True, slots=True)
class SafeProvisioning:
    """The only values the endpoint may return to portal JavaScript."""

    bridge_url: str
    device_id: str
    feed_token: str
    expires_at: int

    def public_json(self) -> dict[str, Any]:
        return {
            "ok": True,
            "bridge_url": self.bridge_url,
            "device_id": self.device_id,
            # The same high-entropy value is scoped to claim/status until the
            # read-only check succeeds; only then does it become a feed token.
            "pending_token": self.feed_token,
            "expires_at": self.expires_at,
            "status": "waiting_for_network",
            "claim_path": PENDING_CLAIM_PATH,
            "status_path": PENDING_STATUS_PATH,
        }


@dataclass(slots=True)
class SetupSession:
    """Short-lived, in-memory setup authorization state."""

    session_id: str
    setup_token: str = field(repr=False)
    csrf_token: str = field(repr=False)
    created_at: int
    expires_at: int
    monotonic_deadline: float
    portal_origin: str = PORTAL_ORIGIN
    endpoint_origin: str = ""
    endpoint_url: str = ""
    local_page_url: str = ""
    _in_flight: bool = field(default=False, init=False, repr=False)
    _used: bool = field(default=False, init=False, repr=False)
    _finished: bool = field(default=False, init=False, repr=False)
    _provisioning: SafeProvisioning | None = field(default=None, init=False, repr=False)
    _lock: threading.Lock = field(
        default_factory=threading.Lock, init=False, repr=False
    )
    provisioned_event: threading.Event = field(
        default_factory=threading.Event, init=False, repr=False
    )
    finished_event: threading.Event = field(
        default_factory=threading.Event, init=False, repr=False
    )
    failed_event: threading.Event = field(
        default_factory=threading.Event, init=False, repr=False
    )
    terminal_event: threading.Event = field(
        default_factory=threading.Event, init=False, repr=False
    )

    @classmethod
    def create(cls, *, ttl_seconds: int = 900) -> SetupSession:
        if not 60 <= ttl_seconds <= 1_800:
            raise ValueError("setup session lifetime must be 60-1800 seconds")
        now = int(time.time())
        return cls(
            session_id=secrets.token_urlsafe(18),
            setup_token=secrets.token_urlsafe(32),
            csrf_token=secrets.token_urlsafe(32),
            created_at=now,
            expires_at=now + ttl_seconds,
            monotonic_deadline=time.monotonic() + ttl_seconds,
        )

    def bind_endpoint(self, port: int) -> None:
        if not 1 <= port <= 65_535:
            raise ValueError("invalid onboarding port")
        self.endpoint_origin = f"http://{LOOPBACK_HOST}:{port}"
        self.endpoint_url = self.endpoint_origin + ONBOARDING_PATH
        self.local_page_url = self.endpoint_origin + f"/setup/{self.session_id}"

    def expired(self) -> bool:
        return time.monotonic() >= self.monotonic_deadline

    def authorize_setup(
        self, *, session_id: str, setup_token: str, csrf_token: str
    ) -> bool:
        with self._lock:
            return bool(
                not self._used
                and not self._finished
                and not self.expired()
                and self.setup_token
                and hmac.compare_digest(session_id, self.session_id)
                and hmac.compare_digest(setup_token, self.setup_token)
                and hmac.compare_digest(csrf_token, self.csrf_token)
            )

    def begin_once(self) -> None:
        with self._lock:
            if self.expired() or self._used or self._in_flight:
                raise SetupSessionError("setup session is unavailable")
            self._in_flight = True

    def fail_attempt(self) -> None:
        with self._lock:
            self._in_flight = False

    def use_once(self) -> None:
        with self._lock:
            if not self._in_flight or self._used or self.expired():
                self._in_flight = False
                raise SetupSessionError("setup session is unavailable")
            self._in_flight = False
            self._used = True
            self.setup_token = ""
            self.provisioned_event.set()

    def mark_finished(self) -> None:
        """Record completion after the ESP, never the browser, claims setup."""

        with self._lock:
            if (
                not self._used
                or self._finished
                or self._provisioning is None
            ):
                raise SetupSessionError("setup session is unavailable")
            self._finished = True
            self._provisioning = None
            self.finished_event.set()
            self.terminal_event.set()

    def set_provisioning(self, provisioning: SafeProvisioning) -> None:
        with self._lock:
            if self.expired() or self._used or not self._in_flight:
                raise SetupSessionError("setup session is unavailable")
            self._provisioning = provisioning

    def safe_provisioning(self) -> SafeProvisioning | None:
        with self._lock:
            if self.expired() or not self._used or self._finished:
                return None
            return self._provisioning

    def page_token(self) -> str | None:
        with self._lock:
            if self.expired() or self._used or self._finished:
                return None
            if not self.setup_token:
                return None
            return self.setup_token

    def abort(self) -> None:
        with self._lock:
            self.setup_token = ""
            self._provisioning = None
            self.failed_event.set()
            self.terminal_event.set()

    @property
    def used(self) -> bool:
        with self._lock:
            return self._used


PermissionChecker = Callable[[Credentials], None]
ServiceStarter = Callable[..., ServiceStartResult]
ReadinessChecker = Callable[[], bool]


JournalPhase = Literal[
    "staged",
    "claimed",
    "checking",
    "applying",
    "credentials_active",
    "device_added",
    "service_starting",
    "service_started",
    "complete",
]


@dataclass(slots=True)
class _OnboardingJournal:
    transaction_id: str
    phase: JournalPhase
    created_at: str
    expires_at: int
    bridge_url: str
    device_id: str
    feed_token_sha256: str
    credential_slot: str
    permission_verified: bool
    credential_switch_started: bool = False
    previous_credential_slot: str | None = None
    service: ServiceStartResult | None = None

    def public_dict(self) -> dict[str, Any]:
        service = self.service
        return {
            "version": ONBOARDING_JOURNAL_VERSION,
            "transaction_id": self.transaction_id,
            "phase": self.phase,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "bridge_url": self.bridge_url,
            "device_id": self.device_id,
            "feed_token_sha256": self.feed_token_sha256,
            "credential_slot": self.credential_slot,
            "permission_verified": self.permission_verified,
            "credential_switch_started": self.credential_switch_started,
            "previous_credential_slot": self.previous_credential_slot,
            "service": (
                None
                if service is None
                else {
                    "status": service.status,
                    "manager": service.manager,
                    "was_active": service.was_active,
                    "loaded_by_quickstart": service.loaded_by_quickstart,
                    "was_enabled": service.was_enabled,
                }
            ),
        }

    @classmethod
    def parse(cls, value: Any) -> _OnboardingJournal:
        if not isinstance(value, dict):
            raise ProvisioningError("onboarding recovery journal is invalid")
        required = {
            "version",
            "transaction_id",
            "phase",
            "created_at",
            "expires_at",
            "bridge_url",
            "device_id",
            "feed_token_sha256",
            "credential_slot",
            "permission_verified",
            "credential_switch_started",
            "previous_credential_slot",
            "service",
        }
        if set(value) != required or value.get("version") != ONBOARDING_JOURNAL_VERSION:
            raise ProvisioningError("onboarding recovery journal is invalid")
        transaction_id = value.get("transaction_id")
        phase = value.get("phase")
        created_at = value.get("created_at")
        expires_at = value.get("expires_at")
        bridge_url = value.get("bridge_url")
        device_id = value.get("device_id")
        digest = value.get("feed_token_sha256")
        credential_slot = value.get("credential_slot")
        permission_verified = value.get("permission_verified")
        switch_started = value.get("credential_switch_started")
        previous = value.get("previous_credential_slot")
        phases = {
            "staged",
            "claimed",
            "checking",
            "applying",
            "credentials_active",
            "device_added",
            "service_starting",
            "service_started",
            "complete",
        }
        expected_slot = (
            f"onboarding_{transaction_id}.bundle"
            if isinstance(transaction_id, str)
            else ""
        )
        if (
            not isinstance(transaction_id, str)
            or not TRANSACTION_ID_RE.fullmatch(transaction_id)
            or phase not in phases
            or not isinstance(created_at, str)
            or not 1 <= len(created_at) <= 40
            or not isinstance(expires_at, int)
            or isinstance(expires_at, bool)
            or expires_at <= 0
            or not isinstance(bridge_url, str)
            or not isinstance(device_id, str)
            or not DEVICE_ID_RE.fullmatch(device_id)
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or credential_slot != expected_slot
            or not isinstance(permission_verified, bool)
            or not isinstance(switch_started, bool)
            or (
                previous is not None
                and (
                    not isinstance(previous, str)
                    or not CREDENTIAL_SLOT_RE.fullmatch(previous)
                )
            )
        ):
            raise ProvisioningError("onboarding recovery journal is invalid")
        try:
            parsed_bridge = urlsplit(bridge_url)
            _bridge_port = parsed_bridge.port
        except ValueError as exc:
            raise ProvisioningError("onboarding recovery journal is invalid") from exc
        if (
            parsed_bridge.scheme not in {"http", "https"}
            or not parsed_bridge.hostname
            or parsed_bridge.username
            or parsed_bridge.password
            or parsed_bridge.query
            or parsed_bridge.fragment
            or parsed_bridge.path != "/v1/device-feed"
        ):
            raise ProvisioningError("onboarding recovery journal is invalid")
        service_value = value.get("service")
        service: ServiceStartResult | None = None
        if service_value is not None:
            if not isinstance(service_value, dict) or set(service_value) != {
                "status",
                "manager",
                "was_active",
                "loaded_by_quickstart",
                "was_enabled",
            }:
                raise ProvisioningError("onboarding recovery journal is invalid")
            status = service_value.get("status")
            manager = service_value.get("manager")
            was_active = service_value.get("was_active")
            loaded = service_value.get("loaded_by_quickstart")
            was_enabled = service_value.get("was_enabled")
            if (
                status not in {"started", "unavailable", "failed"}
                or manager not in {"launchd", "systemd", "none"}
                or not isinstance(was_active, bool)
                or not isinstance(loaded, bool)
                or not isinstance(was_enabled, bool)
            ):
                raise ProvisioningError("onboarding recovery journal is invalid")
            service = ServiceStartResult(
                status,
                manager,
                was_active=was_active,
                loaded_by_quickstart=loaded,
                was_enabled=was_enabled,
            )
        return cls(
            transaction_id=transaction_id,
            phase=phase,
            created_at=created_at,
            expires_at=expires_at,
            bridge_url=bridge_url,
            device_id=device_id,
            feed_token_sha256=digest,
            credential_slot=credential_slot,
            permission_verified=permission_verified,
            credential_switch_started=switch_started,
            previous_credential_slot=previous,
            service=service,
        )


def _check_permissions(credentials: Credentials) -> None:
    CoinbaseClient(JWTSigner(credentials), timeout=8.0).assert_view_only()


def _bridge_ready() -> bool:
    request = urllib.request.Request(  # noqa: S310 - fixed loopback URL
        "http://127.0.0.1:8788/readyz",
        headers={"Accept": "application/json", "Cache-Control": "no-store"},
        method="GET",
    )
    deadline = time.monotonic() + 12.0
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(request, timeout=1.0) as response:  # noqa: S310
                if response.status == HTTPStatus.OK:
                    return True
        except (urllib.error.URLError, TimeoutError, OSError):
            time.sleep(0.25)
    return False


class OnboardingCoordinator:
    """Crash-recoverable, scoped onboarding transaction coordinator."""

    def __init__(
        self,
        data_dir: str | os.PathLike[str],
        *,
        bridge_url: str,
        permission_checker: PermissionChecker = _check_permissions,
        service_starter: ServiceStarter = start_user_service,
        readiness_checker: ReadinessChecker = _bridge_ready,
        finish_timeout_seconds: float = 180.0,
        retry_interval: float = 1.0,
        pending_ttl_seconds: int = DEFAULT_PENDING_TTL_SECONDS,
    ) -> None:
        try:
            parsed = urlsplit(bridge_url)
            _bridge_port = parsed.port
        except ValueError as exc:
            raise ValueError("bridge URL is invalid") from exc
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path != "/v1/device-feed"
        ):
            raise ValueError("bridge URL is invalid")
        if finish_timeout_seconds < 0 or retry_interval < 0:
            raise ValueError("finalization timing must be non-negative")
        if not 60 <= pending_ttl_seconds <= MAX_PENDING_TTL_SECONDS:
            raise ValueError("pending setup lifetime must be 60-3600 seconds")
        self.store = ConfigStore(data_dir)
        self.bridge_url = bridge_url
        self.permission_checker = permission_checker
        self.service_starter = service_starter
        self.readiness_checker = readiness_checker
        self.finish_timeout_seconds = finish_timeout_seconds
        self.retry_interval = retry_interval
        self.pending_ttl_seconds = pending_ttl_seconds
        self._transaction_lock = threading.RLock()
        self._journal_dir = self.store.data_dir / ".onboarding"
        self._journal_path = self._journal_dir / "journal.json"
        self._owner_descriptor: int | None = None
        self._acquire_owner_lock()
        try:
            with self._transaction_lock:
                self._recover_locked()
        except BaseException:
            self.close()
            raise

    @property
    def journal_path(self) -> Path:
        return self._journal_path

    def _acquire_owner_lock(self) -> None:
        if fcntl is None:
            raise ProvisioningError("onboarding requires POSIX process locking")
        ensure_private_directory(self.store.data_dir)
        descriptor = os.open(
            self.store.data_dir / ".onboarding.lock",
            os.O_CREAT | os.O_RDWR,
            0o600,
        )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(descriptor)
            raise ProvisioningError(
                "another local onboarding transaction is active"
            ) from exc
        self._owner_descriptor = descriptor

    def close(self) -> None:
        descriptor = self._owner_descriptor
        self._owner_descriptor = None
        if descriptor is None:
            return
        if fcntl is not None:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(descriptor)

    def __enter__(self) -> OnboardingCoordinator:
        self._require_open()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        del exc_type, exc, traceback
        self.close()

    def __del__(self) -> None:  # pragma: no cover - deterministic callers use close.
        try:
            self.close()
        except Exception:
            pass

    def _require_open(self) -> None:
        if self._owner_descriptor is None:
            raise ProvisioningError("onboarding coordinator is closed")

    def _token_stage_path(self, transaction_id: str) -> Path:
        if not TRANSACTION_ID_RE.fullmatch(transaction_id):
            raise ProvisioningError("onboarding transaction identifier is invalid")
        return self._journal_dir / f"{transaction_id}.device-token"

    def _write_journal(self, journal: _OnboardingJournal) -> None:
        payload = (
            json.dumps(
                journal.public_dict(),
                separators=(",", ":"),
                sort_keys=True,
                ensure_ascii=True,
            )
            + "\n"
        ).encode("ascii")
        if len(payload) > MAX_JOURNAL_BYTES:
            raise ProvisioningError("onboarding recovery journal is too large")
        write_secret_atomic(
            self._journal_path,
            payload,
            replace=self._journal_path.exists(),
        )

    def _read_journal(self) -> _OnboardingJournal | None:
        if not self._journal_path.exists():
            return None
        try:
            if (
                not self._journal_path.is_file()
                or not 1 <= self._journal_path.stat().st_size <= MAX_JOURNAL_BYTES
            ):
                raise ProvisioningError("onboarding recovery journal is invalid")
            raw = self._journal_path.read_bytes()
            value = json.loads(raw.decode("ascii"))
        except ProvisioningError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProvisioningError("onboarding recovery journal is invalid") from exc
        return _OnboardingJournal.parse(value)

    def _unlink_journal(self) -> None:
        self._journal_path.unlink(missing_ok=True)
        try:
            descriptor = os.open(self._journal_dir, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError:
            pass

    def _read_staged_token(self, journal: _OnboardingJournal) -> str:
        path = self._token_stage_path(journal.transaction_id)
        try:
            if not path.is_file() or not 1 <= path.stat().st_size <= 128:
                raise ProvisioningError("staged device authorization is unavailable")
            token = path.read_text(encoding="ascii").strip()
        except (OSError, UnicodeDecodeError) as exc:
            raise ProvisioningError(
                "staged device authorization is unavailable"
            ) from exc
        if not DEVICE_TOKEN_RE.fullmatch(token) or not hmac.compare_digest(
            token_digest(token), journal.feed_token_sha256
        ):
            raise ProvisioningError("staged device authorization is invalid")
        return token

    def _recover_locked(self) -> None:
        journal = self._read_journal()
        if journal is not None:
            if journal.phase == "complete":
                self._cleanup_complete_locked(journal)
            elif journal.expires_at <= int(time.time()):
                self._rollback_journal_locked(journal)
            elif journal.phase in {"staged", "claimed", "checking"}:
                # Staging and claim are intentionally restart-safe.  A process
                # interruption while checking has not activated anything, so it
                # safely resumes from the claimed state.
                if journal.phase == "checking":
                    journal.phase = "claimed"
                    self._write_journal(journal)
            else:
                # Activation phases can include external service-manager side
                # effects. Roll those back deterministically rather than guess.
                self._rollback_journal_locked(journal)
        self._cleanup_orphans_locked(self._read_journal())

    def _cleanup_orphans_locked(self, current: _OnboardingJournal | None = None) -> None:
        active = active_local_credential_slot(self.store.data_dir)
        if self._journal_dir.is_dir():
            for path in self._journal_dir.glob("txn_*.device-token"):
                if current is None or path != self._token_stage_path(
                    current.transaction_id
                ):
                    path.unlink(missing_ok=True)
            try:
                self._journal_dir.rmdir()
            except OSError:
                pass
        slots = self.store.data_dir / "secrets" / "credential-slots"
        if slots.is_dir():
            for path in slots.glob("onboarding_txn_*.bundle"):
                if path.name != active and (
                    current is None or path.name != current.credential_slot
                ):
                    remove_local_credential_slot(self.store.data_dir, path.name)

    def complete(self, credentials: Credentials) -> SafeProvisioning:
        """Locally validate and durably stage secrets without network access.

        ``parse_cdp_key_json`` and ``stage_local_credential_slot`` have already
        parsed the P-256 key.  Calling Coinbase here would break Wi-Fi-only hosts
        attached to the captive AP, so the permission gate is exclusively in the
        ESP claim path.
        """

        expires_at = int(time.time()) + self.pending_ttl_seconds
        provisioning = SafeProvisioning(
            bridge_url=self.bridge_url,
            device_id=generate_device_id(),
            feed_token=generate_device_token(),
            expires_at=expires_at,
        )
        transaction_id = "txn_" + secrets.token_urlsafe(18)
        credential_slot = f"onboarding_{transaction_id}.bundle"
        journal = _OnboardingJournal(
            transaction_id=transaction_id,
            phase="staged",
            created_at=iso_z(),
            expires_at=expires_at,
            bridge_url=self.bridge_url,
            device_id=provisioning.device_id,
            feed_token_sha256=token_digest(provisioning.feed_token),
            credential_slot=credential_slot,
            permission_verified=False,
        )

        with self._transaction_lock:
            self._require_open()
            if self._read_journal() is not None:
                raise ProvisioningError("a setup transaction is already pending")
            token_path = self._token_stage_path(transaction_id)
            try:
                stage_local_credential_slot(
                    self.store.data_dir,
                    credentials=credentials,
                    slot_name=credential_slot,
                )
                write_secret_atomic(
                    token_path, (provisioning.feed_token + "\n").encode("ascii")
                )
                self._write_journal(journal)
            except BaseException as exc:
                cleanup_errors: list[BaseException] = []
                try:
                    token_path.unlink(missing_ok=True)
                except OSError as cleanup_error:
                    cleanup_errors.append(cleanup_error)
                try:
                    remove_local_credential_slot(self.store.data_dir, credential_slot)
                except (OSError, CredentialError) as cleanup_error:
                    cleanup_errors.append(cleanup_error)
                if cleanup_errors:
                    raise ProvisioningError(
                        "local setup staging failed and could not be rolled back"
                    ) from cleanup_errors[0]
                raise exc
        return provisioning

    def pending_provisioning(self) -> SafeProvisioning | None:
        """Return safe restart-recovery data for a still-inactive transaction."""

        with self._transaction_lock:
            self._require_open()
            journal = self._read_journal()
            if journal is None or journal.phase not in {"staged", "claimed", "checking"}:
                return None
            if journal.expires_at <= int(time.time()):
                self._rollback_journal_locked(journal)
                return None
            return SafeProvisioning(
                bridge_url=journal.bridge_url,
                device_id=journal.device_id,
                feed_token=self._read_staged_token(journal),
                expires_at=journal.expires_at,
            )

    def claim_pending(self, *, device_id: str, token: str) -> str:
        """Authenticate the ESP and durably arm the permission gate."""

        with self._transaction_lock:
            self._require_open()
            journal = self._read_journal()
            if journal is None or journal.phase not in {"staged", "claimed", "checking"}:
                raise SetupSessionError("pending setup is unavailable")
            if journal.expires_at <= int(time.time()):
                self._rollback_journal_locked(journal)
                raise SetupSessionError("pending setup is unavailable")
            try:
                candidate_digest = token_digest(token)
            except (AttributeError, UnicodeEncodeError):
                candidate_digest = ""
            if not hmac.compare_digest(device_id, journal.device_id) or not hmac.compare_digest(
                candidate_digest, journal.feed_token_sha256
            ):
                raise SetupSessionError("pending setup is unavailable")
            if journal.phase == "staged":
                journal.phase = "claimed"
                self._write_journal(journal)
            return "checking_read_only_key"

    def finish_pending(
        self,
        provisioning: SafeProvisioning,
        *,
        status_callback: Callable[[str], None] | None = None,
        before_service_start: Callable[[], None] | None = None,
    ) -> None:
        """Validate and activate an ESP-claimed transaction atomically."""

        with self._transaction_lock:
            self._require_open()
            journal = self._read_journal()
            if journal is None or journal.phase not in {"claimed", "checking"}:
                raise ProvisioningError("no claimed setup transaction is pending")
            if (
                journal.bridge_url != provisioning.bridge_url
                or journal.device_id != provisioning.device_id
                or not hmac.compare_digest(
                    journal.feed_token_sha256,
                    token_digest(provisioning.feed_token),
                )
            ):
                raise ProvisioningError("setup transaction changed unexpectedly")
            staged_token = self._read_staged_token(journal)
            journal.phase = "checking"
            self._write_journal(journal)
            try:
                self._finish_locked(
                    journal,
                    staged_token,
                    status_callback=status_callback,
                    before_service_start=before_service_start,
                )
            except BaseException as original_error:
                current = self._read_journal()
                if current is not None and current.phase == "complete":
                    raise
                try:
                    if current is not None:
                        # The in-memory journal may know about a service result
                        # that could not yet be flushed. Prefer it while keeping
                        # the durable transaction identity from disk.
                        if journal.service is not None:
                            current.service = journal.service
                        current.credential_switch_started = (
                            current.credential_switch_started
                            or journal.credential_switch_started
                        )
                        if journal.credential_switch_started:
                            current.previous_credential_slot = (
                                journal.previous_credential_slot
                            )
                        self._rollback_journal_locked(current)
                except BaseException as rollback_error:
                    raise ProvisioningError(
                        "local setup failed and rollback did not complete"
                    ) from rollback_error
                raise original_error

    def _finish_locked(
        self,
        journal: _OnboardingJournal,
        staged_token: str,
        *,
        status_callback: Callable[[str], None] | None,
        before_service_start: Callable[[], None] | None,
    ) -> None:
        if not journal.permission_verified:
            credentials = load_local_credential_slot(
                self.store.data_dir, journal.credential_slot
            )
            deadline = min(
                time.monotonic() + self.finish_timeout_seconds,
                time.monotonic() + max(0, journal.expires_at - int(time.time())),
            )
            retry_delay = self.retry_interval
            while True:
                if status_callback is not None:
                    status_callback("checking_read_only_key")
                try:
                    self.permission_checker(credentials)
                    journal.permission_verified = True
                    self._write_journal(journal)
                    break
                except CoinbaseAPIError as exc:
                    if exc.code not in RETRYABLE_PERMISSION_CODES:
                        raise
                    if time.monotonic() >= deadline:
                        raise ProvisioningError(
                            "Coinbase permission check could not reach the internet"
                        ) from exc
                    if status_callback is not None:
                        status_callback("waiting_for_network")
                    delay = min(
                        retry_delay,
                        PENDING_RETRY_MAX_SECONDS,
                        max(0.0, deadline - time.monotonic()),
                    )
                    if delay:
                        time.sleep(delay)
                    retry_delay = min(
                        PENDING_RETRY_MAX_SECONDS,
                        max(self.retry_interval, retry_delay * 2 or 0.25),
                    )

        journal.phase = "applying"
        self._write_journal(journal)
        previous = active_local_credential_slot(self.store.data_dir)
        journal.credential_switch_started = True
        journal.previous_credential_slot = previous
        self._write_journal(journal)
        if not compare_and_swap_local_credential_slot(
            self.store.data_dir,
            expected=previous,
            replacement=journal.credential_slot,
        ):
            raise ProvisioningError("local credentials changed during setup")
        journal.phase = "credentials_active"
        self._write_journal(journal)

        self.store.initialize()
        provision = DeviceManager(self.store).add(
            device_id=journal.device_id,
            label="USB-onboarded AMOLED terminal",
            token=staged_token,
        )
        canonical_token = provision.token_path.read_text(encoding="ascii").strip()
        if not DEVICE_TOKEN_RE.fullmatch(canonical_token) or not hmac.compare_digest(
            canonical_token, staged_token
        ):
            raise ProvisioningError("device provisioning failed")
        journal.phase = "device_added"
        self._write_journal(journal)

        if before_service_start is not None:
            before_service_start()

        def record_service_baseline(baseline: ServiceStartResult) -> None:
            journal.service = baseline
            journal.phase = "service_starting"
            self._write_journal(journal)

        service = self.service_starter(before_change=record_service_baseline)
        journal.service = service
        self._write_journal(journal)
        if not service.started:
            raise ProvisioningError("bridge service could not be restarted")
        journal.phase = "service_started"
        self._write_journal(journal)
        if not self.readiness_checker():
            raise ProvisioningError("bridge service did not become ready")
        self._verify_owned_state(journal)

        journal.phase = "complete"
        self._write_journal(journal)
        self._cleanup_complete_locked(journal)
        if status_callback is not None:
            status_callback("ready")

    def _verify_owned_state(self, journal: _OnboardingJournal) -> None:
        if active_local_credential_slot(self.store.data_dir) != journal.credential_slot:
            raise ProvisioningError("local credentials changed during setup")
        config = self.store.load()
        record = config["devices"].get(journal.device_id)
        if (
            not isinstance(record, dict)
            or not record.get("enabled")
            or not hmac.compare_digest(
                record.get("token_sha256", ""), journal.feed_token_sha256
            )
        ):
            raise ProvisioningError("onboarding device changed during setup")
        token_path = (
            self.store.data_dir / "secrets" / "devices" / f"{journal.device_id}.token"
        )
        try:
            if not token_path.is_file() or token_path.stat().st_size > 128:
                raise ProvisioningError("onboarding device token changed during setup")
            token = token_path.read_text(encoding="ascii").strip()
        except (OSError, UnicodeDecodeError) as exc:
            raise ProvisioningError(
                "onboarding device token changed during setup"
            ) from exc
        if not DEVICE_TOKEN_RE.fullmatch(token) or not hmac.compare_digest(
            token_digest(token), journal.feed_token_sha256
        ):
            raise ProvisioningError("onboarding device token changed during setup")

    def rollback_pending(self) -> None:
        """Rollback only this journal's owned fields; never replace whole state."""

        with self._transaction_lock:
            self._require_open()
            journal = self._read_journal()
            if journal is None:
                return
            if journal.phase == "complete":
                self._cleanup_complete_locked(journal)
                return
            self._rollback_journal_locked(journal)

    def _remove_scoped_device(self, journal: _OnboardingJournal) -> None:
        if self.store.exists():
            conflict = False

            def remove(config: dict[str, Any]) -> None:
                nonlocal conflict
                record = config["devices"].get(journal.device_id)
                if record is None:
                    return
                if not hmac.compare_digest(
                    record.get("token_sha256", ""), journal.feed_token_sha256
                ):
                    conflict = True
                    return
                del config["devices"][journal.device_id]

            self.store.update(remove)
            if conflict:
                raise ProvisioningError(
                    "onboarding device changed concurrently; scoped rollback refused"
                )

        token_path = (
            self.store.data_dir / "secrets" / "devices" / f"{journal.device_id}.token"
        )
        if token_path.exists():
            try:
                if not token_path.is_file() or token_path.stat().st_size > 128:
                    raise ProvisioningError(
                        "onboarding device token changed during rollback"
                    )
                candidate = token_path.read_text(encoding="ascii").strip()
            except (OSError, UnicodeDecodeError) as exc:
                raise ProvisioningError(
                    "onboarding device token could not be inspected"
                ) from exc
            if not DEVICE_TOKEN_RE.fullmatch(candidate) or not hmac.compare_digest(
                token_digest(candidate), journal.feed_token_sha256
            ):
                raise ProvisioningError(
                    "onboarding device token changed during rollback"
                )
            token_path.unlink()

    def _restore_credential_selector(self, journal: _OnboardingJournal) -> None:
        if not journal.credential_switch_started:
            return
        current = active_local_credential_slot(self.store.data_dir)
        previous = journal.previous_credential_slot
        if current == previous:
            return
        if current != journal.credential_slot:
            raise ProvisioningError(
                "local credentials changed concurrently; scoped rollback refused"
            )
        if not compare_and_swap_local_credential_slot(
            self.store.data_dir,
            expected=journal.credential_slot,
            replacement=previous,
        ):
            raise ProvisioningError(
                "local credentials changed concurrently; scoped rollback refused"
            )

    def _restore_service(self, service: ServiceStartResult | None) -> None:
        if service is None:
            return
        restored = (
            restore_user_service(service)
            if service.was_active
            else rollback_user_service(service)
        )
        if not restored:
            raise ProvisioningError("prior background service state was not restored")

    def _rollback_journal_locked(self, journal: _OnboardingJournal) -> None:
        errors: list[BaseException] = []
        for action in (
            lambda: self._remove_scoped_device(journal),
            lambda: self._restore_credential_selector(journal),
            lambda: self._restore_service(journal.service),
        ):
            try:
                action()
            except BaseException as exc:
                errors.append(exc)

        token_stage = self._token_stage_path(journal.transaction_id)
        try:
            token_stage.unlink(missing_ok=True)
        except OSError as exc:
            errors.append(exc)
        try:
            if (
                active_local_credential_slot(self.store.data_dir)
                != journal.credential_slot
            ):
                remove_local_credential_slot(
                    self.store.data_dir, journal.credential_slot
                )
            else:
                errors.append(
                    ProvisioningError("staged local credentials are still active")
                )
        except (OSError, CredentialError) as exc:
            errors.append(exc)

        if errors:
            # Keep the journal for deterministic startup recovery and make the
            # failure visible to the installer instead of silently losing state.
            raise ProvisioningError(
                "local setup rollback did not complete"
            ) from errors[0]
        self._unlink_journal()
        self._remove_empty_transaction_directories()

    def _cleanup_complete_locked(self, journal: _OnboardingJournal) -> None:
        self._token_stage_path(journal.transaction_id).unlink(missing_ok=True)
        previous = journal.previous_credential_slot
        if previous and previous != active_local_credential_slot(self.store.data_dir):
            remove_local_credential_slot(self.store.data_dir, previous)
        self._unlink_journal()
        self._remove_empty_transaction_directories()

    def _remove_empty_transaction_directories(self) -> None:
        for path in (
            self._journal_dir,
            self.store.data_dir / "secrets" / "devices",
            self.store.data_dir / "secrets" / "credential-slots",
            self.store.data_dir / "secrets",
        ):
            try:
                path.rmdir()
            except OSError:
                pass


@dataclass(slots=True)
class OnboardingApplication:
    session: SetupSession
    coordinator: Any
    on_staged: Callable[[SafeProvisioning], None] | None = None
    pna_preflight_event: threading.Event = field(default_factory=threading.Event)

    @property
    def allowed_origins(self) -> frozenset[str]:
        return frozenset((self.session.portal_origin, self.session.endpoint_origin))


class LocalOnboardingServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 8

    def __init__(
        self,
        address: tuple[str, int],
        app: OnboardingApplication,
    ) -> None:
        self.app = app
        self._connection_slots = threading.BoundedSemaphore(MAX_CONCURRENT_CONNECTIONS)
        self._connection_count_lock = threading.Lock()
        self._active_connections = 0
        self.connections_at_capacity = threading.Event()
        super().__init__(address, OnboardingRequestHandler)
        bound_host, bound_port = self.server_address[:2]
        if bound_host != LOOPBACK_HOST:
            self.server_close()
            raise ValueError("onboarding server must bind to 127.0.0.1")
        app.session.bind_endpoint(int(bound_port))

    def get_request(self) -> tuple[socket.socket, Any]:
        connection, address = super().get_request()
        connection.settimeout(10.0)
        return connection, address

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        if not self._connection_slots.acquire(blocking=False):
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            request.close()
            return
        with self._connection_count_lock:
            self._active_connections += 1
            if self._active_connections == MAX_CONCURRENT_CONNECTIONS:
                self.connections_at_capacity.set()
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self._connection_count_lock:
                self._active_connections -= 1
                self.connections_at_capacity.clear()
            self._connection_slots.release()
            raise

    def process_request_thread(
        self, request: socket.socket, client_address: Any
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._connection_count_lock:
                self._active_connections -= 1
                if self._active_connections < MAX_CONCURRENT_CONNECTIONS:
                    self.connections_at_capacity.clear()
            self._connection_slots.release()


class OnboardingRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "CoinbaseAMOLEDSetup"
    sys_version = ""

    @property
    def app(self) -> OnboardingApplication:
        return self.server.app  # type: ignore[attr-defined,no-any-return]

    def handle_one_request(self) -> None:
        """Read exactly one bounded HTTP/1.x request, then close the socket."""

        self.close_connection = True
        try:
            self.raw_requestline = self.rfile.readline(MAX_REQUEST_LINE + 1)
            if len(self.raw_requestline) > MAX_REQUEST_LINE:
                self.request_version = "HTTP/1.1"
                self.command = ""
                self.path = ""
                self._send_json(HTTPStatus.REQUEST_URI_TOO_LONG, GENERIC_ERROR)
                return
            if not self.raw_requestline:
                return
            if not self.parse_request():
                return
            method = {
                "GET": self.do_GET,
                "POST": self.do_POST,
                "OPTIONS": self.do_OPTIONS,
            }.get(self.command)
            if method is None:
                self._method_not_allowed()
            else:
                method()
            self.wfile.flush()
        except (TimeoutError, ConnectionError, OSError):
            self.close_connection = True

    def parse_request(self) -> bool:
        """Parse request line and headers with aggregate limits before dispatch."""

        self.command = None
        self.path = ""
        self.request_version = "HTTP/1.1"
        self.close_connection = True
        try:
            requestline = self.raw_requestline.decode("iso-8859-1").rstrip("\r\n")
        except UnicodeDecodeError:
            self._send_json(HTTPStatus.BAD_REQUEST, GENERIC_ERROR)
            return False
        self.requestline = ""
        words = requestline.split()
        if len(words) != 3:
            self._send_json(HTTPStatus.BAD_REQUEST, GENERIC_ERROR)
            return False
        command, path, version = words
        if version not in {"HTTP/1.0", "HTTP/1.1"}:
            status = (
                HTTPStatus.HTTP_VERSION_NOT_SUPPORTED
                if version.startswith("HTTP/")
                else HTTPStatus.BAD_REQUEST
            )
            self._send_json(status, GENERIC_ERROR)
            return False
        self.request_version = version
        if (
            not 1 <= len(command) <= 16
            or not command.isascii()
            or not command.isalpha()
            or command.upper() != command
        ):
            self._send_json(HTTPStatus.BAD_REQUEST, GENERIC_ERROR)
            return False
        if len(path.encode("iso-8859-1")) > MAX_REQUEST_TARGET:
            self._send_json(HTTPStatus.REQUEST_URI_TOO_LONG, GENERIC_ERROR)
            return False
        self.command = command
        self.path = path

        raw_headers: list[bytes] = []
        total = 0
        header_count = 0
        while True:
            remaining = MAX_HEADER_BYTES - total
            if remaining <= 0:
                self._send_json(
                    HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE, GENERIC_ERROR
                )
                return False
            line = self.rfile.readline(remaining + 1)
            if not line:
                self._send_json(HTTPStatus.BAD_REQUEST, GENERIC_ERROR)
                return False
            if len(line) > remaining:
                self._send_json(
                    HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE, GENERIC_ERROR
                )
                return False
            total += len(line)
            raw_headers.append(line)
            if line in {b"\r\n", b"\n"}:
                break
            header_count += 1
            if header_count > MAX_HEADER_COUNT or line[:1] in {b" ", b"\t"}:
                self._send_json(
                    HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE, GENERIC_ERROR
                )
                return False
        try:
            self.headers = http.client.parse_headers(
                io.BytesIO(b"".join(raw_headers)), _class=self.MessageClass
            )
        except (http.client.HTTPException, UnicodeError):
            self._send_json(HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE, GENERIC_ERROR)
            return False
        if self.headers.get("Transfer-Encoding") or self.headers.get("Expect"):
            self._send_json(HTTPStatus.BAD_REQUEST, GENERIC_ERROR)
            return False
        return True

    def version_string(self) -> str:
        return self.server_version

    def send_error(
        self,
        code: int,
        message: str | None = None,
        explain: str | None = None,
    ) -> None:
        del message, explain
        self._send_json(code, GENERIC_ERROR)

    def log_message(self, format: str, *args: Any) -> None:
        # Never allow BaseHTTPRequestHandler to render targets, headers, or input.
        return

    def do_GET(self) -> None:
        if not self._valid_host() or not self._simple_request_shape():
            self._send_json(HTTPStatus.BAD_REQUEST, GENERIC_ERROR)
            return
        if self._content_length(maximum=0) != 0 or not self._content_type_is(None):
            self._send_json(HTTPStatus.BAD_REQUEST, GENERIC_ERROR)
            return
        expected = f"/setup/{self.app.session.session_id}"
        if self.path != expected:
            self._send_json(HTTPStatus.NOT_FOUND, GENERIC_ERROR)
            return
        try:
            page = render_local_setup_page(self.app.session)
        except SetupSessionError:
            self._send_json(HTTPStatus.GONE, GENERIC_ERROR)
            return
        self._send_html(HTTPStatus.OK, page)

    def do_OPTIONS(self) -> None:
        if self._content_length(maximum=0) != 0 or not self._content_type_is(None):
            self._send_json(HTTPStatus.BAD_REQUEST, GENERIC_ERROR)
            return
        origin = self._preflight_origin()
        if origin is None:
            self._send_json(HTTPStatus.FORBIDDEN, GENERIC_ERROR)
            return
        self.send_response(HTTPStatus.NO_CONTENT)
        self._security_headers(content_type=None, content_length=0, origin=origin)
        self.send_header("Access-Control-Allow-Methods", "POST")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Authorization, Content-Type, X-CSRF-Token, X-Setup-Session",
        )
        if self.headers.get("Access-Control-Request-Private-Network") == "true":
            self.app.pna_preflight_event.set()
            self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Access-Control-Max-Age", "0")
        self.end_headers()

    def do_POST(self) -> None:
        if self.path == ONBOARDING_PATH:
            self._handle_onboarding()
        else:
            self._send_json(HTTPStatus.NOT_FOUND, GENERIC_ERROR)

    def _method_not_allowed(self) -> None:
        self._send_json(
            HTTPStatus.METHOD_NOT_ALLOWED,
            GENERIC_ERROR,
            extra_headers={"Allow": "GET, POST, OPTIONS"},
        )

    def _handle_onboarding(self) -> None:
        origin, token = self._authenticated_origin()
        if origin is None or token is None:
            self._send_json(HTTPStatus.FORBIDDEN, GENERIC_ERROR, origin=origin)
            return
        if not self._content_type_is("application/json"):
            self._send_json(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE, GENERIC_ERROR, origin=origin
            )
            return
        length = self._content_length(maximum=MAX_CDP_JSON_BYTES)
        if length is None or length < 1:
            self._send_json(HTTPStatus.BAD_REQUEST, GENERIC_ERROR, origin=origin)
            return
        try:
            self.app.session.begin_once()
        except SetupSessionError:
            self._send_json(HTTPStatus.GONE, GENERIC_ERROR, origin=origin)
            return
        try:
            body = self.rfile.read(length)
            if len(body) != length:
                raise SetupSessionError("truncated setup request")
            credentials = parse_cdp_key_json(body)
        except (CredentialError, SetupSessionError):
            self.app.session.fail_attempt()
            self._send_json(HTTPStatus.BAD_REQUEST, GENERIC_ERROR, origin=origin)
            return
        try:
            provisioning = self.app.coordinator.complete(credentials)
            self.app.session.set_provisioning(provisioning)
            if self.app.on_staged is not None:
                self.app.on_staged(provisioning)
            self.app.session.use_once()
        except (CoinbaseAPIError, CredentialError, SetupSessionError):
            self.app.session.fail_attempt()
            if not self._rollback_after_failed_attempt():
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    GENERIC_ERROR,
                    origin=origin,
                )
                return
            self._send_json(HTTPStatus.BAD_REQUEST, GENERIC_ERROR, origin=origin)
            return
        except Exception:
            self.app.session.fail_attempt()
            self._rollback_after_failed_attempt()
            self.app.session.abort()
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                GENERIC_ERROR,
                origin=origin,
            )
            return
        self._send_json(HTTPStatus.OK, provisioning.public_json(), origin=origin)

    def _rollback_after_failed_attempt(self) -> bool:
        rollback = getattr(self.app.coordinator, "rollback_pending", None)
        if rollback is None:
            return True
        try:
            rollback()
            return True
        except Exception:
            self.app.session.abort()
            return False

    def _authenticated_origin(self) -> tuple[str | None, str | None]:
        if not self._valid_host() or not self._simple_request_shape():
            return None, None
        origins = self.headers.get_all("Origin", [])
        authorizations = self.headers.get_all("Authorization", [])
        sessions = self.headers.get_all("X-Setup-Session", [])
        csrf_values = self.headers.get_all("X-CSRF-Token", [])
        if not (
            len(origins)
            == len(authorizations)
            == len(sessions)
            == len(csrf_values)
            == 1
        ):
            return None, None
        origin = origins[0]
        if origin not in self.app.allowed_origins:
            return None, None
        prefix = "Setup "
        authorization = authorizations[0]
        if not authorization.startswith(prefix):
            return origin, None
        token = authorization[len(prefix) :]
        if (
            not token
            or len(token) > 128
            or any(character.isspace() for character in token)
        ):
            return origin, None
        valid = self.app.session.authorize_setup(
            session_id=sessions[0],
            setup_token=token,
            csrf_token=csrf_values[0],
        )
        return (origin, token) if valid else (origin, None)

    def _preflight_origin(self) -> str | None:
        if not self._valid_host() or not self._simple_request_shape():
            return None
        origins = self.headers.get_all("Origin", [])
        if len(origins) != 1 or origins[0] not in self.app.allowed_origins:
            return None
        methods = self.headers.get_all("Access-Control-Request-Method", [])
        requested_header_values = self.headers.get_all(
            "Access-Control-Request-Headers", []
        )
        if len(methods) != 1 or methods[0] != "POST":
            return None
        if len(requested_header_values) != 1:
            return None
        requested = {
            value.strip().lower()
            for value in requested_header_values[0].split(",")
            if value.strip()
        }
        if self.path == ONBOARDING_PATH:
            required = {
                "authorization",
                "content-type",
                "x-csrf-token",
                "x-setup-session",
            }
        else:
            return None
        if requested != required:
            return None
        pna_values = self.headers.get_all("Access-Control-Request-Private-Network", [])
        if len(pna_values) > 1 or (pna_values and pna_values[0] != "true"):
            return None
        return origins[0]

    def _valid_host(self) -> bool:
        hosts = self.headers.get_all("Host", [])
        expected = urlsplit(self.app.session.endpoint_origin).netloc
        return len(hosts) == 1 and hmac.compare_digest(hosts[0], expected)

    def _simple_request_shape(self) -> bool:
        if len(self.path) > MAX_REQUEST_TARGET:
            return False
        try:
            parsed = urlsplit(self.path)
        except ValueError:
            return False
        if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
            return False
        if (
            sum(len(key) + len(value) for key, value in self.headers.items())
            > MAX_HEADER_BYTES
        ):
            return False
        if self.headers.get("Transfer-Encoding") or self.headers.get("Expect"):
            return False
        return True

    def _content_length(self, *, maximum: int) -> int | None:
        values = self.headers.get_all("Content-Length", [])
        if not values and maximum == 0:
            return 0
        if len(values) != 1:
            return None
        raw = values[0]
        if not raw or len(raw) > 10 or not raw.isascii() or not raw.isdigit():
            return None
        value = int(raw)
        return value if 0 <= value <= maximum else None

    def _content_type_is(self, expected: str | None) -> bool:
        values = self.headers.get_all("Content-Type", [])
        if expected is None:
            return not values
        return len(values) == 1 and hmac.compare_digest(values[0], expected)

    def _send_json(
        self,
        status: int,
        value: dict[str, Any],
        *,
        origin: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        payload = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode(
            "utf-8"
        )
        self.send_response(int(status))
        self._security_headers(
            content_type="application/json; charset=utf-8",
            content_length=len(payload),
            origin=origin,
        )
        for name, header_value in (extra_headers or {}).items():
            self.send_header(name, header_value)
        self.end_headers()
        self.wfile.write(payload)

    def _send_html(self, status: int, markup: str) -> None:
        payload = markup.encode("utf-8")
        self.send_response(int(status))
        self._security_headers(
            content_type="text/html; charset=utf-8",
            content_length=len(payload),
            origin=None,
            html_page=True,
        )
        self.end_headers()
        self.wfile.write(payload)

    def _security_headers(
        self,
        *,
        content_type: str | None,
        content_length: int,
        origin: str | None,
        html_page: bool = False,
    ) -> None:
        if content_type:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(content_length))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
        )
        if html_page:
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; "
                "script-src 'unsafe-inline'; connect-src 'self' http://192.168.4.1; "
                "form-action 'none'; base-uri 'none'; frame-ancestors 'none'",
            )
        else:
            self.send_header(
                "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"
            )
        if origin in self.app.allowed_origins:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")


PENDING_WIRE_STATES = frozenset(
    {
        "waiting_for_network",
        "checking_read_only_key",
        "ready",
        "rejected",
    }
)


@dataclass(slots=True)
class PendingClaimApplication:
    """In-memory, token-scoped view over one durable pending transaction."""

    coordinator: OnboardingCoordinator
    expected_host: str
    status: str = "waiting_for_network"
    expires_at: int = 0
    _device_id: str = field(default="", init=False, repr=False)
    _token_sha256: str = field(default="", init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    claimed_event: threading.Event = field(default_factory=threading.Event)
    terminal_event: threading.Event = field(default_factory=threading.Event)
    ip_limiter: TokenBucketLimiter = field(
        default_factory=lambda: TokenBucketLimiter(60, 8, max_entries=512)
    )
    token_limiter: TokenBucketLimiter = field(
        default_factory=lambda: TokenBucketLimiter(30, 6, max_entries=32)
    )
    client_hasher: ClientHasher = field(default_factory=ClientHasher)

    @property
    def allowed_origins(self) -> frozenset[str]:
        # LAN claim/status are firmware APIs, never browser CORS endpoints.
        return frozenset()

    def set_pending(self, provisioning: SafeProvisioning) -> None:
        with self._lock:
            if self._device_id and (
                self._device_id != provisioning.device_id
                or self._token_sha256 != token_digest(provisioning.feed_token)
            ):
                raise ProvisioningError("pending setup changed unexpectedly")
            self._device_id = provisioning.device_id
            self._token_sha256 = token_digest(provisioning.feed_token)
            self.expires_at = provisioning.expires_at
            self.status = "waiting_for_network"

    def authenticate(self, device_id: str, token: str) -> bool:
        try:
            digest = token_digest(token)
        except (AttributeError, UnicodeEncodeError):
            digest = ""
        with self._lock:
            return bool(
                self._device_id
                and hmac.compare_digest(device_id, self._device_id)
                and hmac.compare_digest(digest, self._token_sha256)
            )

    def claim(self, *, device_id: str, token: str) -> str:
        if not self.authenticate(device_id, token):
            raise SetupSessionError("pending setup is unavailable")
        with self._lock:
            if self.status == "rejected" or self.expires_at <= int(time.time()):
                self.status = "rejected"
                self.terminal_event.set()
                raise SetupSessionError("pending setup is unavailable")
        status = self.coordinator.claim_pending(device_id=device_id, token=token)
        with self._lock:
            self.status = status
            self.claimed_event.set()
            return self.status

    def set_status(self, status: str) -> None:
        if status not in PENDING_WIRE_STATES:
            raise ValueError("invalid pending setup status")
        with self._lock:
            self.status = status
            if status in {"ready", "rejected"}:
                self.terminal_event.set()

    def public_status(self) -> dict[str, Any]:
        with self._lock:
            status = self.status
            expires_at = self.expires_at
        value: dict[str, Any] = {
            "ok": status != "rejected",
            "status": status,
            "expires_at": expires_at,
            "retry_after_seconds": 2 if status != "ready" else 0,
        }
        if status == "rejected":
            value["action"] = "restart_setup"
        return value


class PendingClaimServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 8

    def __init__(
        self,
        address: tuple[str, int],
        app: PendingClaimApplication,
    ) -> None:
        self.app = app
        self._connection_slots = threading.BoundedSemaphore(MAX_CONCURRENT_CONNECTIONS)
        super().__init__(address, PendingClaimRequestHandler)

    def get_request(self) -> tuple[socket.socket, Any]:
        connection, address = super().get_request()
        connection.settimeout(10.0)
        return connection, address

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        if not self._connection_slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._connection_slots.release()
            raise

    def process_request_thread(
        self, request: socket.socket, client_address: Any
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()


class PendingClaimRequestHandler(OnboardingRequestHandler):
    server_version = "CoinbaseAMOLEDPending"

    @property
    def app(self) -> PendingClaimApplication:  # type: ignore[override]
        return self.server.app  # type: ignore[attr-defined,no-any-return]

    def do_GET(self) -> None:
        self._handle_pending(claim=False)

    def do_POST(self) -> None:
        self._handle_pending(claim=True)

    def do_OPTIONS(self) -> None:
        self._method_not_allowed()

    def _method_not_allowed(self) -> None:
        self._send_json(
            HTTPStatus.METHOD_NOT_ALLOWED,
            {"ok": False, "status": "rejected"},
            extra_headers={"Allow": "GET, POST"},
        )

    def _valid_host(self) -> bool:
        hosts = self.headers.get_all("Host", [])
        return len(hosts) == 1 and hmac.compare_digest(
            hosts[0], self.app.expected_host
        )

    def _pending_credentials(self) -> tuple[str | None, str | None]:
        authorizations = self.headers.get_all("Authorization", [])
        device_ids = self.headers.get_all("X-Device-ID", [])
        if len(authorizations) != 1 or len(device_ids) != 1:
            return None, None
        authorization = authorizations[0]
        if not authorization.startswith("Bearer "):
            return None, None
        token = authorization[7:]
        device_id = device_ids[0]
        if (
            not token
            or len(token) > 128
            or any(character.isspace() for character in token)
            or len(device_id) > 128
            or any(character.isspace() for character in device_id)
        ):
            return None, None
        return device_id, token

    def _handle_pending(self, *, claim: bool) -> None:
        expected_path = PENDING_CLAIM_PATH if claim else PENDING_STATUS_PATH
        if (
            self.path != expected_path
            or not self._valid_host()
            or not self._simple_request_shape()
            or self._content_length(maximum=0) != 0
            or not self._content_type_is(None)
        ):
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "status": "rejected"})
            return
        remote = str(self.client_address[0])
        allowed, retry_after = self.app.ip_limiter.allow(remote)
        if not allowed:
            self._send_json(
                HTTPStatus.TOO_MANY_REQUESTS,
                {"ok": False, "status": "rejected"},
                extra_headers={"Retry-After": str(retry_after)},
            )
            return
        device_id, token = self._pending_credentials()
        if device_id is None or token is None or not self.app.authenticate(device_id, token):
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"ok": False, "status": "rejected"},
                extra_headers={"WWW-Authenticate": 'Bearer realm="pending-setup"'},
            )
            return
        token_key = self.app.client_hasher.digest(token)
        allowed, retry_after = self.app.token_limiter.allow(token_key)
        if not allowed:
            self._send_json(
                HTTPStatus.TOO_MANY_REQUESTS,
                self.app.public_status(),
                extra_headers={"Retry-After": str(retry_after)},
            )
            return
        if claim:
            try:
                self.app.claim(device_id=device_id, token=token)
            except SetupSessionError:
                self._send_json(HTTPStatus.GONE, self.app.public_status())
                return
        self._send_json(HTTPStatus.OK, self.app.public_status())


def create_pending_claim_server(
    coordinator: OnboardingCoordinator,
    *,
    bridge_url: str,
    bind_host: str = "0.0.0.0",
) -> PendingClaimServer:
    """Create the narrow HTTP LAN handoff used before the feed is active."""

    parsed = urlsplit(bridge_url)
    try:
        port = parsed.port or 80
    except ValueError as exc:
        raise ValueError("pending bridge URL is invalid") from exc
    if (
        parsed.scheme != "http"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path != "/v1/device-feed"
    ):
        raise ValueError("automated pending claim requires a local HTTP bridge URL")
    app = PendingClaimApplication(coordinator=coordinator, expected_host=parsed.netloc)
    recovered = coordinator.pending_provisioning()
    if recovered is not None:
        app.set_pending(recovered)
    return PendingClaimServer((bind_host, port), app)


def create_onboarding_server(
    coordinator: Any,
    *,
    ttl_seconds: int = 900,
    portal_origin: str = PORTAL_ORIGIN,
    on_staged: Callable[[SafeProvisioning], None] | None = None,
) -> LocalOnboardingServer:
    session = SetupSession.create(ttl_seconds=ttl_seconds)
    parsed = urlsplit(portal_origin)
    try:
        _portal_port = parsed.port
    except ValueError as exc:
        raise ValueError("portal origin must be an exact HTTP origin") from exc
    if (
        parsed.scheme != "http"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("portal origin must be an exact HTTP origin")
    session.portal_origin = portal_origin.rstrip("/")
    app = OnboardingApplication(
        session=session,
        coordinator=coordinator,
        on_staged=on_staged,
    )
    return LocalOnboardingServer((LOOPBACK_HOST, 0), app)


def render_local_setup_page(session: SetupSession) -> str:
    """Render the same-computer fallback without cookies or external resources."""

    setup_page_token = session.page_token()
    if setup_page_token is None:
        raise SetupSessionError("setup session is unavailable")
    endpoint = json.dumps(session.endpoint_url)
    session_id = json.dumps(session.session_id)
    setup_token = json.dumps(setup_page_token)
    csrf = json.dumps(session.csrf_token)
    escaped_expiry = html.escape(
        time.strftime("%H:%M", time.localtime(session.expires_at))
    )
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Check the read-only key</title><style>
body{{font:16px system-ui;background:#07101f;color:#f5f7fa;max-width:560px;margin:28px auto;padding:0 18px}}
section{{background:#121826;padding:22px;border-radius:14px}}label{{display:block;margin-top:13px}}
input,textarea,button{{box-sizing:border-box;width:100%;padding:12px;margin:6px 0;border-radius:8px;border:1px solid #526079}}
textarea{{min-height:150px}}button{{background:#377eff;color:white;font-weight:700}}small,.muted{{color:#b8c1d1}}#status{{white-space:pre-wrap}}</style></head>
<body><h1>Finish display setup</h1><p class="muted">This same-computer page can finish setup without sending the Coinbase key to the display.</p>
<section><form id="setup" autocomplete="off"><label>Home Wi-Fi name</label><input id="ssid" maxlength="32" autocomplete="off" required><label>Home Wi-Fi password</label><input id="wifiPassword" type="password" maxlength="64" autocomplete="new-password"><label>Coinbase CDP ECDSA API-key JSON</label><textarea id="keyText" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="Paste the downloaded JSON"></textarea>
<input id="keyFile" type="file" accept="application/json,.json" autocomplete="off"><small>Your key goes only to the bridge on this computer. The display never receives it. This session expires around {escaped_expiry}.</small>
<button id="finish" type="submit">Finish</button><p id="status" aria-live="polite"></p></form></section>
<script>'use strict';
const endpoint={endpoint},sessionId={session_id},setupCsrf={csrf};let setupToken={setup_token};
const authHeaders=()=>({{'Authorization':'Setup '+setupToken,'Content-Type':'application/json','X-Setup-Session':sessionId,'X-CSRF-Token':setupCsrf}});
async function keyDocument(){{const f=document.getElementById('keyFile').files[0];return f?await f.text():document.getElementById('keyText').value;}}
async function saveOnlySafeValues(p){{const body=new URLSearchParams();body.set('setup_csrf',setupCsrf);body.set('ssid',document.getElementById('ssid').value);body.set('password',document.getElementById('wifiPassword').value);body.set('bridge_url',p.bridge_url);body.set('device_id',p.device_id);body.set('pending_token',p.pending_token);body.set('pending_expires_at',String(p.expires_at));const r=await fetch('http://192.168.4.1/save',{{method:'POST',mode:'cors',cache:'no-store',credentials:'omit',redirect:'error',referrerPolicy:'no-referrer',headers:{{'Content-Type':'application/x-www-form-urlencoded'}},body:body.toString()}});if(!r.ok)throw new Error('save');}}
document.getElementById('setup').addEventListener('submit',async e=>{{e.preventDefault();const out=document.getElementById('status'),button=document.getElementById('finish'),text=document.getElementById('keyText'),file=document.getElementById('keyFile'),wifi=document.getElementById('wifiPassword');let key='';button.disabled=true;out.textContent='Saving securely…';try{{key=await keyDocument();const r=await fetch(endpoint,{{method:'POST',mode:'cors',cache:'no-store',credentials:'omit',redirect:'error',referrerPolicy:'no-referrer',headers:authHeaders(),body:key}});if(!r.ok)throw new Error('key');const pending=await r.json();setupToken='';await saveOnlySafeValues(pending);out.textContent='Saved. The display will reconnect and check the read-only key automatically.';}}catch(_error){{out.textContent='Setup could not be saved. Keep this installer running, verify the fields, and try again.';button.disabled=false;}}finally{{key='';text.value='';file.value='';wifi.value='';}}}});
</script></body></html>"""
