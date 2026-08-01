# ruff: noqa: E501
"""One-time localhost onboarding endpoint for the USB-provisioned display.

The endpoint is deliberately separate from the long-running device feed. It binds
only to loopback, accepts one bounded Coinbase CDP JSON document, and returns only
safe device provisioning values. Request bodies and authorization values are
never logged.
"""

from __future__ import annotations

import hmac
import html
import json
import os
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
from typing import Any
from urllib.parse import urlsplit

from .auth import (
    DEVICE_TOKEN_RE,
    Credentials,
    DeviceManager,
    DeviceProvision,
    JWTSigner,
    generate_device_id,
    generate_device_token,
    save_local_credentials_atomic,
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
from .user_service import (
    ServiceStartResult,
    rollback_user_service,
    start_user_service,
)

LOOPBACK_HOST = "127.0.0.1"
PORTAL_ORIGIN = "http://192.168.4.1"
ONBOARDING_PATH = "/v1/onboarding"
PROVISIONING_PATH = "/v1/onboarding/provisioning"
FINISH_PATH = "/v1/onboarding/finish"
MAX_HEADER_BYTES = 16_384
MAX_REQUEST_TARGET = 512
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

    def public_json(self) -> dict[str, Any]:
        return {
            "ok": True,
            "bridge_url": self.bridge_url,
            "device_id": self.device_id,
            "feed_token": self.feed_token,
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
    _finish_token: str = field(default="", init=False, repr=False)
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

    def authorize(self, *, session_id: str, setup_token: str, csrf_token: str) -> bool:
        return bool(
            hmac.compare_digest(session_id, self.session_id)
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

    def finish_once(self, *, setup_token: str) -> None:
        with self._lock:
            # The credential exchange zeroes the primary token. The browser keeps
            # its original copy and proves it again with a constant-time digest
            # retained only for this final acknowledgement.
            expected = self._finish_token
            if not expected:
                raise SetupSessionError("setup session is unavailable")
            if (
                self.expired()
                or not self._used
                or self._finished
                or not hmac.compare_digest(setup_token, expected)
            ):
                raise SetupSessionError("setup session is unavailable")
            self._finished = True
            self._finish_token = ""

    def mark_finished(self) -> None:
        with self._lock:
            if not self._finished:
                raise SetupSessionError("setup session is unavailable")
            self.finished_event.set()

    def preserve_finish_token(self) -> None:
        # Called immediately before use_once clears the primary token.
        self._finish_token = self.setup_token

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

    @property
    def used(self) -> bool:
        with self._lock:
            return self._used


PermissionChecker = Callable[[Credentials], None]
ServiceStarter = Callable[[], ServiceStartResult]
ReadinessChecker = Callable[[], bool]


@dataclass(slots=True)
class _StagedSetup:
    credentials: Credentials = field(repr=False)
    provisioning: SafeProvisioning
    permission_verified: bool


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
    """Validate, persist, provision, and start the bridge as one transaction."""

    def __init__(
        self,
        data_dir: str | os.PathLike[str],
        *,
        bridge_url: str,
        permission_checker: PermissionChecker = _check_permissions,
        service_starter: ServiceStarter = start_user_service,
        readiness_checker: ReadinessChecker = _bridge_ready,
    ) -> None:
        parsed = urlsplit(bridge_url)
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
        self.store = ConfigStore(data_dir)
        self.bridge_url = bridge_url
        self.permission_checker = permission_checker
        self.service_starter = service_starter
        self.readiness_checker = readiness_checker
        self._staged: _StagedSetup | None = None
        self._transaction_lock = threading.Lock()

    def complete(self, credentials: Credentials) -> SafeProvisioning:
        """Stage credentials in memory and return only safe ESP values.

        A Wi-Fi-only computer usually loses internet while joined to the display
        access point. We therefore try the permission check here, but defer only
        transient network/server failures until the display has saved Wi-Fi and
        the computer reconnects. Nothing persistent is written at this stage.
        """

        permission_verified = False
        try:
            self.permission_checker(credentials)
            permission_verified = True
        except CoinbaseAPIError as exc:
            if exc.code not in RETRYABLE_PERMISSION_CODES:
                raise

        provisioning = SafeProvisioning(
            bridge_url=self.bridge_url,
            device_id=generate_device_id(),
            feed_token=generate_device_token(),
        )

        with self._transaction_lock:
            if self._staged is not None:
                raise ProvisioningError("a setup transaction is already pending")
            self._staged = _StagedSetup(
                credentials=credentials,
                provisioning=provisioning,
                permission_verified=permission_verified,
            )
        return provisioning

    def finalize_pending(
        self,
        *,
        timeout_seconds: float = 120.0,
        retry_interval: float = 1.0,
    ) -> SafeProvisioning:
        """Verify permissions, persist state, and start the bridge after ESP save."""

        if timeout_seconds < 0 or retry_interval < 0:
            raise ValueError("finalization timing must be non-negative")
        with self._transaction_lock:
            staged = self._staged
        if staged is None:
            raise ProvisioningError("no setup transaction is pending")

        if not staged.permission_verified:
            deadline = time.monotonic() + timeout_seconds
            while True:
                try:
                    self.permission_checker(staged.credentials)
                    staged.permission_verified = True
                    break
                except CoinbaseAPIError as exc:
                    if exc.code not in RETRYABLE_PERMISSION_CODES:
                        raise
                    if time.monotonic() >= deadline:
                        raise ProvisioningError(
                            "Coinbase permission check could not reach the internet"
                        ) from exc
                    time.sleep(
                        min(retry_interval, max(0.0, deadline - time.monotonic()))
                    )

        with self._transaction_lock:
            if self._staged is not staged:
                raise ProvisioningError("setup transaction changed unexpectedly")
            config_existed = self.store.exists()
            original_config = self.store.load() if config_existed else None
            bundle_path = self.store.data_dir / "secrets" / "coinbase_credentials"
            old_bundle = bundle_path.read_bytes() if bundle_path.is_file() else None
            provision: DeviceProvision | None = None
            service = ServiceStartResult("unavailable", "none")

            try:
                save_local_credentials_atomic(
                    self.store.data_dir,
                    credentials=staged.credentials,
                    replace=bundle_path.exists(),
                )
                self.store.initialize()
                provision = DeviceManager(self.store).add(
                    device_id=staged.provisioning.device_id,
                    label="USB-onboarded AMOLED terminal",
                    token=staged.provisioning.feed_token,
                )
                token = provision.token_path.read_text(encoding="ascii").strip()
                if not DEVICE_TOKEN_RE.fullmatch(token) or not hmac.compare_digest(
                    token, staged.provisioning.feed_token
                ):
                    raise ProvisioningError("device provisioning failed")

                service = self.service_starter()
                if not service.started or not self.readiness_checker():
                    raise ProvisioningError("bridge service did not become ready")
                self._staged = None
                return staged.provisioning
            except BaseException:
                self._restore(
                    config_existed=config_existed,
                    original_config=original_config,
                    bundle_path=bundle_path,
                    old_bundle=old_bundle,
                    provision=provision,
                    service=service,
                )
                self._staged = None
                raise

    def rollback_pending(self) -> None:
        """Forget in-memory credentials after expiry or failed ESP save."""
        with self._transaction_lock:
            self._staged = None

    def _restore(
        self,
        *,
        config_existed: bool,
        original_config: dict[str, Any] | None,
        bundle_path: Path,
        old_bundle: bytes | None,
        provision: DeviceProvision | None,
        service: ServiceStartResult,
    ) -> None:
        if not service.was_active:
            rollback_user_service(service)
        self._rollback(
            config_existed=config_existed,
            original_config=original_config,
            bundle_path=bundle_path,
            old_bundle=old_bundle,
            provision=provision,
        )
        if service.was_active:
            restored = self.service_starter()
            if not restored.started:
                raise ProvisioningError("local setup rollback failed")

    def _rollback(
        self,
        *,
        config_existed: bool,
        original_config: dict[str, Any] | None,
        bundle_path: Path,
        old_bundle: bytes | None,
        provision: DeviceProvision | None,
    ) -> None:
        if config_existed and original_config is not None:
            self.store.replace(original_config)
        else:
            for path in (self.store.path, self.store.lock_path):
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
        if provision is not None:
            try:
                provision.token_path.unlink(missing_ok=True)
            except OSError:
                pass
        try:
            if old_bundle is None:
                bundle_path.unlink(missing_ok=True)
            else:
                write_secret_atomic(bundle_path, old_bundle, replace=True)
        except (OSError, CredentialError) as exc:
            raise ProvisioningError("local setup rollback failed") from exc
        for path in (
            self.store.data_dir / "secrets" / "devices",
            self.store.data_dir / "secrets",
            self.store.data_dir,
        ):
            try:
                path.rmdir()
            except OSError:
                pass


@dataclass(slots=True)
class OnboardingApplication:
    session: SetupSession
    coordinator: Any

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


class OnboardingRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "CoinbaseAMOLEDSetup"
    sys_version = ""

    @property
    def app(self) -> OnboardingApplication:
        return self.server.app  # type: ignore[attr-defined,no-any-return]

    def version_string(self) -> str:
        return self.server_version

    def log_message(self, format: str, *args: Any) -> None:
        # Never allow BaseHTTPRequestHandler to render targets, headers, or input.
        return

    def do_GET(self) -> None:
        if not self._valid_host() or not self._simple_request_shape():
            self._send_json(HTTPStatus.BAD_REQUEST, GENERIC_ERROR)
            return
        expected = f"/setup/{self.app.session.session_id}"
        if self.path != expected or self.app.session.expired():
            self._send_json(HTTPStatus.NOT_FOUND, GENERIC_ERROR)
            return
        self._send_html(HTTPStatus.OK, render_local_setup_page(self.app.session))

    def do_OPTIONS(self) -> None:
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
            self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Access-Control-Max-Age", "0")
        self.end_headers()

    def do_POST(self) -> None:
        if self.path == ONBOARDING_PATH:
            self._handle_onboarding()
        elif self.path == PROVISIONING_PATH:
            self._handle_provisioning()
        elif self.path == FINISH_PATH:
            self._handle_finish()
        else:
            self._send_json(HTTPStatus.NOT_FOUND, GENERIC_ERROR)

    def do_HEAD(self) -> None:
        self._method_not_allowed()

    def do_PUT(self) -> None:
        self._method_not_allowed()

    def do_PATCH(self) -> None:
        self._method_not_allowed()

    def do_DELETE(self) -> None:
        self._method_not_allowed()

    def do_TRACE(self) -> None:
        self._method_not_allowed()

    def do_CONNECT(self) -> None:
        self._method_not_allowed()

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
        if self.headers.get("Content-Type") != "application/json":
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
            provisioning = self.app.coordinator.complete(credentials)
            self.app.session.set_provisioning(provisioning)
            self.app.session.preserve_finish_token()
            self.app.session.use_once()
        except Exception:
            self.app.session.fail_attempt()
            rollback = getattr(self.app.coordinator, "rollback_pending", None)
            if rollback is not None:
                try:
                    rollback()
                except Exception:
                    pass
            self._send_json(HTTPStatus.BAD_REQUEST, GENERIC_ERROR, origin=origin)
            return
        self._send_json(HTTPStatus.OK, provisioning.public_json(), origin=origin)

    def _handle_provisioning(self) -> None:
        origin, token = self._authenticated_origin(allow_used=True)
        if origin is None or token is None or origin != self.app.session.portal_origin:
            self._send_json(HTTPStatus.FORBIDDEN, GENERIC_ERROR, origin=origin)
            return
        length = self._content_length(maximum=0)
        if length != 0 or self.headers.get("Content-Type") not in (None, ""):
            self._send_json(HTTPStatus.BAD_REQUEST, GENERIC_ERROR, origin=origin)
            return
        provisioning = self.app.session.safe_provisioning()
        if provisioning is None:
            self._send_json(HTTPStatus.GONE, GENERIC_ERROR, origin=origin)
            return
        self._send_json(HTTPStatus.OK, provisioning.public_json(), origin=origin)

    def _handle_finish(self) -> None:
        origin, token = self._authenticated_origin(allow_used=True)
        if origin is None or token is None:
            self._send_json(HTTPStatus.FORBIDDEN, GENERIC_ERROR, origin=origin)
            return
        length = self._content_length(maximum=0)
        if length != 0 or self.headers.get("Content-Type") not in (None, ""):
            self._send_json(HTTPStatus.BAD_REQUEST, GENERIC_ERROR, origin=origin)
            return
        try:
            self.app.session.finish_once(setup_token=token)
        except SetupSessionError:
            self._send_json(HTTPStatus.GONE, GENERIC_ERROR, origin=origin)
            return
        try:
            self._send_json(HTTPStatus.OK, {"ok": True}, origin=origin)
        finally:
            self.app.session.mark_finished()

    def _authenticated_origin(
        self, *, allow_used: bool = False
    ) -> tuple[str | None, str | None]:
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
        if allow_used:
            expected = getattr(self.app.session, "_finish_token", "")
            valid = bool(
                expected
                and hmac.compare_digest(sessions[0], self.app.session.session_id)
                and hmac.compare_digest(csrf_values[0], self.app.session.csrf_token)
                and hmac.compare_digest(token, expected)
            )
        else:
            valid = self.app.session.authorize(
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
        if self.headers.get("Access-Control-Request-Method") != "POST":
            return None
        requested = {
            value.strip().lower()
            for value in self.headers.get("Access-Control-Request-Headers", "").split(
                ","
            )
            if value.strip()
        }
        if self.path == ONBOARDING_PATH:
            required = {
                "authorization",
                "content-type",
                "x-csrf-token",
                "x-setup-session",
            }
        elif self.path in {PROVISIONING_PATH, FINISH_PATH}:
            required = {"authorization", "x-csrf-token", "x-setup-session"}
        else:
            return None
        if requested != required:
            return None
        pna = self.headers.get("Access-Control-Request-Private-Network")
        if pna not in (None, "true"):
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
        try:
            value = int(values[0])
        except ValueError:
            return None
        return value if 0 <= value <= maximum else None

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


def create_onboarding_server(
    coordinator: Any,
    *,
    ttl_seconds: int = 900,
    portal_origin: str = PORTAL_ORIGIN,
) -> LocalOnboardingServer:
    session = SetupSession.create(ttl_seconds=ttl_seconds)
    parsed = urlsplit(portal_origin)
    if parsed.scheme != "http" or not parsed.netloc or parsed.path not in ("", "/"):
        raise ValueError("portal origin must be an exact HTTP origin")
    session.portal_origin = portal_origin.rstrip("/")
    app = OnboardingApplication(session=session, coordinator=coordinator)
    return LocalOnboardingServer((LOOPBACK_HOST, 0), app)


def render_local_setup_page(session: SetupSession) -> str:
    """Render the same-computer fallback without cookies or external resources."""

    endpoint = json.dumps(session.endpoint_url)
    session_id = json.dumps(session.session_id)
    setup_token = json.dumps(session.setup_token or session._finish_token)
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
<body><h1>Check the key on this computer</h1><p class="muted">Use this page only if the small captive window could not reach localhost. If the check cannot get online, reconnect this computer to its usual internet network and press Check again.</p>
<section><form id="setup" autocomplete="off"><label>Coinbase CDP ECDSA API-key JSON</label><textarea id="keyText" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="Paste the downloaded JSON"></textarea>
<input id="keyFile" type="file" accept="application/json,.json" autocomplete="off"><small>Your key goes only to the bridge on this computer. The display never receives it. This session expires around {escaped_expiry}.</small>
<button id="finish" type="submit">Check read-only key</button><p id="status" aria-live="polite"></p></form></section>
<script>'use strict';
const endpoint={endpoint},sessionId={session_id},setupToken={setup_token},setupCsrf={csrf};
const authHeaders=()=>({{'Authorization':'Setup '+setupToken,'Content-Type':'application/json','X-Setup-Session':sessionId,'X-CSRF-Token':setupCsrf}});
async function keyDocument(){{const f=document.getElementById('keyFile').files[0];return f?await f.text():document.getElementById('keyText').value;}}
document.getElementById('setup').addEventListener('submit',async e=>{{e.preventDefault();const out=document.getElementById('status'),button=document.getElementById('finish');button.disabled=true;out.textContent='Checking the read-only key…';try{{let key=await keyDocument();const r=await fetch(endpoint,{{method:'POST',mode:'cors',cache:'no-store',credentials:'omit',redirect:'error',referrerPolicy:'no-referrer',headers:authHeaders(),body:key}});key='';document.getElementById('keyText').value='';document.getElementById('keyFile').value='';if(!r.ok)throw new Error('key');await r.json();out.textContent='Key checked. Rejoin the display setup Wi-Fi, open its portal, enter home Wi-Fi, and press Finish. This local setup stays pending until the display confirms its save.';}}catch(_error){{out.textContent='The check could not finish. Confirm the key is P-256 and view-only. If this computer is on the display Wi-Fi, reconnect to its usual internet network and try again.';button.disabled=false;}}}});
</script></body></html>"""
