"""Hardened stdlib HTTP surface: health plus one authenticated feed route."""

from __future__ import annotations

import json
import logging
import secrets
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .auth import DeviceRegistry
from .device_feed import to_device_feed
from .logging_utils import log_event
from .ratelimit import ClientHasher, TokenBucketLimiter

LOGGER = logging.getLogger("coinbase_amoled_bridge.http")
LOGGER.addHandler(logging.NullHandler())
MAX_REQUEST_TARGET = 2_048
MAX_HEADER_BYTES = 16_384
MAX_RESPONSE_BYTES = 2_000_000
PENDING_CLAIM_PATH = "/v1/onboarding/claim"
PENDING_STATUS_PATH = "/v1/onboarding/status"


@dataclass(slots=True)
class BridgeApplication:
    feed_service: Any
    device_registry: DeviceRegistry
    mode: str
    ip_limiter: TokenBucketLimiter
    device_limiter: TokenBucketLimiter
    max_concurrent_requests: int
    ready: bool = True
    _semaphore: threading.BoundedSemaphore = field(init=False, repr=False)
    client_hasher: ClientHasher = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._semaphore = threading.BoundedSemaphore(self.max_concurrent_requests)
        self.client_hasher = ClientHasher()

    @classmethod
    def from_settings(
        cls,
        feed_service: Any,
        device_registry: DeviceRegistry,
        mode: str,
        settings: dict[str, Any],
    ) -> BridgeApplication:
        return cls(
            feed_service=feed_service,
            device_registry=device_registry,
            mode=mode,
            ip_limiter=TokenBucketLimiter(
                int(settings["ip_rate_per_minute"]), int(settings["rate_burst"])
            ),
            device_limiter=TokenBucketLimiter(
                int(settings["device_rate_per_minute"]), int(settings["rate_burst"])
            ),
            max_concurrent_requests=int(settings["max_concurrent_requests"]),
        )


class BridgeHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(
        self,
        server_address: tuple[str, int],
        app: BridgeApplication,
        *,
        max_connections: int | None = None,
    ) -> None:
        self.app = app
        self._connection_slots = threading.BoundedSemaphore(
            max_connections or max(16, app.max_concurrent_requests * 2)
        )
        super().__init__(server_address, BridgeRequestHandler)

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

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()


class BridgeRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "CoinbaseAMOLEDBridge"
    sys_version = ""

    @property
    def app(self) -> BridgeApplication:
        return self.server.app  # type: ignore[attr-defined,no-any-return]

    def version_string(self) -> str:
        return self.server_version

    def log_message(self, format: str, *args: Any) -> None:
        # BaseHTTPRequestHandler logs raw request targets and addresses. All
        # request logging goes through the redacted structured logger instead.
        return

    def do_GET(self) -> None:
        self._handle_read(head_only=False)

    def do_HEAD(self) -> None:
        self._handle_read(head_only=True)

    def do_POST(self) -> None:
        if self.path == PENDING_CLAIM_PATH:
            self._handle_active_claim()
        else:
            self._handle_rejected_method()

    def do_PUT(self) -> None:
        self._handle_rejected_method()

    def do_PATCH(self) -> None:
        self._handle_rejected_method()

    def do_DELETE(self) -> None:
        self._handle_rejected_method()

    def do_OPTIONS(self) -> None:
        self._handle_rejected_method()

    def do_TRACE(self) -> None:
        self._handle_rejected_method()

    def do_CONNECT(self) -> None:
        self._handle_rejected_method()

    def send_error(
        self,
        code: int,
        message: str | None = None,
        explain: str | None = None,
    ) -> None:
        self._request_id = getattr(self, "_request_id", secrets.token_hex(12))
        if code == HTTPStatus.NOT_IMPLEMENTED:
            self.close_connection = True
            self._send_json(
                HTTPStatus.METHOD_NOT_ALLOWED,
                {"error": "method_not_allowed", "read_only": True},
                extra_headers={"Allow": "GET, HEAD"},
                head_only=False,
            )
            return
        self._send_json(code, {"error": "request_rejected"}, head_only=False)

    def _handle_rejected_method(self) -> None:
        self.close_connection = True
        self._request_id = secrets.token_hex(12)
        self._send_json(
            HTTPStatus.METHOD_NOT_ALLOWED,
            {"error": "method_not_allowed", "read_only": True},
            extra_headers={"Allow": "GET, HEAD"},
            head_only=False,
        )
        self._log_request(HTTPStatus.METHOD_NOT_ALLOWED, started=time.monotonic())

    def _handle_active_claim(self) -> None:
        """Idempotently tell a previously claimed device that it is active."""

        started = time.monotonic()
        self._request_id = secrets.token_hex(12)
        status = HTTPStatus.INTERNAL_SERVER_ERROR
        acquired = False
        try:
            if not self.app._semaphore.acquire(blocking=False):
                status = HTTPStatus.SERVICE_UNAVAILABLE
                self._send_json(
                    status,
                    {"ok": False, "status": "checking_read_only_key"},
                    extra_headers={"Retry-After": "1"},
                    head_only=False,
                )
                return
            acquired = True
            parsed = urlsplit(self.path)
            host_values = self.headers.get_all("Host", [])
            lengths = self.headers.get_all("Content-Length", [])
            header_size = sum(
                len(key) + len(value) for key, value in self.headers.items()
            )
            if (
                parsed.scheme
                or parsed.netloc
                or parsed.query
                or parsed.fragment
                or parsed.path != PENDING_CLAIM_PATH
                or len(host_values) != 1
                or len(lengths) > 1
                or (lengths and lengths[0] != "0")
                or self.headers.get("Transfer-Encoding")
                or self.headers.get("Expect")
                or header_size > MAX_HEADER_BYTES
            ):
                status = HTTPStatus.BAD_REQUEST
                self.close_connection = True
                self._send_json(
                    status, {"ok": False, "status": "rejected"}, head_only=False
                )
                return
            remote_address = str(self.client_address[0])
            ip_allowed, retry_after = self.app.ip_limiter.allow(remote_address)
            if not ip_allowed:
                status = HTTPStatus.TOO_MANY_REQUESTS
                self._send_json(
                    status,
                    {"ok": False, "status": "checking_read_only_key"},
                    extra_headers={"Retry-After": str(retry_after)},
                    head_only=False,
                )
                return
            device_id, token = self._device_credentials()
            if not self.app.device_registry.authenticate(device_id, token):
                status = HTTPStatus.UNAUTHORIZED
                self._send_json(
                    status,
                    {"ok": False, "status": "rejected"},
                    extra_headers={"WWW-Authenticate": 'Bearer realm="pending-setup"'},
                    head_only=False,
                )
                return
            device_allowed, retry_after = self.app.device_limiter.allow(device_id or "")
            if not device_allowed:
                status = HTTPStatus.TOO_MANY_REQUESTS
                self._send_json(
                    status,
                    {"ok": True, "status": "ready", "retry_after_seconds": retry_after},
                    extra_headers={"Retry-After": str(retry_after)},
                    head_only=False,
                )
                return
            status = HTTPStatus.OK
            self._send_json(
                status,
                {"ok": True, "status": "ready", "retry_after_seconds": 0},
                head_only=False,
            )
        finally:
            if acquired:
                self.app._semaphore.release()
            self._log_request(status, started=started)

    def _handle_read(self, *, head_only: bool) -> None:
        started = time.monotonic()
        self._request_id = secrets.token_hex(12)
        status = HTTPStatus.INTERNAL_SERVER_ERROR
        acquired = False
        try:
            if not self.app._semaphore.acquire(blocking=False):
                status = HTTPStatus.SERVICE_UNAVAILABLE
                self._send_json(
                    status,
                    {"error": "server_busy"},
                    extra_headers={"Retry-After": "1"},
                    head_only=head_only,
                )
                return
            acquired = True
            remote_address = str(self.client_address[0])
            ip_allowed, retry_after = self.app.ip_limiter.allow(remote_address)
            if not ip_allowed:
                status = HTTPStatus.TOO_MANY_REQUESTS
                self._send_json(
                    status,
                    {"error": "rate_limited"},
                    extra_headers={"Retry-After": str(retry_after)},
                    head_only=head_only,
                )
                return
            if len(self.path) > MAX_REQUEST_TARGET:
                status = HTTPStatus.REQUEST_URI_TOO_LONG
                self._send_json(
                    status, {"error": "request_target_too_long"}, head_only=head_only
                )
                return
            header_size = sum(
                len(key) + len(value) for key, value in self.headers.items()
            )
            if header_size > MAX_HEADER_BYTES:
                status = HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE
                self._send_json(
                    status, {"error": "headers_too_large"}, head_only=head_only
                )
                return
            host_values = self.headers.get_all("Host", [])
            content_length_values = self.headers.get_all("Content-Length", [])
            if (
                len(host_values) != 1
                or len(content_length_values) > 1
                or self.headers.get("Transfer-Encoding")
                or self.headers.get("Expect")
            ):
                status = HTTPStatus.BAD_REQUEST
                self.close_connection = True
                self._send_json(
                    status, {"error": "invalid_request_headers"}, head_only=head_only
                )
                return
            try:
                content_length = (
                    int(content_length_values[0]) if content_length_values else 0
                )
            except ValueError:
                content_length = -1
            if content_length != 0:
                status = HTTPStatus.BAD_REQUEST
                self.close_connection = True
                self._send_json(
                    status, {"error": "request_body_not_allowed"}, head_only=head_only
                )
                return

            parsed = urlsplit(self.path)
            if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
                status = HTTPStatus.BAD_REQUEST
                self._send_json(
                    status, {"error": "invalid_request_target"}, head_only=head_only
                )
                return
            if parsed.path == "/healthz":
                status = HTTPStatus.OK
                self._send_json(
                    status,
                    {"status": "ok", "read_only": True},
                    head_only=head_only,
                )
                return
            if parsed.path == "/readyz":
                status = (
                    HTTPStatus.OK if self.app.ready else HTTPStatus.SERVICE_UNAVAILABLE
                )
                self._send_json(
                    status,
                    {
                        "status": "ready" if self.app.ready else "not_ready",
                        "read_only": True,
                        "mode": self.app.mode,
                    },
                    head_only=head_only,
                )
                return
            if parsed.path not in {"/v1/device-feed", PENDING_STATUS_PATH}:
                status = HTTPStatus.NOT_FOUND
                self._send_json(status, {"error": "not_found"}, head_only=head_only)
                return

            device_id, token = self._device_credentials()
            if not self.app.device_registry.authenticate(device_id, token):
                status = HTTPStatus.UNAUTHORIZED
                self._send_json(
                    status,
                    {"error": "unauthorized"},
                    extra_headers={"WWW-Authenticate": 'Bearer realm="device-feed"'},
                    head_only=head_only,
                )
                return
            device_allowed, retry_after = self.app.device_limiter.allow(device_id or "")
            if not device_allowed:
                status = HTTPStatus.TOO_MANY_REQUESTS
                self._send_json(
                    status,
                    {"error": "rate_limited"},
                    extra_headers={"Retry-After": str(retry_after)},
                    head_only=head_only,
                )
                return
            if not self.app.ready:
                status = HTTPStatus.SERVICE_UNAVAILABLE
                self._send_json(status, {"error": "not_ready"}, head_only=head_only)
                return
            if parsed.path == PENDING_STATUS_PATH:
                status = HTTPStatus.OK
                self._send_json(
                    status,
                    {"ok": True, "status": "ready", "retry_after_seconds": 0},
                    head_only=head_only,
                )
                return
            feed = to_device_feed(self.app.feed_service.get_feed())
            status = HTTPStatus.OK
            self._send_json(status, feed, head_only=head_only)
        except Exception:
            status = HTTPStatus.INTERNAL_SERVER_ERROR
            log_event(
                LOGGER,
                "request_exception",
                level=logging.ERROR,
                error_code="internal_error",
                request_id=self._request_id,
                exc_info=True,
            )
            try:
                self.close_connection = True
                self._send_json(
                    status, {"error": "internal_error"}, head_only=head_only
                )
            except OSError:
                self.close_connection = True
        finally:
            if acquired:
                self.app._semaphore.release()
            self._log_request(status, started=started)

    def _device_credentials(self) -> tuple[str | None, str | None]:
        authorization_values = self.headers.get_all("Authorization", [])
        device_values = self.headers.get_all("X-Device-ID", [])
        if len(authorization_values) != 1 or len(device_values) != 1:
            return None, None
        authorization = authorization_values[0]
        if not authorization.startswith("Bearer "):
            return device_values[0], None
        token = authorization[7:]
        if not token or len(token) > 256 or any(ch.isspace() for ch in token):
            return device_values[0], None
        device_id = device_values[0]
        if len(device_id) > 128 or any(ch.isspace() for ch in device_id):
            return None, token
        return device_id, token

    def _send_json(
        self,
        status: int,
        value: dict[str, Any],
        *,
        extra_headers: dict[str, str] | None = None,
        head_only: bool,
    ) -> None:
        payload = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode(
            "utf-8"
        )
        if len(payload) > MAX_RESPONSE_BYTES:
            status = HTTPStatus.INTERNAL_SERVER_ERROR
            payload = b'{"error":"response_too_large"}'
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"
        )
        self.send_header(
            "X-Request-ID", getattr(self, "_request_id", secrets.token_hex(12))
        )
        for name, header_value in (extra_headers or {}).items():
            self.send_header(name, header_value)
        self.end_headers()
        if not head_only:
            self.wfile.write(payload)

    def _log_request(self, status: int, *, started: float) -> None:
        remote = str(self.client_address[0]) if self.client_address else "unknown"
        log_event(
            LOGGER,
            "http_request",
            method=self.command,
            route=_safe_route(self.path),
            status=int(status),
            duration_ms=max(0, round((time.monotonic() - started) * 1000)),
            request_id=getattr(self, "_request_id", None),
            client_hash=self.app.client_hasher.digest(remote),
        )


def _safe_route(target: str) -> str:
    try:
        parsed = urlsplit(target)
    except ValueError:
        return "invalid"
    if parsed.path in {
        "/healthz",
        "/readyz",
        "/v1/device-feed",
        PENDING_CLAIM_PATH,
        PENDING_STATUS_PATH,
    }:
        return parsed.path
    return "other"


def create_server(
    host: str,
    port: int,
    app: BridgeApplication,
    *,
    tls_cert: str | None = None,
    tls_key: str | None = None,
) -> BridgeHTTPServer:
    server = BridgeHTTPServer((host, port), app)
    if bool(tls_cert) != bool(tls_key):
        server.server_close()
        raise ValueError("both TLS certificate and key are required")
    if tls_cert and tls_key:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.options |= ssl.OP_NO_COMPRESSION
            context.load_cert_chain(certfile=Path(tls_cert), keyfile=Path(tls_key))
            server.socket = context.wrap_socket(server.socket, server_side=True)
        except (OSError, ssl.SSLError) as exc:
            server.server_close()
            raise ValueError("unable to load TLS certificate or key") from exc
    return server
