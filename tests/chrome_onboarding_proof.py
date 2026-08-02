#!/usr/bin/env python3
# ruff: noqa: E501
"""Prove deferred onboarding end to end in installed Google Chrome."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bridge" / "src"))

from coinbase_amoled_bridge.auth import (  # noqa: E402
    Credentials,
    DeviceRegistry,
    JWTSigner,
    active_local_credential_slot,
)
from coinbase_amoled_bridge.coinbase import (  # noqa: E402
    API_ORIGIN,
    API_PREFIX,
    CoinbaseClient,
    TransportResponse,
)
from coinbase_amoled_bridge.config import ConfigStore  # noqa: E402
from coinbase_amoled_bridge.errors import (  # noqa: E402
    CoinbaseAPIError,
    UnsafeCredentialError,
)
from coinbase_amoled_bridge.feed import SampleFeedService  # noqa: E402
from coinbase_amoled_bridge.onboarding import (  # noqa: E402
    FINISH_PATH,
    ONBOARDING_PATH,
    PENDING_CLAIM_PATH,
    PENDING_STATUS_PATH,
    OnboardingCoordinator,
    OnboardingRequestHandler,
    SafeProvisioning,
    create_onboarding_server,
    create_pending_claim_server,
)
from coinbase_amoled_bridge.server import (  # noqa: E402
    BridgeApplication,
    create_server,
)
from coinbase_amoled_bridge.user_service import ServiceStartResult  # noqa: E402

DEFAULT_CHROME = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
DEFAULT_PORTAL_ALIAS = "esp.cbat.test"
SYNTHETIC_KEY_NAME = "organizations/synthetic-test/apiKeys/chrome-proof"
SYNTHETIC_SSID = "SyntheticNetwork"
SYNTHETIC_WIFI_PASSWORD = "synthetic-password"
PORTAL_CSRF = "fake-portal-csrf"
MAX_CDP_MESSAGE_BYTES = 1_048_576
MAX_HTTP_RESPONSE_BYTES = 2_000_000
EXPECTED_ESP_FIELDS = frozenset(
    {
        "csrf",
        "ssid",
        "password",
        "bridge_url",
        "device_id",
        "pending_token",
        "pending_expires_at",
    }
)
REQUIRED_CORS_HEADERS = frozenset(
    {
        "authorization",
        "content-type",
        "x-csrf-token",
        "x-setup-session",
    }
)
PORTAL_ALIAS_RE = re.compile(r"^(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+test$")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _private_ipv4(value: str) -> ipaddress.IPv4Address | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if (
        not isinstance(address, ipaddress.IPv4Address)
        or not address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
    ):
        return None
    return address


def private_portal_host() -> str:
    override = os.environ.get("CBAT_CHROME_PROOF_PORTAL_IP", "").strip()
    candidates = [override] if override else []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.connect(("192.0.2.1", 9))
            candidates.append(str(connection.getsockname()[0]))
    except OSError:
        pass
    try:
        candidates.extend(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    for value in candidates:
        if _private_ipv4(value) is not None:
            return value
    raise RuntimeError("no non-loopback private-LAN IPv4 address is available")


def _validate_portal_alias(value: str) -> str:
    candidate = value.strip().lower().rstrip(".")
    if not PORTAL_ALIAS_RE.fullmatch(candidate):
        raise RuntimeError("portal alias must be a valid reserved .test hostname")
    return candidate


def _free_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind((host, 0))
        return int(listener.getsockname()[1])


def _proof_credentials(scalar: int, marker: str) -> Credentials:
    key = ec.derive_private_key(scalar, ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return Credentials.from_values(
        key_name=f"organizations/synthetic-test/apiKeys/{marker}",
        private_key_pem=pem,
        source="chrome-proof",
    )


def _synthetic_key_json() -> str:
    credentials = _proof_credentials(23, "chrome-proof")
    return json.dumps(
        {
            "name": SYNTHETIC_KEY_NAME,
            "privateKey": credentials.private_key_pem.decode("ascii"),
        },
        separators=(",", ":"),
    )


@dataclass(slots=True)
class FakeEspState:
    expected_host: str = ""
    page: bytes = b""
    saved_body: bytes = b""
    saved_event: threading.Event = field(default_factory=threading.Event)
    host_headers: list[str] = field(default_factory=list)
    client_addresses: list[str] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record_request(self, host: str, client_address: str) -> None:
        with self._lock:
            self.host_headers.append(host)
            self.client_addresses.append(client_address)

    def save_once(self, body: bytes) -> bool:
        with self._lock:
            if self.saved_body:
                return False
            self.saved_body = body
            self.saved_event.set()
            return True


class FakeEspServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, state: FakeEspState, host: str) -> None:
        self.state = state
        super().__init__((host, 0), FakeEspHandler)


class FakeEspHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "SyntheticESP"
    sys_version = ""

    @property
    def state(self) -> FakeEspState:
        return self.server.state  # type: ignore[attr-defined,no-any-return]

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _valid_host(self) -> bool:
        hosts = self.headers.get_all("Host", [])
        if len(hosts) != 1 or hosts[0] != self.state.expected_host:
            return False
        self.state.record_request(hosts[0], str(self.client_address[0]))
        return True

    def _security_headers(self, *, content_type: str, length: int) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Connection", "close")

    def _send_plain(self, status: int, value: bytes) -> None:
        self.send_response(status)
        self._security_headers(content_type="text/plain; charset=utf-8", length=len(value))
        self.end_headers()
        self.wfile.write(value)

    def do_GET(self) -> None:
        if self.path != "/" or not self._valid_host():
            self._send_plain(HTTPStatus.NOT_FOUND, b"not found")
            return
        self.send_response(HTTPStatus.OK)
        self._security_headers(content_type="text/html; charset=utf-8", length=len(self.state.page))
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; "
            "connect-src 'self' http://127.0.0.1:*; "
            "form-action 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(self.state.page)

    def do_POST(self) -> None:
        if self.path != "/save" or not self._valid_host():
            self._send_plain(HTTPStatus.NOT_FOUND, b"not found")
            return
        lengths = self.headers.get_all("Content-Length", [])
        if (
            len(lengths) != 1
            or self.headers.get("Content-Type") != "application/x-www-form-urlencoded"
            or self.headers.get("Transfer-Encoding")
        ):
            self._send_plain(HTTPStatus.BAD_REQUEST, b"rejected")
            return
        try:
            length = int(lengths[0])
        except ValueError:
            self._send_plain(HTTPStatus.BAD_REQUEST, b"rejected")
            return
        if not 1 <= length <= 4096:
            self._send_plain(HTTPStatus.BAD_REQUEST, b"rejected")
            return
        body = self.rfile.read(length)
        if len(body) != length or not self.state.save_once(body):
            self._send_plain(HTTPStatus.CONFLICT, b"rejected")
            return
        self._send_plain(HTTPStatus.OK, b"OK")


@dataclass(frozen=True, slots=True)
class PreflightObservation:
    path: str
    origin: str
    requested_method: str
    requested_headers: frozenset[str]
    private_network: bool


@dataclass(slots=True)
class OnboardingObservation:
    preflights: list[PreflightObservation] = field(default_factory=list)
    post_paths: list[str] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record_preflight(self, handler: OnboardingRequestHandler) -> None:
        requested = frozenset(
            item.strip().lower()
            for item in handler.headers.get("Access-Control-Request-Headers", "").split(",")
            if item.strip()
        )
        value = PreflightObservation(
            path=handler.path,
            origin=handler.headers.get("Origin", ""),
            requested_method=handler.headers.get("Access-Control-Request-Method", ""),
            requested_headers=requested,
            private_network=(
                handler.headers.get("Access-Control-Request-Private-Network") == "true"
            ),
        )
        with self._lock:
            self.preflights.append(value)

    def record_post(self, path: str) -> None:
        with self._lock:
            self.post_paths.append(path)

    def snapshot(self) -> tuple[list[PreflightObservation], list[str]]:
        with self._lock:
            return list(self.preflights), list(self.post_paths)


class ObservedOnboardingRequestHandler(OnboardingRequestHandler):
    @property
    def proof_observation(self) -> OnboardingObservation:
        return self.server.proof_observation  # type: ignore[attr-defined,no-any-return]

    def do_OPTIONS(self) -> None:
        self.proof_observation.record_preflight(self)
        super().do_OPTIONS()

    def do_POST(self) -> None:
        self.proof_observation.record_post(self.path)
        super().do_POST()


class FakeCoinbaseGate:
    """Coinbase permission transport that never opens a network connection."""

    def __init__(
        self,
        *,
        can_view: bool = True,
        can_trade: bool = False,
        can_transfer: bool = False,
    ) -> None:
        self.permissions = {
            "can_view": can_view,
            "can_trade": can_trade,
            "can_transfer": can_transfer,
        }
        self.network_available = threading.Event()
        self.offline_attempt_event = threading.Event()
        self.view_only_verified_event = threading.Event()
        self._lock = threading.Lock()
        self.checker_calls = 0
        self.transport_calls = 0
        self.offline_calls = 0
        self.online_responses = 0
        self.only_permission_route = True
        self.authorization_seen = True

    def set_online(self) -> None:
        self.network_available.set()

    def permission_checker(self, credentials: Credentials) -> None:
        with self._lock:
            self.checker_calls += 1
        client = CoinbaseClient(
            JWTSigner(credentials),
            timeout=1.0,
            transport=self._transport,
        )
        client.assert_view_only()
        self.view_only_verified_event.set()

    def _transport(
        self,
        url: str,
        headers: Mapping[str, str],
        timeout: float,
    ) -> TransportResponse:
        expected_url = API_ORIGIN + API_PREFIX + "/key_permissions"
        route_ok = url == expected_url and timeout == 1.0
        authorization = headers.get("Authorization", "")
        authorization_ok = authorization.startswith("Bearer ") and len(authorization) > 40
        with self._lock:
            self.transport_calls += 1
            self.only_permission_route = self.only_permission_route and route_ok
            self.authorization_seen = self.authorization_seen and authorization_ok
        if not self.network_available.is_set():
            with self._lock:
                self.offline_calls += 1
            self.offline_attempt_event.set()
            raise CoinbaseAPIError("upstream_unreachable")
        with self._lock:
            self.online_responses += 1
        return TransportResponse(
            status=HTTPStatus.OK,
            headers={"content-type": "application/json", "cache-control": "no-store"},
            body=json.dumps(self.permissions, separators=(",", ":")).encode("ascii"),
        )


@dataclass(frozen=True, slots=True)
class HTTPResult:
    status: int
    headers: dict[str, str]
    body: dict[str, Any]
    source_private_non_loopback: bool


def _request_json(
    host: str,
    port: int,
    *,
    host_header: str,
    method: str,
    path: str,
    device_id: str | None = None,
    token: str | None = None,
) -> HTTPResult:
    connection = http.client.HTTPConnection(host, port, timeout=3)
    try:
        connection.connect()
        source = ""
        if connection.sock is not None:
            source = str(connection.sock.getsockname()[0])
        connection.putrequest(
            method,
            path,
            skip_host=True,
            skip_accept_encoding=True,
        )
        connection.putheader("Host", host_header)
        connection.putheader("Accept", "application/json")
        if method == "POST":
            connection.putheader("Content-Length", "0")
        if device_id is not None:
            connection.putheader("X-Device-ID", device_id)
        if token is not None:
            connection.putheader("Authorization", "Bearer " + token)
        connection.endheaders()
        response = connection.getresponse()
        payload = response.read(MAX_HTTP_RESPONSE_BYTES + 1)
        _require(
            len(payload) <= MAX_HTTP_RESPONSE_BYTES,
            "local proof HTTP response exceeded its bound",
        )
        try:
            parsed = json.loads(payload or b"{}")
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("local proof endpoint returned invalid JSON") from exc
        _require(isinstance(parsed, dict), "local proof endpoint returned non-object JSON")
        return HTTPResult(
            status=int(response.status),
            headers={name.lower(): value for name, value in response.getheaders()},
            body=parsed,
            source_private_non_loopback=_private_ipv4(source) is not None,
        )
    finally:
        connection.close()


def _loopback_request(
    port: int,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: Mapping[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request(method, path, body=body, headers=dict(headers or {}))
        response = connection.getresponse()
        payload = response.read(64 * 1024 + 1)
        _require(len(payload) <= 64 * 1024, "localhost proof response exceeded its bound")
        return (
            int(response.status),
            {name.lower(): value for name, value in response.getheaders()},
            payload,
        )
    finally:
        connection.close()


class ProofRuntime:
    """Swap the pending listener for a real authenticated feed after validation."""

    def __init__(
        self,
        *,
        data_dir: str,
        host: str,
        port: int,
        gate: FakeCoinbaseGate,
    ) -> None:
        self.data_dir = data_dir
        self.host = host
        self.port = port
        self.gate = gate
        self.pending_server: Any | None = None
        self.pending_thread: threading.Thread | None = None
        self.bridge_server: Any | None = None
        self.bridge_thread: threading.Thread | None = None
        self.events: list[str] = []
        self._lock = threading.Lock()

    def attach_pending(self, server: Any) -> None:
        self.pending_server = server

    def start_pending(self) -> None:
        _require(self.pending_server is not None, "pending listener was not attached")
        thread = threading.Thread(
            target=self.pending_server.serve_forever,
            kwargs={"poll_interval": 0.05},
            name="proof-pending-claim",
            daemon=True,
        )
        self.pending_thread = thread
        thread.start()

    def stop_pending(self) -> None:
        with self._lock:
            server = self.pending_server
            thread = self.pending_thread
            self.pending_server = None
            self.pending_thread = None
        if server is None:
            return
        server.shutdown()
        server.server_close()
        if thread is not None:
            thread.join(timeout=3)
            _require(not thread.is_alive(), "pending claim listener did not stop")

    def start_bridge(
        self,
        *,
        before_change: Callable[[ServiceStartResult], None] | None = None,
    ) -> ServiceStartResult:
        if before_change is not None:
            before_change(ServiceStartResult("unavailable", "none"))
        _require(
            self.gate.view_only_verified_event.is_set(),
            "feed service started before read-only permission validation",
        )
        store = ConfigStore(self.data_dir)
        config = store.load()
        registry = DeviceRegistry(store, reload_interval=0)
        feed = SampleFeedService(config["settings"], clock=lambda: 1_700_005_000)
        app = BridgeApplication.from_settings(
            feed,
            registry,
            "sample",
            config["settings"],
        )
        server = create_server(self.host, self.port, app)
        thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.05},
            name="proof-active-feed",
            daemon=True,
        )
        with self._lock:
            self.bridge_server = server
            self.bridge_thread = thread
            self.events.append("feed_listener_started_after_validation")
        thread.start()
        return ServiceStartResult("started", "none")

    def bridge_ready(self) -> bool:
        try:
            result = _request_json(
                self.host,
                self.port,
                host_header=f"{self.host}:{self.port}",
                method="GET",
                path="/readyz",
            )
        except (OSError, RuntimeError):
            return False
        return result.status == HTTPStatus.OK and result.body.get("read_only") is True

    def stop_bridge(self) -> None:
        with self._lock:
            server = self.bridge_server
            thread = self.bridge_thread
            self.bridge_server = None
            self.bridge_thread = None
        if server is None:
            return
        server.shutdown()
        server.server_close()
        if thread is not None:
            thread.join(timeout=3)
            _require(not thread.is_alive(), "active feed listener did not stop")

    def close(self) -> None:
        self.stop_bridge()
        self.stop_pending()


def render_portal(server: Any) -> bytes:
    """Render setup metadata and empty controls, never Coinbase JSON."""

    session = server.app.session
    values = {
        "endpoint": session.endpoint_url,
        "session": session.session_id,
        "setup_token": session.setup_token,
        "setup_csrf": session.csrf_token,
        "portal_csrf": PORTAL_CSRF,
    }
    encoded = {name: json.dumps(value) for name, value in values.items()}
    return f"""<!doctype html><meta charset="utf-8">
<form id="setup" autocomplete="off">
<input id="ssid" autocomplete="off"><input id="wifiPassword" type="password" autocomplete="new-password">
<textarea id="keyText" autocomplete="off" spellcheck="false"></textarea><input id="keyFile" type="file" accept="application/json,.json">
<button id="finish" type="submit">Finish</button></form><p id="status">waiting-for-browser-input</p>
<script>'use strict';
const endpoint={encoded["endpoint"]},sessionId={encoded["session"]},setupCsrf={encoded["setup_csrf"]},portalCsrf={encoded["portal_csrf"]};
let setupToken={encoded["setup_token"]};
const authHeaders=()=>({{'Authorization':'Setup '+setupToken,'X-Setup-Session':sessionId,'X-CSRF-Token':setupCsrf,'Content-Type':'application/json'}});
async function keyDocument(){{const file=document.getElementById('keyFile').files[0];return file?await file.text():document.getElementById('keyText').value;}}
async function saveOnlySafeValues(pending){{const body=new URLSearchParams();body.set('csrf',portalCsrf);body.set('ssid',document.getElementById('ssid').value);body.set('password',document.getElementById('wifiPassword').value);body.set('bridge_url',pending.bridge_url);body.set('device_id',pending.device_id);body.set('pending_token',pending.pending_token);body.set('pending_expires_at',String(pending.expires_at));const saved=await fetch('/save',{{method:'POST',cache:'no-store',credentials:'omit',redirect:'error',referrerPolicy:'no-referrer',headers:{{'Content-Type':'application/x-www-form-urlencoded'}},body:body.toString()}});document.documentElement.dataset.saveCacheControl=saved.headers.get('cache-control')||'';if(!saved.ok)throw new Error('save');}}
document.getElementById('setup').addEventListener('submit',async event=>{{event.preventDefault();const input=document.getElementById('keyText'),file=document.getElementById('keyFile'),wifi=document.getElementById('wifiPassword'),status=document.getElementById('status'),button=document.getElementById('finish');let key='';button.disabled=true;status.textContent='staging';try{{key=await keyDocument();if(!key.trim())throw new Error('key');const response=await fetch(endpoint,{{method:'POST',mode:'cors',cache:'no-store',credentials:'omit',redirect:'error',referrerPolicy:'no-referrer',headers:authHeaders(),body:key}});key='';document.documentElement.dataset.setupResponseType=response.type;document.documentElement.dataset.setupCacheControl=response.headers.get('cache-control')||'';if(!response.ok)throw new Error('key');const pending=await response.json();setupToken='';await saveOnlySafeValues(pending);status.textContent='saved-pending';}}catch(_error){{status.textContent='failed';button.disabled=false;}}finally{{key='';input.value='';file.value='';wifi.value='';}}}});
</script>""".encode()


def _read_exact(connection: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise RuntimeError("Chrome DevTools connection closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class DevToolsConnection:
    """Small dependency-free WebSocket client for local Chrome DevTools."""

    def __init__(self, url: str) -> None:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "ws" or parsed.hostname not in {"127.0.0.1", "localhost"}:
            raise RuntimeError("Chrome returned an unsafe DevTools URL")
        port = parsed.port
        if port is None:
            raise RuntimeError("Chrome DevTools URL has no port")
        self.connection = socket.create_connection((parsed.hostname, port), timeout=5)
        self.connection.settimeout(10)
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        target = urllib.parse.urlunsplit(("", "", parsed.path, parsed.query, ""))
        request = (
            f"GET {target} HTTP/1.1\r\n"
            f"Host: {parsed.hostname}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Origin: http://127.0.0.1\r\n\r\n"
        ).encode("ascii")
        self.connection.sendall(request)
        response = bytearray()
        while b"\r\n\r\n" not in response and len(response) <= 16_384:
            response.extend(self.connection.recv(4096))
        if not response.startswith(b"HTTP/1.1 101 "):
            self.connection.close()
            raise RuntimeError("Chrome refused the local DevTools WebSocket")
        expected = base64.b64encode(
            hashlib.sha1(  # noqa: S324 - required by RFC 6455, not security use.
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
            ).digest()
        )
        if b"sec-websocket-accept: " + expected.lower() not in bytes(response).lower():
            self.connection.close()
            raise RuntimeError("Chrome DevTools WebSocket handshake was invalid")
        self._next_id = 1

    def close(self) -> None:
        try:
            self._send_frame(b"", opcode=0x8)
        except OSError:
            pass
        self.connection.close()

    def _send_frame(self, payload: bytes, *, opcode: int = 0x1) -> None:
        mask = secrets.token_bytes(4)
        length = len(payload)
        if length < 126:
            header = bytes((0x80 | opcode, 0x80 | length))
        elif length <= 0xFFFF:
            header = bytes((0x80 | opcode, 0x80 | 126)) + struct.pack(">H", length)
        else:
            header = bytes((0x80 | opcode, 0x80 | 127)) + struct.pack(">Q", length)
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        self.connection.sendall(header + mask + masked)

    def _receive_text(self) -> str:
        fragments = bytearray()
        while True:
            first, second = _read_exact(self.connection, 2)
            final = bool(first & 0x80)
            opcode = first & 0x0F
            masked = bool(second & 0x80)
            length = second & 0x7F
            if length == 126:
                length = struct.unpack(">H", _read_exact(self.connection, 2))[0]
            elif length == 127:
                length = struct.unpack(">Q", _read_exact(self.connection, 8))[0]
            if length > MAX_CDP_MESSAGE_BYTES:
                raise RuntimeError("Chrome DevTools message exceeded its bound")
            mask = _read_exact(self.connection, 4) if masked else b""
            payload = _read_exact(self.connection, length)
            if masked:
                payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
            if opcode == 0x8:
                raise RuntimeError("Chrome DevTools connection closed")
            if opcode == 0x9:
                self._send_frame(payload, opcode=0xA)
                continue
            if opcode not in {0x0, 0x1}:
                continue
            fragments.extend(payload)
            if final:
                return fragments.decode("utf-8")

    def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        identifier = self._next_id
        self._next_id += 1
        message = {"id": identifier, "method": method, "params": params or {}}
        self._send_frame(json.dumps(message, separators=(",", ":")).encode("utf-8"))
        while True:
            value = json.loads(self._receive_text())
            if value.get("id") != identifier:
                continue
            if "error" in value:
                raise RuntimeError("Chrome DevTools command failed")
            result = value.get("result")
            return result if isinstance(result, dict) else {}


def _wait_for_devtools(profile: Path, process: subprocess.Popen[bytes], target_url: str) -> str:
    active_port = profile / "DevToolsActivePort"
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Google Chrome proof process exited early")
        if active_port.is_file():
            lines = active_port.read_text(encoding="ascii").splitlines()
            if lines and lines[0].isdigit():
                endpoint = f"http://127.0.0.1:{int(lines[0])}/json/list"
                try:
                    with urllib.request.urlopen(endpoint, timeout=1) as response:  # noqa: S310
                        targets = json.load(response)
                except (OSError, ValueError):
                    targets = []
                for target in targets:
                    if (
                        isinstance(target, dict)
                        and target.get("type") == "page"
                        and str(target.get("url", "")).startswith(target_url)
                        and isinstance(target.get("webSocketDebuggerUrl"), str)
                    ):
                        return target["webSocketDebuggerUrl"]
        time.sleep(0.05)
    raise RuntimeError("Google Chrome DevTools endpoint did not become ready")


def _evaluate_value(devtools: DevToolsConnection, expression: str) -> Any:
    result = devtools.call(
        "Runtime.evaluate",
        {
            "expression": expression,
            "returnByValue": True,
            "awaitPromise": True,
        },
    )
    if result.get("exceptionDetails"):
        raise RuntimeError("Chrome page evaluation failed")
    remote = result.get("result")
    return remote.get("value") if isinstance(remote, dict) else None


def _focus_and_insert(devtools: DevToolsConnection, selector: str, value: str) -> None:
    expression = (
        "(()=>{const input=document.querySelector("
        + json.dumps(selector)
        + ");if(!input)return false;input.focus();input.value='';return true;})()"
    )
    _require(
        _evaluate_value(devtools, expression) is True,
        "Chrome could not focus a synthetic proof input",
    )
    devtools.call("Input.insertText", {"text": value})


def _fill_and_submit_browser_form(devtools: DevToolsConnection) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        ready = _evaluate_value(
            devtools,
            "document.readyState === 'complete' && !!document.getElementById('keyText')",
        )
        if ready is True:
            break
        time.sleep(0.05)
    else:
        raise RuntimeError("fake ESP form did not become ready in Chrome")

    _focus_and_insert(devtools, "#ssid", SYNTHETIC_SSID)
    _focus_and_insert(devtools, "#wifiPassword", SYNTHETIC_WIFI_PASSWORD)
    key_document = _synthetic_key_json()
    try:
        _focus_and_insert(devtools, "#keyText", key_document)
    finally:
        key_document = ""
    submitted = _evaluate_value(
        devtools,
        "(()=>{const form=document.getElementById('setup');"
        "if(!form||!document.getElementById('keyText').value)return false;"
        "form.requestSubmit();return true;})()",
    )
    _require(submitted is True, "Chrome did not submit the synthetic browser input")


def _wait_browser_status(devtools: DevToolsConnection, expected: str) -> None:
    deadline = time.monotonic() + 15
    status: Any = ""
    while time.monotonic() < deadline:
        status = _evaluate_value(devtools, "document.getElementById('status').textContent")
        if status == expected or status == "failed":
            break
        time.sleep(0.05)
    if status != expected:
        raise RuntimeError(f"Chrome portal did not reach {expected!r}; status={status!r}")


def _chrome_version(chrome: Path) -> str:
    completed = subprocess.run(
        [str(chrome), "--version"],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=5,
    )
    value = completed.stdout.decode("utf-8", errors="replace").strip()
    return value if completed.returncode == 0 and value else "Google Chrome (version unavailable)"


def _decode_fake_esp_payload(
    state: FakeEspState,
    expected: SafeProvisioning,
) -> SafeProvisioning:
    try:
        decoded = urllib.parse.parse_qs(
            state.saved_body.decode("utf-8"),
            keep_blank_values=True,
            strict_parsing=True,
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise RuntimeError("fake ESP received malformed form data") from exc
    _require(set(decoded) == EXPECTED_ESP_FIELDS, "fake ESP fields were not the safe allowlist")
    _require(
        all(len(values) == 1 for values in decoded.values()),
        "fake ESP received duplicate form fields",
    )
    values = {name: entries[0] for name, entries in decoded.items()}
    _require(values["csrf"] == PORTAL_CSRF, "fake ESP portal CSRF changed")
    _require(values["ssid"] == SYNTHETIC_SSID, "fake ESP Wi-Fi name changed")
    _require(
        values["password"] == SYNTHETIC_WIFI_PASSWORD,
        "fake ESP Wi-Fi password changed",
    )
    try:
        expires_at = int(values["pending_expires_at"])
    except ValueError as exc:
        raise RuntimeError("fake ESP pending expiry was invalid") from exc
    observed = SafeProvisioning(
        bridge_url=values["bridge_url"],
        device_id=values["device_id"],
        feed_token=values["pending_token"],
        expires_at=expires_at,
    )
    _require(observed == expected, "fake ESP safe provisioning values changed")
    _require("feed_token" not in decoded, "active feed token field reached fake ESP")
    return observed


def _assert_no_coinbase_material_in_esp(state: FakeEspState) -> None:
    decoded_body = urllib.parse.unquote_plus(
        state.saved_body.decode("ascii", errors="ignore")
    ).encode("utf-8")
    state_material = state.page + b"\n" + state.saved_body + b"\n" + decoded_body
    lowered = state_material.lower()
    for marker in (
        SYNTHETIC_KEY_NAME.encode("ascii").lower(),
        b"privatekey",
        b"begin private key",
        b"begin ec private key",
    ):
        _require(marker not in lowered, "Coinbase key name or material reached fake ESP state")


def _wait_pending_status(app: Any, expected: str) -> None:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if app.public_status().get("status") == expected:
            return
        time.sleep(0.02)
    raise RuntimeError("pending listener did not expose the expected status")


def _run_browser_flow(
    chrome: Path,
    *,
    portal_host: str,
    portal_alias: str,
) -> tuple[dict[str, Any], bool]:
    selected_address = _private_ipv4(portal_host)
    _require(selected_address is not None, "portal host was not a private-LAN IPv4 address")
    bridge_port = _free_port(portal_host)
    bridge_url = f"http://{portal_host}:{bridge_port}/v1/device-feed"
    bridge_host_header = f"{portal_host}:{bridge_port}"

    temporary = tempfile.TemporaryDirectory(prefix="cbat-deferred-proof-")
    profile = Path(tempfile.mkdtemp(prefix="cbat-chrome-proof-"))
    gate = FakeCoinbaseGate()
    runtime = ProofRuntime(
        data_dir=temporary.name,
        host=portal_host,
        port=bridge_port,
        gate=gate,
    )
    coordinator: OnboardingCoordinator | None = None
    onboarding: Any | None = None
    esp: FakeEspServer | None = None
    onboarding_thread: threading.Thread | None = None
    esp_thread: threading.Thread | None = None
    process: subprocess.Popen[bytes] | None = None
    devtools: DevToolsConnection | None = None
    finish_thread: threading.Thread | None = None
    finish_errors: list[BaseException] = []
    finalized = False

    try:
        coordinator = OnboardingCoordinator(
            temporary.name,
            bridge_url=bridge_url,
            permission_checker=gate.permission_checker,
            service_starter=runtime.start_bridge,
            readiness_checker=runtime.bridge_ready,
            finish_timeout_seconds=8,
            retry_interval=0.1,
            pending_ttl_seconds=60,
        )
        pending_server = create_pending_claim_server(
            coordinator,
            bridge_url=bridge_url,
            bind_host=portal_host,
        )
        runtime.attach_pending(pending_server)

        state = FakeEspState()
        esp = FakeEspServer(state, portal_host)
        portal_origin = f"http://{portal_alias}:{esp.server_address[1]}"
        state.expected_host = urllib.parse.urlsplit(portal_origin).netloc
        onboarding = create_onboarding_server(
            coordinator,
            ttl_seconds=120,
            portal_origin=portal_origin,
            on_staged=pending_server.app.set_pending,
        )
        observation = OnboardingObservation()
        onboarding.proof_observation = observation
        onboarding.RequestHandlerClass = ObservedOnboardingRequestHandler
        replay_token = onboarding.app.session.setup_token
        state.page = render_portal(onboarding)
        _assert_no_coinbase_material_in_esp(state)
        _require(
            FINISH_PATH.encode("ascii") not in state.page,
            "legacy browser finalization metadata reached portal",
        )

        runtime.start_pending()
        onboarding_thread = threading.Thread(
            target=onboarding.serve_forever,
            kwargs={"poll_interval": 0.05},
            name="proof-localhost-onboarding",
            daemon=True,
        )
        esp_thread = threading.Thread(
            target=esp.serve_forever,
            kwargs={"poll_interval": 0.05},
            name="proof-private-lan-esp",
            daemon=True,
        )
        onboarding_thread.start()
        esp_thread.start()

        process = subprocess.Popen(
            [
                str(chrome),
                "--headless=new",
                "--incognito",
                "--disable-gpu",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-background-networking",
                "--disable-component-update",
                "--disable-sync",
                "--no-proxy-server",
                f"--host-resolver-rules=MAP {portal_alias} {portal_host}",
                "--remote-debugging-port=0",
                "--remote-allow-origins=http://127.0.0.1",
                f"--user-data-dir={profile}",
                portal_origin + "/",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        websocket_url = _wait_for_devtools(profile, process, portal_origin)
        devtools = DevToolsConnection(websocket_url)
        _fill_and_submit_browser_form(devtools)
        if not state.saved_event.wait(timeout=15):
            status = _evaluate_value(devtools, "document.getElementById('status').textContent")
            raise RuntimeError(f"fake ESP did not receive pending setup; status={status!r}")
        _wait_browser_status(devtools, "saved-pending")
        _require(
            onboarding.app.session.provisioned_event.is_set(),
            "localhost setup was not durably staged",
        )
        pending = onboarding.app.session.safe_provisioning()
        _require(pending is not None, "staged provisioning was unavailable")
        assert pending is not None
        esp_pending = _decode_fake_esp_payload(state, pending)
        _assert_no_coinbase_material_in_esp(state)

        ui = _evaluate_value(
            devtools,
            "(()=>({origin:location.origin,status:document.getElementById('status').textContent,"
            "keyLength:document.getElementById('keyText').value.length,"
            "fileLength:document.getElementById('keyFile').value.length,"
            "wifiLength:document.getElementById('wifiPassword').value.length,"
            "setupTokenEmpty:setupToken==='',localStorageLength:localStorage.length,"
            "sessionStorageLength:sessionStorage.length,responseType:document.documentElement.dataset.setupResponseType||'',"
            "setupCache:document.documentElement.dataset.setupCacheControl||'',"
            "saveCache:document.documentElement.dataset.saveCacheControl||''}))()",
        )
        _require(isinstance(ui, dict), "Chrome did not return safe UI observations")
        _require(ui.get("origin") == portal_origin, "Chrome used the wrong portal origin")
        _require(ui.get("status") == "saved-pending", "browser waited for a legacy ACK")
        _require(ui.get("keyLength") == 0, "browser key textarea was not cleared")
        _require(ui.get("fileLength") == 0, "browser key file input was not cleared")
        _require(ui.get("wifiLength") == 0, "browser Wi-Fi password was not cleared")
        _require(ui.get("setupTokenEmpty") is True, "browser setup bearer was not cleared")
        _require(ui.get("localStorageLength") == 0, "browser stored setup data locally")
        _require(ui.get("sessionStorageLength") == 0, "browser stored setup data in session")
        _require(ui.get("responseType") == "cors", "Chrome did not expose a CORS response")
        _require(
            ui.get("setupCache") == "no-store, max-age=0",
            "localhost setup response was cacheable",
        )
        _require(
            ui.get("saveCache") == "no-store, max-age=0",
            "fake ESP save response was cacheable",
        )

        browser_preflights, browser_posts = observation.snapshot()
        _require(browser_posts == [ONBOARDING_PATH], "browser used an unexpected setup POST route")
        matching_preflights = [
            item
            for item in browser_preflights
            if item.path == ONBOARDING_PATH
            and item.origin == portal_origin
            and item.requested_method == "POST"
            and item.requested_headers == REQUIRED_CORS_HEADERS
        ]
        _require(bool(matching_preflights), "Chrome did not perform the exact CORS preflight")
        browser_pna_observed = any(item.private_network for item in matching_preflights)
        _require(
            onboarding.app.pna_preflight_event.is_set() == browser_pna_observed,
            "browser PNA observation was inconsistent",
        )

        _require(gate.transport_calls == 0, "Coinbase validation ran during local staging")
        _require(
            active_local_credential_slot(temporary.name) is None,
            "credentials became active during local staging",
        )
        _require(
            not Path(temporary.name, "config.json").exists(),
            "device feed config became active during local staging",
        )

        replay_status, replay_headers, _ = _loopback_request(
            onboarding.server_address[1],
            "POST",
            ONBOARDING_PATH,
            body=b"{}",
            headers={
                "Origin": portal_origin,
                "Authorization": "Setup " + replay_token,
                "X-Setup-Session": onboarding.app.session.session_id,
                "X-CSRF-Token": onboarding.app.session.csrf_token,
                "Content-Type": "application/json",
            },
        )
        _require(replay_status == HTTPStatus.FORBIDDEN, "setup bearer was reusable")
        _require(
            replay_headers.get("cache-control") == "no-store, max-age=0",
            "one-use rejection was cacheable",
        )
        _require(onboarding.app.session.setup_token == "", "used setup bearer was retained")

        page_status, _, page_body = _loopback_request(
            onboarding.server_address[1],
            "GET",
            f"/setup/{onboarding.app.session.session_id}",
        )
        _require(page_status == HTTPStatus.GONE, "used local setup page remained available")
        _require(replay_token.encode("ascii") not in page_body, "used setup bearer was re-rendered")

        legacy_status, _, _ = _loopback_request(
            onboarding.server_address[1],
            "POST",
            FINISH_PATH,
            body=b"",
        )
        _require(
            legacy_status == HTTPStatus.NOT_FOUND, "legacy browser finish route remained active"
        )

        pna_status, pna_headers, _ = _loopback_request(
            onboarding.server_address[1],
            "OPTIONS",
            ONBOARDING_PATH,
            headers={
                "Origin": portal_origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": ", ".join(sorted(REQUIRED_CORS_HEADERS)),
                "Access-Control-Request-Private-Network": "true",
            },
        )
        _require(pna_status == HTTPStatus.NO_CONTENT, "PNA opt-in preflight failed")
        _require(
            pna_headers.get("access-control-allow-origin") == portal_origin,
            "PNA opt-in used the wrong CORS origin",
        )
        _require(
            pna_headers.get("access-control-allow-private-network") == "true",
            "localhost endpoint did not opt into PNA",
        )
        _require(
            pna_headers.get("cache-control") == "no-store, max-age=0",
            "PNA response was cacheable",
        )

        _require(state.host_headers, "Chrome did not reach the fake ESP alias")
        _require(
            all(value == state.expected_host for value in state.host_headers),
            "Chrome bypassed the fake ESP host alias",
        )
        _require(
            all(_private_ipv4(value) is not None for value in state.client_addresses),
            "fake ESP traffic used a loopback source",
        )

        pending_status = _request_json(
            portal_host,
            bridge_port,
            host_header=bridge_host_header,
            method="GET",
            path=PENDING_STATUS_PATH,
            device_id=esp_pending.device_id,
            token=esp_pending.feed_token,
        )
        _require(pending_status.status == HTTPStatus.OK, "ESP pending status failed")
        _require(
            pending_status.body.get("status") == "waiting_for_network",
            "pending setup had the wrong initial state",
        )
        _require(
            pending_status.headers.get("cache-control") == "no-store, max-age=0",
            "pending status response was cacheable",
        )
        _require(
            pending_status.source_private_non_loopback,
            "ESP status request did not use the LAN interface",
        )

        staged_feed = _request_json(
            portal_host,
            bridge_port,
            host_header=bridge_host_header,
            method="GET",
            path="/v1/device-feed",
            device_id=esp_pending.device_id,
            token=esp_pending.feed_token,
        )
        _require(staged_feed.status != HTTPStatus.OK, "device feed was active before claim")

        claim = _request_json(
            portal_host,
            bridge_port,
            host_header=bridge_host_header,
            method="POST",
            path=PENDING_CLAIM_PATH,
            device_id=esp_pending.device_id,
            token=esp_pending.feed_token,
        )
        _require(claim.status == HTTPStatus.OK, "ESP claim failed")
        _require(
            claim.body.get("status") == "checking_read_only_key",
            "ESP claim did not arm deferred validation",
        )
        _require(claim.source_private_non_loopback, "ESP claim did not use the LAN interface")
        _require(pending_server.app.claimed_event.is_set(), "ESP claim event was not recorded")

        def finish() -> None:
            try:
                coordinator.finish_pending(
                    esp_pending,
                    status_callback=pending_server.app.set_status,
                    before_service_start=runtime.stop_pending,
                )
            except BaseException as exc:
                finish_errors.append(exc)

        finish_thread = threading.Thread(target=finish, name="proof-deferred-validation")
        finish_thread.start()
        _require(
            gate.offline_attempt_event.wait(timeout=3),
            "claimed setup did not attempt the fake offline Coinbase gate",
        )
        _wait_pending_status(pending_server.app, "waiting_for_network")
        offline_status = _request_json(
            portal_host,
            bridge_port,
            host_header=bridge_host_header,
            method="GET",
            path=PENDING_STATUS_PATH,
            device_id=esp_pending.device_id,
            token=esp_pending.feed_token,
        )
        _require(
            offline_status.status == HTTPStatus.OK
            and offline_status.body.get("status") == "waiting_for_network",
            "ESP did not observe the offline deferred-validation state",
        )
        offline_feed = _request_json(
            portal_host,
            bridge_port,
            host_header=bridge_host_header,
            method="GET",
            path="/v1/device-feed",
            device_id=esp_pending.device_id,
            token=esp_pending.feed_token,
        )
        _require(
            offline_feed.status != HTTPStatus.OK,
            "device feed activated while Coinbase was unavailable",
        )
        _require(
            active_local_credential_slot(temporary.name) is None,
            "credentials activated before read-only validation",
        )
        _require(
            not Path(temporary.name, "config.json").exists(),
            "device allowlist activated before read-only validation",
        )

        gate.set_online()
        finish_thread.join(timeout=12)
        _require(not finish_thread.is_alive(), "deferred validation did not finish")
        if finish_errors:
            raise RuntimeError("deferred validation failed") from finish_errors[0]
        _require(
            gate.view_only_verified_event.is_set(),
            "fake Coinbase read-only permission validation did not pass",
        )
        _require(gate.offline_calls >= 1, "offline Coinbase state was not exercised")
        _require(gate.online_responses == 1, "read-only permission gate was not one success")
        _require(gate.only_permission_route, "fake Coinbase saw a non-permission route")
        _require(gate.authorization_seen, "fake Coinbase request was not JWT-authenticated")
        _require(
            gate.permissions == {"can_view": True, "can_trade": False, "can_transfer": False},
            "fake Coinbase permissions were not view-only",
        )
        _require(
            runtime.events == ["feed_listener_started_after_validation"],
            "feed listener activation order was wrong",
        )
        onboarding.app.session.mark_finished()

        active_feed = _request_json(
            portal_host,
            bridge_port,
            host_header=bridge_host_header,
            method="GET",
            path="/v1/device-feed",
            device_id=esp_pending.device_id,
            token=esp_pending.feed_token,
        )
        _require(active_feed.status == HTTPStatus.OK, "validated device feed was not active")
        _require(active_feed.body.get("read_only") is True, "active feed was not read-only")
        _require(active_feed.body.get("mode") == "sample", "proof feed was not offline sample data")
        _require(
            active_feed.headers.get("cache-control") == "no-store",
            "active feed response was cacheable",
        )
        active_status = _request_json(
            portal_host,
            bridge_port,
            host_header=bridge_host_header,
            method="GET",
            path=PENDING_STATUS_PATH,
            device_id=esp_pending.device_id,
            token=esp_pending.feed_token,
        )
        _require(
            active_status.status == HTTPStatus.OK and active_status.body.get("status") == "ready",
            "active bridge did not return the ready receipt",
        )
        _require(onboarding.app.session.finished_event.is_set(), "setup session was not finished")
        _require(not coordinator.journal_path.exists(), "completed onboarding journal remained")
        _require(
            active_local_credential_slot(temporary.name) is not None,
            "validated credentials were not active",
        )
        _require(
            _evaluate_value(devtools, "document.getElementById('status').textContent")
            == "saved-pending",
            "browser incorrectly performed final activation",
        )
        _assert_no_coinbase_material_in_esp(state)
        finalized = True

        result = {
            "browser_completion_route_status": int(legacy_status),
            "coinbase_transport": "in-memory fake",
            "cors_preflight_exact": True,
            "cors_response_type": "cors",
            "device_feed_status": {
                "staged": int(staged_feed.status),
                "claimed_offline": int(offline_feed.status),
                "validated": int(active_feed.status),
            },
            "esp_payload_fields": sorted(EXPECTED_ESP_FIELDS),
            "fake_esp_key_name_or_material": False,
            "fake_permissions": gate.permissions,
            "key_input_source": "Chrome CDP Input.insertText",
            "localhost_no_store": True,
            "pending_claim_from_private_lan": True,
            "portal_alias": portal_alias,
            "portal_bound_private_non_loopback": True,
            "setup_bearer_replay_status": int(replay_status),
            "ui_secret_inputs_cleared": True,
            "validation_deferred_until_esp_claim": True,
            "validated_feed_read_only": True,
        }
        return result, browser_pna_observed
    finally:
        gate.set_online()
        if finish_thread is not None and finish_thread.is_alive():
            finish_thread.join(timeout=10)
        if devtools is not None:
            devtools.close()
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        shutil.rmtree(profile, ignore_errors=True)
        if onboarding is not None and onboarding_thread is not None:
            onboarding.shutdown()
            onboarding.server_close()
            onboarding_thread.join(timeout=3)
        if esp is not None and esp_thread is not None:
            esp.shutdown()
            esp.server_close()
            esp_thread.join(timeout=3)
        runtime.close()
        if coordinator is not None:
            if not finalized:
                try:
                    coordinator.rollback_pending()
                except Exception as cleanup_error:
                    finish_errors.append(cleanup_error)
            coordinator.close()
        temporary.cleanup()


def _prove_unsafe_permissions() -> dict[str, bool]:
    results: dict[str, bool] = {}
    for index, capability in enumerate(("can_trade", "can_transfer"), start=1):
        with tempfile.TemporaryDirectory(prefix="cbat-unsafe-proof-") as data_dir:
            permissions = {
                "can_view": True,
                "can_trade": capability == "can_trade",
                "can_transfer": capability == "can_transfer",
            }
            gate = FakeCoinbaseGate(**permissions)
            gate.set_online()
            service_called = False

            def forbidden_service(**kwargs: Any) -> ServiceStartResult:
                nonlocal service_called
                service_called = True
                raise AssertionError("unsafe credential reached service activation")

            coordinator = OnboardingCoordinator(
                data_dir,
                bridge_url="http://127.0.0.1:48788/v1/device-feed",
                permission_checker=gate.permission_checker,
                service_starter=forbidden_service,
                readiness_checker=lambda: False,
                finish_timeout_seconds=1,
                retry_interval=0,
                pending_ttl_seconds=60,
            )
            try:
                pending = coordinator.complete(
                    _proof_credentials(30 + index, f"unsafe-{capability}")
                )
                _require(gate.transport_calls == 0, "unsafe key was checked before claim")
                coordinator.claim_pending(
                    device_id=pending.device_id,
                    token=pending.feed_token,
                )
                rejected = False
                try:
                    coordinator.finish_pending(pending)
                except UnsafeCredentialError:
                    rejected = True
                _require(rejected, f"{capability} permission was not rejected")
                _require(not service_called, "unsafe credential activated the feed service")
                _require(not coordinator.journal_path.exists(), "unsafe pending journal remained")
                _require(
                    active_local_credential_slot(data_dir) is None,
                    "unsafe credentials became active",
                )
                config_path = Path(data_dir, "config.json")
                if config_path.exists():
                    _require(
                        pending.device_id not in ConfigStore(data_dir).load()["devices"],
                        "unsafe device entered the allowlist",
                    )
                results[capability] = True
            finally:
                coordinator.rollback_pending()
                coordinator.close()
    return results


def _prove_pending_expiry_cleanup() -> dict[str, bool]:
    with tempfile.TemporaryDirectory(prefix="cbat-expiry-proof-") as data_dir:
        first = OnboardingCoordinator(
            data_dir,
            bridge_url="http://127.0.0.1:48789/v1/device-feed",
            permission_checker=lambda credentials: None,
            service_starter=lambda **kwargs: ServiceStartResult("started", "none"),
            readiness_checker=lambda: True,
            finish_timeout_seconds=1,
            retry_interval=0,
            pending_ttl_seconds=60,
        )
        try:
            first.complete(_proof_credentials(41, "expired"))
            journal = first.journal_path
            value = json.loads(journal.read_text(encoding="ascii"))
            value["expires_at"] = int(time.time()) - 1
            journal.write_text(
                json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n",
                encoding="ascii",
            )
            os.chmod(journal, stat.S_IRUSR | stat.S_IWUSR)
        finally:
            first.close()

        recovered = OnboardingCoordinator(
            data_dir,
            bridge_url="http://127.0.0.1:48789/v1/device-feed",
            permission_checker=lambda credentials: None,
            service_starter=lambda **kwargs: ServiceStartResult("started", "none"),
            readiness_checker=lambda: True,
            finish_timeout_seconds=1,
            retry_interval=0,
            pending_ttl_seconds=60,
        )
        try:
            _require(recovered.pending_provisioning() is None, "expired setup recovered")
            _require(not recovered.journal_path.exists(), "expired journal remained")
            _require(
                active_local_credential_slot(data_dir) is None,
                "expired credentials became active",
            )
            _require(
                not list(Path(data_dir).glob(".onboarding/txn_*.device-token")),
                "expired pending token remained",
            )
            slots = Path(data_dir, "secrets", "credential-slots")
            _require(
                not slots.exists() or not list(slots.glob("onboarding_*.bundle")),
                "expired credential slot remained",
            )
            return {
                "feed_never_activated": True,
                "journal_removed": True,
                "pending_token_removed": True,
                "staged_credentials_removed": True,
            }
        finally:
            recovered.rollback_pending()
            recovered.close()


def run(
    chrome: Path,
    *,
    portal_host: str | None = None,
    portal_alias: str = DEFAULT_PORTAL_ALIAS,
) -> dict[str, Any]:
    selected_host = portal_host or private_portal_host()
    alias = _validate_portal_alias(portal_alias)
    browser_assertions, browser_pna_observed = _run_browser_flow(
        chrome,
        portal_host=selected_host,
        portal_alias=alias,
    )
    unsafe = _prove_unsafe_permissions()
    expiry = _prove_pending_expiry_cleanup()
    chrome_version = _chrome_version(chrome)
    limitation = None
    if not browser_pna_observed:
        limitation = (
            "This Chrome build omitted the legacy "
            "Access-Control-Request-Private-Network header; exact CORS preflight, "
            "private-LAN-to-loopback success, and server PNA opt-in were verified."
        )
    return {
        "assertions": browser_assertions,
        "chrome": chrome_version,
        "host_os": f"macOS {platform.mac_ver()[0] or 'unknown'}",
        "pna": {
            "browser_legacy_header_observed": browser_pna_observed,
            "limitation": limitation,
            "server_allow_private_network_verified": True,
        },
        "supporting_assertions": {
            "pending_expiry_cleanup": expiry,
            "unsafe_permission_rejection": unsafe,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chrome", type=Path, default=DEFAULT_CHROME)
    parser.add_argument("--portal-host")
    parser.add_argument("--portal-alias", default=DEFAULT_PORTAL_ALIAS)
    args = parser.parse_args()
    if not args.chrome.is_file():
        parser.error("Google Chrome was not found")
    print(
        json.dumps(
            run(
                args.chrome,
                portal_host=args.portal_host,
                portal_alias=args.portal_alias,
            ),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
