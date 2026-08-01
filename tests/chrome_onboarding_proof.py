#!/usr/bin/env python3
# ruff: noqa: E501
"""Exercise private-LAN-to-loopback onboarding in real Google Chrome."""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bridge" / "src"))

from coinbase_amoled_bridge.onboarding import (  # noqa: E402
    FINISH_PATH,
    SafeProvisioning,
    create_onboarding_server,
)

DEFAULT_CHROME = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
MAX_CDP_MESSAGE_BYTES = 1_048_576


class ProofCoordinator:
    def __init__(self) -> None:
        self.calls = 0
        self.finishes = 0

    def complete(self, credentials: Any) -> SafeProvisioning:
        del credentials
        self.calls += 1
        return SafeProvisioning(
            bridge_url="http://100.100.20.10:8788/v1/device-feed",
            device_id="123e4567-e89b-42d3-a456-426614174000",
            feed_token="cbat_" + ("A" * 43),
        )

    def finish_pending(self, provisioning: SafeProvisioning) -> None:
        del provisioning
        self.finishes += 1

    def rollback_pending(self) -> None:
        return


@dataclass(slots=True)
class FakeEspState:
    page: bytes = b""
    saved_body: bytes = b""
    saved_event: threading.Event = field(default_factory=threading.Event)


class FakeEspServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, state: FakeEspState, host: str) -> None:
        self.state = state
        super().__init__((host, 0), FakeEspHandler)


class FakeEspHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    @property
    def state(self) -> FakeEspState:
        return self.server.state  # type: ignore[attr-defined,no-any-return]

    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        if self.path != "/":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; connect-src 'self' http://127.0.0.1:*",
        )
        self.send_header("Content-Length", str(len(self.state.page)))
        self.end_headers()
        self.wfile.write(self.state.page)

    def do_POST(self) -> None:
        if self.path != "/save":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        lengths = self.headers.get_all("Content-Length", [])
        if (
            len(lengths) != 1
            or self.headers.get("Content-Type") != "application/x-www-form-urlencoded"
        ):
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        try:
            length = int(lengths[0])
        except ValueError:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        if not 1 <= length <= 4096:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        body = self.rfile.read(length)
        if len(body) != length:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        self.state.saved_body = body
        self.state.saved_event.set()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")


def synthetic_key_json() -> str:
    # A deterministic test-only scalar makes the proof reproducible and can
    # never be confused with a downloaded Coinbase credential.
    key = ec.derive_private_key(23, ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode("ascii")
    return json.dumps(
        {
            "name": "organizations/synthetic-test/apiKeys/chrome-proof",
            "privateKey": pem,
        },
        separators=(",", ":"),
    )


def render_portal(server: Any) -> bytes:
    """Render auth metadata and an empty browser input—never a Coinbase key."""

    session = server.app.session
    values = {
        "endpoint": session.endpoint_url,
        "finish": session.endpoint_origin + FINISH_PATH,
        "session": session.session_id,
        "setup_token": session.setup_token,
        "completion_token": session.completion_token,
        "csrf": session.csrf_token,
    }
    encoded = {name: json.dumps(value) for name, value in values.items()}
    return f"""<!doctype html><meta charset="utf-8">
<form id="setup" autocomplete="off"><textarea id="keyText" autocomplete="off"></textarea><button>Finish</button></form><p id="status">waiting-for-browser-input</p>
<script>'use strict';
const endpoint={encoded["endpoint"]},finishEndpoint={encoded["finish"]},sessionId={encoded["session"]},setupCsrf={encoded["csrf"]};
let setupToken={encoded["setup_token"]},completionToken={encoded["completion_token"]};
const headersFor=token=>({{'Authorization':'Setup '+token,'X-Setup-Session':sessionId,'X-CSRF-Token':setupCsrf}});
document.getElementById('setup').addEventListener('submit',async event=>{{event.preventDefault();const input=document.getElementById('keyText'),status=document.getElementById('status');let key=input.value;input.value='';try{{const headers=headersFor(setupToken);headers['Content-Type']='application/json';const response=await fetch(endpoint,{{method:'POST',mode:'cors',cache:'no-store',credentials:'omit',redirect:'error',referrerPolicy:'no-referrer',headers,body:key}});key='';if(!response.ok)throw new Error('key');setupToken='';const provisioning=await response.json();const safe=new URLSearchParams();safe.set('csrf','fake-portal-csrf');safe.set('ssid','SyntheticNetwork');safe.set('password','synthetic-password');safe.set('bridge_url',provisioning.bridge_url);safe.set('device_id',provisioning.device_id);safe.set('bridge_token',provisioning.feed_token);const saved=await fetch('/save',{{method:'POST',cache:'no-store',credentials:'omit',redirect:'error',headers:{{'Content-Type':'application/x-www-form-urlencoded'}},body:safe.toString()}});if(!saved.ok)throw new Error('save');const finished=await fetch(finishEndpoint,{{method:'POST',mode:'cors',cache:'no-store',credentials:'omit',redirect:'error',referrerPolicy:'no-referrer',headers:headersFor(completionToken)}});if(!finished.ok)throw new Error('finish');completionToken='';status.textContent='complete';}}catch(error){{status.textContent='failed:'+error.message;}}finally{{key='';input.value='';}}}});
</script>""".encode()


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
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if (
            isinstance(address, ipaddress.IPv4Address)
            and address.is_private
            and not address.is_loopback
            and not address.is_link_local
        ):
            return str(address)
    raise RuntimeError("no non-loopback private-LAN address is available")


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
    """Small, dependency-free WebSocket client for local Chrome DevTools."""

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
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
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
    deadline = time.monotonic() + 10
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
    remote = result.get("result")
    return remote.get("value") if isinstance(remote, dict) else None


def _inject_browser_key(devtools: DevToolsConnection, key_document: str) -> None:
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
    expression = (
        "(()=>{const input=document.getElementById('keyText');"
        f"input.value={json.dumps(key_document)};"
        "input.dispatchEvent(new Event('input',{bubbles:true}));"
        "document.getElementById('setup').requestSubmit();return true;})()"
    )
    if _evaluate_value(devtools, expression) is not True:
        raise RuntimeError("Chrome did not accept the synthetic browser input")


def run(chrome: Path, *, portal_host: str | None = None) -> dict[str, Any]:
    state = FakeEspState()
    selected_host = portal_host or private_portal_host()
    try:
        selected_address = ipaddress.ip_address(selected_host)
    except ValueError as exc:
        raise RuntimeError("Chrome proof portal host must be an IP address") from exc
    if (
        not isinstance(selected_address, ipaddress.IPv4Address)
        or not selected_address.is_private
        or selected_address.is_loopback
        or selected_address.is_link_local
    ):
        raise RuntimeError(
            "Chrome proof requires a non-loopback private-LAN IPv4 address"
        )
    esp = FakeEspServer(state, selected_host)
    esp_origin = f"http://{selected_host}:{esp.server_address[1]}"
    coordinator = ProofCoordinator()
    onboarding = create_onboarding_server(
        coordinator,
        ttl_seconds=120,
        portal_origin=esp_origin,
    )
    key_document = synthetic_key_json()
    state.page = render_portal(onboarding)
    if key_document.encode() in state.page:
        raise RuntimeError("synthetic Coinbase input was embedded in fake ESP HTML")
    threads = [
        threading.Thread(target=esp.serve_forever, daemon=True),
        threading.Thread(target=onboarding.serve_forever, daemon=True),
    ]
    for thread in threads:
        thread.start()
    process: subprocess.Popen[bytes] | None = None
    devtools: DevToolsConnection | None = None
    profile = Path(tempfile.mkdtemp(prefix="cbat-chrome-proof-"))
    try:
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
                "--remote-debugging-port=0",
                "--remote-allow-origins=http://127.0.0.1",
                f"--user-data-dir={profile}",
                esp_origin + "/",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        websocket_url = _wait_for_devtools(profile, process, esp_origin)
        devtools = DevToolsConnection(websocket_url)
        _inject_browser_key(devtools, key_document)
        if not state.saved_event.wait(timeout=15):
            browser_status = _evaluate_value(
                devtools, "document.getElementById('status').textContent"
            )
            raise RuntimeError(
                f"fake ESP did not receive provisioning; browser status={browser_status!r}"
            )
        if not onboarding.app.session.finished_event.wait(timeout=15):
            browser_status = _evaluate_value(
                devtools, "document.getElementById('status').textContent"
            )
            raise RuntimeError(
                f"localhost transaction did not finish; browser status={browser_status!r}"
            )
        status_deadline = time.monotonic() + 5
        browser_status = ""
        while time.monotonic() < status_deadline:
            browser_status = _evaluate_value(
                devtools, "document.getElementById('status').textContent"
            )
            if browser_status == "complete" or str(browser_status).startswith("failed:"):
                break
            time.sleep(0.05)
        if browser_status != "complete":
            raise RuntimeError(
                "Chrome did not observe the completed transaction; "
                f"browser status={browser_status!r}"
            )
    finally:
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
        onboarding.shutdown()
        onboarding.server_close()
        esp.shutdown()
        esp.server_close()
        for thread in threads:
            thread.join(timeout=2)

    decoded = urllib.parse.parse_qs(state.saved_body.decode("utf-8"), keep_blank_values=True)
    expected = {
        "csrf",
        "ssid",
        "password",
        "bridge_url",
        "device_id",
        "bridge_token",
    }
    if set(decoded) != expected:
        raise RuntimeError("fake ESP payload fields were not the safe allowlist")
    lowered = state.saved_body.lower()
    for marker in (b"privatekey", b"apikey", b"private%20key", b"private+key"):
        if marker in lowered:
            raise RuntimeError("Coinbase credential material reached fake ESP")
    if key_document.encode() in state.saved_body:
        raise RuntimeError("Coinbase JSON reached fake ESP")

    pna_observed = onboarding.app.pna_preflight_event.is_set()
    result: dict[str, Any] = {
        "chrome": chrome.name,
        "cross_origin_onboarding": True,
        "portal_address_space": "private",
        "portal_host": selected_host,
        "portal_host_is_loopback": selected_address.is_loopback,
        "synthetic_key_source": "Chrome DevTools-injected textarea input",
        "synthetic_key_in_fake_esp_html": False,
        "p256_json_parsed": coordinator.calls == 1,
        "esp_payload_fields": sorted(decoded),
        "credential_in_esp_payload": False,
        "authorization_rotated": coordinator.finishes == 1,
        "session_finished": True,
        "pna_preflight_observed": pna_observed,
    }
    if not pna_observed:
        result["pna_blocker"] = (
            "Google Chrome did not emit Access-Control-Request-Private-Network "
            "for this private-LAN-to-loopback request on the host; the exact-origin "
            "cross-origin flow succeeded, but legacy PNA preflight was not provable."
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chrome", type=Path, default=DEFAULT_CHROME)
    parser.add_argument("--portal-host")
    args = parser.parse_args()
    if not args.chrome.is_file():
        parser.error("Google Chrome was not found")
    print(
        json.dumps(
            run(args.chrome, portal_host=args.portal_host),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
