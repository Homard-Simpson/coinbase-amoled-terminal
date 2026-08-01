#!/usr/bin/env python3
# ruff: noqa: E501
"""Run the real localhost CORS flow in Google Chrome against a fake ESP portal."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import urllib.parse
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


class ProofCoordinator:
    def __init__(self) -> None:
        self.calls = 0

    def complete(self, credentials: Any) -> SafeProvisioning:
        self.calls += 1
        return SafeProvisioning(
            bridge_url="http://100.100.20.10:8788/v1/device-feed",
            device_id="123e4567-e89b-42d3-a456-426614174000",
            feed_token="cbat_" + ("A" * 43),
        )


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
        body = self.rfile.read(int(lengths[0]))
        self.state.saved_body = body
        self.state.saved_event.set()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")


def synthetic_key_json() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode("ascii")
    return json.dumps(
        {
            "name": "organizations/example/apiKeys/chrome-proof",
            "privateKey": pem,
        },
        separators=(",", ":"),
    )


def render_auto_portal(server: Any, key_document: str) -> bytes:
    session = server.app.session
    values = {
        "endpoint": session.endpoint_url,
        "finish": session.endpoint_origin + FINISH_PATH,
        "session": session.session_id,
        "token": session.setup_token,
        "csrf": session.csrf_token,
        "key": key_document,
    }
    encoded = {name: json.dumps(value) for name, value in values.items()}
    return f"""<!doctype html><meta charset="utf-8"><p id="status">starting</p>
<script>'use strict';
const endpoint={encoded["endpoint"]},finishEndpoint={encoded["finish"]};
const sessionId={encoded["session"]},setupToken={encoded["token"]},setupCsrf={encoded["csrf"]};
const keyDocument={encoded["key"]};
const headers={{'Authorization':'Setup '+setupToken,'Content-Type':'application/json','X-Setup-Session':sessionId,'X-CSRF-Token':setupCsrf}};
(async()=>{{try{{const r=await fetch(endpoint,{{method:'POST',mode:'cors',cache:'no-store',credentials:'omit',redirect:'error',headers,body:keyDocument}});if(!r.ok)throw new Error('key');const p=await r.json();const safe=new URLSearchParams();safe.set('csrf','fake-portal-csrf');safe.set('ssid','SyntheticNetwork');safe.set('password','synthetic-password');safe.set('bridge_url',p.bridge_url);safe.set('device_id',p.device_id);safe.set('bridge_token',p.feed_token);const saved=await fetch('/save',{{method:'POST',headers:{{'Content-Type':'application/x-www-form-urlencoded'}},body:safe.toString()}});if(!saved.ok)throw new Error('save');const finished=await fetch(finishEndpoint,{{method:'POST',mode:'cors',cache:'no-store',credentials:'omit',redirect:'error',headers:{{'Authorization':'Setup '+setupToken,'X-Setup-Session':sessionId,'X-CSRF-Token':setupCsrf}}}});if(!finished.ok)throw new Error('finish');document.getElementById('status').textContent='complete';}}catch(error){{document.getElementById('status').textContent='failed';}}}})();
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
    raise RuntimeError("no private LAN address is available for the Chrome proof")


def run(chrome: Path, *, portal_host: str | None = None) -> dict[str, Any]:
    state = FakeEspState()
    selected_host = portal_host or private_portal_host()
    esp = FakeEspServer(state, selected_host)
    esp_origin = f"http://{selected_host}:{esp.server_address[1]}"
    coordinator = ProofCoordinator()
    onboarding = create_onboarding_server(
        coordinator,
        ttl_seconds=120,
        portal_origin=esp_origin,
    )
    key_document = synthetic_key_json()
    state.page = render_auto_portal(onboarding, key_document)
    threads = [
        threading.Thread(target=esp.serve_forever, daemon=True),
        threading.Thread(target=onboarding.serve_forever, daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="cbat-chrome-proof-") as profile:
            completed = subprocess.run(
                [
                    str(chrome),
                    "--headless=new",
                    "--incognito",
                    "--disable-gpu",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--disable-background-networking",
                    "--disable-component-update",
                    "--virtual-time-budget=10000",
                    f"--user-data-dir={profile}",
                    "--dump-dom",
                    esp_origin + "/",
                ],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
        if completed.returncode != 0:
            raise RuntimeError("Google Chrome proof process failed")
        if not state.saved_event.wait(timeout=3):
            raise RuntimeError("fake ESP did not receive safe provisioning")
        if not onboarding.app.session.finished_event.wait(timeout=3):
            raise RuntimeError("localhost endpoint did not receive final acknowledgement")
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
        if key_document.encode("utf-8") in state.saved_body:
            raise RuntimeError("Coinbase JSON reached fake ESP")
        return {
            "chrome": chrome.name,
            "cross_origin_onboarding": True,
            "portal_address_space": "private",
            "portal_host": selected_host,
            "p256_json_parsed": coordinator.calls == 1,
            "esp_payload_fields": sorted(decoded),
            "credential_in_esp_payload": False,
            "session_finished": True,
        }
    finally:
        onboarding.shutdown()
        onboarding.server_close()
        esp.shutdown()
        esp.server_close()
        for thread in threads:
            thread.join(timeout=2)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chrome", type=Path, default=DEFAULT_CHROME)
    parser.add_argument("--portal-host")
    args = parser.parse_args()
    if not args.chrome.is_file():
        parser.error("Google Chrome was not found")
    print(json.dumps(run(args.chrome, portal_host=args.portal_host), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
