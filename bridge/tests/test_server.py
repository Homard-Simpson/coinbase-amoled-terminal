from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from urllib.parse import urlsplit

from coinbase_amoled_bridge.auth import DeviceManager, DeviceRegistry
from coinbase_amoled_bridge.config import ConfigStore
from coinbase_amoled_bridge.feed import SampleFeedService
from coinbase_amoled_bridge.server import (
    BridgeApplication,
    create_server,
)


@contextmanager
def running_server(
    *, device_rate: int = 1000
) -> Iterator[tuple[str, str, str, ConfigStore, DeviceManager]]:
    with tempfile.TemporaryDirectory() as temporary:
        store = ConfigStore(temporary)
        config = store.initialize()
        manager = DeviceManager(store)
        provision = manager.add(label="test")
        token = provision.token_path.read_text().strip()
        config = store.load()
        config["settings"]["device_rate_per_minute"] = device_rate
        config["settings"]["ip_rate_per_minute"] = 1000
        config["settings"]["rate_burst"] = 20 if device_rate > 1 else 1
        store.replace(config)
        registry = DeviceRegistry(store, reload_interval=0)
        feed = SampleFeedService(config["settings"], clock=lambda: 1_700_005_000)
        app = BridgeApplication.from_settings(
            feed, registry, "sample", config["settings"]
        )
        server = create_server("127.0.0.1", 0, app)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            yield base, provision.device_id, token, store, manager
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


def fetch_json(
    url: str,
    *,
    device_id: str | None = None,
    token: str | None = None,
    method: str = "GET",
) -> tuple[int, dict, dict[str, str]]:
    headers = {}
    if device_id is not None:
        headers["X-Device-ID"] = device_id
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            body = response.read()
            return response.status, json.loads(body or b"{}"), dict(response.headers)
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read() or b"{}"), dict(exc.headers)
        finally:
            exc.close()


class ServerTests(unittest.TestCase):
    def test_health_ready_and_authenticated_feed(self) -> None:
        with running_server() as (base, device_id, token, _store, _manager):
            status, health, headers = fetch_json(base + "/healthz")
            self.assertEqual(status, 200)
            self.assertTrue(health["read_only"])
            status, ready, _ = fetch_json(base + "/readyz")
            self.assertEqual(status, 200)
            self.assertEqual(ready["mode"], "sample")
            status, feed, headers = fetch_json(
                base + "/v1/device-feed", device_id=device_id, token=token
            )
            self.assertEqual(status, 200)
            self.assertTrue(feed["read_only"])
            self.assertEqual(feed["mode"], "sample")
            # The device receives the compact firmware contract, not the rich
            # internal feed: numeric prices, positions keyed by symbol, a
            # positions-only portfolio, and no cash/account-total fields.
            self.assertEqual(feed["schema_version"], 1)
            self.assertIsInstance(feed["prices"], dict)
            self.assertTrue(all(isinstance(v, float) for v in feed["prices"].values()))
            self.assertIsInstance(feed["positions"], dict)
            self.assertEqual(
                set(feed["portfolio"]),
                {"positions_value", "unrealized_pnl", "realized_pnl_today"},
            )
            self.assertNotIn("account_summary", feed)
            self.assertNotIn("markets", feed)
            serialized = json.dumps(feed)
            self.assertNotIn(token, serialized)
            self.assertNotIn(device_id, serialized)
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
            self.assertTrue(headers.get("X-Request-ID"))

    def test_missing_wrong_or_revoked_credentials_are_generic_401(self) -> None:
        with running_server() as (base, device_id, token, _store, manager):
            for supplied_id, supplied_token in (
                (None, None),
                (device_id, token + "x"),
                ("dev_unknown000", token),
            ):
                status, body, headers = fetch_json(
                    base + "/v1/device-feed",
                    device_id=supplied_id,
                    token=supplied_token,
                )
                self.assertEqual(status, 401)
                self.assertEqual(body, {"error": "unauthorized"})
                self.assertIn("Bearer", headers["WWW-Authenticate"])
            parsed = urlsplit(base)
            connection = http.client.HTTPConnection(
                parsed.hostname, parsed.port, timeout=3
            )
            connection.putrequest("GET", "/v1/device-feed")
            connection.putheader("X-Device-ID", device_id)
            connection.putheader("Authorization", f"Bearer {token}")
            connection.putheader("Authorization", f"Bearer {token}")
            connection.endheaders()
            response = connection.getresponse()
            self.assertEqual(response.status, 401)
            response.read()
            connection.close()
            manager.set_enabled(device_id, False)
            status, body, _ = fetch_json(
                base + "/v1/device-feed", device_id=device_id, token=token
            )
            self.assertEqual(status, 401)

    def test_active_device_claim_and_status_are_narrow_idempotent_ready_receipts(self) -> None:
        with running_server() as (base, device_id, token, _store, _manager):
            for method, path in (
                ("POST", "/v1/onboarding/claim"),
                ("GET", "/v1/onboarding/status"),
            ):
                status, body, headers = fetch_json(
                    base + path,
                    device_id=device_id,
                    token=token,
                    method=method,
                )
                self.assertEqual(status, 200)
                self.assertEqual(body["status"], "ready")
                self.assertEqual(body["retry_after_seconds"], 0)
                self.assertEqual(headers["Cache-Control"], "no-store")
            status, body, _ = fetch_json(
                base + "/v1/onboarding/status",
                device_id=device_id,
                token=token + "x",
            )
            self.assertEqual(status, 401)
            self.assertEqual(body, {"error": "unauthorized"})

    def test_mutations_queries_and_admin_surface_fail_closed(self) -> None:
        with running_server() as (base, device_id, token, _store, _manager):
            parsed = urlsplit(base)
            connection = http.client.HTTPConnection(
                parsed.hostname, parsed.port, timeout=3
            )
            connection.request("POST", "/v1/device-feed", body=b"{}")
            response = connection.getresponse()
            body = json.loads(response.read())
            self.assertEqual(response.status, 405)
            self.assertTrue(body["read_only"])
            connection.close()
            connection = http.client.HTTPConnection(
                parsed.hostname, parsed.port, timeout=3
            )
            connection.request("BREW", "/v1/device-feed")
            response = connection.getresponse()
            body = json.loads(response.read())
            self.assertEqual(response.status, 405)
            self.assertTrue(body["read_only"])
            connection.close()
            status, body, _ = fetch_json(
                base + "/v1/device-feed?debug=1", device_id=device_id, token=token
            )
            self.assertEqual(status, 400)
            status, body, _ = fetch_json(base + "/admin")
            self.assertEqual(status, 404)
            connection = http.client.HTTPConnection(
                parsed.hostname, parsed.port, timeout=3
            )
            connection.putrequest("GET", base + "/healthz", skip_host=True)
            connection.putheader("Host", parsed.netloc)
            connection.endheaders()
            response = connection.getresponse()
            self.assertEqual(response.status, 400)
            response.read()
            connection.close()

    def test_head_and_device_rate_limit(self) -> None:
        with running_server(device_rate=1) as (
            base,
            device_id,
            token,
            _store,
            _manager,
        ):
            status, body, headers = fetch_json(
                base + "/v1/device-feed",
                device_id=device_id,
                token=token,
                method="HEAD",
            )
            self.assertEqual(status, 200)
            self.assertEqual(body, {})
            status, body, headers = fetch_json(
                base + "/v1/device-feed", device_id=device_id, token=token
            )
            self.assertEqual(status, 429)
            self.assertEqual(body["error"], "rate_limited")
            self.assertIn("Retry-After", headers)


if __name__ == "__main__":
    unittest.main()
