from __future__ import annotations

import http.client
import json
import os
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from coinbase_amoled_bridge.auth import Credentials
from coinbase_amoled_bridge.config import ConfigStore
from coinbase_amoled_bridge.errors import (
    CoinbaseAPIError,
    ProvisioningError,
    SetupSessionError,
    UnsafeCredentialError,
)
from coinbase_amoled_bridge.onboarding import (
    FINISH_PATH,
    GENERIC_ERROR,
    ONBOARDING_PATH,
    PORTAL_ORIGIN,
    PROVISIONING_PATH,
    OnboardingCoordinator,
    SafeProvisioning,
    SetupSession,
    create_onboarding_server,
    render_local_setup_page,
)
from coinbase_amoled_bridge.quickstart import MAX_CDP_JSON_BYTES
from coinbase_amoled_bridge.user_service import ServiceStartResult


def key_json(*, curve: ec.EllipticCurve | None = None, marker: str = "test") -> bytes:
    key = ec.generate_private_key(curve or ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode("ascii")
    return json.dumps(
        {
            "name": f"organizations/example/apiKeys/{marker}",
            "privateKey": pem,
        },
        separators=(",", ":"),
    ).encode("utf-8")


class FakeCoordinator:
    def __init__(self, *, error: Exception | None = None) -> None:
        self.error = error
        self.credentials: list[Credentials] = []
        self.commits = 0
        self.rollbacks = 0

    def complete(self, credentials: Credentials) -> SafeProvisioning:
        self.credentials.append(credentials)
        if self.error:
            raise self.error
        return SafeProvisioning(
            bridge_url="http://100.100.20.10:8788/v1/device-feed",
            device_id="123e4567-e89b-42d3-a456-426614174000",
            feed_token="cbat_" + ("A" * 43),
        )

    def commit_pending(self) -> None:
        self.commits += 1

    def rollback_pending(self) -> None:
        self.rollbacks += 1


class RunningServer:
    def __init__(self, coordinator: FakeCoordinator, *, ttl: int = 900) -> None:
        self.server = create_onboarding_server(
            coordinator,
            ttl_seconds=ttl,
            portal_origin=PORTAL_ORIGIN,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def session(self) -> SetupSession:
        return self.server.app.session

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        origin: str = PORTAL_ORIGIN,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_address[1], timeout=3
        )
        request_headers = dict(headers or {})
        if origin:
            request_headers["Origin"] = origin
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        payload = response.read()
        result = (
            response.status,
            {name.lower(): value for name, value in response.getheaders()},
            payload,
        )
        connection.close()
        return result

    def auth_headers(self, *, content_type: bool = True) -> dict[str, str]:
        headers = {
            "Authorization": "Setup " + self.session.setup_token,
            "X-Setup-Session": self.session.session_id,
            "X-CSRF-Token": self.session.csrf_token,
        }
        if content_type:
            headers["Content-Type"] = "application/json"
        return headers

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class SetupSessionTests(unittest.TestCase):
    def test_random_tokens_expire_and_are_single_flight_single_use(self) -> None:
        first = SetupSession.create(ttl_seconds=60)
        second = SetupSession.create(ttl_seconds=60)
        self.assertNotEqual(first.session_id, second.session_id)
        self.assertNotEqual(first.setup_token, second.setup_token)
        self.assertGreaterEqual(len(first.setup_token), 43)
        first.begin_once()
        with self.assertRaises(SetupSessionError):
            first.begin_once()
        first.fail_attempt()
        first.begin_once()
        first.preserve_finish_token()
        first.use_once()
        with self.assertRaises(SetupSessionError):
            first.begin_once()
        first.finish_once(setup_token=first._finish_token)
        first.mark_finished()
        self.assertTrue(first.finished_event.is_set())

        expired = SetupSession.create(ttl_seconds=60)
        expired.monotonic_deadline = time.monotonic() - 1
        with self.assertRaises(SetupSessionError):
            expired.begin_once()

    def test_local_fallback_has_no_external_assets_or_browser_persistence(self) -> None:
        session = SetupSession.create(ttl_seconds=60)
        session.bind_endpoint(43123)
        page = render_local_setup_page(session)
        self.assertIn('autocomplete="off"', page)
        self.assertIn("cache:'no-store'", page)
        self.assertNotIn("192.168.4.1/save", page)
        self.assertNotIn("finishEndpoint", page)
        self.assertNotIn("<script src=", page)
        self.assertNotIn("<link ", page)
        self.assertNotIn("analytics", page.lower())
        self.assertNotIn("localStorage", page)
        self.assertNotIn("sessionStorage", page)


class OnboardingHTTPTests(unittest.TestCase):
    def setUp(self) -> None:
        self.coordinator = FakeCoordinator()
        self.running = RunningServer(self.coordinator)

    def tearDown(self) -> None:
        self.running.close()

    def test_cors_preflight_pna_and_exact_origin(self) -> None:
        requested = "authorization, content-type, x-csrf-token, x-setup-session"
        status, headers, body = self.running.request(
            "OPTIONS",
            ONBOARDING_PATH,
            headers={
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": requested,
                "Access-Control-Request-Private-Network": "true",
            },
        )
        self.assertEqual(status, 204, body)
        self.assertEqual(headers["access-control-allow-origin"], PORTAL_ORIGIN)
        self.assertEqual(headers["access-control-allow-private-network"], "true")
        self.assertEqual(headers["cache-control"], "no-store, max-age=0")

        status, headers, _ = self.running.request(
            "OPTIONS",
            ONBOARDING_PATH,
            origin=PORTAL_ORIGIN + ":81",
            headers={
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": requested,
            },
        )
        self.assertEqual(status, 403)
        self.assertNotIn("access-control-allow-origin", headers)

    def test_valid_key_returns_only_safe_values_and_is_single_use(self) -> None:
        key = key_json(marker="must-not-leak")
        token = self.running.session.setup_token
        headers = self.running.auth_headers()
        status, response_headers, body = self.running.request(
            "POST", ONBOARDING_PATH, body=key, headers=headers
        )
        self.assertEqual(status, 200, body)
        value = json.loads(body)
        self.assertEqual(set(value), {"ok", "bridge_url", "device_id", "feed_token"})
        self.assertNotIn(b"must-not-leak", body)
        self.assertNotIn(b"PRIVATE KEY", body)
        self.assertEqual(response_headers["access-control-allow-origin"], PORTAL_ORIGIN)
        self.assertEqual(len(self.coordinator.credentials), 1)

        provision_headers = {
            "Authorization": "Setup " + token,
            "X-Setup-Session": self.running.session.session_id,
            "X-CSRF-Token": self.running.session.csrf_token,
        }
        status, _, provision_body = self.running.request(
            "POST", PROVISIONING_PATH, body=b"", headers=provision_headers
        )
        self.assertEqual(status, 200, provision_body)
        self.assertEqual(json.loads(provision_body), value)

        status, _, _ = self.running.request(
            "POST",
            PROVISIONING_PATH,
            body=b"",
            origin=self.running.session.endpoint_origin,
            headers=provision_headers,
        )
        self.assertEqual(status, 403)

        status, _, second_body = self.running.request(
            "POST", ONBOARDING_PATH, body=key, headers=headers
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(second_body), GENERIC_ERROR)

        finish_headers = {
            "Authorization": "Setup " + token,
            "X-Setup-Session": self.running.session.session_id,
            "X-CSRF-Token": self.running.session.csrf_token,
        }
        status, _, _ = self.running.request(
            "POST", FINISH_PATH, body=b"", headers=finish_headers
        )
        self.assertEqual(status, 200)
        self.assertTrue(self.running.session.finished_event.is_set())
        status, _, _ = self.running.request(
            "POST", FINISH_PATH, body=b"", headers=finish_headers
        )
        self.assertEqual(status, 403)

    def test_method_content_type_body_limit_and_origin_restrictions(self) -> None:
        key = key_json()
        status, _, _ = self.running.request(
            "PUT", ONBOARDING_PATH, body=key, headers=self.running.auth_headers()
        )
        self.assertEqual(status, 405)

        headers = self.running.auth_headers()
        headers["Content-Type"] = "text/plain"
        status, _, _ = self.running.request(
            "POST", ONBOARDING_PATH, body=key, headers=headers
        )
        self.assertEqual(status, 415)

        headers = self.running.auth_headers()
        headers["Content-Length"] = str(MAX_CDP_JSON_BYTES + 1)
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.running.server.server_address[1], timeout=3
        )
        connection.putrequest("POST", ONBOARDING_PATH)
        for name, value in headers.items():
            connection.putheader(name, value)
        connection.putheader("Origin", PORTAL_ORIGIN)
        connection.endheaders()
        response = connection.getresponse()
        self.assertEqual(response.status, 400)
        response.read()
        connection.close()

        status, _, _ = self.running.request(
            "POST",
            ONBOARDING_PATH,
            body=key,
            origin="null",
            headers=self.running.auth_headers(),
        )
        self.assertEqual(status, 403)

    def test_malformed_or_unsafe_input_has_generic_non_echoing_error(self) -> None:
        marker = b"sensitive-input-marker"
        status, _, body = self.running.request(
            "POST",
            ONBOARDING_PATH,
            body=b"{" + marker,
            headers=self.running.auth_headers(),
        )
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body), GENERIC_ERROR)
        self.assertNotIn(marker, body)

        bad_curve = key_json(curve=ec.SECP384R1(), marker="wrong-curve-marker")
        status, _, body = self.running.request(
            "POST",
            ONBOARDING_PATH,
            body=bad_curve,
            headers=self.running.auth_headers(),
        )
        self.assertEqual(status, 400)
        self.assertNotIn(b"wrong-curve-marker", body)


class CoordinatorTransactionTests(unittest.TestCase):
    def test_permission_refusal_writes_nothing(self) -> None:
        credentials = Credentials.from_values(
            key_name="organizations/example/apiKeys/refused",
            private_key_pem=_pem(),
            source="test",
        )
        with tempfile.TemporaryDirectory() as temporary:
            coordinator = OnboardingCoordinator(
                temporary,
                bridge_url="http://100.100.20.10:8788/v1/device-feed",
                permission_checker=mock.Mock(
                    side_effect=UnsafeCredentialError("unsafe")
                ),
                service_starter=mock.Mock(),
                readiness_checker=mock.Mock(),
            )
            with self.assertRaises(UnsafeCredentialError):
                coordinator.complete(credentials)
            self.assertFalse(Path(temporary, "config.json").exists())
            self.assertFalse(Path(temporary, "secrets").exists())

    def test_atomic_mode_0600_and_revocable_device_token(self) -> None:
        credentials = Credentials.from_values(
            key_name="organizations/example/apiKeys/safe",
            private_key_pem=_pem(),
            source="test",
        )
        with tempfile.TemporaryDirectory() as temporary:
            permission = mock.Mock()
            coordinator = OnboardingCoordinator(
                temporary,
                bridge_url="http://100.100.20.10:8788/v1/device-feed",
                permission_checker=permission,
                service_starter=mock.Mock(
                    return_value=ServiceStartResult("started", "none")
                ),
                readiness_checker=mock.Mock(return_value=True),
            )
            result = coordinator.complete(credentials)
            self.assertFalse(Path(temporary, "config.json").exists())
            coordinator.finalize_pending()
            bundle = Path(temporary, "secrets", "coinbase_credentials")
            mode = stat.S_IMODE(os.stat(bundle).st_mode)
            loaded = Credentials.load_local(temporary)
            config = ConfigStore(temporary).load()
        permission.assert_called_once_with(credentials)
        self.assertEqual(mode, 0o600)
        self.assertEqual(loaded.key_name, credentials.key_name)
        self.assertIn(result.device_id, config["devices"])
        self.assertTrue(result.feed_token.startswith("cbat_"))
        self.assertNotIn(credentials.key_name, json.dumps(result.public_json()))

    def test_service_failure_rolls_back_bundle_config_and_device(self) -> None:
        credentials = Credentials.from_values(
            key_name="organizations/example/apiKeys/rollback",
            private_key_pem=_pem(),
            source="test",
        )
        with tempfile.TemporaryDirectory() as temporary:
            coordinator = OnboardingCoordinator(
                temporary,
                bridge_url="http://100.100.20.10:8788/v1/device-feed",
                permission_checker=mock.Mock(),
                service_starter=mock.Mock(
                    return_value=ServiceStartResult("started", "none")
                ),
                readiness_checker=mock.Mock(return_value=False),
            )
            coordinator.complete(credentials)
            with self.assertRaises(ProvisioningError):
                coordinator.finalize_pending()
            self.assertFalse(Path(temporary, "config.json").exists())
            self.assertFalse(Path(temporary, "secrets").exists())

    def test_unfinished_esp_save_rolls_back_pending_local_state(self) -> None:
        credentials = Credentials.from_values(
            key_name="organizations/example/apiKeys/pending-rollback",
            private_key_pem=_pem(),
            source="test",
        )
        with tempfile.TemporaryDirectory() as temporary:
            coordinator = OnboardingCoordinator(
                temporary,
                bridge_url="http://100.100.20.10:8788/v1/device-feed",
                permission_checker=mock.Mock(),
                service_starter=mock.Mock(
                    return_value=ServiceStartResult("started", "none")
                ),
                readiness_checker=mock.Mock(return_value=True),
            )
            coordinator.complete(credentials)
            self.assertFalse(Path(temporary, "config.json").exists())
            coordinator.rollback_pending()
            self.assertFalse(Path(temporary, "config.json").exists())
            self.assertFalse(Path(temporary, "secrets").exists())

    def test_offline_portal_defers_permission_check_until_network_returns(self) -> None:
        credentials = Credentials.from_values(
            key_name="organizations/example/apiKeys/deferred",
            private_key_pem=_pem(),
            source="test",
        )
        with tempfile.TemporaryDirectory() as temporary:
            permission = mock.Mock(
                side_effect=[CoinbaseAPIError("upstream_unreachable"), None]
            )
            coordinator = OnboardingCoordinator(
                temporary,
                bridge_url="http://100.100.20.10:8788/v1/device-feed",
                permission_checker=permission,
                service_starter=mock.Mock(
                    return_value=ServiceStartResult("started", "none")
                ),
                readiness_checker=mock.Mock(return_value=True),
            )
            coordinator.complete(credentials)
            self.assertFalse(Path(temporary, "config.json").exists())
            self.assertFalse(Path(temporary, "secrets").exists())
            coordinator.finalize_pending(timeout_seconds=1, retry_interval=0)
            self.assertTrue(Path(temporary, "config.json").exists())
            self.assertEqual(permission.call_count, 2)


def _pem() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


if __name__ == "__main__":
    unittest.main()
