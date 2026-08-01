from __future__ import annotations

import http.client
import json
import os
import socket
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from coinbase_amoled_bridge.auth import (
    Credentials,
    DeviceManager,
    active_local_credential_slot,
    compare_and_swap_local_credential_slot,
    stage_local_credential_slot,
)
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
    MAX_CONCURRENT_CONNECTIONS,
    MAX_HEADER_BYTES,
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
    key = ec.derive_private_key(7, curve or ec.SECP256R1())
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
    def __init__(
        self,
        *,
        error: Exception | None = None,
        finish_error: Exception | None = None,
    ) -> None:
        self.error = error
        self.finish_error = finish_error
        self.credentials: list[Credentials] = []
        self.finishes = 0
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

    def finish_pending(self, provisioning: SafeProvisioning) -> None:
        del provisioning
        self.finishes += 1
        if self.finish_error:
            raise self.finish_error

    def rollback_pending(self) -> None:
        self.rollbacks += 1


class RunningServer:
    def __init__(self, coordinator: FakeCoordinator, *, ttl: int = 900) -> None:
        self.server = create_onboarding_server(
            coordinator,
            ttl_seconds=ttl,
            portal_origin=PORTAL_ORIGIN,
        )
        self.setup_token = self.server.app.session.setup_token
        self.completion_token = self.server.app.session.completion_token
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

    def auth_headers(
        self, *, content_type: bool = True, completion: bool = False
    ) -> dict[str, str]:
        headers = {
            "Authorization": "Setup "
            + (self.completion_token if completion else self.setup_token),
            "X-Setup-Session": self.session.session_id,
            "X-CSRF-Token": self.session.csrf_token,
        }
        if content_type:
            headers["Content-Type"] = "application/json"
        return headers

    def raw_request(self, payload: bytes) -> bytes:
        with socket.create_connection(
            ("127.0.0.1", self.server.server_address[1]), timeout=3
        ) as connection:
            connection.sendall(payload)
            chunks: list[bytes] = []
            while True:
                try:
                    chunk = connection.recv(4096)
                except ConnectionResetError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)

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
        self.assertNotEqual(first.completion_token, second.completion_token)
        self.assertGreaterEqual(len(first.setup_token), 43)
        completion_token = first.completion_token
        first.begin_once()
        with self.assertRaises(SetupSessionError):
            first.begin_once()
        first.fail_attempt()
        first.begin_once()
        first.set_provisioning(
            SafeProvisioning(
                bridge_url="http://100.100.20.10:8788/v1/device-feed",
                device_id="123e4567-e89b-42d3-a456-426614174000",
                feed_token="cbat_" + ("A" * 43),
            )
        )
        first.use_once()
        self.assertEqual(first.setup_token, "")
        self.assertEqual(first.completion_token, "")
        with self.assertRaises(SetupSessionError):
            first.begin_once()
        finisher = mock.Mock()
        first.finish_once(
            completion_token=completion_token,
            finisher=finisher,
        )
        finisher.assert_called_once()
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
        self.assertIn("finally{key='';text.value='';file.value='';}", page)


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
        self.assertTrue(self.running.server.app.pna_preflight_event.is_set())

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
        setup_token = self.running.setup_token
        completion_token = self.running.completion_token
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
            "Authorization": "Setup " + completion_token,
            "X-Setup-Session": self.running.session.session_id,
            "X-CSRF-Token": self.running.session.csrf_token,
        }
        status, _, provision_body = self.running.request(
            "POST", PROVISIONING_PATH, body=b"", headers=provision_headers
        )
        self.assertEqual(status, 200, provision_body)
        self.assertEqual(json.loads(provision_body), value)

        setup_headers = dict(provision_headers)
        setup_headers["Authorization"] = "Setup " + setup_token
        status, _, _ = self.running.request(
            "POST", PROVISIONING_PATH, body=b"", headers=setup_headers
        )
        self.assertEqual(status, 403)

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
            "Authorization": "Setup " + completion_token,
            "X-Setup-Session": self.running.session.session_id,
            "X-CSRF-Token": self.running.session.csrf_token,
        }
        status, _, _ = self.running.request(
            "POST", FINISH_PATH, body=b"", headers=finish_headers
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.coordinator.finishes, 1)
        self.assertTrue(self.running.session.finished_event.is_set())
        status, _, _ = self.running.request(
            "POST", FINISH_PATH, body=b"", headers=finish_headers
        )
        self.assertEqual(status, 403)

    def test_used_session_page_never_renders_the_setup_bearer_again(self) -> None:
        local_path = f"/setup/{self.running.session.session_id}"
        status, _, page = self.running.request("GET", local_path, origin="")
        self.assertEqual(status, 200)
        self.assertIn(self.running.setup_token.encode("ascii"), page)

        status, _, _ = self.running.request(
            "POST",
            ONBOARDING_PATH,
            body=key_json(),
            headers=self.running.auth_headers(),
        )
        self.assertEqual(status, 200)
        status, _, body = self.running.request("GET", local_path, origin="")
        self.assertEqual(status, 410)
        self.assertNotIn(self.running.setup_token.encode("ascii"), body)

    def test_finish_failure_is_closed_and_never_reports_success(self) -> None:
        self.coordinator.finish_error = ProvisioningError("synthetic failure")
        status, _, _ = self.running.request(
            "POST",
            ONBOARDING_PATH,
            body=key_json(),
            headers=self.running.auth_headers(),
        )
        self.assertEqual(status, 200)
        status, _, body = self.running.request(
            "POST",
            FINISH_PATH,
            body=b"",
            headers=self.running.auth_headers(
                content_type=False,
                completion=True,
            ),
        )
        self.assertEqual(status, 500)
        self.assertEqual(json.loads(body), GENERIC_ERROR)
        self.assertFalse(self.running.session.finished_event.is_set())
        self.assertTrue(self.running.session.failed_event.is_set())

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
        self.assertEqual(response.getheader("Connection"), "close")
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

    def test_raw_ingress_limits_headers_methods_framing_and_closes(self) -> None:
        expected_host = self.running.session.endpoint_origin.removeprefix("http://")
        oversized = (
            f"GET / HTTP/1.1\r\nHost: {expected_host}\r\nX-Fill: ".encode()
            + (b"a" * MAX_HEADER_BYTES)
            + b"\r\n\r\n"
        )
        response = self.running.raw_request(oversized)
        self.assertTrue(response.startswith(b"HTTP/1.1 431 "), response[:80])
        self.assertIn(b"Connection: close\r\n", response)

        unsupported = (
            f"BREW {ONBOARDING_PATH} HTTP/1.1\r\nHost: {expected_host}\r\n\r\n"
        ).encode()
        response = self.running.raw_request(unsupported)
        self.assertTrue(response.startswith(b"HTTP/1.1 405 "), response[:80])
        self.assertIn(b"Connection: close\r\n", response)

        chunked = (
            f"POST {ONBOARDING_PATH} HTTP/1.1\r\n"
            f"Host: {expected_host}\r\n"
            "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        ).encode()
        response = self.running.raw_request(chunked)
        self.assertTrue(response.startswith(b"HTTP/1.1 400 "), response[:80])
        self.assertIn(b"Connection: close\r\n", response)

    def test_duplicate_content_type_is_rejected_before_body_use(self) -> None:
        expected_host = self.running.session.endpoint_origin.removeprefix("http://")
        key = key_json()
        headers = self.running.auth_headers()
        request = [
            f"POST {ONBOARDING_PATH} HTTP/1.1",
            f"Host: {expected_host}",
            f"Origin: {PORTAL_ORIGIN}",
            f"Authorization: {headers['Authorization']}",
            f"X-Setup-Session: {headers['X-Setup-Session']}",
            f"X-CSRF-Token: {headers['X-CSRF-Token']}",
            "Content-Type: application/json",
            "Content-Type: application/json",
            f"Content-Length: {len(key)}",
            "",
            "",
        ]
        response = self.running.raw_request("\r\n".join(request).encode() + key)
        self.assertTrue(response.startswith(b"HTTP/1.1 415 "), response[:80])
        self.assertEqual(self.coordinator.credentials, [])

    def test_connection_concurrency_is_hard_bounded(self) -> None:
        sockets: list[socket.socket] = []
        address = ("127.0.0.1", self.running.server.server_address[1])
        try:
            for _ in range(MAX_CONCURRENT_CONNECTIONS):
                connection = socket.create_connection(address, timeout=3)
                connection.sendall(b"GET / HTTP/1.1\r\n")
                sockets.append(connection)
            self.assertTrue(self.running.server.connections_at_capacity.wait(timeout=1))
            rejected = socket.create_connection(address, timeout=3)
            try:
                rejected.sendall(b"GET / HTTP/1.1\r\nHost: invalid\r\n\r\n")
                try:
                    payload = rejected.recv(1)
                except ConnectionResetError:
                    payload = b""
                self.assertEqual(payload, b"")
            finally:
                rejected.close()
        finally:
            for connection in sockets:
                connection.close()

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
    def _credentials(self, marker: str) -> Credentials:
        return Credentials.from_values(
            key_name=f"organizations/example/apiKeys/{marker}",
            private_key_pem=_pem(),
            source="test",
        )

    def _coordinator(
        self,
        data_dir: str,
        *,
        permission: mock.Mock | None = None,
        service: mock.Mock | None = None,
        readiness: mock.Mock | None = None,
    ) -> OnboardingCoordinator:
        return OnboardingCoordinator(
            data_dir,
            bridge_url="http://100.100.20.10:8788/v1/device-feed",
            permission_checker=permission or mock.Mock(),
            service_starter=service
            or mock.Mock(return_value=ServiceStartResult("started", "none")),
            readiness_checker=readiness or mock.Mock(return_value=True),
            finish_timeout_seconds=1,
            retry_interval=0,
        )

    def test_permission_refusal_writes_no_secret_or_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            permission = mock.Mock(side_effect=UnsafeCredentialError("unsafe"))
            with self._coordinator(temporary, permission=permission) as coordinator:
                with self.assertRaises(UnsafeCredentialError):
                    coordinator.complete(self._credentials("refused"))
                self.assertFalse(Path(temporary, "config.json").exists())
                self.assertFalse(Path(temporary, "secrets").exists())
                self.assertFalse(coordinator.journal_path.exists())

    def test_durable_staging_atomic_finish_and_revocable_device_token(self) -> None:
        credentials = self._credentials("safe")
        with tempfile.TemporaryDirectory() as temporary:
            permission = mock.Mock()
            with self._coordinator(temporary, permission=permission) as coordinator:
                result = coordinator.complete(credentials)
                self.assertTrue(coordinator.journal_path.is_file())
                self.assertFalse(Path(temporary, "config.json").exists())
                coordinator.finish_pending(result)
                slot_name = active_local_credential_slot(temporary)
                self.assertIsNotNone(slot_name)
                assert slot_name is not None
                bundle = Path(temporary, "secrets", "credential-slots", slot_name)
                mode = stat.S_IMODE(os.stat(bundle).st_mode)
                loaded = Credentials.load_local(temporary)
                config = ConfigStore(temporary).load()
                self.assertFalse(coordinator.journal_path.exists())
        permission.assert_called_once_with(credentials)
        self.assertEqual(mode, 0o600)
        self.assertEqual(loaded.key_name, credentials.key_name)
        self.assertIn(result.device_id, config["devices"])
        self.assertTrue(result.feed_token.startswith("cbat_"))
        self.assertNotIn(credentials.key_name, json.dumps(result.public_json()))

    def test_service_failure_rolls_back_only_onboarding_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            readiness = mock.Mock(return_value=False)
            with self._coordinator(temporary, readiness=readiness) as coordinator:
                result = coordinator.complete(self._credentials("rollback"))
                with self.assertRaises(ProvisioningError):
                    coordinator.finish_pending(result)
                config = ConfigStore(temporary).load()
                self.assertNotIn(result.device_id, config["devices"])
                self.assertIsNone(active_local_credential_slot(temporary))
                self.assertFalse(coordinator.journal_path.exists())
                self.assertFalse(
                    Path(
                        temporary,
                        "secrets",
                        "devices",
                        f"{result.device_id}.token",
                    ).exists()
                )

    def test_unfinished_esp_save_removes_durable_staging(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self._coordinator(temporary) as coordinator:
                coordinator.complete(self._credentials("pending-rollback"))
                self.assertTrue(coordinator.journal_path.exists())
                self.assertTrue(Path(temporary, "secrets").exists())
                coordinator.rollback_pending()
                self.assertFalse(coordinator.journal_path.exists())
                self.assertFalse(Path(temporary, "config.json").exists())
                self.assertFalse(Path(temporary, "secrets").exists())

    def test_offline_portal_defers_fake_permission_check_until_finish(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            permission = mock.Mock(
                side_effect=[CoinbaseAPIError("upstream_unreachable"), None]
            )
            with self._coordinator(temporary, permission=permission) as coordinator:
                result = coordinator.complete(self._credentials("deferred"))
                self.assertFalse(Path(temporary, "config.json").exists())
                coordinator.finish_pending(result)
                self.assertTrue(Path(temporary, "config.json").exists())
        self.assertEqual(permission.call_count, 2)

    def test_startup_recovers_a_crashed_staged_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            first = self._coordinator(temporary)
            first.complete(self._credentials("crash-recovery"))
            self.assertTrue(first.journal_path.exists())
            first.close()  # Simulate process lock release without normal rollback.

            with self._coordinator(temporary) as recovered:
                self.assertFalse(recovered.journal_path.exists())
                self.assertIsNone(active_local_credential_slot(temporary))
                self.assertFalse(Path(temporary, "secrets").exists())

    def test_corrupt_startup_journal_fails_loudly_without_deleting_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            journal = Path(temporary, ".onboarding", "journal.json")
            journal.parent.mkdir(mode=0o700)
            journal.write_text("{}\n", encoding="ascii")
            with self.assertRaisesRegex(
                ProvisioningError, "recovery journal is invalid"
            ):
                self._coordinator(temporary)
            self.assertEqual(journal.read_text(encoding="ascii"), "{}\n")

    def test_cross_process_owner_lock_refuses_a_second_coordinator(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self._coordinator(temporary):
                with self.assertRaises(ProvisioningError):
                    self._coordinator(temporary)

    def test_concurrent_config_edit_and_revocation_survive_failed_finish(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = ConfigStore(temporary)
            store.initialize()
            existing = DeviceManager(store).add(label="existing")

            def fail_after_concurrent_edits(**_kwargs: object) -> ServiceStartResult:
                DeviceManager(store).set_enabled(existing.device_id, False)

                def change_settings(config: dict[str, object]) -> None:
                    settings = config["settings"]
                    assert isinstance(settings, dict)
                    settings["refresh_seconds"] = 30

                store.update(change_settings)
                return ServiceStartResult("failed", "none")

            service = mock.Mock(side_effect=fail_after_concurrent_edits)
            with self._coordinator(temporary, service=service) as coordinator:
                result = coordinator.complete(self._credentials("concurrent"))
                with self.assertRaises(ProvisioningError):
                    coordinator.finish_pending(result)
                config = store.load()
                self.assertFalse(config["devices"][existing.device_id]["enabled"])
                self.assertEqual(config["settings"]["refresh_seconds"], 30)
                self.assertNotIn(result.device_id, config["devices"])

    def test_prior_active_service_is_restored_after_failed_restart(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prior_credentials = self._credentials("prior-active-service")
            prior_slot = "onboarding_txn_" + ("P" * 24) + ".bundle"
            stage_local_credential_slot(
                temporary,
                credentials=prior_credentials,
                slot_name=prior_slot,
            )
            self.assertTrue(
                compare_and_swap_local_credential_slot(
                    temporary,
                    expected=None,
                    replacement=prior_slot,
                )
            )
            service_result = ServiceStartResult("failed", "systemd", was_active=True)
            service = mock.Mock(return_value=service_result)

            def assert_prior_credentials_restored(
                result: ServiceStartResult,
            ) -> bool:
                self.assertEqual(result, service_result)
                self.assertEqual(
                    Credentials.load_local(temporary).key_name,
                    prior_credentials.key_name,
                )
                return True

            with mock.patch(
                "coinbase_amoled_bridge.onboarding.restore_user_service",
                side_effect=assert_prior_credentials_restored,
            ) as restore:
                with self._coordinator(temporary, service=service) as coordinator:
                    result = coordinator.complete(self._credentials("active-service"))
                    with self.assertRaises(ProvisioningError):
                        coordinator.finish_pending(result)
            restore.assert_called_once_with(service_result)
            self.assertEqual(active_local_credential_slot(temporary), prior_slot)

    def test_service_restore_failure_is_loud_and_keeps_recovery_journal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            service_result = ServiceStartResult("failed", "launchd", was_active=True)
            service = mock.Mock(return_value=service_result)
            coordinator = self._coordinator(temporary, service=service)
            with mock.patch(
                "coinbase_amoled_bridge.onboarding.restore_user_service",
                return_value=False,
            ):
                result = coordinator.complete(self._credentials("restore-fails"))
                with self.assertRaisesRegex(
                    ProvisioningError, "rollback did not complete"
                ):
                    coordinator.finish_pending(result)
                self.assertTrue(coordinator.journal_path.exists())
            coordinator.close()
            with mock.patch(
                "coinbase_amoled_bridge.onboarding.restore_user_service",
                return_value=True,
            ) as restore:
                with self._coordinator(temporary) as recovered:
                    self.assertFalse(recovered.journal_path.exists())
            restore.assert_called_once_with(service_result)

    def test_startup_recovers_service_baseline_journaled_before_restart(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            baseline = ServiceStartResult(
                "started",
                "systemd",
                was_active=True,
                was_enabled=True,
            )

            def crash_during_restart(*, before_change: object) -> ServiceStartResult:
                assert callable(before_change)
                before_change(baseline)
                raise RuntimeError("synthetic process interruption")

            service = mock.Mock(side_effect=crash_during_restart)
            coordinator = self._coordinator(temporary, service=service)
            result = coordinator.complete(self._credentials("restart-crash"))
            with (
                mock.patch.object(
                    coordinator,
                    "_rollback_journal_locked",
                    side_effect=ProvisioningError("simulated process exit"),
                ),
                self.assertRaisesRegex(ProvisioningError, "rollback did not complete"),
            ):
                coordinator.finish_pending(result)
            self.assertIn(
                '"phase":"service_starting"',
                coordinator.journal_path.read_text(encoding="ascii"),
            )
            coordinator.close()

            with mock.patch(
                "coinbase_amoled_bridge.onboarding.restore_user_service",
                return_value=True,
            ) as restore:
                with self._coordinator(temporary) as recovered:
                    self.assertFalse(recovered.journal_path.exists())
                    self.assertNotIn(
                        result.device_id,
                        ConfigStore(temporary).load()["devices"],
                    )
            restore.assert_called_once_with(baseline)

    def test_finish_and_rollback_are_serialized_success_cannot_be_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            entered = threading.Event()
            release = threading.Event()

            def blocked_service(**_kwargs: object) -> ServiceStartResult:
                entered.set()
                if not release.wait(timeout=2):
                    raise AssertionError("test did not release service restart")
                return ServiceStartResult("started", "none")

            service = mock.Mock(side_effect=blocked_service)
            with self._coordinator(temporary, service=service) as coordinator:
                result = coordinator.complete(self._credentials("finish-race"))
                errors: list[BaseException] = []

                def finish() -> None:
                    try:
                        coordinator.finish_pending(result)
                    except BaseException as exc:
                        errors.append(exc)

                def rollback() -> None:
                    try:
                        coordinator.rollback_pending()
                    except BaseException as exc:
                        errors.append(exc)

                finish_thread = threading.Thread(target=finish)
                finish_thread.start()
                self.assertTrue(entered.wait(timeout=1))
                rollback_thread = threading.Thread(target=rollback)
                rollback_thread.start()
                release.set()
                finish_thread.join(timeout=2)
                rollback_thread.join(timeout=2)
                self.assertFalse(finish_thread.is_alive())
                self.assertFalse(rollback_thread.is_alive())
                self.assertEqual(errors, [])
                self.assertIn(
                    result.device_id,
                    ConfigStore(temporary).load()["devices"],
                )
                self.assertFalse(coordinator.journal_path.exists())

    def test_finish_fails_when_rollback_removed_pending_state_first(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self._coordinator(temporary) as coordinator:
                result = coordinator.complete(self._credentials("rollback-first"))
                coordinator.rollback_pending()
                with self.assertRaisesRegex(ProvisioningError, "no setup transaction"):
                    coordinator.finish_pending(result)
                self.assertFalse(Path(temporary, "config.json").exists())

    def test_finish_fails_closed_if_owned_state_is_removed_during_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = ConfigStore(temporary)
            result_holder: list[SafeProvisioning] = []

            def remove_owned_state(**_kwargs: object) -> ServiceStartResult:
                result = result_holder[0]

                def remove(config: dict[str, object]) -> None:
                    devices = config["devices"]
                    assert isinstance(devices, dict)
                    devices.pop(result.device_id, None)

                store.update(remove)
                Path(
                    temporary,
                    "secrets",
                    "devices",
                    f"{result.device_id}.token",
                ).unlink(missing_ok=True)
                return ServiceStartResult("started", "none")

            service = mock.Mock(side_effect=remove_owned_state)
            with self._coordinator(temporary, service=service) as coordinator:
                result = coordinator.complete(self._credentials("removed-state"))
                result_holder.append(result)
                with self.assertRaisesRegex(
                    ProvisioningError, "device changed during setup"
                ):
                    coordinator.finish_pending(result)
                self.assertNotIn(result.device_id, store.load()["devices"])
                self.assertFalse(coordinator.journal_path.exists())


def _pem() -> bytes:
    key = ec.derive_private_key(11, ec.SECP256R1())
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


if __name__ == "__main__":
    unittest.main()
