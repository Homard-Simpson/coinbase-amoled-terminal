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
import uuid
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from coinbase_amoled_bridge.auth import (
    Credentials,
    DeviceRegistry,
    active_local_credential_slot,
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
    PENDING_ABORT_PATH,
    PENDING_CLAIM_PATH,
    PENDING_STATUS_PATH,
    PORTAL_ORIGIN,
    PROVISIONING_PATH,
    OnboardingCoordinator,
    SafeProvisioning,
    SetupSession,
    create_onboarding_server,
    create_pending_claim_server,
    render_local_setup_page,
)
from coinbase_amoled_bridge.quickstart import MAX_CDP_JSON_BYTES
from coinbase_amoled_bridge.user_service import ServiceStartResult


def _pem(scalar: int = 11) -> bytes:
    key = ec.derive_private_key(scalar, ec.SECP256R1())
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


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
    def __init__(self, *, error: Exception | None = None) -> None:
        self.error = error
        self.credentials: list[Credentials] = []
        self.rollbacks = 0

    def complete(self, credentials: Credentials) -> SafeProvisioning:
        self.credentials.append(credentials)
        if self.error:
            raise self.error
        return SafeProvisioning(
            bridge_url="http://100.100.20.10:8788/v1/device-feed",
            device_id="123e4567-e89b-42d3-a456-426614174000",
            feed_token="cbat_" + ("A" * 43),
            expires_at=int(time.time()) + 600,
        )

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

    def auth_headers(self) -> dict[str, str]:
        return {
            "Authorization": "Setup " + self.setup_token,
            "X-Setup-Session": self.session.session_id,
            "X-CSRF-Token": self.session.csrf_token,
            "Content-Type": "application/json",
        }

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
    def test_random_setup_bearer_expires_and_is_single_flight_single_use(self) -> None:
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
        first.set_provisioning(
            SafeProvisioning(
                bridge_url="http://100.100.20.10:8788/v1/device-feed",
                device_id="123e4567-e89b-42d3-a456-426614174000",
                feed_token="cbat_" + ("A" * 43),
                expires_at=int(time.time()) + 60,
            )
        )
        first.use_once()
        self.assertEqual(first.setup_token, "")
        with self.assertRaises(SetupSessionError):
            first.begin_once()
        first.mark_finished()
        self.assertTrue(first.finished_event.is_set())

        expired = SetupSession.create(ttl_seconds=60)
        expired.monotonic_deadline = time.monotonic() - 1
        with self.assertRaises(SetupSessionError):
            expired.begin_once()

    def test_local_fallback_clears_inputs_and_saves_only_safe_pending_values(
        self,
    ) -> None:
        session = SetupSession.create(ttl_seconds=60)
        session.bind_endpoint(43123)
        page = render_local_setup_page(session)
        self.assertIn('autocomplete="off"', page)
        self.assertIn("cache:'no-store'", page)
        self.assertIn("http://192.168.4.1/save", page)
        self.assertIn("pending_token", page)
        self.assertIn("pending_expires_at", page)
        self.assertNotIn("finishEndpoint", page)
        self.assertNotIn("completionToken", page)
        self.assertNotIn("reconnect this computer", page.lower())
        self.assertNotIn("localStorage", page)
        self.assertNotIn("sessionStorage", page)
        self.assertIn("await abortPending(pending)", page)
        self.assertIn(
            "key='';text.value='';file.value='';wifi.value='';await abortPending",
            page,
        )
        self.assertIn("/abort-pending", page)
        self.assertIn(
            "key='';pending=null;text.value='';file.value='';wifi.value=''", page
        )
        self.assertNotIn("setupHeaders(),body:safePendingBody", page)


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

    def test_real_generated_uuid_reaches_end_to_end_staging_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            coordinator = OnboardingCoordinator(
                temporary,
                bridge_url="http://100.100.20.10:8788/v1/device-feed",
                permission_checker=mock.Mock(
                    side_effect=AssertionError("staging contacted Coinbase")
                ),
                service_starter=mock.Mock(
                    return_value=ServiceStartResult("started", "none")
                ),
                readiness_checker=mock.Mock(return_value=True),
                pending_ttl_seconds=60,
            )
            running = RunningServer(coordinator)
            try:
                status, _, body = running.request(
                    "POST",
                    ONBOARDING_PATH,
                    body=key_json(marker="real-generated-id"),
                    headers=running.auth_headers(),
                )
                self.assertEqual(status, 200)
                payload = json.loads(body)
                generated = payload["device_id"]
                parsed = uuid.UUID(generated)
                self.assertEqual(parsed.version, 4)
                self.assertEqual(str(parsed), generated)
                self.assertEqual(
                    coordinator.pending_provisioning().device_id,
                    generated,
                )
            finally:
                running.close()
                coordinator.rollback_pending()
                coordinator.close()

    def test_valid_key_returns_only_safe_pending_values_and_no_browser_ack_route(
        self,
    ) -> None:
        key = key_json(marker="must-not-leak")
        headers = self.running.auth_headers()
        status, response_headers, body = self.running.request(
            "POST", ONBOARDING_PATH, body=key, headers=headers
        )
        self.assertEqual(status, 200, body)
        value = json.loads(body)
        self.assertEqual(
            set(value),
            {
                "ok",
                "bridge_url",
                "device_id",
                "pending_token",
                "expires_at",
                "status",
                "claim_path",
                "status_path",
            },
        )
        self.assertEqual(value["status"], "waiting_for_network")
        self.assertNotIn(b"must-not-leak", body)
        self.assertNotIn(b"PRIVATE KEY", body)
        self.assertEqual(response_headers["access-control-allow-origin"], PORTAL_ORIGIN)
        self.assertEqual(len(self.coordinator.credentials), 1)
        self.assertTrue(self.running.session.provisioned_event.is_set())

        status, _, second_body = self.running.request(
            "POST", ONBOARDING_PATH, body=key, headers=headers
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(second_body), GENERIC_ERROR)
        for legacy in (PROVISIONING_PATH, FINISH_PATH):
            status, _, _ = self.running.request("POST", legacy, body=b"")
            self.assertEqual(status, 404)

    def test_used_session_page_never_renders_setup_bearer_again(self) -> None:
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

    def test_method_content_type_limits_origin_and_non_echoing_errors(self) -> None:
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
        status, _, _ = self.running.request(
            "POST",
            ONBOARDING_PATH,
            body=key,
            origin="null",
            headers=self.running.auth_headers(),
        )
        self.assertEqual(status, 403)
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
            "POST", ONBOARDING_PATH, body=bad_curve, headers=self.running.auth_headers()
        )
        self.assertEqual(status, 400)
        self.assertNotIn(b"wrong-curve-marker", body)

    def test_raw_ingress_limits_framing_and_connection_concurrency(self) -> None:
        expected_host = self.running.session.endpoint_origin.removeprefix("http://")
        oversized = (
            f"GET / HTTP/1.1\r\nHost: {expected_host}\r\nX-Fill: ".encode()
            + (b"a" * MAX_HEADER_BYTES)
            + b"\r\n\r\n"
        )
        response = self.running.raw_request(oversized)
        self.assertTrue(response.startswith(b"HTTP/1.1 431 "), response[:80])
        chunked = (
            f"POST {ONBOARDING_PATH} HTTP/1.1\r\n"
            f"Host: {expected_host}\r\n"
            "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        ).encode()
        response = self.running.raw_request(chunked)
        self.assertTrue(response.startswith(b"HTTP/1.1 400 "), response[:80])

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

        sockets: list[socket.socket] = []
        address = ("127.0.0.1", self.running.server.server_address[1])
        try:
            for _ in range(MAX_CONCURRENT_CONNECTIONS):
                sock = socket.create_connection(address, timeout=3)
                sock.sendall(b"GET / HTTP/1.1\r\n")
                sockets.append(sock)
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
            for sock in sockets:
                sock.close()


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
        bridge_url: str = "http://100.100.20.10:8788/v1/device-feed",
        permission: mock.Mock | None = None,
        service: mock.Mock | None = None,
        readiness: mock.Mock | None = None,
    ) -> OnboardingCoordinator:
        return OnboardingCoordinator(
            data_dir,
            bridge_url=bridge_url,
            permission_checker=permission or mock.Mock(),
            service_starter=service
            or mock.Mock(return_value=ServiceStartResult("started", "none")),
            readiness_checker=readiness or mock.Mock(return_value=True),
            finish_timeout_seconds=1,
            retry_interval=0,
            pending_ttl_seconds=60,
        )

    @staticmethod
    def _claim(coordinator: OnboardingCoordinator, pending: SafeProvisioning) -> None:
        coordinator.claim_pending(
            device_id=pending.device_id,
            token=pending.feed_token,
        )

    def test_staging_is_local_only_crash_safe_mode_0600_and_feed_inactive(self) -> None:
        credentials = self._credentials("local-only")
        permission = mock.Mock(
            side_effect=AssertionError("network gate ran during staging")
        )
        with tempfile.TemporaryDirectory() as temporary:
            with self._coordinator(temporary, permission=permission) as coordinator:
                pending = coordinator.complete(credentials)
                parsed_id = uuid.UUID(pending.public_json()["device_id"])
                self.assertEqual(parsed_id.version, 4)
                self.assertEqual(str(parsed_id), pending.device_id)
                self.assertTrue(coordinator.journal_path.is_file())
                self.assertFalse(Path(temporary, "config.json").exists())
                self.assertIsNone(active_local_credential_slot(temporary))
                slot = next(
                    Path(temporary, "secrets", "credential-slots").glob("*.bundle")
                )
                self.assertEqual(stat.S_IMODE(os.stat(slot).st_mode), 0o600)
                self.assertEqual(
                    stat.S_IMODE(os.stat(coordinator.journal_path).st_mode), 0o600
                )
                public = pending.public_json()
                self.assertNotIn(credentials.key_name, json.dumps(public))
                self.assertNotIn("feed_token", public)
                coordinator.rollback_pending()
                self.assertFalse(Path(temporary, "secrets").exists())
        permission.assert_not_called()

    def test_offline_then_online_claim_activates_credentials_and_feed_token(
        self,
    ) -> None:
        credentials = self._credentials("offline-online")
        permission = mock.Mock(
            side_effect=[CoinbaseAPIError("upstream_unreachable"), None]
        )
        states: list[str] = []
        with tempfile.TemporaryDirectory() as temporary:
            with self._coordinator(temporary, permission=permission) as coordinator:
                pending = coordinator.complete(credentials)
                self.assertFalse(Path(temporary, "config.json").exists())
                self._claim(coordinator, pending)
                coordinator.finish_pending(pending, status_callback=states.append)
                registry = DeviceRegistry(ConfigStore(temporary), reload_interval=0)
                self.assertTrue(
                    registry.authenticate(pending.device_id, pending.feed_token)
                )
                self.assertEqual(
                    Credentials.load_local(temporary).key_name,
                    credentials.key_name,
                )
                self.assertFalse(coordinator.journal_path.exists())
        self.assertEqual(permission.call_count, 2)
        self.assertIn("waiting_for_network", states)
        self.assertEqual(states[-1], "ready")

    def test_unsafe_key_rejection_removes_stage_and_never_activates_feed(self) -> None:
        permission = mock.Mock(side_effect=UnsafeCredentialError("unsafe"))
        with tempfile.TemporaryDirectory() as temporary:
            with self._coordinator(temporary, permission=permission) as coordinator:
                pending = coordinator.complete(self._credentials("unsafe"))
                self._claim(coordinator, pending)
                with self.assertRaises(UnsafeCredentialError):
                    coordinator.finish_pending(pending)
                self.assertFalse(coordinator.journal_path.exists())
                self.assertIsNone(active_local_credential_slot(temporary))
                config_path = Path(temporary, "config.json")
                if config_path.exists():
                    self.assertNotIn(
                        pending.device_id, ConfigStore(temporary).load()["devices"]
                    )
                self.assertFalse(
                    Path(
                        temporary,
                        "secrets",
                        "devices",
                        f"{pending.device_id}.token",
                    ).exists()
                )

    def test_delayed_claim_survives_restart_and_completes_automatically(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            first = self._coordinator(temporary)
            pending = first.complete(self._credentials("delayed"))
            first.close()
            with self._coordinator(temporary) as recovered:
                restored = recovered.pending_provisioning()
                self.assertEqual(restored, pending)
                self._claim(recovered, restored)
            with self._coordinator(temporary) as claimed_recovery:
                restored = claimed_recovery.pending_provisioning()
                self.assertEqual(restored, pending)
                claimed_recovery.finish_pending(restored)
                self.assertTrue(
                    DeviceRegistry(
                        ConfigStore(temporary), reload_interval=0
                    ).authenticate(pending.device_id, pending.feed_token)
                )

    def test_expired_unclaimed_stage_is_removed_on_startup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            first = self._coordinator(temporary)
            first.complete(self._credentials("expired"))
            journal = first.journal_path
            value = json.loads(journal.read_text(encoding="ascii"))
            value["expires_at"] = int(time.time()) - 1
            journal.write_text(
                json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n",
                encoding="ascii",
            )
            os.chmod(journal, 0o600)
            first.close()
            with self._coordinator(temporary) as recovered:
                self.assertIsNone(recovered.pending_provisioning())
                self.assertFalse(recovered.journal_path.exists())
                self.assertFalse(Path(temporary, "secrets").exists())

    def test_service_failure_rolls_back_only_owned_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = ConfigStore(temporary)
            store.initialize()
            original = json.loads(json.dumps(store.load()))
            service = mock.Mock(return_value=ServiceStartResult("failed", "none"))
            with self._coordinator(temporary, service=service) as coordinator:
                pending = coordinator.complete(self._credentials("service-fail"))
                self._claim(coordinator, pending)
                with self.assertRaises(ProvisioningError):
                    coordinator.finish_pending(pending)
                current = store.load()
                self.assertNotIn(pending.device_id, current["devices"])
                self.assertEqual(current["settings"], original["settings"])

    def test_owner_lock_refuses_second_coordinator_and_corrupt_journal_is_loud(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self._coordinator(temporary):
                with self.assertRaises(ProvisioningError):
                    self._coordinator(temporary)
        with tempfile.TemporaryDirectory() as temporary:
            journal = Path(temporary, ".onboarding", "journal.json")
            journal.parent.mkdir(mode=0o700)
            journal.write_text("{}\n", encoding="ascii")
            with self.assertRaisesRegex(
                ProvisioningError, "recovery journal is invalid"
            ):
                self._coordinator(temporary)
            self.assertEqual(journal.read_text(encoding="ascii"), "{}\n")


class PendingClaimHTTPTests(unittest.TestCase):
    @staticmethod
    def _free_port() -> int:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            return int(listener.getsockname()[1])

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.port = self._free_port()
        self.bridge_url = f"http://127.0.0.1:{self.port}/v1/device-feed"
        self.permission = mock.Mock()
        self.coordinator = OnboardingCoordinator(
            self.temporary.name,
            bridge_url=self.bridge_url,
            permission_checker=self.permission,
            service_starter=mock.Mock(
                return_value=ServiceStartResult("started", "none")
            ),
            readiness_checker=mock.Mock(return_value=True),
            finish_timeout_seconds=1,
            retry_interval=0,
            pending_ttl_seconds=60,
        )
        self.pending = self.coordinator.complete(
            Credentials.from_values(
                key_name="organizations/example/apiKeys/pending-http",
                private_key_pem=_pem(17),
                source="test",
            )
        )
        self.server = create_pending_claim_server(
            self.coordinator,
            bridge_url=self.bridge_url,
            bind_host="127.0.0.1",
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.coordinator.rollback_pending()
        self.coordinator.close()
        self.temporary.cleanup()

    def request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        device_id: str | None = None,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], dict[str, object]]:
        request_headers = dict(headers or {})
        if token is not None:
            request_headers["Authorization"] = "Bearer " + token
        if device_id is not None:
            request_headers["X-Device-ID"] = device_id
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        payload = response.read()
        result = (
            response.status,
            {key.lower(): value for key, value in response.getheaders()},
            json.loads(payload),
        )
        connection.close()
        return result

    def test_token_authenticated_claim_status_and_inactive_feed(self) -> None:
        status, headers, value = self.request(
            "GET",
            PENDING_STATUS_PATH,
            token=self.pending.feed_token,
            device_id=self.pending.device_id,
        )
        self.assertEqual(status, 200)
        self.assertEqual(value["status"], "waiting_for_network")
        self.assertEqual(headers["cache-control"], "no-store, max-age=0")
        status, _, value = self.request(
            "POST",
            PENDING_CLAIM_PATH,
            token=self.pending.feed_token,
            device_id=self.pending.device_id,
        )
        self.assertEqual(status, 200)
        self.assertEqual(value["status"], "checking_read_only_key")
        self.assertTrue(self.server.app.claimed_event.is_set())
        self.assertFalse(Path(self.temporary.name, "config.json").exists())
        self.permission.assert_not_called()

    def test_wrong_token_queries_bodies_and_methods_fail_closed(self) -> None:
        status, headers, value = self.request(
            "GET",
            PENDING_STATUS_PATH,
            token=self.pending.feed_token + "x",
            device_id=self.pending.device_id,
        )
        self.assertEqual(status, 401)
        self.assertEqual(value, {"ok": False, "status": "rejected"})
        self.assertIn("Bearer", headers["www-authenticate"])
        status, _, _ = self.request(
            "POST",
            PENDING_CLAIM_PATH + "?debug=1",
            token=self.pending.feed_token,
            device_id=self.pending.device_id,
        )
        self.assertEqual(status, 400)
        status, _, _ = self.request(
            "POST",
            PENDING_CLAIM_PATH,
            token=self.pending.feed_token,
            device_id=self.pending.device_id,
            body=b"{}",
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 400)
        status, _, _ = self.request(
            "PUT",
            PENDING_CLAIM_PATH,
            token=self.pending.feed_token,
            device_id=self.pending.device_id,
        )
        self.assertEqual(status, 405)

    def test_authenticated_abort_is_idempotent_and_wrong_token_cannot_abort(
        self,
    ) -> None:
        status, headers, value = self.request(
            "POST",
            PENDING_ABORT_PATH,
            token=self.pending.feed_token + "x",
            device_id=self.pending.device_id,
        )
        self.assertEqual(status, 401)
        self.assertEqual(value, {"ok": False, "status": "rejected"})
        self.assertNotIn("access-control-allow-origin", headers)
        self.assertTrue(self.coordinator.journal_path.exists())
        status, _, value = self.request(
            "POST",
            PENDING_ABORT_PATH,
            token=self.pending.feed_token,
            device_id="wrong-" + self.pending.device_id,
        )
        self.assertEqual(status, 401)
        self.assertEqual(value, {"ok": False, "status": "rejected"})
        self.assertTrue(self.coordinator.journal_path.exists())

        for _attempt in range(2):
            status, headers, value = self.request(
                "POST",
                PENDING_ABORT_PATH,
                token=self.pending.feed_token,
                device_id=self.pending.device_id,
            )
            self.assertEqual(status, 200)
            self.assertEqual(value, {"ok": False, "status": "rejected"})
            self.assertNotIn("access-control-allow-origin", headers)
        self.assertFalse(self.coordinator.journal_path.exists())
        self.assertFalse(Path(self.temporary.name, "secrets").exists())

    def test_expired_claim_rolls_back_before_generic_rejection(self) -> None:
        self.server.app.expires_at = int(time.time()) - 1
        status, _, value = self.request(
            "POST",
            PENDING_CLAIM_PATH,
            token=self.pending.feed_token,
            device_id=self.pending.device_id,
        )
        self.assertEqual(status, 410)
        self.assertEqual(value, {"ok": False, "status": "rejected"})
        self.assertFalse(self.coordinator.journal_path.exists())
        self.assertFalse(Path(self.temporary.name, "secrets").exists())


if __name__ == "__main__":
    unittest.main()
