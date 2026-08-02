from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import shlex
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from coinbase_amoled_bridge.auth import DeviceManager
from coinbase_amoled_bridge.cli import main
from coinbase_amoled_bridge.config import ConfigStore
from coinbase_amoled_bridge.errors import CredentialError, UnsafeCredentialError
from coinbase_amoled_bridge.quickstart import (
    MAX_CDP_JSON_BYTES,
    QUICKSTART_PROMPT,
    parse_cdp_key_input,
)
from coinbase_amoled_bridge.user_service import ServiceStartResult


def _pem_for(key: object) -> bytes:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        private_format = serialization.PrivateFormat.TraditionalOpenSSL
    else:
        private_format = serialization.PrivateFormat.PKCS8
    return key.private_bytes(  # type: ignore[union-attr]
        serialization.Encoding.PEM,
        private_format,
        serialization.NoEncryption(),
    )


def _key_json(
    key: object | None = None,
    *,
    name: str = "organizations/example/apiKeys/quickstart-test",
    extra: dict[str, object] | None = None,
) -> tuple[str, bytes]:
    private_key = _pem_for(key or ec.generate_private_key(ec.SECP256R1()))
    value: dict[str, object] = {
        "name": name,
        "privateKey": private_key.decode("utf-8"),
    }
    value.update(extra or {})
    return json.dumps(value, separators=(",", ":")), private_key


class CDPKeyInputTests(unittest.TestCase):
    def test_minified_official_json_is_accepted(self) -> None:
        raw, pem = _key_json(extra={"keyType": "ECDSA", "algorithm": "ES256"})
        credentials = parse_cdp_key_input(raw)
        self.assertEqual(
            credentials.key_name, "organizations/example/apiKeys/quickstart-test"
        )
        self.assertEqual(credentials.private_key_pem, pem)
        self.assertEqual(credentials.source, "quickstart")

    def test_dragged_or_quoted_file_path_is_accepted(self) -> None:
        raw, _ = _key_json()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "downloaded Coinbase key.json"
            path.write_text(raw, encoding="utf-8")
            quoted = parse_cdp_key_input(shlex.quote(str(path)))
            escaped = parse_cdp_key_input(str(path).replace(" ", "\\ "))
        self.assertEqual(quoted.key_name, escaped.key_name)

    def test_malformed_missing_duplicate_and_legacy_json_are_rejected(self) -> None:
        private_field = "private" + "Key"
        legacy_key_field = "api" + "Key"
        legacy_secret_field = "api" + "Secret"
        duplicate = '{"name":"first","name":"second","' + private_field + '":"x"}'
        values = (
            "{not-json}",
            "[]",
            json.dumps({"name": "organizations/example/apiKeys/missing"}),
            json.dumps(
                {
                    "name": "organizations/example/apiKeys/not-text",
                    private_field: 7,
                }
            ),
            duplicate,
            json.dumps({legacy_key_field: "x", legacy_secret_field: "y"}),
        )
        for value in values:
            with self.subTest(value=value[:20]), self.assertRaises(CredentialError):
                parse_cdp_key_input(value)

    def test_oversized_line_file_name_and_private_key_are_rejected(self) -> None:
        oversized_line = "{" + ("x" * MAX_CDP_JSON_BYTES) + "}"
        with self.assertRaises(CredentialError):
            parse_cdp_key_input(oversized_line)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "oversized.json"
            path.write_bytes(b"x" * (MAX_CDP_JSON_BYTES + 1))
            with self.assertRaises(CredentialError):
                parse_cdp_key_input(str(path))
        too_long_name, _ = _key_json(name="n" * 2_049)
        with self.assertRaises(CredentialError):
            parse_cdp_key_input(too_long_name)
        raw = json.dumps(
            {
                "name": "organizations/example/apiKeys/large",
                "privateKey": "x" * 65_537,
            },
            separators=(",", ":"),
        )
        with self.assertRaises(CredentialError):
            parse_cdp_key_input(raw)

    def test_ed25519_rsa_and_non_p256_keys_are_rejected(self) -> None:
        keys = (
            ed25519.Ed25519PrivateKey.generate(),
            rsa.generate_private_key(public_exponent=65_537, key_size=2_048),
            ec.generate_private_key(ec.SECP384R1()),
        )
        for key in keys:
            raw, _ = _key_json(key)
            with (
                self.subTest(key=type(key).__name__),
                self.assertRaises(CredentialError),
            ):
                parse_cdp_key_input(raw)

    def test_prompt_is_one_clear_hidden_input_line(self) -> None:
        self.assertEqual(QUICKSTART_PROMPT.count("\n"), 0)
        self.assertIn("Paste the Coinbase CDP ECDSA API key JSON", QUICKSTART_PROMPT)
        self.assertIn("drag the JSON file", QUICKSTART_PROMPT)
        self.assertTrue(QUICKSTART_PROMPT.endswith("press Enter: "))


class QuickstartCommandTests(unittest.TestCase):
    def _run_live(
        self,
        data_dir: str,
        raw: str,
        *,
        doctor: object = None,
        service: ServiceStartResult | None = None,
    ) -> tuple[int, str, str, mock.Mock, mock.Mock]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        doctor_mock = (
            mock.Mock(return_value=0)
            if doctor is None
            else mock.Mock(side_effect=doctor)
        )
        service_mock = mock.Mock(
            return_value=service or ServiceStartResult("started", "systemd")
        )
        with (
            mock.patch(
                "coinbase_amoled_bridge.quickstart.getpass.getpass", return_value=raw
            ),
            mock.patch(
                "coinbase_amoled_bridge.cli._assert_live_key_is_view_only"
            ) as permission_gate,
            mock.patch("coinbase_amoled_bridge.cli.command_doctor", doctor_mock),
            mock.patch("coinbase_amoled_bridge.cli.start_user_service", service_mock),
            mock.patch(
                "coinbase_amoled_bridge.cli._lan_feed_url",
                return_value="http://host.example.invalid/v1/device-feed",
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = main(["--data-dir", data_dir, "quickstart"])
        return (
            result,
            stdout.getvalue(),
            stderr.getvalue(),
            permission_gate,
            service_mock,
        )

    def test_success_never_prints_or_logs_coinbase_or_device_credentials(self) -> None:
        raw, private_key = _key_json(name="organizations/example/apiKeys/do-not-leak")
        with tempfile.TemporaryDirectory() as temporary:
            result, stdout, stderr, gate, service = self._run_live(temporary, raw)
            config = ConfigStore(temporary).load()
            device_id = next(iter(config["devices"]))
            token_path = Path(temporary) / "secrets" / "devices" / f"{device_id}.token"
            token = token_path.read_text(encoding="ascii").strip()
            name_mode = stat.S_IMODE(
                os.stat(Path(temporary) / "secrets" / "coinbase_api_key_name").st_mode
            )
            key_mode = stat.S_IMODE(
                os.stat(
                    Path(temporary) / "secrets" / "coinbase_api_private_key"
                ).st_mode
            )
        output = stdout + stderr
        self.assertEqual(result, 0)
        self.assertEqual(gate.call_count, 1)
        self.assertEqual(service.call_count, 1)
        self.assertNotIn("do-not-leak", output)
        self.assertNotIn(private_key.decode("utf-8"), output)
        self.assertNotIn(token, output)
        self.assertNotIn(raw, output)
        self.assertEqual(name_mode & 0o077, 0)
        self.assertEqual(key_mode & 0o077, 0)

    def test_initial_permission_refusal_writes_nothing_and_leaks_nothing(self) -> None:
        raw, _ = _key_json(name="organizations/example/apiKeys/refused-marker")
        with tempfile.TemporaryDirectory() as temporary:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch(
                    "coinbase_amoled_bridge.quickstart.getpass.getpass",
                    return_value=raw,
                ),
                mock.patch(
                    "coinbase_amoled_bridge.cli._assert_live_key_is_view_only",
                    side_effect=UnsafeCredentialError(
                        "Coinbase key must have view permission and no trade or "
                        "transfer permission"
                    ),
                ),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                result = main(["--data-dir", temporary, "quickstart"])
            self.assertEqual(result, 2)
            self.assertFalse((Path(temporary) / "config.json").exists())
            self.assertFalse((Path(temporary) / "secrets").exists())
            self.assertNotIn("refused-marker", stdout.getvalue() + stderr.getvalue())

    def test_second_permission_gate_failure_rolls_back_new_state(self) -> None:
        raw, _ = _key_json()
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch(
                "coinbase_amoled_bridge.cli.rollback_user_service"
            ) as rollback_service:
                result, _, _, _, _ = self._run_live(
                    temporary,
                    raw,
                    doctor=UnsafeCredentialError("unsafe permissions"),
                )
            self.assertEqual(result, 2)
            rollback_service.assert_called_once()
            self.assertFalse((Path(temporary) / "config.json").exists())
            self.assertFalse((Path(temporary) / "secrets").exists())

    def test_failed_live_upgrade_preserves_existing_config_and_device_token(
        self,
    ) -> None:
        raw, _ = _key_json()
        with tempfile.TemporaryDirectory() as temporary:
            store = ConfigStore(temporary)
            store.initialize()
            provision = DeviceManager(store).add(label="existing display")
            original_config = store.load()
            original_token = provision.token_path.read_bytes()
            result, _, _, _, _ = self._run_live(
                temporary,
                raw,
                doctor=UnsafeCredentialError("unsafe permissions"),
            )
            self.assertEqual(result, 2)
            self.assertEqual(store.load(), original_config)
            self.assertEqual(provision.token_path.read_bytes(), original_token)
            self.assertFalse(
                (Path(temporary) / "secrets" / "coinbase_api_key_name").exists()
            )
            self.assertFalse(
                (Path(temporary) / "secrets" / "coinbase_api_private_key").exists()
            )

    def test_service_starts_before_doctor_and_permission_gate_runs_first(self) -> None:
        raw, _ = _key_json()
        events: list[str] = []

        def doctor(args: argparse.Namespace, store: ConfigStore) -> int:
            self.assertTrue(args.local_only)
            events.append("doctor")
            return 0

        with tempfile.TemporaryDirectory() as temporary:
            with (
                mock.patch(
                    "coinbase_amoled_bridge.quickstart.getpass.getpass",
                    return_value=raw,
                ),
                mock.patch(
                    "coinbase_amoled_bridge.cli._assert_live_key_is_view_only",
                    side_effect=lambda credentials: events.append("permissions"),
                ),
                mock.patch(
                    "coinbase_amoled_bridge.cli.start_user_service",
                    side_effect=lambda: (
                        events.append("service")
                        or ServiceStartResult("started", "systemd")
                    ),
                ),
                mock.patch(
                    "coinbase_amoled_bridge.cli.command_doctor",
                    side_effect=doctor,
                ),
                mock.patch(
                    "coinbase_amoled_bridge.cli._lan_feed_url",
                    return_value="http://host.example.invalid/v1/device-feed",
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(main(["--data-dir", temporary, "quickstart"]), 0)
        self.assertEqual(events, ["permissions", "service", "doctor"])

    def test_sample_quickstart_is_idempotent_and_offline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = io.StringIO()
            with (
                mock.patch(
                    "coinbase_amoled_bridge.cli.start_user_service",
                    return_value=ServiceStartResult("unavailable", "none"),
                ) as service,
                mock.patch(
                    "coinbase_amoled_bridge.cli._lan_feed_url",
                    return_value="http://host.example.invalid/v1/device-feed",
                ),
                mock.patch(
                    "coinbase_amoled_bridge.cli._assert_live_key_is_view_only"
                ) as live_gate,
                contextlib.redirect_stdout(output),
            ):
                for _ in range(2):
                    self.assertEqual(
                        main(["--data-dir", temporary, "quickstart", "--sample"]),
                        0,
                    )
            config = ConfigStore(temporary).load()
            self.assertEqual(len(config["devices"]), 1)
            device_id = next(iter(config["devices"]))
            token_path = Path(temporary) / "secrets" / "devices" / f"{device_id}.token"
            token = token_path.read_text(encoding="ascii").strip()
        self.assertEqual(service.call_count, 2)
        live_gate.assert_not_called()
        self.assertNotIn(token, output.getvalue())
        self.assertIn("sample/offline", output.getvalue())

    def test_malformed_input_error_does_not_echo_input(self) -> None:
        marker = "malformed-sensitive-marker"
        with tempfile.TemporaryDirectory() as temporary:
            result, stdout, stderr, _, _ = self._run_live(temporary, "{" + marker)
        self.assertEqual(result, 2)
        self.assertNotIn(marker, stdout + stderr)


if __name__ == "__main__":
    unittest.main()
