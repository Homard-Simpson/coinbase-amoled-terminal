from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from coinbase_amoled_bridge.auth import Credentials
from coinbase_amoled_bridge.cli import main
from coinbase_amoled_bridge.config import ConfigStore


class CLITests(unittest.TestCase):
    def test_noninteractive_sample_setup_never_prints_token(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(
                    [
                        "--data-dir",
                        temporary,
                        "setup",
                        "--sample",
                        "--non-interactive",
                    ]
                )
            self.assertEqual(result, 0)
            config = ConfigStore(temporary).load()
            self.assertEqual(len(config["devices"]), 1)
            device_id = next(iter(config["devices"]))
            token_path = Path(temporary) / "secrets" / "devices" / f"{device_id}.token"
            token = token_path.read_text().strip()
            self.assertNotIn(token, stdout.getvalue())
            self.assertNotIn(token, ConfigStore(temporary).path.read_text())
            self.assertIn("was not printed", stdout.getvalue())

    def test_file_setup_does_not_echo_coinbase_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            key = ec.generate_private_key(ec.SECP256R1())
            pem = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
            key_name = "organizations/example/apiKeys/sensitive-test-name"
            input_dir = Path(temporary) / "inputs"
            input_dir.mkdir()
            name_path = input_dir / "name"
            key_path = input_dir / "private.pem"
            name_path.write_text(key_name)
            key_path.write_bytes(pem)
            data_dir = Path(temporary) / "data"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(
                    [
                        "--data-dir",
                        str(data_dir),
                        "setup",
                        "--non-interactive",
                        "--key-name-file",
                        str(name_path),
                        "--private-key-file",
                        str(key_path),
                        "--no-device",
                    ]
                )
            self.assertEqual(result, 0)
            output = stdout.getvalue()
            self.assertNotIn(key_name, output)
            self.assertNotIn("BEGIN EC PRIVATE KEY", output)
            loaded = Credentials.load(data_dir, environ={})
            self.assertEqual(loaded.key_name, key_name)

    def test_plain_public_bind_requires_explicit_acknowledgement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with (
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(
                    main(
                        [
                            "--data-dir",
                            temporary,
                            "setup",
                            "--sample",
                            "--non-interactive",
                        ]
                    ),
                    0,
                )
                result = main(
                    [
                        "--data-dir",
                        temporary,
                        "serve",
                        "--sample",
                        "--host",
                        "0.0.0.0",
                    ]
                )
            self.assertEqual(result, 2)


if __name__ == "__main__":
    unittest.main()
