from __future__ import annotations

import base64
import os
import stat
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from coinbase_amoled_bridge.auth import (
    Credentials,
    DeviceManager,
    DeviceRegistry,
    JWTSigner,
    save_local_credentials,
)
from coinbase_amoled_bridge.config import ConfigStore
from coinbase_amoled_bridge.errors import CredentialError, ReadOnlyViolation

from .helpers import decode_segment, make_credentials


class JWTTests(unittest.TestCase):
    def test_es256_jwt_claims_and_signature(self) -> None:
        credentials, private_key = make_credentials()
        token = JWTSigner(credentials).sign(
            "GET", "/api/v3/brokerage/accounts", now=1_700_000_000
        )
        header_part, payload_part, signature_part = token.split(".")
        header = decode_segment(header_part)
        payload = decode_segment(payload_part)
        self.assertEqual(header["alg"], "ES256")
        self.assertEqual(header["kid"], credentials.key_name)
        self.assertGreaterEqual(len(header["nonce"]), 32)
        self.assertEqual(payload["iss"], "cdp")
        self.assertEqual(payload["sub"], credentials.key_name)
        self.assertEqual(payload["nbf"], 1_700_000_000)
        self.assertEqual(payload["exp"], 1_700_000_120)
        self.assertEqual(
            payload["uri"], "GET api.coinbase.com/api/v3/brokerage/accounts"
        )
        padded = signature_part + "=" * (-len(signature_part) % 4)
        raw_signature = base64.urlsafe_b64decode(padded)
        self.assertEqual(len(raw_signature), 64)
        r_value = int.from_bytes(raw_signature[:32], "big")
        s_value = int.from_bytes(raw_signature[32:], "big")
        private_key.public_key().verify(
            encode_dss_signature(r_value, s_value),
            f"{header_part}.{payload_part}".encode("ascii"),
            ec.ECDSA(hashes.SHA256()),
        )

    def test_signer_rejects_non_get_and_query(self) -> None:
        credentials, _ = make_credentials()
        signer = JWTSigner(credentials)
        with self.assertRaises(ReadOnlyViolation):
            signer.sign("POST", "/api/v3/brokerage/orders")
        with self.assertRaises(ReadOnlyViolation):
            signer.sign("GET", "/api/v3/brokerage/accounts?limit=1")

    def test_credentials_from_environment_and_files(self) -> None:
        credentials, _ = make_credentials()
        env = {
            "COINBASE_API_KEY_NAME": credentials.key_name,
            "COINBASE_API_PRIVATE_KEY": credentials.private_key_pem.decode().replace(
                "\n", "\\n"
            ),
        }
        loaded = Credentials.load("/unused", environ=env)
        self.assertEqual(loaded.source, "environment")
        self.assertEqual(loaded.key_name, credentials.key_name)
        with tempfile.TemporaryDirectory() as temporary:
            key_name = Path(temporary) / "name"
            private_key = Path(temporary) / "key"
            key_name.write_text(credentials.key_name)
            private_key.write_bytes(credentials.private_key_pem)
            loaded = Credentials.load(
                temporary,
                environ={
                    "COINBASE_API_KEY_NAME_FILE": str(key_name),
                    "COINBASE_API_PRIVATE_KEY_FILE": str(private_key),
                },
            )
            self.assertEqual(loaded.source, "file_environment")

    def test_local_credential_pair_does_not_leave_partial_write(self) -> None:
        credentials, _ = make_credentials()
        with tempfile.TemporaryDirectory() as temporary:
            secrets_dir = Path(temporary) / "secrets"
            secrets_dir.mkdir()
            private_path = secrets_dir / "coinbase_api_private_key"
            private_path.write_text("existing-value")
            with self.assertRaises(CredentialError):
                save_local_credentials(
                    temporary,
                    key_name=credentials.key_name,
                    private_key_pem=credentials.private_key_pem,
                )
            self.assertFalse((secrets_dir / "coinbase_api_key_name").exists())
            self.assertEqual(private_path.read_text(), "existing-value")

    def test_credentials_reject_partial_or_non_ec(self) -> None:
        with self.assertRaises(CredentialError):
            Credentials.load("/unused", environ={"COINBASE_API_KEY_NAME": "only-one"})
        with tempfile.TemporaryDirectory() as temporary:
            key_name = Path(temporary) / "name"
            private_key = Path(temporary) / "key"
            key_name.write_text("organizations/x/apiKeys/y")
            private_key.write_text("not a private key")
            with self.assertRaises(CredentialError):
                Credentials.load(
                    temporary,
                    environ={
                        "COINBASE_API_KEY_NAME_FILE": str(key_name),
                        "COINBASE_API_PRIVATE_KEY_FILE": str(private_key),
                    },
                )


class DeviceAuthTests(unittest.TestCase):
    def test_device_token_is_hashed_at_rest_and_revocation_reloads(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = ConfigStore(temporary)
            store.initialize()
            manager = DeviceManager(store)
            provision = manager.add(label="test terminal")
            token = provision.token_path.read_text().strip()
            config_text = store.path.read_text()
            self.assertNotIn(token, config_text)
            self.assertNotIn("bearer_token", config_text)
            mode = stat.S_IMODE(os.stat(provision.token_path).st_mode)
            self.assertEqual(mode & 0o077, 0)
            registry = DeviceRegistry(store, reload_interval=0)
            self.assertTrue(registry.authenticate(provision.device_id, token))
            self.assertFalse(registry.authenticate(provision.device_id, token + "x"))
            self.assertFalse(registry.authenticate("dev_unknown000", token))
            manager.set_enabled(provision.device_id, False)
            self.assertFalse(registry.authenticate(provision.device_id, token))

    def test_token_paths_cannot_overwrite_config_or_unapproved_custom_file(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = ConfigStore(temporary)
            store.initialize()
            manager = DeviceManager(store)
            with self.assertRaises(CredentialError):
                manager.add(token_path=store.path)
            provision = manager.add()
            custom = Path(temporary) / "already-there.token"
            custom.write_text("do-not-overwrite")
            with self.assertRaises(CredentialError):
                manager.rotate(provision.device_id, token_path=custom)
            self.assertEqual(custom.read_text(), "do-not-overwrite")
            self.assertTrue(store.load()["devices"][provision.device_id]["enabled"])

    def test_rotation_invalidates_old_token_without_printable_return(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = ConfigStore(temporary)
            store.initialize()
            manager = DeviceManager(store)
            provision = manager.add()
            old_token = provision.token_path.read_text().strip()
            rotated = manager.rotate(provision.device_id)
            new_token = rotated.token_path.read_text().strip()
            self.assertNotEqual(old_token, new_token)
            registry = DeviceRegistry(store, reload_interval=0)
            self.assertFalse(registry.authenticate(provision.device_id, old_token))
            self.assertTrue(registry.authenticate(provision.device_id, new_token))
            self.assertFalse(hasattr(rotated, "token"))


if __name__ == "__main__":
    unittest.main()
