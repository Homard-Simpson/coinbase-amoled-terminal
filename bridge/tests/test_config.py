from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from coinbase_amoled_bridge.config import (
    CURRENT_SCHEMA_VERSION,
    ConfigStore,
    default_config,
)
from coinbase_amoled_bridge.errors import ConfigError


class ConfigStoreTests(unittest.TestCase):
    def test_initialize_is_private_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = ConfigStore(temporary)
            first = store.initialize()
            second = store.initialize()
            self.assertEqual(first, second)
            self.assertEqual(first["schema_version"], CURRENT_SCHEMA_VERSION)
            self.assertEqual(stat.S_IMODE(os.stat(store.path).st_mode) & 0o077, 0)
            self.assertEqual(stat.S_IMODE(os.stat(store.data_dir).st_mode) & 0o077, 0)

    def test_schema_zero_migrates_with_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = ConfigStore(temporary)
            Path(temporary).mkdir(exist_ok=True)
            legacy = {"settings": {"symbols": ["BTC", "ETH"]}, "devices": {}}
            store.path.write_text(json.dumps(legacy))
            migrated = store.load()
            self.assertEqual(migrated["schema_version"], 1)
            self.assertEqual(migrated["settings"]["symbols"], ["BTC", "ETH"])
            backups = list(Path(temporary).glob("config.json.bak-v0-*"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(json.loads(backups[0].read_text()), legacy)

    def test_migration_refuses_raw_secret_without_copying_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = ConfigStore(temporary)
            store.path.parent.mkdir(parents=True, exist_ok=True)
            store.path.write_text(json.dumps({"token": "raw-secret", "devices": {}}))
            with self.assertRaises(ConfigError):
                store.load()
            self.assertEqual(list(Path(temporary).glob("*.bak-*")), [])

    def test_future_schema_and_unknown_fields_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = ConfigStore(temporary)
            config = default_config()
            config["schema_version"] = 999
            store.path.parent.mkdir(parents=True, exist_ok=True)
            store.path.write_text(json.dumps(config))
            with self.assertRaises(ConfigError):
                store.load()
            config = default_config()
            config["unexpected"] = True
            store.path.write_text(json.dumps(config))
            with self.assertRaises(ConfigError):
                store.load()

    def test_unicode_device_identifier_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = ConfigStore(temporary)
            config = store.initialize()
            config["devices"]["dev_éééééééééééé"] = {
                "token_sha256": "a" * 64,
                "enabled": True,
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
                "label": "",
            }
            with self.assertRaises(ConfigError):
                store.replace(config)

    def test_update_validates_and_preserves_original_on_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = ConfigStore(temporary)
            original = store.initialize()

            def invalid(config: dict) -> None:
                config["settings"]["refresh_seconds"] = 0

            with self.assertRaises(ConfigError):
                store.update(invalid)
            self.assertEqual(store.load(), original)


if __name__ == "__main__":
    unittest.main()
