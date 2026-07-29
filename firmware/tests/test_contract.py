#!/usr/bin/env python3
import json
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ContractTests(unittest.TestCase):
    def load_json(self, relative):
        return json.loads((ROOT / relative).read_text(encoding="utf-8"))

    def test_runtime_schema_is_sanitized_and_has_no_defaults(self):
        schema = self.load_json("config/runtime-config.schema.json")
        self.assertEqual(schema["properties"]["schema_version"]["const"], 1)
        self.assertTrue(schema["properties"]["bridge_bearer_token"]["writeOnly"])
        self.assertTrue(schema["properties"]["device_id"]["readOnly"])
        self.assertNotIn("default", json.dumps(schema).lower())

    def test_feed_contract_requires_boolean_true(self):
        schema = self.load_json("docs/bridge-feed.schema.json")
        self.assertIs(schema["properties"]["read_only"]["const"], True)
        self.assertIn("read_only", schema["required"])
        safe = self.load_json("tests/fixtures/feed-safe.json")
        unsafe = self.load_json("tests/fixtures/feed-unsafe.json")
        self.assertIs(safe["read_only"], True)
        self.assertIs(unsafe["read_only"], False)

    def test_fixture_candles_are_valid_ohlcv(self):
        safe = self.load_json("tests/fixtures/feed-safe.json")
        for series in safe.get("candles", {}).values():
            for timestamp, opening, high, low, close, volume in series:
                self.assertGreater(timestamp, 0)
                self.assertGreaterEqual(high, max(opening, close))
                self.assertLessEqual(low, min(opening, close))
                self.assertGreaterEqual(volume, 0)

    def test_firmware_has_runtime_credentials_and_fail_closed_parser(self):
        main = (ROOT / "main/main.cc").read_text(encoding="utf-8")
        runtime = (ROOT / "main/runtime_config.cc").read_text(encoding="utf-8")
        self.assertIn("cJSON_IsTrue(ro)", main)
        self.assertIn("cJSON_ParseWithLengthOpts", main)
        self.assertIn("ro_count!=1", main)
        self.assertIn("disable_auto_redirect=true", main)
        self.assertIn("nvs_set_str", runtime)
        self.assertNotIn("FEED_" + "TOKEN", main)
        self.assertNotIn("FEED_" + "URL", main)
        self.assertNotIn("DEVICE_" + "ID", main)

    def test_no_private_literals_or_publishable_artifacts(self):
        old_private_token_name = "coinbase" + "-epaper-token"
        forbidden_text = re.compile(
            r"tail[0-9a-z]+\.ts\.net|" + re.escape(old_private_token_name) + r"|"
            r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"
        )
        forbidden_suffixes = {".bin", ".elf", ".map", ".log"}
        for path in ROOT.rglob("*"):
            if not path.is_file() or "build" in path.parts or "managed_components" in path.parts:
                continue
            self.assertNotIn(path.suffix.lower(), forbidden_suffixes, str(path))
            if path.suffix.lower() in {".cc", ".h", ".json", ".md", ".sh", ".txt", ""}:
                text = path.read_text(encoding="utf-8", errors="ignore")
                self.assertIsNone(forbidden_text.search(text), str(path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
