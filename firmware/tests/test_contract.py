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

    def test_usb_onboarding_partition_and_esp_payload_exclude_coinbase_key(self):
        partitions = (ROOT / "partitions.csv").read_text(encoding="utf-8")
        portal = (ROOT / "main/network_portal.cc").read_text(encoding="utf-8")
        metadata = (ROOT / "main/onboarding_metadata.cc").read_text(
            encoding="utf-8"
        )
        self.assertIn("onboarding, data, 0x40,    0xE20000, 0x2000", partitions)
        self.assertIn("kMagic", metadata)
        self.assertIn("{'C', 'B', 'A', 'T', 'S', 'T', '0', '1'}", metadata)
        self.assertIn("mbedtls_sha256(", metadata)
        self.assertIn("OnboardingMetadata::GetInstance().Clear()", portal)
        self.assertIn("SafeProvisioningForm", portal)
        reset_script = (ROOT / "scripts/factory-reset.sh").read_text(encoding="utf-8")
        self.assertIn("erase_region 0x9000 0x6000", reset_script)
        self.assertIn("erase_region 0xE20000 0x2000", reset_script)

        start = portal.index("async function saveOnlySafeValues")
        end = portal.index("async function acknowledge", start)
        esp_request_builder = portal[start:end]
        self.assertIn("bridge_url", esp_request_builder)
        self.assertIn("device_id", esp_request_builder)
        self.assertIn("bridge_token", esp_request_builder)
        self.assertNotIn("private" + "Key", esp_request_builder)
        self.assertNotIn("api" + "Key", esp_request_builder)
        self.assertNotIn("PRIVATE " + "KEY-----", esp_request_builder)

    def test_physical_button_contract_and_v2_pmu_guard_are_unchanged(self):
        main = (ROOT / "main/main.cc").read_text(encoding="utf-8")
        self.assertIn("now-button_at>=10000", main)
        self.assertIn("held>=750", main)
        self.assertIn("#if BOARD_IS_V1", main)
        v1_start = main.index("static const uint8_t axp_seq")
        v2_boundary = main.index("#else", v1_start)
        self.assertIn("i2c_master_transmit", main[v1_start:v2_boundary])
        self.assertNotIn("i2c_master_transmit", main[v2_boundary:main.index("#endif", v2_boundary)])

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
