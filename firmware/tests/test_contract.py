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
        metadata = (ROOT / "main/onboarding_metadata.cc").read_text(encoding="utf-8")
        self.assertIn("onboarding, data, 0x40,    0xE20000, 0x2000", partitions)
        self.assertIn("kMagic", metadata)
        self.assertIn("{'C', 'B', 'A', 'T', 'S', 'T', '0', '1'}", metadata)
        self.assertIn("mbedtls_sha256(", metadata)
        self.assertIn('JsonString(root, "setup_token"', metadata)
        self.assertNotIn('JsonString(root, "completion_token"', metadata)
        self.assertIn("OnboardingMetadata::GetInstance().Clear()", portal)
        self.assertIn("SafeProvisioningForm", portal)
        self.assertIn("setupToken=''", portal)
        self.assertNotIn("completionToken", portal)
        self.assertIn(
            "finally{key='';pending=null;text.value='';file.value='';wifi.value=''}",
            portal,
        )
        self.assertIn("await abortPending(pending)", portal)
        self.assertIn(
            "key='';text.value='';file.value='';wifi.value='';await abortPending",
            portal,
        )
        self.assertIn("'/abort-pending'", portal)
        reset_script = (ROOT / "scripts/factory-reset.sh").read_text(encoding="utf-8")
        self.assertIn("erase_region 0x9000 0x6000", reset_script)
        self.assertIn("erase_region 0xE20000 0x2000", reset_script)

        start = portal.index("function safePendingBody")
        end = portal.index("document.getElementById('setup')", start)
        esp_request_builder = portal[start:end]
        self.assertIn("bridge_url", esp_request_builder)
        self.assertIn("device_id", esp_request_builder)
        self.assertIn("pending_token", esp_request_builder)
        self.assertNotIn("private" + "Key", esp_request_builder)
        self.assertNotIn("api" + "Key", esp_request_builder)
        self.assertNotIn("PRIVATE " + "KEY-----", esp_request_builder)

    def test_pending_nvs_is_two_phase_fail_closed_and_expires_by_wall_clock(self):
        runtime = (ROOT / "main/runtime_config.cc").read_text(encoding="utf-8")
        portal = (ROOT / "main/network_portal.cc").read_text(encoding="utf-8")
        main = (ROOT / "main/main.cc").read_text(encoding="utf-8")

        self.assertIn('kPendingStateKey[] = "pending_state"', runtime)
        self.assertIn("kPendingStateStaged", runtime)
        self.assertIn("kPendingStateCommitted", runtime)
        self.assertIn("pending_state != kPendingStateCommitted", runtime)
        self.assertIn("ErasePending(nvs)", runtime)
        self.assertNotIn("nvs_erase_all", runtime)
        stage_start = runtime.index("RuntimeConfig::StagePendingProvisioning")
        commit_start = runtime.index("RuntimeConfig::CommitPendingProvisioning")
        promote_start = runtime.index("RuntimeConfig::PromotePendingProvisioning")
        stage = runtime[stage_start:commit_start]
        commit = runtime[commit_start:promote_start]
        self.assertNotIn("config_.pending_bridge_url =", stage)
        self.assertIn("config_.pending_bridge_url = staged_pending_", commit)

        save_start = portal.index("esp_err_t SaveHandler")
        save_end = portal.index("esp_err_t AbortPendingHandler", save_start)
        save = portal[save_start:save_end]
        self.assertLess(save.index("StagePendingProvisioning"), save.index("SaveCredential"))
        self.assertLess(
            save.index("OnboardingMetadata::GetInstance().Clear()"),
            save.index("httpd_resp_sendstr"),
        )
        self.assertLess(save.index("httpd_resp_sendstr"), save.index("CommitPendingProvisioning"))
        self.assertIn("ClearPendingProvisioning", save)

        self.assertIn("WallClockExpired(loaded.pending_expires_at)", runtime)
        self.assertIn("pending_expired_by_wall_clock", main)
        self.assertIn("time(nullptr)", main)
        self.assertIn("MIN_VALID_EPOCH=1577836800", main)

    def test_pending_abort_and_factory_reset_are_bounded_and_key_free(self):
        portal = (ROOT / "main/network_portal.cc").read_text(encoding="utf-8")
        self.assertIn('"/v1/onboarding/rejection/abort"', portal)
        self.assertIn("config.timeout_ms = 5000", portal)
        self.assertIn("config.disable_auto_redirect = true", portal)
        self.assertIn("if (portal.IsConnected()) AbortPendingBridgeBestEffort(runtime)", portal)
        abort_start = portal.index("esp_err_t AbortPendingHandler")
        abort_end = portal.index("esp_err_t SaveOptionsHandler", abort_start)
        abort = portal[abort_start:abort_end]
        self.assertIn("SafePendingAbortForm", abort)
        self.assertIn("PendingBearerToken", abort)
        self.assertNotIn("privateKey", abort)
        self.assertNotIn("setupToken", abort)

    def test_power_standby_split_preserves_boot_ota_and_pmu_contracts(self):
        main = (ROOT / "main/main.cc").read_text(encoding="utf-8")
        controls = (ROOT / "main/control_policy.h").read_text(encoding="utf-8")
        portal_h = (ROOT / "main/network_portal.h").read_text(encoding="utf-8")
        portal_cc = (ROOT / "main/network_portal.cc").read_text(encoding="utf-8")
        ota_cc = (ROOT / "main/auto_ota_v2.cc").read_text(encoding="utf-8")
        coordinator_h = (ROOT / "main/ota_coordination.h").read_text(encoding="utf-8")
        coordinator_cc = (ROOT / "main/ota_coordination.cc").read_text(encoding="utf-8")
        version_policy = (ROOT / "main/ota_version_policy.h").read_text(encoding="utf-8")

        self.assertIn("kBootPrivacyHoldMs = 800", controls)
        self.assertIn("kBootOtaHoldMs = 10000", controls)
        self.assertIn("kPowerPollSliceUs = 250000", controls)
        self.assertIn("boot_should_arm_ota_on_release", controls)
        self.assertIn("boot_should_arm_ota_on_release", main)
        self.assertIn("BOOT >=10s release edge", main)
        self.assertIn("activate_bottom_action(selected_chart,detail)", main)
        self.assertIn("BootReleaseAction::kBottomAction&&!portal", main)
        self.assertNotIn("BootReleaseAction::kBottomAction&&!portal&&screen_on", main)
        self.assertIn("POWER short=standby/wake", main)
        self.assertIn("BOOT 0.8-<10s=privacy", main)
        self.assertNotIn("set_screen(!screen_on)", main)

        self.assertIn("power_standby_mode(g_batt.vbus,g_batt.present)", main)
        self.assertIn("if(!sample_valid)", main)
        self.assertIn("POWER standby deferred: unable to sample live VBUS", main)
        self.assertIn("power_standby_transition", main)
        self.assertIn("VBUS inserted during full standby", main)
        self.assertIn("VBUS removed during display-only standby", main)
        self.assertIn("PowerStandbyMode::kDisplayOnly", main)
        self.assertIn("waking USB display-only standby", main)
        self.assertIn("entering USB display-only standby", main)
        self.assertIn("enter_full_standby(network)", main)
        self.assertIn("touch_input_enabled.load", main)
        display_start = main.index("if(mode==PowerStandbyMode::kDisplayOnly)")
        display_end = main.index("} else {", display_start)
        display_only = main[display_start:display_end]
        self.assertIn("set_screen(false)", display_only)
        self.assertIn("touch_input_enabled.store(false", display_only)
        self.assertNotIn("network.Suspend()", display_only)
        full_start = main.index("static bool enter_full_standby")
        full_end = main.index('extern "C" void app_main()', full_start)
        full_standby = main[full_start:full_end]
        self.assertIn("FirmwareUpdateGuard update_guard(20000)", full_standby)
        self.assertIn("network.Suspend()", full_standby)
        self.assertIn("network.Resume()", full_standby)
        self.assertIn("STANDBY_REQUEST", full_standby)

        self.assertIn("FirmwareUpdateGuard update_guard(0)", portal_cc)
        self.assertIn("FirmwareUpdateGuard update_guard(1000)", ota_cc)
        self.assertIn("ota_upload_active.store(true)", portal_cc)
        self.assertIn("if (self->IsOtaBusy())", portal_cc)
        stop_start = portal_cc.index("void NetworkPortal::StopPortal()")
        stop_end = portal_cc.index("void NetworkPortal::ArmOta()", stop_start)
        self.assertIn("IsOtaBusy()", portal_cc[stop_start:stop_end])
        self.assertIn("FirmwareUpdateGuard operation_guard(UINT32_MAX)", portal_cc)
        self.assertIn("InitializeFirmwareUpdateGate", coordinator_h)
        self.assertIn("xSemaphoreCreateMutex", coordinator_cc)
        self.assertIn("AcquireFirmwareUpdateGate", coordinator_cc)
        self.assertIn("portMAX_DELAY", coordinator_cc)
        self.assertNotIn("SemaphoreHandle_t ota_gate", ota_cc)
        self.assertIn("bool IsOtaBusy() const;", portal_h)
        self.assertIn("network.IsOtaArmed()||network.IsOtaBusy()", main)

        self.assertIn("BoundedCStringView(desc->version", portal_cc)
        self.assertIn("terminal::ota::EndsWith(version, kBoardVersionSuffix)", portal_cc)
        self.assertIn("accepted_version.c_str()", portal_cc)
        self.assertNotIn("new_app_desc.version", portal_cc)
        self.assertIn("kMaxFirmwareVersionLength", version_policy)
        self.assertIn("kMaxVersionComponentDigits", version_policy)

        resume_start = portal_cc.index("void NetworkPortal::Resume()")
        resume_end = portal_cc.index("void NetworkPortal::CompletePendingSetup()", resume_start)
        resume = portal_cc[resume_start:resume_end]
        self.assertIn("esp_timer_start_once", resume)
        self.assertIn("kPortalFallbackSeconds", resume)

        self.assertIn("#if BOARD_IS_V1", main)
        v1_start = main.index("static const uint8_t axp_seq")
        v2_boundary = main.index("#else", v1_start)
        v1_block = main[v1_start:v2_boundary]
        self.assertIn("i2c_master_transmit", v1_block)
        rail_registers = [
            int(value, 16) for value in re.findall(r"\{0x([89][0-9A-Fa-f]),", v1_block)
        ]
        self.assertEqual(rail_registers, [0x80, 0x90, 0x91, 0x82, 0x92, 0x90])
        self.assertEqual(main.count("i2c_master_transmit(axp,"), 1)
        self.assertNotIn(
            "i2c_master_transmit", main[v2_boundary : main.index("#endif", v2_boundary)]
        )
        self.assertIn("axp_irq_write(0x41,0x08)", main)
        self.assertIn("axp_irq_write(0x49,0x08)", main)
        self.assertNotIn("en|0x08", main)
        self.assertNotIn("axp_irq_write(0x48", main)

    def test_both_variants_share_single_clock_row_privacy_and_chart_price_levels(self):
        main = (ROOT / "main/main.cc").read_text(encoding="utf-8")
        bridge = (
            ROOT.parent
            / "bridge/src/coinbase_amoled_bridge/device_feed.py"
        ).read_text(encoding="utf-8")

        self.assertIn('static std::string display_time="--:-- --"', main)
        self.assertIn("valid_display_time", main)
        helpers = (ROOT / "main/ui_helpers.h").read_text(encoding="utf-8")
        self.assertIn("kTopBarSafeInsetPx = 24", helpers)
        self.assertIn("constexpr TopBarAnchors top_bar=top_bar_anchors(W)", main)
        self.assertIn("draw_battery(top_bar.left,10)", main)
        self.assertIn("text_right(top_bar.right,12,display_time.c_str(),AXIS_BLUE,2)", main)
        self.assertNotIn("draw_battery(16,10)", main)
        self.assertNotIn("text_right(352,12,display_time.c_str(),AXIS_BLUE,2)", main)
        self.assertIn("AXIS_BLUE=rgb(125,175,210)", main)
        self.assertEqual(main.count("format_axis_price(axis"), 2)
        self.assertEqual(main.count("chart_level_value(lo,hi,i,4)"), 2)
        capture = (
            ROOT.parent / "tools/framebuffer_capture/production_draw.inc"
        ).read_text(encoding="utf-8")
        geometry_pattern = r"int gx=(\d+),gy=top\+50,gw=(\d+);"
        production_geometry = re.findall(geometry_pattern, main)
        capture_geometry = re.findall(geometry_pattern, capture)
        self.assertIn("constexpr TopBarAnchors top_bar=top_bar_anchors(W)", capture)
        self.assertIn("draw_battery(top_bar.left,10)", capture)
        self.assertIn(
            "text_right(top_bar.right,12,display_time.c_str(),AXIS_BLUE,2)", capture
        )
        self.assertEqual(production_geometry, [("94", "242")])
        self.assertEqual(capture_geometry, production_geometry)
        gx, gw = map(int, production_geometry[0])
        self.assertEqual(gx + gw, 336)
        production_levels = (ROOT / "main/key_levels.h").read_text(encoding="utf-8")
        capture_levels = (
            ROOT.parent / "tools/framebuffer_capture/key_levels.h"
        ).read_text(encoding="utf-8")
        self.assertEqual(capture_levels, production_levels)
        self.assertIn("key_levels_nearly_equal", production_levels)
        self.assertIn("pos > 0", production_levels)
        self.assertIn("privacy_mode", main)
        self.assertIn('privacy_mode?"MARKET":"FLAT"', main)
        self.assertNotIn("#if !BOARD_IS_V1\n      draw_price_levels", main)
        self.assertIn("display_time", bridge)
        self.assertIn('suffix = "AM" if now.hour < 12 else "PM"', bridge)
        self.assertIn('f"{hour:02d}:{now.minute:02d} {suffix}"', bridge)

    def test_v2_automatic_ota_is_signed_forward_only_and_v1_excluded(self):
        main = (ROOT / "main/main.cc").read_text(encoding="utf-8")
        cmake = (ROOT / "main/CMakeLists.txt").read_text(encoding="utf-8")
        ota = (ROOT / "main/auto_ota_v2.cc").read_text(encoding="utf-8")
        component = (ROOT / "main/idf_component.yml").read_text(encoding="utf-8")

        self.assertIn('"ota_coordination.cc"', cmake)
        self.assertIn("if(CONFIG_TERMINAL_BOARD_V2)", cmake)
        self.assertIn('list(APPEND terminal_sources "auto_ota_v2.cc")', cmake)
        self.assertIn("#if !BOARD_IS_V1\n  StartV2AutomaticOta();\n#endif", main)
        self.assertIn('espressif/libsodium: "1.0.22"', component)
        self.assertIn("crypto_sign_verify_detached", ota)
        self.assertIn("kReleasePublicKey", ota)
        self.assertIn("UniqueTrue(evidence, \"production_ready\")", ota)
        self.assertIn("UniqueTrue(attested, \"v2\")", ota)
        self.assertIn("terminal::ota::IsNewer(candidate.semantic_version, current)", ota)
        self.assertIn("ParseBoardFirmwareVersion", ota)
        self.assertIn("BoundedCStringView", ota)
        self.assertIn("terminal::ota::kMaxReleaseVersionLength + 1", ota)
        self.assertIn("terminal::ota::kAppVersionCapacity, &firmware", ota)
        self.assertIn("esp_ota_get_next_update_partition", ota)
        self.assertIn("esp_ota_end", ota)
        self.assertIn("esp_ota_set_boot_partition", ota)
        self.assertIn("ConstantTimeEqual(digest.data()", ota)
        self.assertIn("portal.IsPortalActive() || portal.IsOtaArmed()", ota)
        self.assertIn("FirmwareUpdateGuard update_guard(1000)", ota)
        self.assertNotIn("ota_gate", ota)

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
