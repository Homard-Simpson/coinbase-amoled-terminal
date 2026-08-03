#pragma once

#include <cstdint>

enum class BootReleaseAction {
  kBottomAction,
  kTogglePrivacy,
  kNone,
};

enum class PowerStandbyMode {
  kFull,
  kDisplayOnly,
};

constexpr uint64_t kBootPrivacyHoldMs = 800;
constexpr uint64_t kBootOtaHoldMs = 10000;
constexpr uint64_t kPowerPollSliceUs = 250000;

constexpr BootReleaseAction boot_release_action(uint64_t held_ms, bool ota_was_armed) {
  if (ota_was_armed || held_ms >= kBootOtaHoldMs) return BootReleaseAction::kNone;
  return held_ms >= kBootPrivacyHoldMs ? BootReleaseAction::kTogglePrivacy
                                       : BootReleaseAction::kBottomAction;
}

constexpr bool boot_should_arm_ota(bool button_down, uint64_t held_ms, bool already_handled) {
  return button_down && !already_handled && held_ms >= kBootOtaHoldMs;
}

// VBUS alone selects display-only standby. Battery presence is intentionally
// irrelevant so charging/full batteries and USB operation without a battery
// all keep networking and background tasks alive.
constexpr PowerStandbyMode power_standby_mode(bool vbus_present,
                                              bool /*battery_present*/) {
  return vbus_present ? PowerStandbyMode::kDisplayOnly
                      : PowerStandbyMode::kFull;
}

// Runtime AXP writes are limited to enabling and consuming PWRKEY short press.
constexpr bool axp_runtime_write_allowed(uint8_t reg, uint8_t value) {
  return (reg == 0x41 && (value & 0x08) != 0) ||
         (reg == 0x49 && value == 0x08);
}

// Shared by touch and BOOT so both execute precisely the blue bottom button.
constexpr void activate_bottom_action(int& selected_chart, bool& detail) {
  if (selected_chart >= 0) {
    selected_chart = -1;
    detail = false;
  } else {
    detail = !detail;
  }
}
