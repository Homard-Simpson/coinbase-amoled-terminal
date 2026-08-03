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

enum class PowerStandbyTransition {
  kStay,
  kToFull,
  kToDisplayOnly,
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

// A release can be the first sample at or beyond 10 seconds. Arm OTA rather
// than falling through to privacy or the bottom action.
constexpr bool boot_should_arm_ota_on_release(bool was_down, bool button_down,
                                              uint64_t held_ms,
                                              bool already_handled) {
  return was_down && !button_down && !already_handled &&
         held_ms >= kBootOtaHoldMs;
}

// VBUS alone selects display-only standby. Battery presence is intentionally
// irrelevant so charging/full batteries and USB operation without a battery
// all keep networking and background tasks alive.
constexpr PowerStandbyMode power_standby_mode(bool vbus_present,
                                              bool /*battery_present*/) {
  return vbus_present ? PowerStandbyMode::kDisplayOnly
                      : PowerStandbyMode::kFull;
}

// Invalid PMU samples preserve the current mode. Valid VBUS changes transition
// between background-capable display-only standby and battery full standby.
constexpr PowerStandbyTransition power_standby_transition(
    PowerStandbyMode current, bool sample_valid, bool vbus_present) {
  if (!sample_valid) return PowerStandbyTransition::kStay;
  if (current == PowerStandbyMode::kDisplayOnly && !vbus_present)
    return PowerStandbyTransition::kToFull;
  if (current == PowerStandbyMode::kFull && vbus_present)
    return PowerStandbyTransition::kToDisplayOnly;
  return PowerStandbyTransition::kStay;
}

// Runtime AXP writes are limited to exact PWRKEY IRQ enable/status values.
constexpr bool axp_runtime_write_allowed(uint8_t reg, uint8_t value) {
  return (reg == 0x41 || reg == 0x49) && value == 0x08;
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
