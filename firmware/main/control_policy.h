#pragma once

#include <cstdint>

enum class BootReleaseAction {
  kBottomAction,
  kTogglePrivacy,
  kNone,
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
