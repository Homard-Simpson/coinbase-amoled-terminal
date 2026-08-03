#include <cassert>
#include "../main/control_policy.h"

int main() {
  assert(boot_release_action(0, false) == BootReleaseAction::kBottomAction);
  assert(boot_release_action(799, false) == BootReleaseAction::kBottomAction);
  assert(boot_release_action(800, false) == BootReleaseAction::kTogglePrivacy);
  assert(boot_release_action(9999, false) == BootReleaseAction::kTogglePrivacy);
  assert(boot_release_action(10000, false) == BootReleaseAction::kNone);
  assert(boot_release_action(10001, false) == BootReleaseAction::kNone);
  assert(boot_release_action(UINT64_MAX, false) == BootReleaseAction::kNone);
  assert(boot_release_action(500, true) == BootReleaseAction::kNone);
  assert(!boot_should_arm_ota(true, 9999, false));
  assert(boot_should_arm_ota(true, 10000, false));
  assert(!boot_should_arm_ota(false, 12000, false));
  assert(!boot_should_arm_ota(true, 12000, true));
  assert(!boot_should_arm_ota_on_release(true, false, 9999, false));
  assert(boot_should_arm_ota_on_release(true, false, 10000, false));
  assert(boot_should_arm_ota_on_release(true, false, 10001, false));
  assert(!boot_should_arm_ota_on_release(true, false, 10001, true));
  assert(!boot_should_arm_ota_on_release(false, false, 10001, false));

  // Battery-only operation retains full standby. Any valid VBUS source selects
  // display-only standby, independent of whether a battery is fitted.
  assert(power_standby_mode(false, true) == PowerStandbyMode::kFull);
  assert(power_standby_mode(false, false) == PowerStandbyMode::kFull);
  assert(power_standby_mode(true, true) == PowerStandbyMode::kDisplayOnly);
  assert(power_standby_mode(true, false) == PowerStandbyMode::kDisplayOnly);
  assert(power_standby_transition(PowerStandbyMode::kDisplayOnly, false, false) ==
         PowerStandbyTransition::kStay);
  assert(power_standby_transition(PowerStandbyMode::kDisplayOnly, true, false) ==
         PowerStandbyTransition::kToFull);
  assert(power_standby_transition(PowerStandbyMode::kDisplayOnly, true, true) ==
         PowerStandbyTransition::kStay);
  assert(power_standby_transition(PowerStandbyMode::kFull, true, true) ==
         PowerStandbyTransition::kToDisplayOnly);
  assert(power_standby_transition(PowerStandbyMode::kFull, true, false) ==
         PowerStandbyTransition::kStay);

  // Both touch and BOOT call this same action: chart -> PRICES, then
  // PRICES <-> POSITIONS.
  int chart = 3;
  bool positions = true;
  activate_bottom_action(chart, positions);
  assert(chart == -1 && !positions);
  activate_bottom_action(chart, positions);
  assert(chart == -1 && positions);
  activate_bottom_action(chart, positions);
  assert(chart == -1 && !positions);

  assert(kPowerPollSliceUs == 250000);
  assert(axp_runtime_write_allowed(0x41, 0x08));
  assert(!axp_runtime_write_allowed(0x41, 0x0c));
  assert(!axp_runtime_write_allowed(0x41, 0xff));
  assert(!axp_runtime_write_allowed(0x41, 0x00));
  assert(axp_runtime_write_allowed(0x49, 0x08));
  assert(!axp_runtime_write_allowed(0x49, 0xff));
  assert(!axp_runtime_write_allowed(0x48, 0xff));
  for (int reg = 0x80; reg <= 0x99; ++reg)
    assert(!axp_runtime_write_allowed(static_cast<uint8_t>(reg), 0xff));
}
