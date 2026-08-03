#include <cassert>
#include <cstring>
#include <string>
#include <string_view>

#include "../main/ota_version_policy.h"

int main() {
  using terminal::ota::BoundedCStringView;
  using terminal::ota::IsNewer;
  using terminal::ota::ParseBoardFirmwareVersion;
  using terminal::ota::SemanticVersion;

  std::string_view view;
  const char terminated[] = "2.0.1-v2";
  assert(BoundedCStringView(terminated, sizeof(terminated), &view));
  assert(view == "2.0.1-v2");
  char maximum[terminal::ota::kAppVersionCapacity];
  std::memset(maximum, '1', sizeof(maximum));
  maximum[sizeof(maximum) - 1] = '\0';
  assert(BoundedCStringView(maximum, sizeof(maximum), &view));
  assert(view.size() == terminal::ota::kMaxFirmwareVersionLength);
  char unterminated[terminal::ota::kAppVersionCapacity];
  std::memset(unterminated, '7', sizeof(unterminated));
  assert(!BoundedCStringView(unterminated, sizeof(unterminated), &view));

  SemanticVersion parsed;
  assert(ParseBoardFirmwareVersion("2.0.1-v2", "-v2", &parsed));
  assert(parsed.major == 2 && parsed.minor == 0 && parsed.patch == 1);
  assert(!ParseBoardFirmwareVersion("2.0.1-v1", "-v2", &parsed));
  assert(!ParseBoardFirmwareVersion("2.0-v2", "-v2", &parsed));
  assert(!ParseBoardFirmwareVersion("2.0.1-rc1-v2", "-v2", &parsed));
  assert(!ParseBoardFirmwareVersion("01.0.1-v2", "-v2", &parsed));
  assert(!ParseBoardFirmwareVersion("2.00.1-v2", "-v2", &parsed));
  assert(!ParseBoardFirmwareVersion("2.0.01-v2", "-v2", &parsed));
  assert(ParseBoardFirmwareVersion("4294967295.1.1-v2", "-v2", &parsed));
  assert(!ParseBoardFirmwareVersion("4294967296.1.1-v2", "-v2", &parsed));
  assert(!ParseBoardFirmwareVersion("00000000000.1.1-v2", "-v2", &parsed));
  const std::string oversized(terminal::ota::kMaxFirmwareVersionLength + 1, '1');
  assert(!ParseBoardFirmwareVersion(oversized, "-v2", &parsed));

  SemanticVersion current{2, 0, 0};
  assert(IsNewer(SemanticVersion{2, 0, 1}, current));
  assert(!IsNewer(current, current));
  assert(!IsNewer(SemanticVersion{1, 99, 99}, current));
  return 0;
}
