#include <cassert>
#include <cmath>
#include <cstring>
#include "../main/ui_helpers.h"

int main() {
  constexpr TopBarAnchors top_bar = top_bar_anchors(368);
  static_assert(top_bar.left == 24 && top_bar.right == 344);
  static_assert(top_bar.left == 368 - top_bar.right);
  static_assert(top_bar.left > 16);

  assert(std::fabs(chart_level_value(80.0, 120.0, 0, 4) - 120.0) < 1e-12);
  assert(std::fabs(chart_level_value(80.0, 120.0, 2, 4) - 100.0) < 1e-12);
  assert(std::fabs(chart_level_value(80.0, 120.0, 4, 4) - 80.0) < 1e-12);

  char price[16]{};
  format_axis_price(price, sizeof(price), 68420.0);
  assert(std::strcmp(price, "$68.4K") == 0);
  format_axis_price(price, sizeof(price), 188.25);
  assert(std::strcmp(price, "$188.2") == 0);
  format_axis_price(price, sizeof(price), 0.01234);
  assert(std::strcmp(price, "$0.0123") == 0);

  char clock[16]{};
  std::tm local{};
  local.tm_hour = 0; local.tm_min = 5;
  format_time_12h(local, clock, sizeof(clock));
  assert(std::strcmp(clock, "12:05 AM") == 0);
  local.tm_hour = 12; local.tm_min = 30;
  format_time_12h(local, clock, sizeof(clock));
  assert(std::strcmp(clock, "12:30 PM") == 0);
  local.tm_hour = 21; local.tm_min = 7;
  format_time_12h(local, clock, sizeof(clock));
  assert(std::strcmp(clock, "09:07 PM") == 0);
  return 0;
}
