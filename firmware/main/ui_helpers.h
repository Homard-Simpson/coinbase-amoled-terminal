#pragma once

#include <cmath>
#include <cstddef>
#include <cstdio>
#include <ctime>

// Deterministic helpers shared by the firmware UI and host tests.
constexpr int kTopBarSafeInsetPx = 24;

struct TopBarAnchors {
  int left;
  int right;
};

constexpr TopBarAnchors top_bar_anchors(int display_width) {
  return {kTopBarSafeInsetPx, display_width - kTopBarSafeInsetPx};
}

inline double chart_level_value(double low, double high, int level, int intervals) {
  if (!std::isfinite(low) || !std::isfinite(high) || intervals <= 0) return 0;
  if (level < 0) level = 0;
  if (level > intervals) level = intervals;
  return high - (high - low) * static_cast<double>(level) / intervals;
}

// Keep axis labels inside the chart's narrow left gutter.
inline void format_axis_price(char* out, std::size_t size, double value) {
  if (!out || !size) return;
  const double a = std::fabs(value);
  if (!std::isfinite(value)) std::snprintf(out, size, "--");
  else if (a >= 100000.0) std::snprintf(out, size, "$%.0fK", value / 1000.0);
  else if (a >= 10000.0) std::snprintf(out, size, "$%.1fK", value / 1000.0);
  else if (a >= 1000.0) std::snprintf(out, size, "$%.0f", value);
  else if (a >= 100.0) std::snprintf(out, size, "$%.1f", value);
  else if (a >= 10.0) std::snprintf(out, size, "$%.2f", value);
  else if (a >= 1.0) std::snprintf(out, size, "$%.3f", value);
  else if (a >= 0.01) std::snprintf(out, size, "$%.4f", value);
  else std::snprintf(out, size, "$%.5f", value);
}

inline void format_time_12h(const std::tm& local, char* out, std::size_t size) {
  if (!out || !size) return;
  int hour = local.tm_hour % 12;
  if (hour == 0) hour = 12;
  std::snprintf(out, size, "%02d:%02d %s", hour, local.tm_min,
                local.tm_hour < 12 ? "AM" : "PM");
}
