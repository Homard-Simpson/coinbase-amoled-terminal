#pragma once

#include <cmath>
#include <cstddef>

static constexpr int BOLLINGER_PERIOD = 20;
static constexpr int BOLLINGER_MAX_SAMPLES = 36;
static constexpr double BOLLINGER_SIGMAS = 2.0;
static constexpr double BOLLINGER_SCALE_NEAR_FRAC = 0.50;

struct BollingerPoint {
  double middle = 0;
  double upper = 0;
  double lower = 0;
  bool valid = false;
};

// Compute BB20 from contiguous finite positive closes. Invalid closes reset the
// rolling window, so no point is emitted until 20 valid samples follow it.
// Input and output are both hard-capped to the chart's 36-candle storage.
inline std::size_t compute_bollinger_bands(const double *closes,
                                           std::size_t count,
                                           BollingerPoint *out,
                                           std::size_t out_capacity) {
  if (!closes || !out) return 0;
  const std::size_t bounded = count < out_capacity ? count : out_capacity;
  const std::size_t n = bounded < static_cast<std::size_t>(BOLLINGER_MAX_SAMPLES)
                            ? bounded
                            : static_cast<std::size_t>(BOLLINGER_MAX_SAMPLES);
  double window[BOLLINGER_PERIOD] = {};
  int valid_run = 0;
  for (std::size_t i = 0; i < n; ++i) {
    out[i] = BollingerPoint{};
    const double close = closes[i];
    if (!(close > 0) || !std::isfinite(close)) {
      valid_run = 0;
      continue;
    }
    window[valid_run % BOLLINGER_PERIOD] = close;
    ++valid_run;
    if (valid_run < BOLLINGER_PERIOD) continue;
    double sum = 0;
    for (double value : window) sum += value;
    const double middle = sum / BOLLINGER_PERIOD;
    double squared = 0;
    for (double value : window) {
      const double delta = value - middle;
      squared += delta * delta;
    }
    const double deviation = std::sqrt(squared / BOLLINGER_PERIOD);
    const double upper = middle + BOLLINGER_SIGMAS * deviation;
    const double lower = middle - BOLLINGER_SIGMAS * deviation;
    if (std::isfinite(middle) && std::isfinite(upper) &&
        std::isfinite(lower)) {
      out[i] = {middle, upper, lower, true};
    }
  }
  return n;
}

// Bands may expand a candle chart by at most half its raw market-data range on
// either side. Values outside that guard are neither scaled nor drawn.
inline bool bollinger_point_near_range(const BollingerPoint &point,
                                       double candle_low,
                                       double candle_high) {
  if (!point.valid || !std::isfinite(candle_low) ||
      !std::isfinite(candle_high) || !(candle_high > candle_low)) return false;
  const double range = candle_high - candle_low;
  const double guarded_low = candle_low - range * BOLLINGER_SCALE_NEAR_FRAC;
  const double guarded_high = candle_high + range * BOLLINGER_SCALE_NEAR_FRAC;
  return point.lower >= guarded_low && point.upper <= guarded_high;
}
