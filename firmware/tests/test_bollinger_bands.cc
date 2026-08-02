#include <cassert>
#include <cmath>
#include <limits>
#include "../main/bollinger_bands.h"

static bool close_to(double actual, double expected, double tolerance = 1e-12) {
  return std::fabs(actual - expected) <= tolerance;
}

int main() {
  double closes[50] = {};
  BollingerPoint points[50] = {};
  for (int i = 0; i < 50; ++i) closes[i] = i + 1;

  const std::size_t count = compute_bollinger_bands(closes, 50, points, 50);
  assert(count == BOLLINGER_MAX_SAMPLES);
  for (int i = 0; i < BOLLINGER_PERIOD - 1; ++i) assert(!points[i].valid);

  // 1..20: mean=10.5, population variance=33.25.
  const double deviation = std::sqrt(33.25);
  assert(points[19].valid);
  assert(close_to(points[19].middle, 10.5));
  assert(close_to(points[19].upper, 10.5 + 2.0 * deviation));
  assert(close_to(points[19].lower, 10.5 - 2.0 * deviation));
  assert(points[20].valid);
  assert(close_to(points[20].middle, 11.5));

  double constant[BOLLINGER_PERIOD] = {};
  BollingerPoint constant_points[BOLLINGER_PERIOD] = {};
  for (double &value : constant) value = 100.0;
  compute_bollinger_bands(constant, BOLLINGER_PERIOD, constant_points,
                          BOLLINGER_PERIOD);
  assert(constant_points[19].valid);
  assert(constant_points[19].middle == 100.0);
  assert(constant_points[19].upper == 100.0);
  assert(constant_points[19].lower == 100.0);

  double interrupted[40] = {};
  BollingerPoint interrupted_points[40] = {};
  for (double &value : interrupted) value = 100.0;
  interrupted[10] = std::numeric_limits<double>::quiet_NaN();
  compute_bollinger_bands(interrupted, 40, interrupted_points, 40);
  assert(!interrupted_points[19].valid);
  assert(!interrupted_points[29].valid);
  assert(interrupted_points[30].valid);  // 20 valid closes after index 10.

  BollingerPoint nearby{100.0, 112.0, 88.0, true};
  BollingerPoint distant{100.0, 160.0, 40.0, true};
  assert(bollinger_point_near_range(nearby, 80.0, 120.0));
  assert(!bollinger_point_near_range(distant, 80.0, 120.0));
  return 0;
}
