#pragma once

#include <cmath>
#include <cstdint>

static constexpr int KEY_LEVEL_CAPACITY = 8;

struct KeyLevels {
  double values[KEY_LEVEL_CAPACITY] = {};
  uint8_t count = 0;
};

inline void clear_key_levels(KeyLevels &levels) { levels.count = 0; }

// Sorted insertion keeps storage deterministic and bounded even for a malformed
// or oversized feed. Once full, retain the eight lowest sorted values; the feed
// contract itself is capped at eight, so this is only defensive behavior.
inline bool add_key_level(KeyLevels &levels, double value) {
  if (!(value > 0) || !std::isfinite(value)) return false;
  int pos = 0;
  while (pos < levels.count && levels.values[pos] < value) pos++;
  if (pos < levels.count && std::fabs(levels.values[pos] - value) <=
      std::fmax(1e-12, std::fabs(value) * 1e-9)) return false;
  if (levels.count == KEY_LEVEL_CAPACITY && pos == KEY_LEVEL_CAPACITY) return false;
  int last = levels.count < KEY_LEVEL_CAPACITY ? levels.count : KEY_LEVEL_CAPACITY - 1;
  for (int i = last; i > pos; --i) levels.values[i] = levels.values[i - 1];
  levels.values[pos] = value;
  if (levels.count < KEY_LEVEL_CAPACITY) levels.count++;
  return true;
}

inline void nearest_key_levels(const KeyLevels &levels, double price,
                               double &support, double &resistance) {
  support = 0;
  resistance = 0;
  if (!(price > 0) || !std::isfinite(price)) return;
  for (int i = 0; i < levels.count; ++i) {
    const double level = levels.values[i];
    if (level < price) support = level;
    else if (level > price) { resistance = level; break; }
  }
}
