#include <cassert>
#include <cmath>
#include <initializer_list>
#include "../main/key_levels.h"

int main() {
  KeyLevels levels;
  assert(!add_key_level(levels, 0));
  assert(!add_key_level(levels, NAN));
  for (double value : {105.0, 95.0, 110.0, 90.0, 100.0, 105.0, 85.0, 80.0, 75.0, 70.0, 65.0})
    add_key_level(levels, value);
  assert(levels.count == KEY_LEVEL_CAPACITY);
  for (int i = 1; i < levels.count; ++i) assert(levels.values[i - 1] < levels.values[i]);

  double support = 0, resistance = 0;
  nearest_key_levels(levels, 97.0, support, resistance);
  assert(support == 95.0);
  assert(resistance == 100.0);

  nearest_key_levels(levels, -1.0, support, resistance);
  assert(support == 0);
  assert(resistance == 0);
  return 0;
}
