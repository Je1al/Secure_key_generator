#include "entropy_test.h"

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>

namespace secure_keygen {

EntropyResult shannon_entropy_test(const std::vector<uint8_t>& data) {
  constexpr double kIdeal = 8.0; // 8 bits per byte for a uniform distribution.

  if (data.empty()) {
    return {0.0, kIdeal, 0.0};
  }

  std::array<std::size_t, 256> counts{};
  for (uint8_t byte : data) {
    counts[byte]++;
  }

  double entropy = 0.0;
  double total = static_cast<double>(data.size());
  for (std::size_t count : counts) {
    if (count == 0) {
      continue;
    }
    double p = static_cast<double>(count) / total;
    entropy -= p * std::log2(p);
  }

  double percent = (entropy / kIdeal) * 100.0;
  return {entropy, kIdeal, percent};
}

} // namespace secure_keygen
