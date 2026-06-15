#include "securekg/entropy/min_entropy.h"

#include <array>
#include <cmath>

namespace securekg::entropy {
namespace {

// SP 800-90B 6.3.1 Most Common Value estimate.
// L samples, the most common value occurs c_max times. p_hat = c_max / L,
// upper 99% bound p_u = p_hat + 2.576 * sqrt(p_hat(1-p_hat)/(L-1)), and the
// min-entropy estimate is -log2(min(1, p_u)).
double mcv_min_entropy(std::size_t most_common, std::size_t total) {
  if (total == 0) return 0.0;
  double p_hat = static_cast<double>(most_common) / static_cast<double>(total);
  double p_u = p_hat;
  if (total > 1) {
    p_u += 2.576 * std::sqrt(p_hat * (1.0 - p_hat) /
                             static_cast<double>(total - 1));
  }
  if (p_u > 1.0) p_u = 1.0;
  if (p_u <= 0.0) return 0.0;
  return -std::log2(p_u);
}

}  // namespace

EntropyEstimate estimate_entropy(const Bytes& data) {
  EntropyEstimate e;
  if (data.empty()) return e;

  e.byte_count = data.size();
  e.bit_count = data.size() * 8;

  // Byte-symbol histogram.
  std::array<std::size_t, 256> hist{};
  for (std::uint8_t b : data) ++hist[b];

  std::size_t byte_mode = 0;
  double shannon = 0.0;
  for (std::size_t count : hist) {
    if (count > byte_mode) byte_mode = count;
    if (count > 0) {
      double p = static_cast<double>(count) / static_cast<double>(e.byte_count);
      shannon -= p * std::log2(p);
    }
  }
  e.shannon_per_byte = shannon;
  e.mcv_min_entropy_per_byte = mcv_min_entropy(byte_mode, e.byte_count);

  // Bit-symbol histogram.
  std::size_t ones = 0;
  for (std::uint8_t b : data)
    for (int i = 0; i < 8; ++i) ones += (b >> i) & 1u;
  std::size_t zeros = e.bit_count - ones;
  std::size_t bit_mode = ones > zeros ? ones : zeros;
  e.mcv_min_entropy_per_bit = mcv_min_entropy(bit_mode, e.bit_count);

  return e;
}

}  // namespace securekg::entropy
