#include "randomness_test.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

namespace secure_keygen {
namespace {

struct BitCounts {
  std::size_t ones = 0;
  std::size_t zeros = 0;
};

BitCounts count_bits(const std::vector<uint8_t>& data) {
  BitCounts counts;
  for (uint8_t byte : data) {
    for (int bit = 7; bit >= 0; --bit) {
      if ((byte >> bit) & 0x01u) {
        counts.ones++;
      } else {
        counts.zeros++;
      }
    }
  }
  return counts;
}

std::size_t count_runs(const std::vector<uint8_t>& data) {
  bool has_bit = false;
  int last_bit = 0;
  std::size_t runs = 0;

  for (uint8_t byte : data) {
    for (int bit = 7; bit >= 0; --bit) {
      int current = (byte >> bit) & 0x01u;
      if (!has_bit) {
        has_bit = true;
        last_bit = current;
        runs = 1;
        continue;
      }
      if (current != last_bit) {
        runs++;
        last_bit = current;
      }
    }
  }

  return runs;
}

} // namespace

RandomnessReport run_randomness_tests(const std::vector<uint8_t>& data) {
  RandomnessReport report{};

  if (data.empty()) {
    return report;
  }

  BitCounts counts = count_bits(data);
  std::size_t total_bits = counts.ones + counts.zeros;

  report.frequency.ones = counts.ones;
  report.frequency.zeros = counts.zeros;
  report.frequency.ones_ratio = total_bits == 0 ? 0.0 : static_cast<double>(counts.ones) / total_bits;
  report.frequency.imbalance = total_bits == 0
                                  ? 0.0
                                  : static_cast<double>(std::llabs(static_cast<long long>(counts.ones) -
                                                                   static_cast<long long>(counts.zeros))) /
                                        static_cast<double>(total_bits);

  // Runs test (NIST SP 800-22 approximation): only meaningful if ones ratio close to 0.5.
  double pi = report.frequency.ones_ratio;
  if (total_bits > 1) {
    double tau = 2.0 / std::sqrt(static_cast<double>(total_bits));
    if (std::fabs(pi - 0.5) < tau) {
      report.runs.applicable = true;
      report.runs.runs = count_runs(data);
      report.runs.expected_runs = (2.0 * total_bits * pi * (1.0 - pi)) + 1.0;
      double variance = (2.0 * total_bits * pi * (1.0 - pi) *
                         (2.0 * total_bits * pi * (1.0 - pi) - 1.0)) /
                        (static_cast<double>(total_bits) - 1.0);
      report.runs.z_score = variance > 0.0 ? (report.runs.runs - report.runs.expected_runs) /
                                                 std::sqrt(variance)
                                           : 0.0;
    }
  }

  report.bit_distribution.total_bytes = data.size();
  for (uint8_t byte : data) {
    for (int bit = 0; bit < 8; ++bit) {
      if ((byte >> bit) & 0x01u) {
        report.bit_distribution.ones_per_bit[bit]++;
      }
    }
  }

  return report;
}

} // namespace secure_keygen
