#ifndef SECURE_KEYGEN_RANDOMNESS_TEST_H
#define SECURE_KEYGEN_RANDOMNESS_TEST_H

#include <array>
#include <cstdint>
#include <vector>

namespace secure_keygen {

struct FrequencyTestResult {
  std::size_t ones = 0;
  std::size_t zeros = 0;
  double ones_ratio = 0.0;
  double imbalance = 0.0; // |ones - zeros| / total_bits
};

struct RunsTestResult {
  std::size_t runs = 0;
  double expected_runs = 0.0;
  double z_score = 0.0;
  bool applicable = false;
};

struct BitDistributionResult {
  std::array<std::size_t, 8> ones_per_bit{};
  std::size_t total_bytes = 0;
};

struct RandomnessReport {
  FrequencyTestResult frequency;
  RunsTestResult runs;
  BitDistributionResult bit_distribution;
};

RandomnessReport run_randomness_tests(const std::vector<uint8_t>& data);

} // namespace secure_keygen

#endif // SECURE_KEYGEN_RANDOMNESS_TEST_H
