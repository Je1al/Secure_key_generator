#ifndef SECUREKG_STATS_STS_H_
#define SECUREKG_STATS_STS_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace securekg::stats {

using Bytes = std::vector<std::uint8_t>;
using Bits = std::vector<std::uint8_t>;  // each element is 0 or 1

// A subset of the NIST SP 800-22 Rev. 1a statistical test suite for random and
// pseudorandom number generators. Each test returns a p-value; the sequence
// "passes" a test at significance level alpha when p_value >= alpha (the NIST
// default alpha is 0.01).
struct TestResult {
  std::string name;
  bool applicable = false;  // false if the input was too small / preconditions failed
  double p_value = 0.0;
  bool passed = false;
  std::string detail;       // parameters or precondition notes
};

// Default significance level recommended by SP 800-22.
constexpr double kAlpha = 0.01;

// Expand bytes to a bit vector, most-significant-bit first within each byte.
Bits bytes_to_bits(const Bytes& data);

// Individual tests (operate on an already-expanded bit vector).
TestResult frequency_monobit(const Bits& bits, double alpha = kAlpha);
TestResult block_frequency(const Bits& bits, std::size_t block_size,
                           double alpha = kAlpha);
TestResult runs(const Bits& bits, double alpha = kAlpha);
TestResult longest_run_of_ones(const Bits& bits, double alpha = kAlpha);
// Cumulative sums returns two results: forward (mode 0) and backward (mode 1).
std::vector<TestResult> cumulative_sums(const Bits& bits, double alpha = kAlpha);
TestResult approximate_entropy(const Bits& bits, std::size_t m,
                               double alpha = kAlpha);
// Serial returns two results (the two p-values defined by the test).
std::vector<TestResult> serial(const Bits& bits, std::size_t m,
                               double alpha = kAlpha);

// Run the whole subset with parameters chosen automatically from the input
// length.
std::vector<TestResult> run_all(const Bytes& data, double alpha = kAlpha);

}  // namespace securekg::stats

#endif  // SECUREKG_STATS_STS_H_
