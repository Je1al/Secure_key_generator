#include "entropy_test.h"
#include "keygen.h"
#include "randomness_test.h"

#include <iomanip>
#include <iostream>
#include <string>

using secure_keygen::EntropyResult;
using secure_keygen::KeyGenerator;
using secure_keygen::KeyOutput;
using secure_keygen::RandomnessReport;

namespace {

void print_key(const std::string& label, const KeyOutput& key) {
  std::cout << "\n=== " << label << " ===\n";
  std::cout << "Hex     : " << key.hex << "\n";
  std::cout << "Binary  : " << key.binary << "\n";
  std::cout << "Base64  : " << key.base64 << "\n";
}

void print_entropy(const EntropyResult& result) {
  std::cout << "\nEntropy Test (Shannon)\n";
  std::cout << "- Entropy: " << std::fixed << std::setprecision(4)
            << result.shannon_entropy_bits_per_byte << " bits/byte\n";
  std::cout << "- Ideal  : " << result.ideal_bits_per_byte << " bits/byte\n";
  std::cout << "- Score  : " << std::setprecision(2) << result.percent_of_ideal
            << "% of ideal randomness\n";
  std::cout << "Explanation: Values near 8.0 bits/byte indicate a nearly uniform byte distribution.\n";
}

void print_randomness(const RandomnessReport& report) {
  std::cout << "\nRandomness Tests\n";
  std::cout << "Frequency (Monobit) Test\n";
  std::cout << "- Ones  : " << report.frequency.ones << "\n";
  std::cout << "- Zeros : " << report.frequency.zeros << "\n";
  std::cout << "- Ones ratio : " << std::fixed << std::setprecision(4)
            << report.frequency.ones_ratio << "\n";
  std::cout << "- Imbalance  : " << report.frequency.imbalance << "\n";
  std::cout << "Explanation: A ratio close to 0.5 indicates balanced 0s and 1s.\n";

  std::cout << "\nRuns Test\n";
  if (report.runs.applicable) {
    std::cout << "- Runs observed : " << report.runs.runs << "\n";
    std::cout << "- Runs expected : " << std::fixed << std::setprecision(2)
              << report.runs.expected_runs << "\n";
    std::cout << "- Z-score       : " << std::setprecision(3) << report.runs.z_score << "\n";
    std::cout << "Explanation: Runs measure switching between 0s and 1s; extreme Z-scores may indicate bias.\n";
  } else {
    std::cout << "- Not applicable (bit balance too far from 0.5 for a valid runs test).\n";
  }

  std::cout << "\nBit Distribution Test\n";
  for (int bit = 0; bit < 8; ++bit) {
    double ratio = report.bit_distribution.total_bytes == 0
                       ? 0.0
                       : static_cast<double>(report.bit_distribution.ones_per_bit[bit]) /
                             static_cast<double>(report.bit_distribution.total_bytes);
    std::cout << "- Bit " << bit << " ones ratio: " << std::fixed << std::setprecision(4)
              << ratio << "\n";
  }
  std::cout << "Explanation: Each bit position should be close to a 0.5 ones ratio in a uniform key.\n";
}

} // namespace

int main() {
  KeyGenerator generator;

  const KeyGenerator::KeySizeBits sizes[] = {
      KeyGenerator::KeySizeBits::Bits128,
      KeyGenerator::KeySizeBits::Bits256,
      KeyGenerator::KeySizeBits::Bits512};

  for (auto size : sizes) {
    KeyOutput key = generator.generate(size);

    std::string label;
    if (size == KeyGenerator::KeySizeBits::Bits128) {
      label = "128-bit Key";
    } else if (size == KeyGenerator::KeySizeBits::Bits256) {
      label = "256-bit Key";
    } else {
      label = "512-bit Key";
    }

    print_key(label, key);

    EntropyResult entropy = secure_keygen::shannon_entropy_test(key.bytes);
    print_entropy(entropy);

    RandomnessReport report = secure_keygen::run_randomness_tests(key.bytes);
    print_randomness(report);
  }

  std::cout << "\nNote: These tests provide basic statistical checks and are not a substitute for\n";
  std::cout << "full NIST randomness testing or formal cryptographic validation.\n";

  return 0;
}
