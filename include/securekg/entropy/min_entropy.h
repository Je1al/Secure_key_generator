#ifndef SECUREKG_ENTROPY_MIN_ENTROPY_H_
#define SECUREKG_ENTROPY_MIN_ENTROPY_H_

#include <cstddef>
#include <cstdint>
#include <vector>

namespace securekg::entropy {

using Bytes = std::vector<std::uint8_t>;

// Entropy assessment of a raw sample, following NIST SP 800-90B.
//
// The Most Common Value (MCV) estimate (SP 800-90B Section 6.3.1) is a real
// non-IID min-entropy estimator: it bounds the probability of the most likely
// value with a 99% upper confidence bound and converts it to min-entropy. We
// report it both over 8-bit symbols (bytes) and over the raw bit stream.
// Shannon entropy is reported alongside for context only -- it is an *upper*
// bound on the usable entropy, never the security-relevant figure.
struct EntropyEstimate {
  std::size_t byte_count = 0;
  std::size_t bit_count = 0;

  double shannon_per_byte = 0.0;       // 0..8 bits
  double mcv_min_entropy_per_byte = 0.0;  // 0..8 bits (SP 800-90B 6.3.1)
  double mcv_min_entropy_per_bit = 0.0;   // 0..1 bits (SP 800-90B 6.3.1)

  // Convenience: total estimated min-entropy of the sample using the per-byte
  // MCV estimate, in bits.
  double total_min_entropy_bits() const {
    return mcv_min_entropy_per_byte * static_cast<double>(byte_count);
  }
};

EntropyEstimate estimate_entropy(const Bytes& data);

}  // namespace securekg::entropy

#endif  // SECUREKG_ENTROPY_MIN_ENTROPY_H_
