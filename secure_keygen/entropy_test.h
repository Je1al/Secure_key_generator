#ifndef SECURE_KEYGEN_ENTROPY_TEST_H
#define SECURE_KEYGEN_ENTROPY_TEST_H

#include <cstdint>
#include <vector>

namespace secure_keygen {

struct EntropyResult {
  double shannon_entropy_bits_per_byte;
  double ideal_bits_per_byte;
  double percent_of_ideal;
};

EntropyResult shannon_entropy_test(const std::vector<uint8_t>& data);

} // namespace secure_keygen

#endif // SECURE_KEYGEN_ENTROPY_TEST_H
