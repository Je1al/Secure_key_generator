#ifndef SECURE_KEYGEN_ENTROPY_COLLECTOR_H
#define SECURE_KEYGEN_ENTROPY_COLLECTOR_H

#include <cstddef>
#include <cstdint>
#include <vector>

namespace secure_keygen {

class EntropyCollector {
public:
  // Collects entropy from multiple system sources to build a pool.
  std::vector<uint8_t> collect(std::size_t min_bytes = 64) const;

private:
  static void append_u64(std::vector<uint8_t>& out, std::uint64_t value);
  static void append_bytes(std::vector<uint8_t>& out, const std::vector<uint8_t>& bytes);

  std::vector<uint8_t> os_random_bytes(std::size_t count) const;
  std::vector<uint8_t> timing_bytes() const;
  std::vector<uint8_t> process_bytes() const;
  std::vector<uint8_t> memory_bytes() const;
};

} // namespace secure_keygen

#endif // SECURE_KEYGEN_ENTROPY_COLLECTOR_H
